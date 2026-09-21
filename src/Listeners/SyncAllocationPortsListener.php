<?php

namespace OciPortSentinel\Listeners;

use App\Models\Allocation;
use App\Models\Server;
use Illuminate\Support\Facades\Log;
use OciPortSentinel\OciPortSentinel;
use OciPortSentinel\Services\OciFirewallService;

/**
 * Keeps the OCI Security List in sync when a server's allocations change after
 * creation (adding, removing or moving an allocation, or editing its port).
 *
 * Allocation assignment/unassignment that goes through model save()/create()
 * fires these Eloquent events. Release-on-delete uses a query-builder update
 * and does NOT fire events — that path is handled by CloseFirewallPortsListener
 * via the Server::deleting hook instead.
 */
class SyncAllocationPortsListener
{
    public function __construct(private readonly OciFirewallService $firewallService)
    {
    }

    public function created(Allocation $allocation): void
    {
        if ($allocation->server_id === null) {
            return; // Pool allocation, not bound to a server yet
        }

        $this->openForAllocation($allocation);
    }

    public function updated(Allocation $allocation): void
    {
        $oldServer = $allocation->getOriginal('server_id');
        $newServer = $allocation->server_id;
        $oldPort   = (int) $allocation->getOriginal('port');
        $newPort   = (int) $allocation->port;

        if ($oldServer === $newServer) {
            // Same server, port edited in place
            if ($oldPort !== $newPort) {
                $this->closePort($oldPort);
                $this->openForAllocation($allocation);
            }

            return;
        }

        // Allocation moved between servers (or assigned/unassigned)
        if ($oldServer !== null) {
            $this->closePort($oldPort);
        }

        if ($newServer !== null) {
            $this->openForAllocation($allocation);
        }
    }

    public function deleted(Allocation $allocation): void
    {
        // Pelican refuses to delete an allocation while it is assigned, so a
        // server_id here only exists if the release did not fire an event.
        if ($allocation->server_id === null) {
            return;
        }

        $this->closePort((int) $allocation->port);
    }

    private function openForAllocation(Allocation $allocation): void
    {
        $server = Server::query()->find($allocation->server_id);

        if (!$server || !OciPortSentinel::shouldManageNode($server->node_id)) {
            return;
        }

        try {
            $this->firewallService->openPorts([(int) $allocation->port], $server->id, $server->name);
            Log::channel('daily')->info('[OciPortSentinel] Allocation ' . $allocation->id . ' opened port ' . $allocation->port . ' for server ' . $server->id . ' ("' . $server->name . '").');
        } catch (\Throwable $e) {
            Log::channel('daily')->error('[OciPortSentinel] Failed to open port ' . $allocation->port . ' for server ' . $server->id . ': ' . $e->getMessage());
        }
    }

    private function closePort(int $port): void
    {
        if (!config('oci-port-sentinel.auto_close_ports', true)) {
            return;
        }

        try {
            $this->firewallService->closePorts([$port]);
            Log::channel('daily')->info('[OciPortSentinel] Closed port ' . $port . ' after an allocation change.');
        } catch (\Throwable $e) {
            Log::channel('daily')->error('[OciPortSentinel] Failed to close port ' . $port . ' after an allocation change: ' . $e->getMessage());
        }
    }
}