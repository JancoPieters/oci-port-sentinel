<?php

namespace OciPortSentinel\Listeners;

use App\Models\Server;
use Illuminate\Support\Facades\Log;
use OciPortSentinel\Services\OciFirewallService;

class CloseFirewallPortsListener
{
    public function __construct(private readonly OciFirewallService $firewallService)
    {
    }

    /**
     * Called from the Server::deleting Eloquent hook. Pelican releases every
     * allocation from the server BEFORE this hook fires (query-builder update,
     * no model events), so the allocation ports can no longer be read from the
     * database. Instead we remove the ingress rules tagged with this server's
     * "#<id>" description.
     *
     * Cleanup always runs, even for Wings excluded by the firewall filter: only
     * rules this plugin created for this server are removed, so this is safe.
     */
    public function handleServerDeleting(Server $server): void
    {
        Log::channel('daily')->info('[OciPortSentinel] Closing firewall rules for deleted server ' . $server->id . ' ("' . $server->name . '").');

        try {
            $this->firewallService->closeServerRules($server->id);
            Log::channel('daily')->info('[OciPortSentinel] Successfully removed firewall rules for server ' . $server->id);
        } catch (\Throwable $e) {
            Log::channel('daily')->error('[OciPortSentinel] Failed to remove firewall rules for server ' . $server->id . ': ' . $e->getMessage());
        }
    }
}
