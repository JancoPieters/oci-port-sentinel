<?php

namespace OciPortSentinel\Listeners;

use App\Events\Server\Installed as ServerInstalled;
use Illuminate\Support\Facades\Log;
use OciPortSentinel\OciPortSentinel;
use OciPortSentinel\Services\OciFirewallService;

class OpenFirewallPortsListener
{
    public function __construct(private readonly OciFirewallService $firewallService)
    {
    }

    public function handle(ServerInstalled $event): void
    {
        // Only open ports on initial install, not reinstall
        if (!$event->initialInstall) {
            return;
        }

        $server = $event->server;

        if (!OciPortSentinel::shouldManageNode($server->node_id)) {
            Log::channel('daily')->info('[OciPortSentinel] Skipping firewall update for server ' . $server->id . ' ("' . $server->name . '") on node ' . $server->node_id . ' (excluded by Wing filtering).');
            return;
        }

        $server->loadMissing('allocations');

        $ports = $server->allocations->pluck('port')->unique()->values()->toArray();

        if (empty($ports)) {
            Log::channel('daily')->warning('[OciPortSentinel] Server ' . $server->id . ' ("' . $server->name . '") has no port allocations; skipping firewall update.');
            return;
        }

        Log::channel('daily')->info('[OciPortSentinel] Opening ports for server ' . $server->id . ' ("' . $server->name . '"): ' . implode(', ', $ports));

        try {
            $this->firewallService->openPorts($ports, $server->id, $server->name);
            Log::channel('daily')->info('[OciPortSentinel] Successfully opened ports for server ' . $server->id);
        } catch (\Throwable $e) {
            Log::channel('daily')->error('[OciPortSentinel] Failed to open ports for server ' . $server->id . ': ' . $e->getMessage());
        }
    }
}
