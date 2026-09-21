<?php

namespace OciPortSentinel\Providers;

use App\Events\Server\Installed as ServerInstalled;
use App\Models\Allocation;
use App\Models\Server;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use OciPortSentinel\Listeners\CloseFirewallPortsListener;
use OciPortSentinel\Listeners\OpenFirewallPortsListener;
use OciPortSentinel\Listeners\SyncAllocationPortsListener;
use OciPortSentinel\Services\OciFirewallService;

class OciPortSentinelServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(OciFirewallService::class, function () {
            return new OciFirewallService(
                tenancyOcid:         config('oci-port-sentinel.tenancy_ocid'),
                userOcid:            config('oci-port-sentinel.user_ocid'),
                keyFingerprint:      config('oci-port-sentinel.key_fingerprint'),
                privateKeyPath:      config('oci-port-sentinel.private_key_path'),
                privateKeyPassphrase: config('oci-port-sentinel.private_key_passphrase'),
                region:              config('oci-port-sentinel.region'),
                securityListOcid:    config('oci-port-sentinel.security_list_ocid'),
                sourceCidr:          config('oci-port-sentinel.source_cidr'),
            );
        });
    }

    public function boot(): void
    {
        // Open ports when a server finishes its initial installation
        Event::listen(ServerInstalled::class, OpenFirewallPortsListener::class);

        // Sync ports when a server's allocations change after creation
        Allocation::observe(app(SyncAllocationPortsListener::class));

        // Close ports when a server is deleted (Eloquent model observer)
        Server::deleting(function (Server $server) {
            if (!config('oci-port-sentinel.auto_close_ports', true)) {
                return;
            }

            /** @var CloseFirewallPortsListener $listener */
            $listener = app(CloseFirewallPortsListener::class);
            $listener->handleServerDeleting($server);
        });
    }
}
