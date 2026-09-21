<?php

namespace OciPortSentinel;

use App\Contracts\Plugins\HasPluginSettings;
use App\Models\Node;
use Filament\Contracts\Plugin;
use Filament\Forms\Components\FileUpload;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Notifications\Notification;
use Filament\Panel;
use Filament\Schemas\Components\Section;
use Illuminate\Support\Facades\Storage;

class OciPortSentinel implements Plugin, HasPluginSettings
{
    use \App\Traits\EnvironmentWriterTrait;

    public function getId(): string
    {
        return 'oci-port-sentinel';
    }

    public function register(Panel $panel): void
    {
        // No panel-specific resources needed
    }

    public function boot(Panel $panel): void
    {
        // No panel-specific boot needed
    }

    // -------------------------------------------------------------------------
    // Node (Wing) filtering policy
    // -------------------------------------------------------------------------

    /**
     * Returns true when the plugin should open firewall rules for a server
     * living on the given node, based on the whitelist/blacklist config.
     */
    public static function shouldManageNode(?int $nodeId): bool
    {
        $mode = config('oci-port-sentinel.node_mode', 'all');

        if ($mode === 'all' || $nodeId === null) {
            return true;
        }

        $ids = array_map('intval', array_filter(explode(',', (string) config('oci-port-sentinel.node_ids', ''))));

        if ($mode === 'whitelist') {
            return in_array($nodeId, $ids, true);
        }

        // blacklist
        return !in_array($nodeId, $ids, true);
    }

    // -------------------------------------------------------------------------
    // HasPluginSettings implementation
    // -------------------------------------------------------------------------

    public function getSettingsFormData(): array
    {
        return [
            'tenancy_ocid'           => config('oci-port-sentinel.tenancy_ocid'),
            'user_ocid'              => config('oci-port-sentinel.user_ocid'),
            'key_fingerprint'        => config('oci-port-sentinel.key_fingerprint'),
            'private_key_path'       => config('oci-port-sentinel.private_key_path'),
            'private_key_passphrase' => config('oci-port-sentinel.private_key_passphrase'),
            'region'                 => config('oci-port-sentinel.region'),
            'security_list_ocid'     => config('oci-port-sentinel.security_list_ocid'),
            'source_cidr'            => config('oci-port-sentinel.source_cidr'),
            'auto_close_ports'       => config('oci-port-sentinel.auto_close_ports', true),
            'node_mode'              => config('oci-port-sentinel.node_mode', 'all'),
            'node_ids'               => array_values(array_filter(array_map(
                'intval',
                explode(',', (string) config('oci-port-sentinel.node_ids', ''))
            ))),
        ];
    }

    public function getSettingsForm(): array
    {
        return [
            Section::make('OCI Authentication')
                ->description('Credentials for the Oracle Cloud Infrastructure API. All values are stored in your .env file.')
                ->schema([
                    TextInput::make('tenancy_ocid')
                        ->label('Tenancy OCID')
                        ->placeholder('ocid1.tenancy.oc1..aaa...')
                        ->required()
                        ->columnSpanFull(),

                    TextInput::make('user_ocid')
                        ->label('User OCID')
                        ->placeholder('ocid1.user.oc1..aaa...')
                        ->required()
                        ->columnSpanFull(),

                    TextInput::make('key_fingerprint')
                        ->label('API Key Fingerprint')
                        ->placeholder('a1:b2:c3:d4:e5:f6:a7:b8:c9:d0:e1:f2:a3:b4:c5:d6')
                        ->required(),

                    TextInput::make('region')
                        ->label('OCI Region')
                        ->placeholder('us-ashburn-1')
                        ->required(),
                ])
                ->columns(2),

            Section::make('Private Key')
                ->description('Upload the RSA private key used to sign OCI API requests, or point to an existing key file on the server. Uploaded keys are stored outside the web root.')
                ->schema([
                    FileUpload::make('private_key')
                        ->label('Private Key (PEM file)')
                        ->helperText('Upload your oci_api_key.pem. Only valid PEM private keys are accepted; everything else is rejected on save.')
                        ->maxSize(8192)
                        ->previewable(false)
                        ->columnSpanFull(),

                    TextInput::make('private_key_path')
                        ->label('Private Key Path (optional)')
                        ->placeholder('/etc/pelican/oci_api_key.pem')
                        ->helperText('Only used if you place the key on the server yourself instead of uploading it.')
                        ->columnSpanFull(),

                    TextInput::make('private_key_passphrase')
                        ->label('Private Key Passphrase')
                        ->placeholder('Leave blank if the key has no passphrase')
                        ->password()
                        ->revealable()
                        ->columnSpanFull(),
                ]),

            Section::make('Firewall Target')
                ->description('The OCI Security List that will be updated when servers are created or deleted.')
                ->schema([
                    TextInput::make('security_list_ocid')
                        ->label('Security List OCID')
                        ->placeholder('ocid1.securitylist.oc1.iad.aaa...')
                        ->required()
                        ->columnSpanFull(),

                    TextInput::make('source_cidr')
                        ->label('Source CIDR')
                        ->placeholder('0.0.0.0/0')
                        ->helperText('IP range allowed to reach opened ports. Use 0.0.0.0/0 to allow all internet traffic.')
                        ->required(),
                ])
                ->columns(2),

            Section::make('Behaviour')
                ->schema([
                    Toggle::make('auto_close_ports')
                        ->label('Auto-close ports on server deletion')
                        ->helperText('When enabled, ingress rules for this server\'s ports are removed from the Security List when the server is deleted. Only rules that were tagged with the Pelican description are removed.')
                        ->inline(false),
                ]),

            Section::make('Wing Filtering')
                ->description('Restrict which Wings port rules are opened for. Servers installed on an excluded Wing do not get their ports added to the Security List.')
                ->schema([
                    Select::make('node_mode')
                        ->label('Mode')
                        ->options([
                            'all' => 'All Wings',
                            'whitelist' => 'Whitelist — only these Wings',
                            'blacklist' => 'Blacklist — all Wings except these',
                        ])
                        ->default('all'),

                    Select::make('node_ids')
                        ->label('Wings')
                        ->options(fn () => Node::query()->orderBy('name')->pluck('name', 'id'))
                        ->multiple()
                        ->searchable()
                        ->helperText('Select the Wings to whitelist or blacklist.'),
                ])
                ->columns(2),
        ];
    }

    public function saveSettings(array $data): void
    {
        $keyPath = trim($data['private_key_path'] ?? config('oci-port-sentinel.private_key_path', ''));

        $uploadedKey = $data['private_key'] ?? null;
        if (is_string($uploadedKey) && $uploadedKey !== '') {
            $targetFile = $this->storeUploadedKey($data);

            if ($targetFile === null) {
                return; // An error notification was already sent
            }

            $keyPath = $targetFile;
        }

        $this->writeToEnvironment([
            'OCI_SENTINEL_TENANCY_OCID'           => $data['tenancy_ocid'] ?? '',
            'OCI_SENTINEL_USER_OCID'              => $data['user_ocid'] ?? '',
            'OCI_SENTINEL_KEY_FINGERPRINT'        => $data['key_fingerprint'] ?? '',
            'OCI_SENTINEL_PRIVATE_KEY_PATH'       => $keyPath,
            'OCI_SENTINEL_PRIVATE_KEY_PASSPHRASE' => $data['private_key_passphrase'] ?? '',
            'OCI_SENTINEL_REGION'                 => $data['region'] ?? 'us-ashburn-1',
            'OCI_SENTINEL_SECURITY_LIST_OCID'     => $data['security_list_ocid'] ?? '',
            'OCI_SENTINEL_SOURCE_CIDR'            => $data['source_cidr'] ?? '0.0.0.0/0',
            'OCI_SENTINEL_AUTO_CLOSE_PORTS'       => ($data['auto_close_ports'] ?? true) ? 'true' : 'false',
            'OCI_SENTINEL_NODE_MODE'              => $data['node_mode'] ?? 'all',
            'OCI_SENTINEL_NODE_IDS'               => implode(',', array_filter(array_map(
                'intval',
                (array) ($data['node_ids'] ?? [])
            ))),
        ]);

        Notification::make()
            ->title('OCI Port Sentinel settings saved')
            ->success()
            ->send();
    }

    /**
     * Persist an uploaded key file to secure storage and return its absolute path.
     * Sends an error notification and returns null when the file can't be used.
     */
    private function storeUploadedKey(array $data): ?string
    {
        $keyContent = $this->readUploadedFile($data['private_key']);

        if ($keyContent === null) {
            Notification::make()
                ->danger()
                ->title('Could not read uploaded key')
                ->body('The uploaded private key file could not be read from storage. No changes were saved.')
                ->send();

            return null;
        }

        if (!str_contains($keyContent, 'PRIVATE KEY')) {
            Notification::make()
                ->danger()
                ->title('Invalid private key file')
                ->body('The uploaded file does not look like a PEM private key. No changes were saved.')
                ->send();

            return null;
        }

        $passphrase = ($data['private_key_passphrase'] ?? '') ?: null;
        if (openssl_pkey_get_private($keyContent, $passphrase) === false) {
            Notification::make()
                ->danger()
                ->title('Could not parse private key')
                ->body('The key could not be parsed. Check that it is a valid RSA PEM key and that the passphrase is correct.')
                ->send();

            return null;
        }

        $targetDir = storage_path('app/oci-port-sentinel');
        if (!is_dir($targetDir) && !@mkdir($targetDir, 0700, true)) {
            Notification::make()
                ->danger()
                ->title('Could not store private key')
                ->body('Failed to create the key storage directory. No changes were saved.')
                ->send();

            return null;
        }

        $targetFile = $targetDir . DIRECTORY_SEPARATOR . 'oci_api_key.pem';
        if (@file_put_contents($targetFile, $keyContent) === false) {
            Notification::make()
                ->danger()
                ->title('Could not store private key')
                ->body('Failed to write the key file to disk. No changes were saved.')
                ->send();

            return null;
        }

        @chmod($targetFile, 0600);

        return $targetFile;
    }

    /**
     * Read the contents of a Filament temp upload. The value may be a path
     * relative to the local disk (with or without the livewire-tmp prefix).
     */
    private function readUploadedFile(string $value): ?string
    {
        $disk = Storage::disk('local');

        foreach ([$value, 'livewire-tmp/' . $value] as $candidate) {
            if ($disk->exists($candidate)) {
                $content = $disk->get($candidate);

                if (is_string($content)) {
                    return $content;
                }
            }

            if (is_file($candidate) && is_readable($candidate)) {
                $content = file_get_contents($candidate);

                if (is_string($content)) {
                    return $content;
                }
            }
        }

        return null;
    }
}
