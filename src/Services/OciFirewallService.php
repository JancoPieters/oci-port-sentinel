<?php

namespace OciPortSentinel\Services;

use GuzzleHttp\Client;

class OciFirewallService
{
    private const RULE_DESCRIPTION_PREFIX = 'Pelican server port ';

    private Client $http;
    private string $baseUrl;
    private string $host;

    public function __construct(
        private readonly string $tenancyOcid,
        private readonly string $userOcid,
        private readonly string $keyFingerprint,
        private readonly string $privateKeyPath,
        private readonly string $privateKeyPassphrase,
        private readonly string $region,
        private readonly string $securityListOcid,
        private readonly string $sourceCidr,
    ) {
        $this->host    = "iaas.{$region}.oraclecloud.com";
        $this->baseUrl = "https://{$this->host}/20160918";
        $this->http    = new Client(['timeout' => 30]);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Open the given ports (TCP + UDP) in the OCI Security List.
     * Existing rules are preserved; duplicates are not added.
     *
     * @param int[] $ports
     */
    public function openPorts(array $ports, ?int $serverId = null, ?string $serverName = null): void
    {
        if (empty($ports) || empty($this->securityListOcid)) {
            return;
        }

        [$currentList, $etag] = $this->getSecurityList();

        $existingIngress = $currentList['ingressSecurityRules'] ?? [];
        $existingEgress  = $currentList['egressSecurityRules'] ?? [];

        $newRules = [];
        foreach ($ports as $port) {
            $port = (int) $port;
            foreach ([6, 17] as $protocol) { // 6 = TCP, 17 = UDP
                if (!$this->ruleExists($existingIngress, $protocol, $port)) {
                    $newRules[] = $this->buildIngressRule($protocol, $port, $serverId, $serverName);
                }
            }
        }

        if (empty($newRules)) {
            return; // All ports already open
        }

        $this->updateSecurityList(
            array_merge($existingIngress, $newRules),
            $existingEgress,
            $etag
        );
    }

    /**
     * Remove Pelican-managed ingress rules for the given ports (TCP + UDP).
     * Only rules whose description starts with our prefix are removed;
     * manually created rules for the same ports are left untouched.
     *
     * @param int[] $ports
     */
    public function closePorts(array $ports): void
    {
        if (empty($ports) || empty($this->securityListOcid)) {
            return;
        }

        [$currentList, $etag] = $this->getSecurityList();

        $existingIngress = $currentList['ingressSecurityRules'] ?? [];
        $existingEgress  = $currentList['egressSecurityRules'] ?? [];

        $portSet = array_map('intval', $ports);

        $filteredIngress = array_values(array_filter(
            $existingIngress,
            fn (array $rule) => !$this->isManagedRuleForPorts($rule, $portSet)
        ));

        // Nothing changed — avoid a pointless PUT
        if (count($filteredIngress) === count($existingIngress)) {
            return;
        }

        $this->updateSecurityList($filteredIngress, $existingEgress, $etag);
    }

    /**
     * Remove every Pelican-managed ingress rule that was created for the given
     * server (identified by the "#<id>" tag in the rule description). Used when
     * a server is deleted, at which point Pelican has already released the
     * allocations so the ports can no longer be read from the database.
     */
    public function closeServerRules(int $serverId): void
    {
        if ($this->securityListOcid === '') {
            return;
        }

        [$currentList, $etag] = $this->getSecurityList();

        $existingIngress = $currentList['ingressSecurityRules'] ?? [];
        $existingEgress  = $currentList['egressSecurityRules'] ?? [];

        $filteredIngress = array_values(array_filter(
            $existingIngress,
            fn (array $rule) => !$this->isRuleForServer($rule, $serverId)
        ));

        if (count($filteredIngress) === count($existingIngress)) {
            return;
        }

        $this->updateSecurityList($filteredIngress, $existingEgress, $etag);
    }

    // -------------------------------------------------------------------------
    // OCI REST helpers
    // -------------------------------------------------------------------------

    /** @return array{0: array, 1: string} [listData, etag] */
    private function getSecurityList(): array
    {
        $path = '/securityLists/' . rawurlencode($this->securityListOcid);
        $url  = $this->baseUrl . $path;
        $date = gmdate('D, d M Y H:i:s') . ' GMT';
        $host = $this->host;

        // The signed (request-target) must be exactly the path sent on the wire
        // (including the /20160918 API version prefix), or OCI rejects the signature.
        $requestTarget = 'get ' . parse_url($url, PHP_URL_PATH);

        // OCI rebuilds the signing string in the order declared here; this order
        // matches the official OCI SDK: date, (request-target), host (+ body headers).
        // (request-target) is virtual — it is NEVER sent as a real HTTP header.
        $signHeaders = [
            'date'             => $date,
            '(request-target)' => $requestTarget,
            'host'             => $host,
        ];

        [$signingString, $headerList] = $this->buildSigningString($signHeaders);
        $authHeader = $this->buildAuthHeader($headerList, $this->sign($signingString));

        $wireHeaders = $this->wireHeaders($signHeaders, $authHeader);

        $response = $this->http->get($url, [
            'headers' => $wireHeaders,
        ]);

        $etag = $response->getHeader('etag')[0] ?? '';
        $data = json_decode($response->getBody()->getContents(), true);

        return [$data, $etag];
    }

    private function updateSecurityList(array $ingressRules, array $egressRules, string $etag): void
    {
        $path = '/securityLists/' . rawurlencode($this->securityListOcid);
        $url  = $this->baseUrl . $path;

        $body          = json_encode(['ingressSecurityRules' => $ingressRules, 'egressSecurityRules' => $egressRules]);
        $date          = gmdate('D, d M Y H:i:s') . ' GMT';
        $host          = $this->host;
        $contentType   = 'application/json';
        $contentLength = (string) strlen($body);
        $bodyHash      = base64_encode(hash('sha256', $body, true));

        // The signed (request-target) must be exactly the path sent on the wire
        // (including the /20160918 API version prefix), or OCI rejects the signature.
        $requestTarget = 'put ' . parse_url($url, PHP_URL_PATH);

        // (request-target) is virtual — it is NEVER sent as a real HTTP header.
        $signHeaders = [
            'date'             => $date,
            '(request-target)' => $requestTarget,
            'host'             => $host,
            'content-length'   => $contentLength,
            'content-type'     => $contentType,
            'x-content-sha256' => $bodyHash,
        ];

        [$signingString, $headerList] = $this->buildSigningString($signHeaders);
        $authHeader = $this->buildAuthHeader($headerList, $this->sign($signingString));

        $wireHeaders = $this->wireHeaders($signHeaders, $authHeader);

        if ($etag !== '') {
            $wireHeaders['if-match'] = $etag;
        }

        $this->http->put($url, ['headers' => $wireHeaders, 'body' => $body]);
    }

    /**
     * Strip the virtual (request-target) header from the signing set and add the
     * computed Authorization header to produce the headers actually sent on the wire.
     */
    private function wireHeaders(array $signHeaders, string $authHeader): array
    {
        $wireHeaders = $signHeaders;
        unset($wireHeaders['(request-target)']);
        $wireHeaders['Authorization'] = $authHeader;

        return $wireHeaders;
    }

    // -------------------------------------------------------------------------
    // Rule helpers
    // -------------------------------------------------------------------------

    /**
     * Returns true if an existing ingress rule already covers protocol+port,
     * either as an exact match, a port range, or a protocol-wide rule.
     */
    private function ruleExists(array $rules, int $protocol, int $port): bool
    {
        $protoStr = (string) $protocol;

        foreach ($rules as $rule) {
            if (($rule['protocol'] ?? '') !== $protoStr) {
                continue;
            }

            $optKey    = $protocol === 6 ? 'tcpOptions' : 'udpOptions';
            $opts      = $rule[$optKey] ?? null;
            $destRange = $opts['destinationPortRange'] ?? null;

            // No port restriction at all — protocol-wide rule covers everything
            if ($opts === null || $destRange === null) {
                return true;
            }

            $min = (int) ($destRange['min'] ?? 0);
            $max = (int) ($destRange['max'] ?? 0);
            if ($port >= $min && $port <= $max) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true when the rule was created by this plugin for one of the given ports
     * (identified by the description prefix we set) AND covers exactly that single port.
     * This prevents us from accidentally removing manually created range rules.
     */
    private function isManagedRuleForPorts(array $rule, array $ports): bool
    {
        $description = $rule['description'] ?? '';
        if (!str_starts_with($description, self::RULE_DESCRIPTION_PREFIX)) {
            return false;
        }

        $protocol = (int) ($rule['protocol'] ?? -1);
        $optKey   = $protocol === 6 ? 'tcpOptions' : 'udpOptions';
        $min      = (int) ($rule[$optKey]['destinationPortRange']['min'] ?? -1);
        $max      = (int) ($rule[$optKey]['destinationPortRange']['max'] ?? -1);

        // Only remove if it is an exact single-port rule for one of our ports
        return $min === $max && in_array($min, $ports, true);
    }

    /**
     * Returns true when the rule was created by this plugin for the given server,
     * matched by the "#<id>" tag at the end of the description.
     */
    private function isRuleForServer(array $rule, int $serverId): bool
    {
        $description = $rule['description'] ?? '';

        return str_starts_with($description, self::RULE_DESCRIPTION_PREFIX)
            && (bool) preg_match('/ #' . $serverId . '\)$/', $description);
    }

    private function buildIngressRule(int $protocol, int $port, ?int $serverId = null, ?string $serverName = null): array
    {
        $optKey  = $protocol === 6 ? 'tcpOptions' : 'udpOptions';
        $protoName = $protocol === 6 ? 'TCP' : 'UDP';

        $description = self::RULE_DESCRIPTION_PREFIX . $port . ' ' . $protoName;
        $nameTag = ($serverName !== null && $serverName !== '') ? $serverName : '';
        if ($serverId !== null) {
            $description .= ' (' . $nameTag . ' #' . $serverId . ')';
        } elseif ($nameTag !== '') {
            $description .= ' (' . $nameTag . ')';
        }

        return [
            'source'      => $this->sourceCidr,
            'protocol'    => (string) $protocol,
            'isStateless' => false,
            'description' => $description,
            $optKey       => [
                'destinationPortRange' => ['min' => $port, 'max' => $port],
            ],
        ];
    }

    // -------------------------------------------------------------------------
    // OCI HTTP Signature (RSA-SHA256)
    // -------------------------------------------------------------------------

    private function sign(string $signingString): string
    {
        $key = openssl_pkey_get_private(
            file_get_contents($this->privateKeyPath),
            $this->privateKeyPassphrase ?: null
        );

        if ($key === false) {
            throw new \RuntimeException('[OciPortSentinel] Failed to load OCI private key from: ' . $this->privateKeyPath);
        }

        $raw = '';
        openssl_sign($signingString, $raw, $key, OPENSSL_ALGO_SHA256);

        return base64_encode($raw);
    }

    /**
     * Build the OCI signing string and the matching ordered header list from a single
     * ordered header map. OCI reconstructs the signing string from the order declared
     * in the Authorization `headers` parameter, so both must be derived from the same
     * order or verification always fails (401 NotAuthenticated).
     *
     * The map may include the virtual `(request-target)` header, which must appear
     * AFTER `date` and BEFORE `host` to match the official OCI SDK construction.
     *
     * @param array<string, string> $headers ordered header name => value (lowercase names)
     * @return array{0: string, 1: string} [signingString, orderedHeaderList]
     */
    private function buildSigningString(array $headers): array
    {
        $components = [];
        foreach ($headers as $name => $value) {
            $components[] = $name . ': ' . $value;
        }

        return [
            implode("\n", $components),
            implode(' ', array_keys($headers)),
        ];
    }

    private function buildAuthHeader(string $signedHeaders, string $signature): string
    {
        $keyId = "{$this->tenancyOcid}/{$this->userOcid}/{$this->keyFingerprint}";

        return sprintf(
            'Signature algorithm="rsa-sha256",headers="%s",keyId="%s",signature="%s",version="1"',
            $signedHeaders,
            $keyId,
            $signature
        );
    }
}
