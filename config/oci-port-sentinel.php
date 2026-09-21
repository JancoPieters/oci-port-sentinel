<?php

return [
    'tenancy_ocid'           => env('OCI_SENTINEL_TENANCY_OCID', ''),
    'user_ocid'              => env('OCI_SENTINEL_USER_OCID', ''),
    'key_fingerprint'        => env('OCI_SENTINEL_KEY_FINGERPRINT', ''),
    'private_key_path'       => env('OCI_SENTINEL_PRIVATE_KEY_PATH', ''),
    'private_key_passphrase' => env('OCI_SENTINEL_PRIVATE_KEY_PASSPHRASE', ''),
    'region'                 => env('OCI_SENTINEL_REGION', 'us-ashburn-1'),
    'security_list_ocid'     => env('OCI_SENTINEL_SECURITY_LIST_OCID', ''),
    'source_cidr'            => env('OCI_SENTINEL_SOURCE_CIDR', '0.0.0.0/0'),
    'auto_close_ports'       => env('OCI_SENTINEL_AUTO_CLOSE_PORTS', true),
    'node_mode'              => env('OCI_SENTINEL_NODE_MODE', 'all'),
    'node_ids'               => env('OCI_SENTINEL_NODE_IDS', ''),
];
