# OCI Port Sentinel — Pelican Panel Plugin

**OCI Port Sentinel** keeps an OCI Security List in sync with your Pelican game servers:

- **Opens** TCP + UDP ingress rules for a server's allocated ports when it is installed.
- **Closes** them again when the server is deleted (toggleable).
- **Syncs** port changes after creation (adding, removing or editing allocations).
- Configured entirely from the admin panel settings UI.

---

## Requirements

- Pelican Panel with the plugin system enabled
- PHP `openssl` extension (standard)
- An OCI IAM user with `manage security-lists` permission on the compartment
- `guzzlehttp/guzzle` is already a Pelican dependency; no extra packages needed

---

## Installation

1. Copy the plugin — the folder name **must** match the ID `oci-port-sentinel`:

   ```bash
   cp -r /path/to/oci-port-sentinel /var/www/pelican/plugins/oci-port-sentinel
   ```

2. Place your OCI private key on the server if you're not uploading it via the UI (see [Settings UI](#settings-ui)):

   ```bash
   sudo mkdir -p /etc/pelican
   sudo cp ~/oci_api_key.pem /etc/pelican/oci_api_key.pem
   sudo chmod 600 /etc/pelican/oci_api_key.pem
   sudo chown www-data:www-data /etc/pelican/oci_api_key.pem
   ```

3. Set the key path so the plugin works before the UI is configured:

   ```dotenv
   OCI_SENTINEL_PRIVATE_KEY_PATH=/etc/pelican/oci_api_key.pem
   ```

4. Install the plugin from the admin panel (Plugins → Import/Install), or via CLI:

   ```bash
   cd /var/www/pelican
   php artisan p:plugin:install   # select oci-port-sentinel
   php artisan optimize:clear
   php artisan queue:restart
   ```

5. Fill in the remaining settings — see below.

---

## Settings UI

**Admin → Plugins → OCI Port Sentinel → Settings.** Save writes values straight to `.env`; no restart needed.

| Section | Fields |
|---|---|
| **OCI Authentication** | Tenancy OCID, User OCID, Key Fingerprint, Region |
| **Private Key** | Upload PEM file (recommended), or Private Key Path + Passphrase |
| **Firewall Target** | Security List OCID, Source CIDR |
| **Behaviour** | Auto-close ports on server deletion (toggle) |
| **Wing Filtering** | Mode (all / whitelist / blacklist) and selected Wings |

> Uploaded keys are stored at `storage/app/oci-port-sentinel/oci_api_key.pem` (chmod `600`, outside the web root).

## Environment Variables

Managed through the Settings UI; shown here for reference.

| Variable | Required | Default | Description |
|---|---|---|---|
| `OCI_SENTINEL_TENANCY_OCID` | Yes | — | Tenancy OCID (`ocid1.tenancy.oc1..`) |
| `OCI_SENTINEL_USER_OCID` | Yes | — | IAM user OCID (`ocid1.user.oc1..`) |
| `OCI_SENTINEL_KEY_FINGERPRINT` | Yes | — | MD5 fingerprint of the API key |
| `OCI_SENTINEL_PRIVATE_KEY_PATH` | * | — | Path to the RSA private key (set automatically when uploaded via the UI) |
| `OCI_SENTINEL_PRIVATE_KEY_PASSPHRASE` | No | empty | Passphrase for an encrypted key |
| `OCI_SENTINEL_REGION` | Yes | `us-ashburn-1` | OCI region (e.g. `eu-frankfurt-1`) |
| `OCI_SENTINEL_SECURITY_LIST_OCID` | Yes | — | Security List to update |
| `OCI_SENTINEL_SOURCE_CIDR` | No | `0.0.0.0/0` | Source IP range allowed by opened rules |
| `OCI_SENTINEL_AUTO_CLOSE_PORTS` | No | `true` | Set `false` to never auto-remove rules |
| `OCI_SENTINEL_NODE_MODE` | No | `all` | `all`, `whitelist`, or `blacklist` Wing filtering |
| `OCI_SENTINEL_NODE_IDS` | No | empty | Comma-separated Wing IDs for whitelist/blacklist |

---

## Obtaining OCI Credentials

1. **Tenancy OCID & User OCID** — OCI Console → your Profile → Tenancy/User Details; copy the OCID.
2. **API key** — User Details → API Keys → *Add API Key* → *Generate API Key Pair*, download the keys, copy the shown **fingerprint**, and move the private key to the server.
3. **Security List OCID** — Networking → Virtual Cloud Networks → your VCN → Security Lists → click the list → copy the OCID.

---

## How It Works

- **Opening** — on initial install, each allocated port gets a TCP (`6`) and UDP (`17`) ingress rule. Existing rules are never duplicated; already-covered ports are skipped.
- **Closing** — `Server::deleting` removes every rule tagged with that server's id (e.g. `Pelican server port 25565 TCP (spoonbill #23)`). Pelican releases allocations before the hook fires, so rules are matched by description tag rather than by allocation.
- **Allocation changes** — `Allocation` events open/close the affected port as allocations are added, removed, moved, or renumbered.
- **Safety** — the ETag from the GET is sent as `If-Match` on the PUT, so concurrent changes cause a `412` instead of silent overwrites. Only this plugin's rules (description prefix `Pelican server port`) are ever removed.

---

## Important Notes

- Reinstalls do **not** re-open ports; only the initial install does.
- Manually created rules for the same ports are never touched.
- Cleanup on deletion is not subject to Wing filtering — only the deleted server's own tagged rules are removed.
- Changing the Wing filter does not backfill existing servers; it affects future events only.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Failed to load OCI private key` | Wrong path or permissions | Check `OCI_SENTINEL_PRIVATE_KEY_PATH`; `chmod 600`, owner `www-data` |
| `404` on security list | Wrong OCID or region | Double-check `OCI_SENTINEL_SECURITY_LIST_OCID` and `OCI_SENTINEL_REGION` |
| `412 Precondition Failed` | Concurrent Security List change | Harmless; retried on the next event |
| Ports not opening, no logs | Queue worker stale or plugin inactive | `php artisan queue:restart`; verify plugin status |
| Ports not closing on deletion | Auto-close disabled | Toggle `OCI_SENTINEL_AUTO_CLOSE_PORTS` |
| IAM permission error | User lacks permission | Grant `manage security-lists` on the compartment |

Logs use Laravel's **daily** channel, prefixed with `[OciPortSentinel]`:

```bash
grep '\[OciPortSentinel\]' /var/www/pelican/storage/logs/laravel-$(date +%F).log
```
