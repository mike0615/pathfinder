# Installation and operation

## Development install

Python 3.9+ is required. On a connected Rocky host install Python, virtualenv/pip support, `python3-cryptography` if using system packages, and `net-snmp-utils` for live discovery. Exact package availability and installation on Rocky 9/10 are not yet qualified. A demo works without Net-SNMP.

Use the README virtualenv instructions. Dependency installation may need internet or an approved wheelhouse. After installation, the UI, help and demo make no CDN or internet requests. An installable offline dependency bundle and RPM are pending; this source package alone is not that bundle.

## Single-server systemd deployment (experimental)

1. Create a dedicated `pathfinder` system account with no login shell.
2. Install a reviewed checkout/virtual environment under `/opt/pathfinder`; root owns code, service account only reads it.
3. Create `/var/lib/pathfinder` owned by the service account, mode 0700.
4. As that account run `/opt/pathfinder/.venv/bin/pathfinder --state-dir /var/lib/pathfinder --init`.
5. Read `/var/lib/pathfinder/admin.password` privately as an administrator. File must be 0600. Optionally create a distinct random 16+ character `/var/lib/pathfinder/operator.password`, owner pathfinder, mode 0600. Restart to apply UI password changes; all sessions expire at restart.
6. Install `packaging/pathfinder.service` in `/etc/systemd/system/` and `packaging/pathfinder.env.example` as `/etc/pathfinder.env`. Edit only the authorized management CIDRs. Do not put device credentials in this file.
7. Run `systemctl daemon-reload` and `systemctl enable --now pathfinder`.

The service binds 127.0.0.1:8765 only. Use an SSH tunnel for initial testing. For shared remote access, deploy a trusted HTTPS reverse proxy; restrict ingress, overwrite forwarded headers and preserve the original Host/Origin consistently. TLS certificates, proxy hardening and remote session security need local validation. Do not publish the development server directly on the internet.

## Live discovery

Set `PATHFINDER_ALLOWED_CIDRS=192.0.2.0/24,198.51.100.0/24` with your actual authorized management networks, restart and verify the UI allowlist. Create a read-only SNMPv3 SHA/AES authPriv profile on the device using its management process, then enter the same credentials into Pathfinder. A scan uses four workers, no retries, at most 256 addresses and a five-second ceiling per table. Missing tables are recorded rather than fabricated. SNMP fields containing whitespace, quotes, #, backslashes or control characters are rejected by the current adapter.

Credentials are passed to Net-SNMP in a mode-0600 temporary configuration directory, not command-line arguments. No SNMP SET operations, SSH commands or device configuration writes are implemented. Worker plaintext and temporary files are accessible to privileged server administrators. Consider your service account's temporary-directory policy and encrypted swap/storage.

## Backup, restore and upgrade

Stop the service. Copy SQLite and password files into access-restricted encrypted backup storage. Back up profiles.key separately with the same care as device credentials. Restore directory mode 0700 and file modes 0600 with service-account ownership. Losing profiles.key makes existing profile ciphertext unrecoverable. Restart and verify snapshots, help, role permissions and one authorized seed.

Before upgrading, keep both the previous source/wheel and matching state backup. Install the reviewed replacement into a fresh virtualenv, run checks, then switch the service to it and restart. For rollback restore previous code and state together. Automatic schema migration, key rotation and service lifecycle qualification are pending.

## Removal

Disable/stop the service, remove the unit and reload systemd. Remove program files after preserving required source/licenses. Retain state securely unless you explicitly intend to destroy topology and credentials. State deletion is separate from uninstall.
