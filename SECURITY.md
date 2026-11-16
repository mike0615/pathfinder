# Security and reporting

Development software; production and vendor qualification are pending. Report vulnerabilities privately through the repository owner's GitHub profile contact or GitHub private vulnerability reporting when enabled. Do not disclose passwords, keys or real topology in public issues.

Local HTTP only; SSH tunnel or restricted trusted HTTPS proxy required for remote use. Sessions expire after eight hours and restart. Administrators manage profiles; operators can run scans using references but cannot reveal secrets. Both roles can view topology and export it. This is a single-server shared-password role model, not enterprise identity or a multi-tenant boundary.

Profile ciphertext uses authenticated Fernet encryption. The random key resides separately from the SQLite file with permission checks. It is not protected from root or the service account. No key-unlock password, automatic rotation or Vault integration is implemented. Wrong key/tampered ciphertext fails closed. Workers decrypt secrets in memory and write mode-0600 temporary Net-SNMP configuration. Logs omit requests and subprocess stderr. Secret strings must never be included in fixtures or exports.

Scans are read-only standard SNMP queries restricted to configured management CIDRs, not vulnerability exploitation. UI session permissions do not grant device permissions. Use minimum read-only device views and approved management networks. The external collector has timeouts; encrypted swap, persistent job recovery, multiuser audit logs, request concurrency limits and production HTTP hardening remain outstanding.

Database/state directories and backups contain sensitive network inventory. Never commit runtime state or real captures. Synthetic fixtures use documentation addresses only.
