# Pathfinder help

Generated from pathfinder/help.json.

## First scan

Initialize Pathfinder, read the private admin.password file locally, sign in, and load the demo. Demo addresses are documentation-only 192.0.2.0/24. To scan live devices, install net-snmp-utils, configure PATHFINDER_ALLOWED_CIDRS, add an SNMPv3 profile, and enter seed IPs or a bounded subnet. Live collection is experimental and has not been verified on physical switches.

## Scope and cancellation

Only IP literals and strict CIDRs within the server allowlist are accepted. A scan permits at most 256 addresses and four concurrent device collectors. Each table has a five-second deadline and zero retries. One scan may run at a time. Cancel stops queued work and active processes, retaining partial observations in a snapshot.

## Credential profiles and roles

Administrators create and delete encrypted profiles. Operators select saved profiles and run scans but cannot manage or reveal secrets. Profiles use Fernet authenticated encryption; the 0600 key is separate from SQLite ciphertext in the private 0700 state directory. Workers decrypt to connect; privileged server administrators can access secrets. SHA-1/AES-128 authPriv is the only current SNMP mode. Spaces, quotes, backslashes, # and control characters in SNMP fields are currently unsupported.

## Vendor capabilities

Current adapter uses numeric standard SNMP OIDs: system identity, interface names/status/speed, LLDP names and port IDs, bridge FDB, Q-BRIDGE FDB and legacy IPv4 ARP. Cisco CDP, SSH vendor commands, SNMP contexts, chassis inventory, reliable SRX switched/routed classification and IPv6 neighbor tables are pending. Cisco IOS XE/NX-OS, Junos and Netgear live qualification is pending; device support is not certified.

## Map evidence and VLANs

Solid links are supported confirmed relationships in the synthetic fixture. Current live LLDP name matches are always dashed inferences, because chassis identities are not yet corroborated. A learned MAC is not direct attachment proof. Q-BRIDGE FDB identifiers are preserved separately, never assumed to equal VLAN IDs. Unknown and routed segments require explicit evidence; no automatic endpoint or unmanaged-switch inference is made by this development collector.

## Port panels

The generic grid shows actual discovered interface names in discovery order. Select a port to see its relationships and MAC evidence. Positions are generic rather than physical chassis mappings. Optional SFP modules, inventory validation, custom photography and the position editor are pending.

## Snapshots and comparison

Live scans automatically save their results, including cancellation and capability errors. Save demo snapshots explicitly. Select saved snapshots to reload them. Compare reports added/removed/changed devices and relationship additions/removals; observation timestamps alone do not change device status. Snapshots have no retention policy yet; monitor state directory capacity.

## Exports

JSON exports the complete saved snapshot, including raw normalized SNMP table evidence and errors. CSV includes discovered interfaces and FDB/ARP records, with spreadsheet formula protection. JSON and CSV export the full snapshot regardless of map search. SVG exports the currently filtered view with editable SVG text and lines. Native Visio VSDX and arbitrary imported captures are not implemented; desktop Visio qualification is pending.

## Offline help and About

F1 opens this searchable dialog when the browser permits interception. The Help button works on mobile. Escape closes the dialog and restores focus. Repository HELP.md is generated from the same canonical help.json. All browser assets are local with no CDN or external font requests. About includes version, attribution, project and vendor independence. A custom logo and context-specific topic selection are pending.

## Installation and HTTPS

See docs/INSTALL.md. The server intentionally binds only 127.0.0.1. For remote access, use an SSH tunnel or a trusted HTTPS reverse proxy that overwrites forwarded headers. Do not expose the development HTTP server directly. Use a dedicated unprivileged systemd account. Rocky 9 and 10 installation, lifecycle, and offline dependency bundle qualification are pending.

## Backup, restore and rotation

Stop the service before copying state. Back up the SQLite database and password files securely; back up profiles.key separately in secure storage. Restore all files with directory 0700 and files 0600. Losing the key makes stored profiles unrecoverable; delete their encrypted rows through the admin UI and recreate profiles with known credentials. Automatic key rotation and unlock-password-derived keys are pending. Rotate device passphrases on the device, create a replacement profile, then delete the old profile. Change UI password files and restart to invalidate all sessions.

## Troubleshooting and upgrades

No devices: check the allowlist, route, UDP 161, device SNMP ACLs and profile permissions. Missing tables are retained as capability notices. LLDP names must match a uniquely discovered system name to produce a dashed connection. No secret-reveal endpoint exists. Update from a reviewed commit, back up state, reinstall in the virtual environment and restart. To roll back, restore the previous code and matching state backup. This is a development build, not a production-qualified release.
