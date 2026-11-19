# Cyber Chief Pathfinder

An offline-first network topology investigation tool for the Cyber Chief toolset by Mike Anderson.

**0.1.0.dev1 is a runnable development foundation, not a qualified network mapper release.** Physical Cisco, Juniper and Netgear devices, Rocky 9/10 installs and browser visual QA remain unverified. See [release report](docs/RELEASE_REPORT.md) and the original [specification](docs/SPEC.md).

**Who it's for:** Network administrators who want to investigate network topology offline, using SNMPv3 collection and a local map (a development foundation; see the status above).

## Try it locally

Requires Python 3.9+ and `cryptography`. From a reviewed checkout:

```bash
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/pathfinder --state-dir ./state --init
# Read ./state/admin.password privately; do not paste it into logs or tickets.
.venv/bin/pathfinder --state-dir ./state
```

Open **http://127.0.0.1:8765**, sign in with the generated administrator password, then click **Load demo network**. No switch or internet connection is needed to use the demo. Save the demo snapshot before JSON/CSV export. To access a host remotely, use an SSH tunnel: `ssh -L 8765:127.0.0.1:8765 user@host`, then open the same local URL.

## Implemented

- Authenticated administrator/operator sessions, CSRF protection and encrypted SNMPv3 profiles with no secret-reveal API.
- Bounded, cancellable background SNMPv3 collection via local Net-SNMP, with explicit capability failures and retained raw table evidence.
- Interactive SVG device/connection map, generic discovered-interface panel and MAC/IP search.
- SQLite snapshots, device/link comparison, complete JSON and table CSV exports, filtered SVG export.
- Bundled offline F1/searchable help, mobile Help button, About and a synthetic test network.

## Deliberate development limits

Live collection currently uses standard SNMP system, interface, LLDP, BRIDGE, Q-BRIDGE and legacy IPv4 ARP tables. LLDP name matches remain **inferences**, not confirmed links. FDB IDs are retained but not assumed to equal VLAN IDs. Learned MAC addresses do not automatically become directly attached endpoint claims. Only SNMPv3 SHA-1/AES-128 authPriv is implemented. Device-side support and policy must be checked by the operator.

Pending: Cisco CDP, SSH vendor adapters, chassis/port identity correlation, full VLAN mapping, routed SRX classification, IPv6 neighbor discovery, Cytoscape map, physical module layouts, uploaded panel editor, key rotation, context-sensitive help, native VSDX, RPM and redistributable offline dependency bundles. The built-in HTTP server is for local development or trusted, restricted access; it is not hardened for public exposure.

See [installation](docs/INSTALL.md), [help](HELP.md), [security](SECURITY.md), [changes](CHANGELOG.md) and [dependency notices](THIRD_PARTY_NOTICES.md).

## Verification

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build_help.py
node --check pathfinder/static/app.js
```

All fixtures use synthetic data. Never commit real topology, state databases, keys, passwords or device captures. MIT license. Independent project; no Cisco, Juniper, Netgear or Microsoft affiliation or endorsement.

---

**Part of the Cyber Chief toolkit** by Anderson Computer. Sibling projects: [Flagship](https://github.com/mike0615/flagship) · [Flagship Web](https://github.com/mike0615/flagship-web) · [Porthole](https://github.com/mike0615/porthole) · [Skiff](https://github.com/mike0615/skiff) · [Sonar](https://github.com/mike0615/sonar) · [Helm RDP](https://github.com/mike0615/helm-rdp) · [FleetOps](https://github.com/mike0615/fleet-ops) · [Dockyard](https://github.com/mike0615/dockyard) · [CommShack](https://github.com/mike0615/commshack).
