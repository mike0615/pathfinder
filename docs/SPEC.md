# Cyber Chief Pathfinder — first-release draft specification

Status: specification only; no scanner implementation or release has been qualified. Pathfinder is a proposed working name, not a confirmed unique product name. Proposed repository: mike0615/cyberchief-pathfinder, public. Do not publish credentials, real customer topology, private fixtures or production configuration.

## Platform and architecture

Rocky Linux 9 and 10 with a browser interface; Python API and background workers, SQLite for the first single-server deployment, bundled Cytoscape.js for an offline interactive map. Separate credential service, vendor collectors, normalized observations, topology correlation and exporters. Package with systemd, explicit configuration and local assets; installation must not require fetching a CDN at runtime.

## Discovery

Operator provides subnets, seed devices, allowed management networks and a saved credential profile. Subnet enumeration alone does not reveal remote switch ports: collect authorized switch management data separately. Validate and bound CIDRs, timeouts, concurrency and retry counts; scans are cancellable. Use read-only SNMPv3 and SSH commands; implement no network configuration writes.

Collect LLDP neighbors, Cisco CDP where supported, interfaces, VLAN-aware bridge/MAC tables, and gateway ARP tables. Preserve source device, interface indexes and names, VLAN context, collection time and protocol for every observation. Retain partial results and explicit capability/permission errors.

Vendor scope: Cisco Catalyst 9300/IOS XE and Nexus/NX-OS; Juniper SRX300, SRX340 and SRX345/Junos; managed Netgear standards-based collection. Other Cisco models remain configurable and discovered rather than guessed from voice transcription. SRXs must distinguish switched and routed interfaces. Unmanaged switches appear as unknown segments. A MAC learned through an uplink is not automatically a directly attached endpoint.

## Credentials and access

Encrypted local storage for release one; HashiCorp Vault integration is deferred. Authenticated encryption, key stored separately from ciphertext or derived from an unlock password using an appropriate password KDF; restricted filesystem permissions, authenticated UI and HTTPS when accessed remotely. Operators can use approved profile references without a secret-reveal endpoint. Administrators manage profiles. Workers necessarily decrypt secrets to connect; this is not protection from a privileged server administrator. Redact logs and exports; verify SSH host keys; document backup, restore, rotation, unlock and lost-key behavior.

## Map and panels

Interactive device/port/VLAN map, IP/MAC lookup table, saved scan snapshots and change comparison. Solid links represent supported confirmed relationships; dashed links represent inferences with visible evidence and limitations. Clicking nodes/links exposes evidence and timestamps. Routed, Wi-Fi, virtualization and unknown segments remain explicit.

Start with a generic 48-port panel and optional eight-position SFP+ uplink module. Tie port positions to actual discovered interface names; verify module presence and speeds from inventory rather than assume. Clicking a port highlights its attached or downstream devices. Support later user-uploaded vendor panel pictures and an admin port-position editor; first release must work without vendor photography.

## Exports

JSON preserves the complete normalized topology and evidence; CSV contains device/port/MAC tables; SVG exports the diagram. Basic native Visio VSDX export uses editable device shapes, connectors and port labels. Export full topology or filtered view and label which was exported. Validate the generated VSDX in desktop Visio before claiming Visio compatibility. Vendor-specific stencils are deferred.

## Help and About

F1 opens bundled, searchable help inside the web application; Help button/menu offers the same route for mobile and keyboards where the browser intercepts F1. Keyboard handling prevents browser help when possible, supports Escape, restores focus and uses accessible dialogs. Context-sensitive topics cover current screens. Help remains available offline and is included as application data, not optional package documentation.

Help covers first scan, scope/seed devices, credential profiles, vendor capabilities, map evidence, VLANs, panel mapping, snapshots, export, systemd installation, upgrades, backup/restore and troubleshooting. Generate repository HELP.md and in-app help from one canonical source; test that both stay synchronized.

About follows inspected Skiff, Sonar, Helm and Flagship fields: app name, version/build, logo, tagline, Mike Anderson, Copyright (c) 2026 Mike Anderson, Cyber Chief toolset membership, project link and https://www.andersoncomputer.net. MIT is the draft default matching Skiff/Sonar/Helm; Flagship uses BSD 2-Clause and must not be described as MIT. Include license text, third-party notices and an independent-project/vendor affiliation notice. Keep version metadata shared between UI, package and release.

## Public repository and Releases

Initial push at a coherent milestone includes all application source, bundled help/assets, tests with synthetic fixtures, this specification, README, HELP.md, LICENSE, CHANGELOG, release notes, installation/upgrade instructions, security reporting guidance, dependency/license notices and packaging scripts. Never push real scan captures or secrets.

Use tagged GitHub Releases, development prereleases until qualified, and downloadable Rocky installation packages plus source archive and SHA-256 checksums. Prefer RPMs and an offline dependency bundle with sources/notices where redistribution requires them. Keep a release report listing exact commit/tag, artifacts, supported platforms, checks performed, known limitations and pending live-device/Visio validation. CI must fail rather than publish if qualification checks fail; no stable label based solely on unit tests.

## Acceptance gates

1. Clean Rocky 9 and 10 install, service start, upgrade, removal and network-disabled help/UI tests.
2. Authentication and role enforcement; credential ciphertext tamper, wrong unlock, rotation, permissions and secret-redaction checks.
3. Synthetic and live read-only collections for supported devices; missing privileges and partial responses surfaced.
4. Correct port correlation under VLANs, uplinks, duplicate MAC observations, routed SRX, unmanaged segments and stale evidence.
5. Cancellation, bounded retries and large-scope limits verified.
6. Map, filters, port panel, evidence, snapshots and every export checked against the same saved topology.
7. F1 and Help navigation/focus tested; About fields match verified reference conventions and package version.
8. Native VSDX opened and edited in desktop Visio before marking that exporter qualified.
9. Public repository and Release asset download verified, with reproducible commands and truthful limitations.

## Build sequence

A. Repository/specification and help/About foundations.
B. Credential handling, discovery workers and vendor adapters.
C. Correlation, interactive map and snapshots.
D. Generic port panels and exports.
E. Rocky packages, offline bundles, qualification and first development Release.
