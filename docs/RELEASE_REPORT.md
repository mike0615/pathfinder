# Development readiness report — 0.1.0.dev1

Date: 2026-11-16. This report describes an initial runnable implementation, not completion of every acceptance gate in SPEC.md. Source commit is the Git commit containing this report; no tag or GitHub Release is claimed by this file.

## Implemented and checked

- Local authenticated administrator/operator web app, session expiry, CSRF/origin checks, private state permissions.
- Authenticated-encryption SNMPv3 profiles, no reveal API, ciphertext tamper and wrong-key rejection, config injection checks.
- Standard-OID Net-SNMP collector, four workers, 256-address limit, no retries, cancellation mechanism and saved partial/capability results.
- Evidence-preserving SQLite snapshots; conservative inferred LLDP name relationships; no direct-attachment claims from MAC learning.
- Local SVG map, generic interface grid, search, snapshots/comparison, complete JSON/CSV and filtered SVG exports.
- Canonical offline help source, synchronized HELP.md, F1/mobile Help/Escape code, About/shared package version.
- Sixteen automated core/API tests passed in the development container. JavaScript syntax check passed.

## Qualification and missing features

- Physical Cisco Catalyst/Nexus, Juniper SRX and Netgear verification: NOT performed.
- Rocky Linux 9/10 clean install, service lifecycle, upgrade/removal: NOT performed.
- Browser functional/visual QA: attempted but Chromium could not start because the execution environment denied its process socket; no browser pass is claimed.
- Cancellation subprocess behavior, large tables, large networks and device-specific failure modes need integration tests; a mock partial-results test is not live qualification.
- SNMPv3 SHA-1/AES-128 only; SSH/CDP, reliable chassis correlation, accurate VLAN/FDB mapping, routed SRX classification, IPv6 neighbors, unmanaged segment inference and inventory-based modules pending.
- Cytoscape, photo/port editor, context-sensitive help, custom logo, automatic key rotation and password-derived unlock pending.
- VSDX not implemented, so desktop Visio validation is pending.
- Native RPM and offline dependency bundle not built. Source installation requires dependencies from approved packages/wheelhouse.
- Production web-server hardening, persistent job recovery, user-specific audit history and operational retention pending.

## Artifacts

Source is available in the repository. Local source/wheel package checks are recorded by the task result; no prebuilt RPM, offline bundle, published Release or stable qualification is implied. All included fixture data is synthetic. Do not deploy to a production network until the applicable acceptance gates have been completed.
