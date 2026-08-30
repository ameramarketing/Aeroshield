# License Compliance Verification Record

**Repository-level license compliance verified based on the inspected files.**

This document records the final compliance audit of the AeroShield Wireless Security Assessment Platform relative to its upstream foundation, Airgorah.

---

## 1. Compliance Status Summary

*   **MIT License Verification**: The MIT License text is complete, unmodified, and legally accurate.
*   **Copyright Notices Preservation**: Martin Olivier's original copyright notices have been fully preserved across all derived source files. No original copyright notices have been replaced, removed, or obscured.
*   **AeroShield Copyright Claims**: Amjad Khan's copyright notices are strictly limited to files containing original AeroShield contributions (Category B). No ownership is claimed over inherited upstream components.
*   **Ownership Statement Verification**: There are no misleading ownership statements in the codebase. All attributions are correct and consistent.

---

## 2. File-by-File Compliance Inventory

The following table lists all 43 source files currently present in the AeroShield repository workspace:

| File | Upstream Source | Classification | Martin Notice | AeroShield Notice |
| :--- | :--- | :---: | :---: | :---: |
| `crates/common/src/channel.rs` | `crates/common/src/channel.rs` | A | Yes | No |
| `crates/common/src/deps.rs` | `crates/common/src/deps.rs` | B | Yes | Yes |
| `crates/common/src/handshake.rs` | `crates/common/src/handshake.rs` | B | Yes | Yes |
| `crates/common/src/ipc.rs` | `crates/common/src/ipc.rs` | B | Yes | Yes |
| `crates/common/src/types.rs` | `crates/common/src/types.rs` | B | Yes | Yes |
| `crates/agent/src/backend/deauth.rs` | `crates/agent/src/backend/deauth.rs` | A | Yes | No |
| `crates/agent/src/backend/interface.rs` | `crates/agent/src/backend/interface.rs` | A | Yes | No |
| `crates/agent/src/backend/pcap.rs` | `crates/agent/src/backend/pcap.rs` | A | Yes | No |
| `crates/agent/src/backend/raw_socket.rs` | `crates/agent/src/backend/raw_socket.rs` | A | Yes | No |
| `crates/agent/src/backend/scan.rs` | `crates/agent/src/backend/scan.rs` | A | Yes | No |
| `crates/agent/src/backend/vendors.rs` | `crates/agent/src/backend/vendors.rs` | A | Yes | No |
| `crates/agent/src/backend/sniffer.rs` | `crates/agent/src/backend/sniffer.rs` | B | Yes | Yes |
| `crates/agent/src/backend/app.rs` | `crates/agent/src/backend/app.rs` | B | Yes | Yes |
| `crates/agent/src/backend/gps.rs` | *N/A (New)* | C | No | Yes |
| `crates/agent/src/backend/wps.rs` | *N/A (New)* | C | No | Yes |
| `crates/agent/src/backend/evil_twin.rs` | *N/A (New)* | C | No | Yes |
| `crates/agent/src/server.rs` | `crates/agent/src/server.rs` | B | Yes | Yes |
| `crates/agent/src/main.rs` | `crates/agent/src/main.rs` | B | Yes | Yes |
| `crates/agent/src/globals.rs` | `crates/agent/src/globals.rs` | B | Yes | Yes |
| `crates/agent/src/validate.rs` | `crates/agent/src/validate.rs` | A | Yes | No |
| `crates/gui/src/globals.rs` | `crates/gui/src/globals.rs` | B | Yes | Yes |
| `crates/gui/src/main.rs` | `crates/gui/src/main.rs` | A | Yes | No |
| `crates/gui/src/types.rs` | `crates/gui/src/types.rs` | A | Yes | No |
| `crates/gui/src/backend/client.rs` | `crates/gui/src/backend/client.rs` | B | Yes | Yes |
| `crates/gui/src/backend/decrypt.rs` | `crates/gui/src/backend/decrypt.rs` | A | Yes | No |
| `crates/gui/src/backend/iface.rs` | `crates/gui/src/backend/iface.rs` | A | Yes | No |
| `crates/gui/src/backend/settings.rs` | `crates/gui/src/backend/settings.rs` | A | Yes | No |
| `crates/gui/src/backend/report.rs` | `crates/gui/src/backend/report.rs` | B | Yes | Yes |
| `crates/gui/src/frontend/interfaces/app.rs` | `crates/gui/src/frontend/interfaces/app.rs` | B | Yes | Yes |
| `crates/gui/src/frontend/interfaces/deauth.rs` | `crates/gui/src/frontend/interfaces/deauth.rs` | A | Yes | No |
| `crates/gui/src/frontend/interfaces/decrypt.rs` | `crates/gui/src/frontend/interfaces/decrypt.rs` | A | Yes | No |
| `crates/gui/src/frontend/interfaces/interface.rs` | `crates/gui/src/frontend/interfaces/interface.rs` | A | Yes | No |
| `crates/gui/src/frontend/interfaces/settings.rs` | `crates/gui/src/frontend/interfaces/settings.rs` | A | Yes | No |
| `crates/gui/src/frontend/connections/app.rs` | `crates/gui/src/frontend/connections/app.rs` | B | Yes | Yes |
| `crates/gui/src/frontend/connections/deauth.rs` | `crates/gui/src/frontend/connections/deauth.rs` | B | Yes | Yes |
| `crates/gui/src/frontend/connections/scan.rs` | `crates/gui/src/frontend/connections/scan.rs` | B | Yes | Yes |
| `crates/gui/src/frontend/connections/decrypt.rs` | `crates/gui/src/frontend/connections/decrypt.rs` | A | Yes | No |
| `crates/gui/src/frontend/connections/interface.rs` | `crates/gui/src/frontend/connections/interface.rs` | A | Yes | No |
| `crates/gui/src/frontend/connections/settings.rs` | `crates/gui/src/frontend/connections/settings.rs` | A | Yes | No |
| `crates/gui/src/frontend/widgets/graph.rs` | *N/A (New)* | C | No | Yes |
| `crates/gui/src/frontend/widgets/wps_tab.rs` | *N/A (New)* | C | No | Yes |
| `crates/gui/src/frontend/widgets/evil_twin_tab.rs` | *N/A (New)* | C | No | Yes |
| `crates/gui/src/frontend/widgets/session_tab.rs` | *N/A (New)* | C | No | Yes |

*Legend*:
*   **A**: Directly Airgorah-derived (retained legacy implementation).
*   **B**: Modified Airgorah-derived (contains original AeroShield additions/modifications).
*   **C**: Original AeroShield implementation (written completely from scratch).

---

## 3. Copyright Boundaries

### Upstream Airgorah Code Components
The following functionalities remain derived from the original Airgorah codebase:
*   **Deauthentication injection frame loop**: `crates/agent/src/backend/deauth.rs`.
*   **Monitor mode switcher**: `crates/agent/src/backend/interface.rs`.
*   **Airodump scanner execution**: `crates/agent/src/backend/scan.rs` / `crates/agent/src/backend/pcap.rs`.
*   **Scanner CSV parsing logic**: `crates/agent/src/backend/sniffer.rs`.
*   **Basic Unix Stream IPC framing**: `crates/agent/src/server.rs` and `crates/gui/src/backend/client.rs`.
*   **Offline handshake cracking GUI**: `crates/gui/src/frontend/interfaces/decrypt.rs` / `decrypt.rs (connections)`.

### Original AeroShield Code Components
The following components are original AeroShield designs developed by Amjad Khan:
*   **Audit Session State Engine**: `crates/common/src/types.rs` / `crates/gui/src/globals.rs`.
*   **Compliance Vuln Checker (WEP / Open networks)**: `crates/gui/src/frontend/connections/app.rs`.
*   **Auditing Session Dashboard & Operator Notes Widget**: `crates/gui/src/frontend/widgets/session_tab.rs`.
*   **Timeline Event Logger & Findings Registry**: `crates/gui/src/frontend/connections/app.rs` (`log_timeline_event`, `log_finding`).
*   **Cairo Canvas Signal Strength Graph**: `crates/gui/src/frontend/widgets/graph.rs`.
*   **GPS Coordinate Poller (gpsd client)**: `crates/agent/src/backend/gps.rs`.
*   **Comprehensive HTML/KML Audit Exporters**: `crates/gui/src/backend/report.rs`.
*   **WPS auditor tab & background dispatcher**: `crates/gui/src/frontend/widgets/wps_tab.rs` and `crates/agent/src/backend/wps.rs`.
*   **Evil Twin rogue AP setup & DHCP controller**: `crates/gui/src/frontend/widgets/evil_twin_tab.rs` and `crates/agent/src/backend/evil_twin.rs`.

---

## 4. Third-Party Dependencies Audit

All crate dependencies have been audited for licensing compliance:

| Dependency | License | Required Action / Notice | Compliant? |
| :--- | :--- | :--- | :---: |
| `gtk4` | MIT / Apache-2.0 | Include standard license in distribution binary package | Yes |
| `serde` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `serde_json` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `toml` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `regex` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `chrono` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `lazy_static` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `nix` | MIT | Standard dependency headers in Cargo.lock | Yes |
| `ureq` | MIT | Standard dependency headers in Cargo.lock | Yes |
| `log` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `env_logger` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `thiserror` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `csv` | MIT / Unlicense | Standard dependency headers in Cargo.lock | Yes |
| `ctrlc` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |
| `libwifi` | MIT | Standard dependency headers in Cargo.lock | Yes |
| `radiotap` | MIT | Standard dependency headers in Cargo.lock | Yes |
| `libc` | MIT / Apache-2.0 | Standard dependency headers in Cargo.lock | Yes |

*Note*: No bundled fonts, third-party binary datasets, or proprietary assets are present in the repository. All graphical icons are standard SVG/PNG resources built for AeroShield.
