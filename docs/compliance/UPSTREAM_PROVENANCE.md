# Upstream Provenance Verification Record

This document records the exact upstream provenance of the AeroShield codebase, verifying its structural relationship to its source foundation.

---

## 1. Upstream Base Details

*   **Original Project**: Airgorah
*   **Upstream Author**: Martin Olivier <martin.olivier@live.fr>
*   **Upstream Repository**: [https://github.com/martin-olivier/airgorah](https://github.com/martin-olivier/airgorah)
*   **Target Upstream Tag/Version**: **v0.8.1**
*   **Foundation Commit Verification**: 
    "Exact upstream commit could not be conclusively established."
    
    *Note*: The Git database of AeroShield was initialized as a clean import on August 30, 2026. However, package metadata versions (`0.8.1`) and dependency configurations in Cargo lock files confirm that the codebase was originally branched or cloned from the release snapshot of Airgorah version v0.8.1.

---

## 2. Derivative Relationship Documentation

AeroShield is a derivative work of Airgorah, inheriting low-level wrapper modules for wireless device control and packet capture, while adding a new product architecture and functional capabilities:

1.  **Shared Foundation (Airgorah)**: 
    *   Low-level 802.11 management frame generation and deauthentication socket loops.
    *   Subprocess wrappers for standard tools like `iw`, `ip`, and `airodump-ng`.
    *   Wayland-compatible privilege split (GUI/agent IPC architecture).
2.  **AeroShield Original Engineering**:
    *   Centralized, state-driven `AuditSession` structure replacing independent component cache maps.
    *   Passive vulnerability scanner checks (identifying and logging WEP/Open issues automatically).
    *   A GTK4-based dashboard displaying event timeline logs, vulnerability registries, notes widgets, and signal metrics.
    *   Comprehensive export system producing detailed HTML reports and KML geographical overlays.
    *   Backend interfaces for simulated Evil Twin gateway APs and WPS Pin recovery threads.
