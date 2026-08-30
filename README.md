<h1 align="center">
  <img src="crates/gui/icons/app_icon.png" width=100 height=100/><br>
  AeroShield
</h1>

<p align="center">
  <span>A WiFi security auditing and penetration testing software written in Rust and GTK4, built on top of wireless utility suites.</span>
</p>

---

`AeroShield` is a powerful, modern WiFi security auditing tool. It is designed to run efficiently on Linux and provides a sleek graphical interface to capture WiFi traffic, audit WPA/WPA2/WPA3 networks, capture handshakes, parse and extract PMKIDs, perform active deauthentication tests, and audit WPS configurations.

## Features

AeroShield offers a robust suite of tools to evaluate the security of wireless networks:

- 📶 **Real-Time Traffic Sniffer**: Capture nearby WiFi traffic and automatically discover access points and client relationships.
- ⚡ **PMKID Cracking (Client-less)**: Capture and extract PMKIDs from RSN Information Elements in EAPOL frames, allowing security audits of networks even when no clients are connected.
- 💥 **Deauthentication Attacks**: Test target client connections by performing targeted deauthentication frame injections.
- 🤝 **Handshake Acquisition**: Monitor and capture full WPA/WPA2 4-way cryptographic handshakes.
- 🔑 **Offline Password Decryption**: Audit password strength using dictionary-based or brute-force attacks powered by `aircrack-ng`.
- 🛡️ **Evil Twin Testing**: Launch captive portal access points to audit user vulnerability to phishing.
- ⚙️ **WPS PIN Recovery**: Audit WPS-enabled networks for vulnerabilities using integrated PIN recovery engines.
- 📊 **Visual Graphs & Reports**: Graph live signal strengths and generate detailed HTML reports of audit sessions.

## Architecture

AeroShield is designed around a secure architecture:
1. **Unprivileged Frontend (`aeroshield`)**: A GTK4-based desktop client that handles settings, target selection, and result rendering. It runs as a normal user and works smoothly under both X11 and Wayland.
2. **Privileged Backend (`aeroshield-agent`)**: A small, native background agent that runs as root. When the frontend needs to perform a privileged operation (like interface state changes, raw frame injection, or monitoring), it spawns this agent via `polkit` (prompting for administrator authentication once). The agent communication is secured over a local Unix domain socket.

## Requirements

To run AeroShield, you will need:
- A **Linux** environment.
- A **wireless network card** that supports **monitor mode** and **packet injection**.
- Standard system dependencies: `bash`, `xterm`, `iw`, `macchanger`, `aircrack-ng`, and `adwaita-icon-theme`.
- Polkit / PolicyKit (installed by default on most desktop environments).

## Installation

### Building from Source

AeroShield is built in Rust. Ensure you have the Rust toolchain installed:

```bash
# Clone the repository
git clone https://github.com/ameramarketing/aeroshield.git
cd aeroshield

# Build in release mode
cargo build --release
```

After building, you will find the binaries under `target/release/`.

### Installation in System Path
Move the binaries to your path and copy the desktop shortcut and security policies:
```bash
sudo cp target/release/aeroshield /usr/bin/
sudo cp target/release/aeroshield-agent /usr/bin/
sudo cp package/.desktop /usr/share/applications/com.molivier.aeroshield.desktop
sudo cp package/.policy /usr/share/polkit-1/actions/org.freedesktop.policykit.aeroshield.policy
sudo cp crates/gui/icons/app_icon.png /usr/share/pixmaps/aeroshield.png
```

## Legal Disclaimer

⚠️ **AeroShield is designed for security auditing, network penetration testing, and education.** Running attacks on WiFi networks you do not own or do not have explicit authorization to audit is illegal in almost all countries. The authors and contributors assume no liability for any damage or legal issues caused by the misuse of this software.

## License

This project is licensed under the [MIT License](LICENSE).
