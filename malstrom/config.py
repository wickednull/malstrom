"""Runtime configuration + filesystem paths.

These mirror the old config.sh defaults. Every value can be overridden with a
MALSTROM_* environment variable, or from the dashboard at runtime (those
overrides go into the engine's state file and this module is only consulted
for defaults).
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STATE_DIR = os.environ.get('MALSTROM_STATE_DIR', '/var/lib/malstrom')
WWW_DIR = os.path.join(ROOT, 'www')
TEMPLATES_DIR = os.path.join(ROOT, 'portal', 'templates')
DETECTION_DIR = os.path.join(ROOT, 'portal', 'detection')
# Canonical vault (the old payload.sh hard-coded /root/loot/malstrom and the
# deploy env template documents it). Fixed — not `~/loot/malstrom` — so
# `malstrom --check`, `wipe-loot` and `reset` resolve the SAME path the root
# daemon writes to no matter who invokes them (a non-root `--check` used to
# report a different, empty per-user dir than the real daemon's loot tree).
LOOT_DIR = os.environ.get('MALSTROM_LOOT_DIR', '/root/loot/malstrom')

PORTAL_IP = os.environ.get('MALSTROM_PORTAL_IP', '172.16.52.1')
PORTAL_NET = os.environ.get('MALSTROM_PORTAL_NET', '172.16.52.0/24')
DHCP_START = os.environ.get('MALSTROM_DHCP_START', '172.16.52.100')
DHCP_END = os.environ.get('MALSTROM_DHCP_END', '172.16.52.200')
DNS_PORT = int(os.environ.get('MALSTROM_DNS_PORT', '1053'))
PORTAL_PORT = int(os.environ.get('MALSTROM_PORTAL_PORT', '80'))
DASH_PORT = int(os.environ.get('MALSTROM_DASH_PORT', '8888'))
DASH_HOST = os.environ.get('MALSTROM_DASH_HOST', '0.0.0.0')
DHCP_LEASE_FILE = os.path.join(STATE_DIR, 'dhcp.leases')
PCAP_DIR = os.path.join(LOOT_DIR, 'pcaps')
CUSTOM_TEMPLATES_DIR = os.path.join(STATE_DIR, 'templates', 'custom')
MAX_DEVICES = int(os.environ.get('MALSTROM_MAX_DEVICES', '256'))
MAX_PROBES = int(os.environ.get('MALSTROM_MAX_PROBES', '500'))
MAX_CREDS = int(os.environ.get('MALSTROM_MAX_CREDS', '5000'))

AP_IFACE = os.environ.get('MALSTROM_AP_IFACE', '')
MON_IFACE = os.environ.get('MALSTROM_MON_IFACE', '')
RECON_IFACE = os.environ.get('MALSTROM_RECON_IFACE', '')
WLAN_DEV = os.environ.get('MALSTROM_WLAN_DEV', '')
AP_VIF_NAME = os.environ.get('MALSTROM_AP_VIF', 'ap0')
MON_VIF_NAME = os.environ.get('MALSTROM_MON_VIF', 'mon0')

# Optional hardening gate for virtual-interface creation. Some kernel/builds
# of the 88xxau-family USB Realtek drivers (8821au/8812au -> rtw_*) wedge the
# WHOLE box the moment a monitor/AP vif is added (a Raspberry Pi needs a hard
# power-cycle) — but this is build- and box-specific, and the same cards
# work fine on others. The default is EMPTY so the attack radio is never
# refused out of the box. If a specific build/box is confirmed to hang,
# re-add the driver module names (lowercased, comma-separated), e.g.:
#   MALSTROM_DANGEROUS_DRIVERS=8821au,8812au,88xxau,rtw_8821au,rtl88xxau
# The list only gates AUTO-created/auto-chosen vifs — setting
# MALSTROM_MON_IFACE / MALSTROM_AP_IFACE / MALSTROM_WLAN_DEV to an explicit
# interface always opts the operator in.
DANGEROUS_VIF_DRIVERS = tuple(
    d.strip().lower() for d in os.environ.get(
        'MALSTROM_DANGEROUS_DRIVERS', ''
    ).split(',') if d.strip())

DEAUTH_METHOD = os.environ.get('MALSTROM_DEAUTH_METHOD', 'auto')
MONITOR_INTERVAL = float(os.environ.get('MALSTROM_MONITOR_INTERVAL', '4'))
POLL = float(os.environ.get('MALSTROM_POLL', '2'))
CLIENT_WINDOW = int(os.environ.get('MALSTROM_CLIENT_WINDOW', '10'))

# Clone fidelity. WPA3 transition (WPA-PSK + SAE with PMF optional) lets the
# evil-WPA twin accept WPA3-capable clients too — opt-in per engagement from
# the attack form, because some hostapd/driver combos reject SAE outright.
WPA3_TRANSITION = os.environ.get('MALSTROM_WPA3', '0') != '0'

# Radio/AP backoff. Cheap USB wifi cards (rtl88xxau, rtl8xxxu) are slow to
# flip interface modes and can wedge the whole radio stack when hammered. These
# throttle how often the engine re-probes hostapd liveness and how long it
# waits between failed AP bring-up retries, and how often a failing monitor-vif
# creation is re-attempted.
STACK_ALIVE_INTERVAL = float(os.environ.get('MALSTROM_STACK_ALIVE_INTERVAL', '5'))
STACK_RETRY_UP = float(os.environ.get('MALSTROM_STACK_RETRY_UP', '8'))
STACK_RETRY_DOWN = float(os.environ.get('MALSTROM_STACK_RETRY_DOWN', '15'))
VIF_RETRY_GAP = float(os.environ.get('MALSTROM_VIF_RETRY_GAP', '5'))
# Grace window from hostapd launch during which a still-running process is
# trusted to be mid-transition into AP mode: cheap USB radios (rtl88xxau) take
# several seconds per interface flip, and killing a healthy AP just because
# `iw` hadn't caught up yet is how the old code kill-looped working APs.
AP_TRANSITION_GRACE = float(os.environ.get('MALSTROM_AP_TRANSITION_GRACE', '25'))

# Auto-crack pipeline (handshake/PMKID + NetNTLMv2). MALSTROM_CRACK_WORDLIST
# overrides the auto-detected list; empty = auto (rockyou et al, gunzipping
# rockyou.txt.gz into the state dir once when only the .gz exists).
CRACK_ENABLED = os.environ.get('MALSTROM_CRACK', '1') != '0'
CRACK_WORDLIST = os.environ.get('MALSTROM_CRACK_WORDLIST', '')
CRACK_TIMEOUT = int(os.environ.get('MALSTROM_CRACK_TIMEOUT', '600'))
HASHCAT_BIN = os.environ.get('MALSTROM_HASHCAT_BIN', 'hashcat')

# Auto-harvester (pwnagotchi-style) settings.
AUTO_HARVEST = os.environ.get('MALSTROM_AUTO_HARVEST', '0') != '0'
AUTO_DWELL = int(os.environ.get('MALSTROM_AUTO_DWELL', '60'))
AUTO_RECON_INTERVAL = int(os.environ.get('MALSTROM_AUTO_RECON_INTERVAL', '120'))
AUTO_MIN_RSSI = int(os.environ.get('MALSTROM_AUTO_MIN_RSSI', '-80'))
AUTO_MAX_INTERACTIONS = int(os.environ.get('MALSTROM_AUTO_MAX_INTERACTIONS', '3'))
AUTO_CHANNELS = [c.strip() for c in os.environ.get('MALSTROM_AUTO_CHANNELS', '').split(',')
                 if c.strip().isdigit()]
AUTO_SKIP_CAPTURED = os.environ.get('MALSTROM_AUTO_SKIP_CAPTURED', '1') != '0'

# TLS victim portal: self-signed cert, second listener that the 443 DNAT
# targets so https-first captive probes land on a real (if untrusted) TLS
# portal instead of a broken plaintext redirect.
PORTAL_TLS = os.environ.get('MALSTROM_PORTAL_TLS', '1') != '0'
PORTAL_TLS_PORT = int(os.environ.get('MALSTROM_PORTAL_TLS_PORT', '8443'))

# Dashboard port fallback range when the configured port is already taken
# (falling back beats crash-looping the daemon on every restart).
DASH_PORT_FALLBACKS = 10

# Rogue-segment client isolation. On by default: victims on the portal subnet
# must not reach each other or the operator's own LAN behind the box's other
# interfaces. hostapd `ap_isolate=1` stops station-to-station frames at L2 and
# iptables drops routed client<->client + portal->local-net in FORWARD. Public
# internet passthrough (beacon C2, whitelisted clients) is unaffected — the
# DROPs are anchored to the AP interface and to private local nets only.
CLIENT_ISOLATION = os.environ.get('MALSTROM_CLIENT_ISOLATION', '1') != '0'

# Firewall backend: auto = iptables when present else nft; can force either.
# Accepts the historical values too ('iptables-legacy' -> iptables).
FIREWALL_BACKEND = os.environ.get('MALSTROM_FIREWALL', 'auto').lower()
if FIREWALL_BACKEND in ('iptables-legacy', 'ip6tables', 'auto'):
    FIREWALL_BACKEND = 'auto' if FIREWALL_BACKEND == 'auto' else 'iptables'

# Guard IPv6 while armed: the rogue mesh serves no v6 (no RAs on the portal
# net), so anything attempting to route v6 through the AP interface is either
# broken or hostile — drop it and confine per-interface forwarding.
IPV6_GUARD = os.environ.get('MALSTROM_IPV6_GUARD', '1') != '0'

REDIRECT_TARGET = os.environ.get('MALSTROM_REDIRECT', 'http://example.com')
DEFAULT_TEMPLATE = os.environ.get('MALSTROM_TEMPLATE', 'wifi_login')
WPA_PSK = os.environ.get('MALSTROM_WPA_PSK', '')
CLONE_BSSID = os.environ.get('MALSTROM_CLONE_BSSID', '0') != '0'
PORTAL_SSID = os.environ.get('MALSTROM_PORTAL_SSID', '')

# Beacon fidelity + evasion. BEACON_FIDELITY mirrors the target's observed rate
# set / beacon interval / DTIM / HT capability hints into the twin's hostapd
# conf (sanitized at write time so a hostile/broken beacon can never take the
# rogue AP down). BEACON_ROTATE swaps the decoy BSSID for a fresh
# locally-administered MAC every N minutes while armed — decoy mode only, since
# cloning the target's exact BSSID IS the identity. SSID_CLOAK drops the SSID
# from beacons + wildcard probe responses (ignore_broadcast_ssid): the twin
# serves directed probes but no longer broadcasts its name.
BEACON_FIDELITY = os.environ.get('MALSTROM_BEACON_FIDELITY', '1') != '0'
BEACON_ROTATE = int(os.environ.get('MALSTROM_BEACON_ROTATE', '0') or 0)
SSID_CLOAK = os.environ.get('MALSTROM_SSID_CLOAK', '0') != '0'

CAPTURE_MODE = os.environ.get('MALSTROM_CAPTURE', 'handshake')   # off|handshake|pmkid|both
KARMA = os.environ.get('MALSTROM_KARMA', '1') != '0'
SHIELD_AFTER_CAPTURE = os.environ.get('MALSTROM_SHIELD', '1') != '0'

# Karma auto-respond (PineAP-style). OFF by default: answering probe requests
# means *transmitting*, which makes the box detectable as an AP storm — the
# passive listener never is. When ON, karma answers only broadcast probes and
# directed probes for the LIVE twin's SSID — never other identities — so
# clients that saved the cloned network join faster without AP-storming a
# dozen fake SSIDs. Responses are injected on the monitor radio tuned to the
# target channel, sourced from the rogue BSSID.
KARMA_RESPOND = os.environ.get('MALSTROM_KARMA_RESPOND', '0') != '0'
KARMA_RESPOND_GAP = float(os.environ.get('MALSTROM_KARMA_RESPOND_GAP', '2'))

# Scan-channel awareness: while the chain is IDLE, karma cycles the monitor
# radio through every channel so the operator gets a full-band client-interest
# map before picking targets. The moment the chain is armed the monitor must
# stay pinned on the target channel — deauth/capture coherence is sacred — so
# hopping only ever happens idle (purely passive, TX-free). 0 disables idle
# hopping entirely (karma then only listens on whatever channel the radio is on).
KARMA_HOP = os.environ.get('MALSTROM_KARMA_HOP', '1') != '0'
KARMA_HOP_DWELL = float(os.environ.get('MALSTROM_KARMA_HOP_DWELL', '4'))
KARMA_HOP_RETRY = float(os.environ.get('MALSTROM_KARMA_HOP_RETRY', '30'))
KARMA_HOP_CHANNELS = [c.strip() for c in
                      os.environ.get('MALSTROM_KARMA_HOP_CHANNELS', '').split(',')
                      if c.strip().isdigit()]

# HTTP relay / SSL-strip-lite: when ON, the portal stops answering every
# request with the captive page and instead transparently relays victim
# cleartext HTTP to its real destination (the rogue AP is the victim's
# gateway, so all outbound :80 lands here). Responses are rewritten so any
# https:// reference becomes http:// — victims' browsers then ask for the
# cleartext version of the same resource, which relays the same way. Switch
# on AFTER creds are captured to keep the victim "online" while their plain
# HTTP session streams to the loot vault. OFF by default: the sole purpose of
# the portal is the captive page.
RELAY = os.environ.get('MALSTROM_RELAY', '0') != '0'

SCAN_BIN = os.environ.get('MALSTROM_SCAN_BIN', 'nmap')
SCAN_PORT_RANGE = os.environ.get('MALSTROM_SCAN_PORT_RANGE', '1-1000')
MITM_IFACE = os.environ.get('MALSTROM_MITM_IFACE', '')
RESPONDER_BIN = os.environ.get('MALSTROM_RESPONDER_BIN', 'responder')
NETEXEC_BIN = os.environ.get('MALSTROM_NETEXEC_BIN', 'netexec')
SPRAY_LIMIT = int(os.environ.get('MALSTROM_SPRAY_LIMIT', '15'))
BEACON_INTERVAL = int(os.environ.get('MALSTROM_BEACON_INTERVAL', '20'))
BEACON_MAXOUT = int(os.environ.get('MALSTROM_BEACON_MAXOUT', '1000000'))

AUTH_REQUIRED = os.environ.get('MALSTROM_AUTH', '0') != '0'
TOKEN = os.environ.get('MALSTROM_TOKEN', '')

# Dashboard hardening. DASH_TLS terminates the operator dashboard over TLS
# with a self-signed cert (generated once, like the victim portal) so the
# token handshake and the SSR/SSE stream never leave the box in the clear.
# VAULT encrypts the mirrored loot copy at rest (creds.json/creds.log become
# *.vault Fernet blobs; requires python3-cryptography, else the mirror stays
# plaintext and an ALERT is raised). EXFIL_WEBHOOK enables out-of-band
# alerting: on every ALERT-class event the daemon POSTs a small JSON payload
# (type/timestamp/msg — never loot contents) to the URL, fire-and-forget.
DASH_TLS = os.environ.get('MALSTROM_DASH_TLS', '0') != '0'
VAULT = os.environ.get('MALSTROM_VAULT', '0') != '0'
EXFIL_WEBHOOK = (os.environ.get('MALSTROM_EXFIL_WEBHOOK', '') or
                 os.environ.get('MALSTROM_WEBHOOK', '')).strip()
NOTIFY_DETAIL = os.environ.get('MALSTROM_NOTIFY_DETAIL', '0') != '0'

# Desktop-launcher mode: starts clean (idle) and self-stops once the
# dashboard is closed. `MALSTROM_APP_IDLE` is the grace period (seconds)
# after the last dashboard connection drops before shutdown.
APP_MODE = os.environ.get('MALSTROM_APP_MODE', '0') != '0'
APP_IDLE = float(os.environ.get('MALSTROM_APP_IDLE', '45'))

DEFAULT_STATE = {
    'active': False,
    'target_ssid': '',
    'target_bssid': '',
    'target_channel': '6',
    'portal_mode': 'open',
    'wpa_psk': '',
    'portal_ssid': PORTAL_SSID,
    'clone_bssid': CLONE_BSSID,
    'wpa3_transition': WPA3_TRANSITION,
    'beacon_fidelity': BEACON_FIDELITY,
    'beacon_rotate': BEACON_ROTATE,
    'ssid_cloak': SSID_CLOAK,
    'deauth_mode': 'broadcast',
    'deauth_burst': 25,
    'deauth_delay': 1,
    'deauth_continuous': True,
    'capture_mode': CAPTURE_MODE,
    'karma': KARMA,
    'karma_respond': KARMA_RESPOND,
    'relay': RELAY,
    'shield_after_capture': SHIELD_AFTER_CAPTURE,
    'template': DEFAULT_TEMPLATE,
    'redir_target': REDIRECT_TARGET,
    'auto_harvest': AUTO_HARVEST,
    'auto_armed': False,
    'updated': 0,
}