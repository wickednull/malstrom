"""Wi-Fi recon: enumerate nearby APs for the target picker.

Replaces PineAP recon. Scans with `iw scan` and parses the plain-text BSS
dump into rich AP records (security, band, vendor OUI, WPS). Choosing a
managed interface briefly drops its link, which is fine for a recon pass
but worth knowing if wlan0 is the box's uplink — so a radio already
serving the rogue AP (AP/monitor vif) is never picked for scanning.
"""

import re
import threading
import time

from . import config
from . import linuxutil

# Last successful scan snapshot, kept so the arming path can mirror the
# target's beacon elements (rates/beacon interval/HT profile) into the twin's
# hostapd conf without forcing another scan at arm time.
_last_aps = []

# --- vendor (OUI) lookup -------------------------------------------------------

_OUI_PATHS = (
    '/usr/share/nmap/nmap-mac-prefixes',     # nmap: "F01898 Apple"
    '/var/lib/ieee-data/oui.txt',            # ieee: "F0-18-98   (hex)\tApple"
    '/usr/share/ieee-data/oui.txt',
)
_oui_cache = None
_oui_lock = threading.Lock()


def _load_ouis():
    """OUI prefix -> vendor name, parsed lazily from any local OUI source.

    No hardcoded vendor guesses: when no OUI database exists on the box the
    vendor column is simply left empty.
    """
    global _oui_cache
    with _oui_lock:
        if _oui_cache is not None:
            return _oui_cache
        table = {}
        for path in _OUI_PATHS:
            try:
                with open(path, encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        # nmap-mac-prefixes: "F01898 Apple, Inc." — the vendor
                        # must not open with '(', which would swallow the
                        # ieee "(base 16)" continuation lines.
                        m = re.match(r'^([0-9A-Fa-f]{6})\s+([^\s(]\S*)', line)
                        if m:
                            table[m.group(1).upper()] = \
                                line[m.start(2):].strip()[:40]
                            continue
                        # ieee oui.txt: "F0-18-98   (hex)\t\tApple, Inc."
                        m = re.match(r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-'
                                     r'[0-9A-Fa-f]{2})\s*\(hex\)\s+(\S.*)$',
                                     line)
                        if m:
                            table[m.group(1).replace('-', '').upper()] = \
                                m.group(2).strip()[:40]
            except OSError:
                continue
        _oui_cache = table
        return table


def vendor_of(bssid):
    """Vendor string for a BSSID's OUI (best-effort, '' when unknown)."""
    oui = re.sub(r'[^0-9A-Fa-f]', '', (bssid or '')[:8]).upper()
    if len(oui) == 6:
        return _load_ouis().get(oui, '')
    return ''


# --- interface selection -------------------------------------------------------

def _scannable(iface):
    """True when the netdev can actually run a managed-mode scan right now."""
    return bool(iface) and linuxutil.iface_mode(iface) == 'managed'


def default_scan_iface():
    if config.RECON_IFACE:
        return config.RECON_IFACE
    uplink = linuxutil.default_route_iface()
    order = linuxutil.ordered_devices()
    # The uplink radio gives the freshest view while it is still an associated
    # managed client — but once hostapd owns it (operator sacrificed the
    # uplink) `iw scan` just fails; skip to a real managed radio.
    for dev in order:
        if dev['iface'] == uplink and _scannable(dev['iface']):
            return dev['iface']
    # Prefer the first radio that can actually run a managed scan — never a
    # monitor/AP vif, never a driver blacklisted for wedging the system.
    for dev in order:
        if linuxutil.phy_banned(dev['phy']):
            continue
        if _scannable(dev['iface']) \
                and 'managed' in linuxutil.phy_modes(dev['phy']):
            return dev['iface']
    for dev in order:
        return dev['iface']
    return None


# --- iw scan parsing -----------------------------------------------------------

_BSS_RE = re.compile(r'^BSS\s+([0-9A-Fa-f:]{17})(?:\s*\(on\s+\S+\))?',
                     re.IGNORECASE)
_SIGNAL_RE = re.compile(r'(-?\d+(?:\.\d+)?)')
_FREQ_RE = re.compile(r'freq:\s*(\d+)')
_AUTHS_RE = re.compile(r'\*\s*Auth(?:entication)?\s*suites?:\s*(.*)')
_CIPHER_RE = re.compile(r'\*\s*(?:Group cipher|Pairwise ciphers?):\s*(.*)')
_CAP_RE = re.compile(r'capability:\s*(.*)')
_RATES_RE = re.compile(r'^(?:Supported|Extended supported) rates?:\s*(.*)$',
                       re.IGNORECASE)
_BI_RE = re.compile(r'beacon interval:\s*(\d+)\s*TUs?', re.IGNORECASE)
_DTIM_RE = re.compile(r'DTIM period:\s*(\d+)', re.IGNORECASE)
_HT40_RE = re.compile(r'secondary channel offset:\s*(above|below)',
                      re.IGNORECASE)
# Whole-Mbps rates hostapd accepts in conf (`supported_rates`/`basic_rates`).
# Fractional rates (5.5) are dropped rather than risk a hostapd parse surprise.
RATE_TABLE = (54, 48, 36, 24, 18, 12, 11, 9, 6, 2, 1)


def freq_to_channel(freq):
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2484:
        return (freq - 2407) // 5
    if 4910 <= freq <= 4980:                       # 5 GHz sub-band (JP)
        return (freq - 4000) // 5
    if 5035 <= freq <= 5885:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:                       # 6 GHz (Wi-Fi 6E)
        return (freq - 5950) // 5
    return 0


def freq_to_band(freq):
    if 2400 <= freq <= 2494:
        return '2.4 GHz'
    if 4900 <= freq <= 5899:
        return '5 GHz'
    if 5925 <= freq <= 7125:
        return '6 GHz'
    return ''


def _summarize_security(ap):
    """Human security tag derived from RSN/WPA IE + capability privacy bit."""
    auths = ap.pop('_auths')
    cipher = ap.pop('_cipher')
    rsn, wpa, privacy = ap['_rsn'], ap['_wpa'], ap['_privacy']
    if rsn or wpa:
        modes = []
        if wpa and 'PSK' in auths:
            modes.append('WPA')
        if rsn:
            if 'SAE' in auths:
                modes.append('WPA3')
            elif 'OWE' in auths:
                modes.append('OWE')
            elif '802.1X' in auths:
                modes.append('WPA2-ENT')
            else:
                modes.append('WPA2')
        tag = '/'.join(modes) if modes else 'WPA'
        if cipher:
            tag += '-' + cipher
        return tag
    return 'WEP' if privacy else 'OPEN'


def _new_ap(bssid):
    return {'bssid': bssid.upper(), 'ssid': '[hidden]', 'channel': 0,
            'band': '', 'signal': None, 'security': 'OPEN',
            'vendor': vendor_of(bssid), 'wps': False, 'adhoc': False,
            '_rsn': False, '_wpa': False, '_privacy': False,
            '_auths': set(), '_cipher': '', '_freq': 0,
            'rates': [], 'basic': [], 'beacon_int': 0, 'dtim': 0,
            '_ht': False, '_ht40dir': '', '_sg20': False, '_sg40': False,
            '_rxstbc': False, '_ldpc': False, '_vht': False, '_he': False}


def _parse_rates(text):
    """Split an `iw` rate-set string into (rates, basic) as floats.

    Tokens carry a trailing `*` when the rate is advertised as basic. Values
    jitter like `6.0*`, `5.5`, `108.0`.
    """
    rates, basic = [], []
    for tok in (text or '').split():
        tok = tok.strip()
        if not tok:
            continue
        mark = tok.endswith('*')
        raw = tok.rstrip('*').strip()
        try:
            val = float(raw)
        except ValueError:
            continue
        if val <= 0 or val != val:      # no zeros / weird infinities
            continue
        (basic if mark else rates).append(val)
    return rates, basic


def fidelity_of(ap):
    """Beacon elements worth replaying on the twin ({} for a naked beacon).

    Nothing here is ever trusted to change the twin's *identity* (SSID/BSSID
    come from the operator), only its non-identifying beacon wall-paper: rates,
    beacon interval, DTIM and HT/VHT/HE capability hints. The arming path
    sanitizes the whole dict again before it lands in hostapd conf.
    """
    f = {}
    all_rates = list(ap.get('rates') or []) + list(ap.get('basic') or [])
    rates = []
    for r in all_rates:
        if isinstance(r, (int, float)) and r > 0 and r not in rates:
            rates.append(r)
    if rates:
        f['rates'] = rates
    basic = [r for r in ap.get('basic') or []
             if isinstance(r, (int, float)) and r > 0]
    if basic:
        f['basic'] = basic
    if ap.get('beacon_int'):
        f['beacon_int'] = int(ap['beacon_int'])
    if ap.get('dtim'):
        f['dtim'] = int(ap['dtim'])
    h = {}
    if ap.get('_ht'):
        if ap.get('_ht40dir') in ('+', '-'):
            h['ht40'] = ap['_ht40dir']
        if ap.get('_sg20'):
            h['short_gi20'] = True
        if ap.get('_sg40'):
            h['short_gi40'] = True
        if ap.get('_rxstbc'):
            h['rx_stbc'] = True
        if ap.get('_ldpc'):
            h['ldpc'] = True
    if ap.get('_vht'):
        h['vht'] = True
    if ap.get('_he'):
        h['he'] = True
    if h:
        f['ht'] = h
    return f


def _finish(ap, merged):
    """Summarize one parsed BSS block and fold it into the BSSID table."""
    if ap is None:
        return
    ap['security'] = _summarize_security(ap)
    ap['fidelity'] = fidelity_of(ap)
    for k in ('_freq', '_rsn', '_wpa', '_privacy', '_ht', '_ht40dir',
              '_sg20', '_sg40', '_rxstbc', '_ldpc', '_vht', '_he'):
        ap.pop(k, None)
    old = merged.get(ap['bssid'])
    if old is None:
        merged[ap['bssid']] = ap
        return
    # Same BSS twice (beacon + probe response, mesh): keep the strongest
    # signal and the richest elements of the two blocks.
    for k in ('ssid', 'band', 'vendor'):
        if (not old[k] or old[k] == '[hidden]') and ap[k] \
                and ap[k] != '[hidden]':
            old[k] = ap[k]
    if ap['security'] != 'OPEN' and old['security'] == 'OPEN':
        old['security'] = ap['security']
    old['wps'] = old['wps'] or ap['wps']
    old['adhoc'] = old['adhoc'] or ap['adhoc']
    if ap['signal'] is not None and (old['signal'] is None
                                     or ap['signal'] > old['signal']):
        old['signal'] = ap['signal']
        old['channel'] = ap['channel'] or old['channel']
    else:
        old['channel'] = old['channel'] or ap['channel']


def parse_iw_scan(out):
    """Parse an `iw scan` dump into AP dicts, strongest signal first."""
    merged = {}
    current = None
    section = None        # 'rsn' | 'wpa' — which IE sub-block we are inside
    htsection = None      # 'ht' | 'htop' — HT capability / operation blocks

    for line in out.splitlines():
        depth = len(line) - len(line.lstrip('\t'))
        stripped = line.strip()
        m = _BSS_RE.match(stripped)
        if m:
            _finish(current, merged)
            current = _new_ap(m.group(1))
            section = None
            htsection = None
            continue
        if current is None or not stripped:
            continue
        if depth >= 2 and htsection == 'ht':
            # HT capability sub-block (`HT20/HT40`, `Short GI 20MHz: 1`,
            # `RX STBC: 1`, `LDPC Coding Capability: 1`, ...).
            if 'HT40' in stripped:
                current['_ht40dir'] = current['_ht40dir'] or '+'
            if 'Short GI 20MHz' in stripped:
                current['_sg20'] = True
            if 'Short GI 40MHz' in stripped:
                current['_sg40'] = True
            if 'RX STBC' in stripped:
                current['_rxstbc'] = True
            if 'LDPC' in stripped:
                current['_ldpc'] = True
            continue
        if depth >= 2 and htsection == 'htop':
            m = _HT40_RE.search(stripped)
            if m:
                current['_ht40dir'] = '+' if m.group(1) == 'above' else '-'
            continue
        if stripped.startswith('SSID:'):
            section = None
            htsection = None
            current['ssid'] = stripped.split(':', 1)[1].strip() or '[hidden]'
        elif stripped.startswith('signal:'):
            m = _SIGNAL_RE.search(stripped)
            if m:
                current['signal'] = float(m.group(1))
        elif stripped.startswith('DS Parameter set:') \
                or stripped.startswith('DS Param set:'):
            section = None
            htsection = None
            m = re.search(r'channel\s+(\d+)', stripped)
            if m and not current['_freq']:
                current['channel'] = int(m.group(1))
        elif stripped.startswith('freq:'):
            section = None
            htsection = None
            m = _FREQ_RE.search(stripped)
            if m:
                freq = int(m.group(1))
                current['_freq'] = freq
                ch = freq_to_channel(freq)
                if ch:
                    current['channel'] = ch
                current['band'] = freq_to_band(freq)
        elif stripped.startswith('capability:'):
            section = None
            htsection = None
            m = _CAP_RE.search(stripped)
            if m:
                caps = m.group(1)
                current['_privacy'] = 'Privacy' in caps
                current['adhoc'] = 'IBSS' in caps
        elif _RATES_RE.match(stripped):
            rates, basic = _parse_rates(_RATES_RE.match(stripped).group(1))
            current['rates'].extend(r for r in rates if r not in current['rates'])
            current['basic'].extend(r for r in basic if r not in current['basic'])
        elif _BI_RE.search(stripped):
            m = _BI_RE.search(stripped)
            current['beacon_int'] = int(m.group(1))
        elif _DTIM_RE.search(stripped):
            m = _DTIM_RE.search(stripped)
            current['dtim'] = int(m.group(1))
        elif stripped.startswith('HT capabilities:'):
            section = None
            htsection = 'ht'
            current['_ht'] = True
        elif stripped.startswith('HT operation:'):
            section = None
            htsection = 'htop'
            current['_ht'] = True
        elif stripped.startswith('VHT capabilities:'):
            section = None
            htsection = None
            current['_vht'] = True
        elif stripped.startswith('HE capabilities:') \
                or stripped.startswith('HE Operation:') \
                or stripped.startswith('EHT capabilities:') \
                or stripped.startswith('EHT Operation:'):
            section = None
            htsection = None
            current['_he'] = True
        elif stripped.startswith('RSN:'):
            current['_rsn'] = True
            htsection = None
            section = 'rsn'
        elif stripped.startswith('WPA:'):
            current['_wpa'] = True
            htsection = None
            section = 'wpa'
        elif stripped.startswith('WPS:'):
            section = None
            htsection = None
            current['wps'] = True
        elif stripped.startswith('*'):
            m = _AUTHS_RE.match(stripped)
            if m and section:
                current['_auths'].update(a.strip() for a in m.group(1).split())
                continue
            m = _CIPHER_RE.match(stripped)
            if m and section and not current['_cipher']:
                for c in ('CCMP', 'GCMP', 'TKIP', 'WEP-40', 'WEP-104'):
                    if c in m.group(1):
                        current['_cipher'] = c
                        break
    _finish(current, merged)
    return sorted(merged.values(),
                  key=lambda a: (a['signal'] if a['signal'] is not None
                                 else -1000), reverse=True)


# --- scan driver ----------------------------------------------------------------

def scan_wifi(iface=None, timeout=12):
    """Run one managed-mode scan and return a rich result dict.

    ok=0 carries a human `error` (no scannable radio, iw failure, driver
    refusal) instead of an empty list, so the dashboard can explain why a
    recon pass returned nothing.
    """
    global _last_aps
    iface = iface or default_scan_iface()
    res = {'ok': 1, 'iface': iface or '', 'error': '',
           'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'), 'aps': []}
    if not iface:
        res['ok'] = 0
        res['error'] = ('no wifi interface available for scanning '
                        '(all radios are AP/monitor mode or missing)')
        return res
    r = linuxutil.run(['iw', 'dev', iface, 'scan'], timeout=timeout)
    if r.returncode != 0:
        res['ok'] = 0
        err = (r.stderr or r.stdout or '').strip()
        res['error'] = (err.splitlines()[0][:200] if err
                        else 'iw scan failed on %s' % iface)
        _last_aps = []
        return res
    res['aps'] = parse_iw_scan(r.stdout)
    _last_aps = res['aps']
    return res


def fidelity_for(bssid):
    """Beacon-fidelity elements for a BSSID from the most recent scan.

    Best-effort: the operator (or autopwn) picks a target from a scan, and the
    arm path reuses this snapshot to mirror the target's rates/beacon profile
    into the twin's hostapd conf. Returns None when the BSSID is blank, unknown,
    or the last scan failed — the twin then falls back to its default conf
    (which is indistinguishable from a hand-tuned deployment).
    """
    if not bssid:
        return None
    up = (bssid or '').upper()
    for ap in _last_aps:
        if (ap.get('bssid') or '').upper() == up:
            return ap.get('fidelity') or None
    return None


def scan_aps(iface=None, timeout=12):
    """Legacy list-only wrapper over scan_wifi."""
    return scan_wifi(iface, timeout=timeout)['aps']
