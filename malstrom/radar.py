"""Live 802.11 radar: passive spectrum + AP/client telemetry.

This is the always-on "eye" behind the Recon deck. While the kill chain is
idle the monitor radio is already hopping the band for karma, so this engine
piggybacks on that sweep without ever transmitting: it reads raw 802.11
frames off the monitor vif, decodes radiotap (channel/signal/noise), classifies
every frame and keeps rolling one-second series for the dashboard graphs
(packets/s, events/s, per-channel load, retry ratio).

It also maintains a live AP/client inventory richer than an `iw scan` pass:
SSID, security, WPS, band, channel, RSSI, beacon count, client list, probes
seen per station and a feed of the interesting management frames (deauth /
disassoc / auth / assoc / probe). Radio survey data (`iw ... survey dump`)
adds busy/RX/TX air-time and noise floor for the tuned channel.

Everything is in-memory and bounded; nothing is written to the loot vault
from this engine (karma/capture own persistence), so a busy band can never
turn into a disk-write storm.
"""

import collections
import os
import re
import socket
import struct
import threading
import time

from . import config
from . import linuxutil
from . import recon

# --- bounds ------------------------------------------------------------------
AP_CAP = 600
CLIENT_CAP = 900
PROBE_CAP = 400
EVENT_CAP = 240
BUCKET_KEEP = 200          # seconds of one-second counters retained
SERIES_POINTS = 90         # points returned to the UI
CHANNEL_HIST = 30          # per-channel history points
SURVEY_HIST = 90

MGMT, CTRL, DATA = 0, 1, 2

# 802.11 management subtypes we care about
KIND_BY_SUBTYPE = {
    0: 'ASSOC', 1: 'ASSOC_RESP', 2: 'ASSOC', 3: 'ASSOC_RESP',
    4: 'PROBE', 5: 'PROBE_RESP', 8: 'BEACON', 9: 'ATIM',
    10: 'DISASSOC', 11: 'AUTH', 12: 'DEAUTH', 13: 'ACTION', 14: 'ACTION',
}

REASONS = {
    1: 'unspecified', 2: 'prev auth invalid', 3: 'leaving BSS',
    4: 'inactivity', 5: 'AP capacity', 6: 'class-2 frame', 7: 'class-3 frame',
    8: 'leaving BSS', 9: 'not authenticated', 10: 'power cap',
    11: 'supported channels', 12: 'BSS transition', 13: 'reason invalid',
    14: 'MIC failure', 15: '4-way timeout', 16: 'group key timeout',
    17: 'IE mismatch', 18: 'group cipher invalid', 19: 'pairwise cipher',
    20: 'AKM unsupported', 21: 'RSN version', 22: 'RSN capabilities',
    23: '802.1X auth failed', 24: 'cipher rejected', 25: 'TKIP only',
}

FRAME_NAMES = {
    (MGMT, 8): 'BEACON', (MGMT, 5): 'PROBE RESP', (MGMT, 4): 'PROBE REQ',
    (MGMT, 11): 'AUTH', (MGMT, 0): 'ASSOC REQ', (MGMT, 2): 'REASSOC REQ',
    (MGMT, 1): 'ASSOC RESP', (MGMT, 3): 'REASSOC RESP',
    (MGMT, 10): 'DISASSOC', (MGMT, 12): 'DEAUTH',
    (MGMT, 13): 'ACTION', (MGMT, 14): 'ACTION',
    (CTRL, 11): 'RTS', (CTRL, 12): 'CTS', (CTRL, 13): 'ACK',
    (CTRL, 8): 'BLOCK ACK REQ', (CTRL, 9): 'BLOCK ACK',
    (CTRL, 10): 'PS-POLL', (CTRL, 14): 'CF-END', (CTRL, 15): 'CF-END ACK',
    (DATA, 0): 'DATA', (DATA, 4): 'NULL', (DATA, 8): 'QOS DATA',
    (DATA, 12): 'QOS NULL',
}

# radiotap field -> (alignment, size) for the fields we decode
_RT_FIELDS = {
    0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 3), 5: (1, 1),
    6: (1, 1), 7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1),
    12: (1, 1), 13: (1, 1), 14: (2, 2),
}

MAC_RE = re.compile(r'^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


# --- low-level parsing -------------------------------------------------------

def _mac(raw):
    return ':'.join('%02X' % b for b in raw)


def _broadcast(mac):
    return (not mac) or mac == 'FF:FF:FF:FF:FF:FF' or \
        (int(mac[:2], 16) & 1)


def _signal_ok(value):
    return isinstance(value, int) and -120 <= value <= -1


def parse_radiotap(buf):
    """Decode the useful radiotap header fields into a dict.

    Returns None when the header is malformed. Only the first 15 fields are
    decoded (everything the radar needs: TSF, flags, rate, channel, signal,
    noise); later fields cannot influence those and are ignored.
    """
    if len(buf) < 8 or buf[0] != 0:
        return None
    rt_len = struct.unpack_from('<H', buf, 2)[0]
    if rt_len < 8 or rt_len > len(buf):
        return None
    words = []
    off = 4
    while off + 4 <= rt_len:
        word = struct.unpack_from('<I', buf, off)[0]
        off += 4
        words.append(word)
        if not (word & 0x80000000):
            break
    out = {'len': rt_len, 'freq': 0, 'signal': None, 'noise': None,
           'rate': None, 'flags': 0, 'badfcs': False}
    # walk the present bitmap in bit order
    field = 0
    for word in words:
        for bit in range(32):
            if not (word & (1 << bit)):
                field += 1
                continue
            if field > 14:
                return out
            align, size = _RT_FIELDS.get(field, (1, 0))
            off = (off + align - 1) & ~(align - 1)
            if off + size > rt_len:
                return out
            if field == 1:
                out['flags'] = buf[off]
            elif field == 2:
                out['rate'] = buf[off] * 0.5
            elif field == 3:
                out['freq'] = struct.unpack_from('<H', buf, off)[0]
            elif field == 5:
                out['signal'] = struct.unpack_from('<b', buf, off)[0]
            elif field == 6:
                out['noise'] = struct.unpack_from('<b', buf, off)[0]
            off += size
            field += 1
    out['badfcs'] = bool(out['flags'] & 0x40)
    return out


def _parse_rsn(body, out):
    """Fill AKM/cipher hints from an RSN (or WPA vendor) element body."""
    if len(body) < 2:
        return
    pos = 2                                     # version
    if pos + 4 <= len(body):                    # group cipher
        out['ciphers'].add(body[pos + 3])
        pos += 4
    if pos + 2 > len(body):
        return
    n = struct.unpack_from('<H', body, pos)[0]
    pos += 2
    for _ in range(min(n, 8)):
        if pos + 4 > len(body):
            return
        out['ciphers'].add(body[pos + 3])
        pos += 4
    if pos + 2 > len(body):
        return
    n = struct.unpack_from('<H', body, pos)[0]
    pos += 2
    for _ in range(min(n, 12)):
        if pos + 4 > len(body):
            return
        out['akms'].add(body[pos + 3])
        pos += 4


def parse_ies(data, start):
    """Walk tagged parameters from `start`; returns the fields we display."""
    out = {'ssid': None, 'channel': 0, 'rsn': False, 'wpa': False,
           'wps': False, 'ht': False, 'vht': False, 'he': False,
           'akms': set(), 'ciphers': set()}
    i = start
    n = len(data)
    while i + 2 <= n:
        eid = data[i]
        ln = data[i + 1]
        i += 2
        if i + ln > n:
            break
        body = data[i:i + ln]
        i += ln
        if eid == 0 and out['ssid'] is None:
            out['ssid'] = body.decode('utf-8', 'replace')
        elif eid == 3 and ln >= 1:
            out['channel'] = body[0]
        elif eid == 48:
            out['rsn'] = True
            _parse_rsn(body, out)
        elif eid == 221 and len(body) >= 4:
            if body[:4] == b'\x00\x50\xf2\x01':
                out['wpa'] = True
                _parse_rsn(body[4:], out)
            elif body[:4] == b'\x00\x50\xf2\x04':
                out['wps'] = True
        elif eid == 45:
            out['ht'] = True
        elif eid == 191:
            out['vht'] = True
        elif eid == 255 and len(body) >= 1 and body[0] in (35, 36):
            out['he'] = True
    return out


def security_of(ies, privacy=False):
    """Human security label from parsed RSN/WPA IEs + capability bit."""
    akms, ciphers = ies['akms'], ies['ciphers']
    cipher = ''
    for code, name in ((9, 'GCMP'), (8, 'GCMP256'), (4, 'CCMP'),
                       (2, 'TKIP'), (1, 'WEP')):
        if code in ciphers:
            cipher = name
            break
    if ies['rsn']:
        if 8 in akms or 9 in akms:
            tag = 'WPA3'
        elif 18 in akms:
            tag = 'OWE'
        elif 1 in akms or 3 in akms or 5 in akms:
            tag = 'WPA2-ENT'
        elif 6 in akms:
            tag = 'WPA3-SHA256'
        else:
            tag = 'WPA2'
        return tag + ('-' + cipher if cipher else '')
    if ies['wpa']:
        return 'WPA' + ('-' + cipher if cipher else '')
    return 'WEP' if privacy else 'OPEN'


def parse_80211(buf, rt_len, rt_flags=0):
    """Decode one 802.11 frame into a flat record (None when unusable)."""
    end = len(buf)
    if rt_flags & 0x02 and end > rt_len + 4:    # FCS included
        end -= 4
    if end - rt_len < 24:
        return None
    fc = struct.unpack_from('<H', buf, rt_len)[0]
    ftype = (fc >> 2) & 3
    subtype = (fc >> 4) & 0xF
    flags = (fc >> 8) & 0xFF
    hdr = 24
    if ftype == DATA and (subtype & 0x08):
        hdr += 2                                # QoS control
        if flags & 0x80:
            hdr += 4                            # HT control
    if end - rt_len < hdr:
        return None
    a1 = _mac(buf[rt_len + 4:rt_len + 10])
    a2 = _mac(buf[rt_len + 10:rt_len + 16])
    a3 = _mac(buf[rt_len + 16:rt_len + 22]) if end - rt_len >= 22 else ''
    rec = {
        'type': ftype, 'subtype': subtype, 'hdr': hdr,
        'name': FRAME_NAMES.get((ftype, subtype), ''),
        'retry': bool(flags & 0x08), 'protected': bool(flags & 0x40),
        'to_ds': bool(flags & 0x01), 'from_ds': bool(flags & 0x02),
        'addr1': a1, 'addr2': a2, 'addr3': a3,
        'bssid': '', 'sta': '', 'ssid': None, 'channel': 0, 'freq': 0,
        'ies': None, 'reason': None, 'eapol': False, 'privacy': False,
    }
    if ftype == MGMT:
        rec['kind'] = KIND_BY_SUBTYPE.get(subtype, 'MGMT')
        rec['bssid'] = a3
        body = rt_len + hdr
        if subtype in (8, 5):                   # beacon / probe response
            ies = parse_ies(buf, body + 12)
            rec['ies'] = ies
            rec['ssid'] = ies['ssid']
            rec['channel'] = ies['channel']
            rec['bssid'] = a3 or a2
            if end - rt_len >= hdr + 12:
                cap = struct.unpack_from('<H', buf, body + 10)[0]
                rec['privacy'] = bool(cap & 0x0010)
        elif subtype == 4:                      # probe request
            ies = parse_ies(buf, body)
            rec['ies'] = ies
            rec['ssid'] = ies['ssid']
            rec['sta'] = a2
        elif subtype in (0, 2):                 # assoc / reassoc request
            ies = parse_ies(buf, body + (4 if subtype == 0 else 10))
            rec['ies'] = ies
            rec['ssid'] = ies['ssid']
            rec['sta'] = a2
        elif subtype in (1, 3):                 # assoc / reassoc response
            ies = parse_ies(buf, body + 6)
            rec['ies'] = ies
        elif subtype == 11:                     # authentication
            rec['sta'] = a2
        elif subtype in (10, 12) and end - rt_len >= hdr + 2:
            rec['reason'] = struct.unpack_from('<H', buf, rt_len + hdr)[0]
            # Deauth/disassoc can travel either direction: the BSSID (addr3)
            # tells us which endpoint is the AP, so we never record the AP as
            # a client station.
            if a3 == a1:
                rec['sta'] = a2
            else:
                rec['sta'] = a1
    elif ftype == DATA:
        rec['kind'] = 'DATA'
        if rec['to_ds'] and not rec['from_ds']:
            rec['bssid'], rec['sta'] = a1, a2
        elif rec['from_ds'] and not rec['to_ds']:
            rec['bssid'], rec['sta'] = a2, a1
        elif not rec['to_ds'] and not rec['from_ds']:
            rec['bssid'], rec['sta'] = a3, a2
        if not rec['protected']:
            # EAPOL rides LLC/SNAP + ethertype 0x888e; only unencrypted
            # management-of-keys frames expose it.
            if buf.find(b'\x88\x8e', rt_len + hdr) >= 0:
                rec['eapol'] = True
    else:
        rec['kind'] = 'CTRL'
        if subtype in (11, 8, 9, 10):           # RTS / block ack / PS-poll
            rec['sta'] = a2
    return rec


# --- engine ------------------------------------------------------------------

class RadarEngine(object):
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._radio_thread = None
        self._lock = threading.Lock()
        self._cmd = {'active': config.RADAR, 'hop': config.RADAR_HOP,
                     'dwell': config.RADAR_DWELL, 'armed': False}
        self._sock = None
        self._bound = None
        self._mon = None
        self._hop_idx = 0
        self._next_hop = 0.0
        self._tune_fail_at = 0.0
        self._tuned = ''
        self._iface = ''
        self._error = ''
        self._started = 0.0
        self._last_frame = 0.0
        self._frames = 0

        self._aps = {}
        self._clients = {}
        self._probes = {}
        self._events = collections.deque(maxlen=EVENT_CAP)
        self._buckets = {}
        self._tot = {}
        self._channels = {}
        self._ch_band = {}
        self._last_probe_evt = {}
        self._no_mon_warned = False

        self._radio = {}
        self._survey = []
        self._survey_hist = collections.deque(maxlen=SURVEY_HIST)
        self._radio_at = 0.0
        self._phy_at = 0.0

    # --- lifecycle ---------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._started = time.time()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name='radar',
                                        daemon=True)
        self._thread.start()
        self._radio_thread = threading.Thread(target=self._radio_loop,
                                              name='radar-radio', daemon=True)
        self._radio_thread.start()

    def stop(self):
        self._stop.set()
        for th in (self._thread, self._radio_thread):
            if th:
                th.join(timeout=3)
        self._thread = None
        self._radio_thread = None
        self._close_sock()

    def _close_sock(self):
        sock, self._sock = self._sock, None
        self._bound = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # --- command -----------------------------------------------------------
    def _cmd_snapshot(self):
        with self._lock:
            return dict(self._cmd)

    def set_cmd(self, **kw):
        with self._lock:
            self._cmd.update(kw)

    def wants_hop(self):
        """True when the UI asked the radar to own idle channel hopping."""
        with self._lock:
            return bool(self._cmd.get('hop'))

    def hop_owned(self):
        """True when radar is actually hopping (idle + enabled + UI hop on)."""
        with self._lock:
            return (bool(self._cmd.get('active')) and bool(self._cmd.get('hop'))
                    and not bool(self._cmd.get('armed')))

    def command(self, on=None, hop=None, dwell=None, reset=False):
        with self._lock:
            if on is not None:
                self._cmd['active'] = bool(on)
            if hop is not None:
                self._cmd['hop'] = bool(hop)
            if dwell is not None:
                try:
                    self._cmd['dwell'] = max(0.5, min(30.0, float(dwell)))
                except (TypeError, ValueError):
                    pass
            if reset:
                self._aps.clear()
                self._clients.clear()
                self._probes.clear()
                self._events.clear()
                self._buckets.clear()
                self._channels.clear()
                self._ch_band.clear()
                self._survey_hist.clear()
                self._tot = {}
                self._last_probe_evt.clear()
        return self.snapshot()

    # --- sniff loop --------------------------------------------------------
    def _monitor(self):
        if self._mon:
            return self._mon
        mon = linuxutil.ensure_monitor_iface()
        if mon:
            self._mon = mon
        return mon

    def _run(self):
        while not self._stop.is_set():
            try:
                self._cycle()
            except Exception as exc:
                with self._lock:
                    self._error = 'radar: %s' % exc
                self._close_sock()
                self._stop.wait(2.0)
            self._stop.wait(0.3)

    def _cycle(self):
        cmd = self._cmd_snapshot()
        if not cmd.get('active'):
            self._close_sock()
            self._stop.wait(1.0)
            return
        mon = self._monitor()
        if not mon:
            with self._lock:
                self._error = ('no monitor interface — plug a spare radio or '
                               'set MALSTROM_MON_IFACE')
            if not self._no_mon_warned:
                self._no_mon_warned = True
                # The engine already explains missing radios elsewhere; keep
                # this quiet so a box without a spare radio isn't alarmed.
            self._stop.wait(5.0)
            return
        self._iface = mon
        if self._sock is None or self._bound != mon:
            self._close_sock()
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.htons(0x0003))
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                    4 * 1024 * 1024)
                except OSError:
                    pass
                sock.bind((mon, 0))
                sock.settimeout(0.5)
            except OSError as exc:
                with self._lock:
                    self._error = 'cannot bind %s: %s' % (mon, exc)
                self._stop.wait(5.0)
                return
            self._sock = sock
            self._bound = mon
            with self._lock:
                self._error = ''
            self._next_hop = time.time() + float(cmd.get('dwell', 2.0))

        while not self._stop.is_set():
            cmd = self._cmd_snapshot()
            if not cmd.get('active'):
                break
            hop = bool(cmd.get('hop')) and not bool(cmd.get('armed'))
            now = time.time()
            if hop and now >= self._next_hop:
                self._hop(mon, cmd)
                self._next_hop = time.time() + float(cmd.get('dwell', 2.0))
            try:
                data = self._sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                continue
            self._ingest(data)
        self._close_sock()

    def _hop(self, mon, cmd):
        """Advance the idle hop plan (only when the UI hands us the radio)."""
        plan = config.RADAR_HOP_CHANNELS or config.KARMA_HOP_CHANNELS or \
            list(recon_hop_channels())
        if not plan:
            return
        now = time.time()
        if now - self._tune_fail_at < 30:
            return
        ch = plan[self._hop_idx % len(plan)]
        self._hop_idx = (self._hop_idx + 1) % len(plan)
        if linuxutil.set_channel(mon, ch):
            self._tuned = str(ch)
            with self._lock:
                self._radio['channel'] = str(ch)
                self._radio['freq'] = 0
        else:
            self._tune_fail_at = now

    # --- packet ingest -----------------------------------------------------
    def _bucket(self, sec):
        b = self._buckets.get(sec)
        if b is None:
            b = {'total': 0, 'mgmt': 0, 'ctrl': 0, 'data': 0, 'events': 0,
                 'retry': 0, 'deauth': 0, 'disassoc': 0, 'auth': 0,
                 'assoc': 0, 'probe': 0, 'bytes': 0, 'ch': {}}
            self._buckets[sec] = b
            # prune old buckets outside the lock-held call path
            if len(self._buckets) > BUCKET_KEEP + 60:
                cutoff = sec - BUCKET_KEEP
                for old in [k for k in self._buckets if k < cutoff]:
                    self._buckets.pop(old, None)
        return b

    def _totals(self):
        if not self._tot:
            self._tot = {
                'frames': 0, 'bytes': 0, 'mgmt': 0, 'ctrl': 0, 'data': 0,
                'retry': 0, 'errors': 0, 'beacons': 0, 'probe_req': 0,
                'probe_resp': 0, 'auth': 0, 'assoc': 0, 'deauth': 0,
                'disassoc': 0, 'eapol': 0, 'actions': 0, 'events': 0,
            }
        return self._tot

    def _ingest(self, buf):
        rt = parse_radiotap(buf)
        if not rt:
            return
        now = time.time()
        sec = int(now)
        frame = parse_80211(buf, rt['len'], rt['flags'])
        if frame is None:
            return
        if rt['badfcs']:
            with self._lock:
                self._totals()['errors'] += 1
                self._bucket(sec)['total'] += 1
            return
        freq = rt['freq']
        ch = recon.freq_to_channel(freq) if freq else 0
        band = recon.freq_to_band(freq) if freq else ''
        # If radiotap doesn't have frequency, use the tuned channel
        # (NOT the channel from frame IEs, which is the AP's advertised channel)
        if not ch and self._tuned:
            try:
                ch = int(self._tuned)
            except (TypeError, ValueError):
                ch = 0
        if not band and ch:
            band = _band_of_channel(ch)
        signal = rt['signal'] if _signal_ok(rt['signal']) else None
        frame['freq'] = freq
        frame['signal'] = signal

        with self._lock:
            tot = self._totals()
            b = self._bucket(sec)
            cat = frame['type']
            b['total'] += 1
            b['bytes'] += len(buf)
            tot['frames'] += 1
            tot['bytes'] += len(buf)
            if cat == MGMT:
                b['mgmt'] += 1
                tot['mgmt'] += 1
            elif cat == DATA:
                b['data'] += 1
                tot['data'] += 1
            else:
                b['ctrl'] += 1
                tot['ctrl'] += 1
            if frame['retry']:
                b['retry'] += 1
                tot['retry'] += 1
            if ch:
                b['ch'][ch] = b['ch'].get(ch, 0) + 1
                ci = self._channels.get(ch)
                if ci is None:
                    ci = {'total': 0, 'last': 0}
                    self._channels[ch] = ci
                ci['total'] += 1
                ci['last'] = now
                self._ch_band[ch] = band or self._ch_band.get(ch, '')
            # Don't update radio's tuned channel from frame frequency
            # The radio channel is set by _hop when we actually tune the interface
            self._last_frame = now
            self._frames += 1
            self._apply(frame, ch, band, signal, now, b, tot)

    def _apply(self, f, ch, band, signal, now, b, tot):
        subtype = f['subtype']
        bssid = f.get('bssid') or ''
        sta = f.get('sta') or ''

        def _evt():
            b['events'] += 1
            tot['events'] = tot.get('events', 0) + 1

        if f['type'] == MGMT:
            if subtype == 8:
                tot['beacons'] += 1
                self._upsert_ap(f, ch, band, signal, now, beacon=True)
            elif subtype == 5:
                tot['probe_resp'] += 1
                self._upsert_ap(f, ch, band, signal, now, beacon=False)
            elif subtype == 4:
                tot['probe_req'] += 1
                b['probe'] += 1
                _evt()
                self._upsert_client(f, ch, band, signal, now)
                self._probe(f, ch, now)
                if sta and now - self._last_probe_evt.get(sta, 0) > 12:
                    self._last_probe_evt[sta] = now
                    self._event('PROBE', sta, bssid or 'broadcast',
                                f.get('ssid') or 'wildcard', ch, signal,
                                now, payload=f.get('ssid') or '')
            elif subtype in (0, 2):
                tot['assoc'] += 1
                b['assoc'] += 1
                _evt()
                self._upsert_client(f, ch, band, signal, now)
                self._event('ASSOC', sta, bssid, f.get('ssid') or '',
                            ch, signal, now)
            elif subtype == 11:
                tot['auth'] += 1
                b['auth'] += 1
                _evt()
                self._upsert_client(f, ch, band, signal, now)
                self._event('AUTH', sta, bssid, '', ch, signal, now)
            elif subtype == 12:
                tot['deauth'] += 1
                b['deauth'] += 1
                _evt()
                self._upsert_client(f, ch, band, signal, now)
                self._event('DEAUTH', sta, bssid or f['addr1'],
                            _reason(f.get('reason')), ch, signal, now)
            elif subtype == 10:
                tot['disassoc'] += 1
                b['disassoc'] += 1
                _evt()
                self._upsert_client(f, ch, band, signal, now)
                self._event('DISASSOC', sta, bssid or f['addr1'],
                            _reason(f.get('reason')), ch, signal, now)
            elif subtype in (13, 14):
                tot['actions'] += 1
                _evt()
        else:
            if f['type'] == DATA:
                if f.get('eapol'):
                    tot['eapol'] += 1
                self._upsert_client(f, ch, band, signal, now)

    # --- inventories -------------------------------------------------------
    def _upsert_ap(self, f, ch, band, signal, now, beacon):
        bssid = (f.get('bssid') or '').upper()
        if not bssid or MAC_RE.match(bssid) is None or _broadcast(bssid):
            return
        ap = self._aps.get(bssid)
        if ap is None:
            if len(self._aps) >= AP_CAP:
                self._evict(self._aps, AP_CAP - 1, 'last_ts')
            ap = {
                'bssid': bssid, 'ssid': '', 'security': 'OPEN', 'wps': False,
                'vendor': recon.vendor_of(bssid), 'channel': 0, 'band': '',
                'signal': None, 'beacons': 0, 'frames': 0,
                'clients': set(), 'randomized': False,
                'first_ts': now, 'last_ts': now, 'freq': 0,
                'ies': {},
            }
            self._aps[bssid] = ap
        ies = f.get('ies') or {}
        ssid = f.get('ssid')
        if ssid:
            ap['ssid'] = ssid
        elif not ap['ssid']:
            ap['ssid'] = ''
        if ies:
            ap['security'] = security_of(ies, privacy=bool(f.get('privacy')))
            ap['wps'] = bool(ies.get('wps'))
        ap['channel'] = ch or ap['channel'] or ies.get('channel', 0)
        ap['band'] = band or ap['band']
        ap['freq'] = int(f.get('freq') or ap.get('freq') or 0)
        if signal is not None:
            ap['signal'] = signal
        ap['last_ts'] = now
        ap['frames'] += 1
        if beacon:
            ap['beacons'] += 1

    def _upsert_client(self, f, ch, band, signal, now):
        mac = (f.get('sta') or '').upper()
        if not mac or MAC_RE.match(mac) is None or _broadcast(mac):
            return
        # Never let a BSSID masquerade as a station (deauth/auth frames can
        # carry the AP's own address depending on direction).
        if mac in self._aps:
            return
        c = self._clients.get(mac)
        if c is None:
            if len(self._clients) >= CLIENT_CAP:
                self._evict(self._clients, CLIENT_CAP - 1, 'last_ts')
            c = {
                'mac': mac, 'vendor': recon.vendor_of(mac),
                'randomized': bool(int(mac[:2], 16) & 0x02),
                'bssid': '', 'channel': 0, 'band': '', 'signal': None,
                'frames': 0, 'data': 0, 'probes': [],
                'first_ts': now, 'last_ts': now,
            }
            self._clients[mac] = c
        if f['type'] == DATA:
            c['data'] += 1
        c['frames'] += 1
        c['last_ts'] = now
        if f.get('bssid'):
            c['bssid'] = f['bssid'].upper()
            ap = self._aps.get(c['bssid'])
            if ap is not None and len(ap['clients']) < 512:
                ap['clients'].add(mac)
        if ch:
            c['channel'] = ch
            c['band'] = band or c['band']
        if signal is not None:
            c['signal'] = signal

    def _probe(self, f, ch, now):
        ssid = f.get('ssid')
        if not ssid or len(ssid) > 32:
            return
        p = self._probes.get(ssid)
        if p is None:
            if len(self._probes) >= PROBE_CAP:
                self._evict(self._probes, PROBE_CAP - 1, 'last_ts')
            p = {'ssid': ssid, 'count': 0, 'clients': set(),
                 'channel': 0, 'first_ts': now, 'last_ts': now}
            self._probes[ssid] = p
        p['count'] += 1
        p['last_ts'] = now
        if ch:
            p['channel'] = ch
        sta = f.get('sta')
        if sta and len(p['clients']) < 64:
            p['clients'].add(sta)
        c = self._clients.get(sta)
        if c is not None and ssid not in c['probes']:
            c['probes'] = (c['probes'] + [ssid])[-8:]

    def _event(self, kind, src, dst, detail, ch, signal, now, payload=''):
        self._events.appendleft({
            't': int(now), 'ts': time.strftime('%H:%M:%S', time.localtime(now)),
            'kind': kind, 'src': src or '', 'dst': dst or '',
            'detail': detail or '', 'ch': ch or 0, 'signal': signal,
            'payload': payload,
        })

    @staticmethod
    def _evict(table, keep, key):
        if len(table) <= keep:
            return
        victim = min(table, key=lambda k: table[k].get(key, 0))
        table.pop(victim, None)

    # --- radio sampling ----------------------------------------------------
    def _radio_loop(self):
        while not self._stop.is_set():
            iface = self._iface or self._monitor()
            if iface:
                try:
                    self._sample_radio(iface)
                except Exception:
                    pass
            self._stop.wait(2.5)

    def _sample_radio(self, iface):
        now = time.time()
        radio = {'iface': iface, 'kernel': _kernel()}
        info = linuxutil.run(['iw', 'dev', iface, 'info'], timeout=4)
        if info.returncode == 0:
            text = info.stdout
            m = re.search(r'^\s*type\s+(\S+)', text, re.M)
            if m:
                radio['mode'] = m.group(1)
            m = re.search(r'^\s*addr\s+([0-9a-fA-F:]{17})', text, re.M)
            if m:
                radio['mac'] = m.group(1).upper()
            m = re.search(r'^\s*channel\s+(\d+)\s*\((\d+)\s*MHz\)'
                          r'(?:,\s*width:\s*([^,\n]+))?', text, re.M)
            if m:
                radio['channel'] = m.group(1)
                radio['freq'] = int(m.group(2))
                radio['width'] = (m.group(3) or '20 MHz').strip()
            elif self._tuned:
                radio['channel'] = str(self._tuned)
            m = re.search(r'txpower\s+([\d.]+)\s*dBm', text)
            if m:
                radio['txpower'] = m.group(1)
        phy = linuxutil.phy_of(iface) or ''
        if phy:
            radio['phy'] = phy
            radio['driver'] = linuxutil.phy_driver(phy)
        if now - self._phy_at > 30:
            self._phy_at = now
            radio.update(self._phy_details(iface, phy))
            radio['regdom'] = linuxutil.regdom()
        else:
            radio['regdom'] = self._radio.get('regdom', '')
        self._survey = self._sample_survey(iface, radio)
        radio['band'] = recon.freq_to_band(radio.get('freq', 0)) or \
            _band_of_channel(radio.get('channel', ''))

        with self._lock:
            self._radio = radio
            entry = self._survey_entry(radio.get('channel'))
            if entry is not None:
                ch = entry.get('ch') or radio.get('channel') or 0
                try:
                    ch = int(ch)
                except (TypeError, ValueError):
                    ch = 0
                self._survey_hist.append({
                    't': int(now), 'ch': ch,
                    'busy': entry['busy_pct'], 'rx': entry['rx_pct'],
                    'tx': entry['tx_pct'], 'noise': entry.get('noise'),
                })

    def _survey_entry(self, channel):
        if not self._survey:
            return None
        if channel:
            for e in self._survey:
                if str(e.get('ch')) == str(channel):
                    return e
        # Most drivers expose only the tuned channel.
        return max(self._survey, key=lambda e: e.get('active') or 0)

    @staticmethod
    def _sample_survey(iface, radio):
        r = linuxutil.run(['iw', 'dev', iface, 'survey', 'dump'], timeout=4)
        if r.returncode != 0:
            return []
        out = []
        cur = None
        for line in r.stdout.splitlines():
            s = line.strip()
            m = re.match(r'frequency:\s+(\d+)\s*MHz(.*)', s)
            if m:
                if cur:
                    out.append(cur)
                freq = int(m.group(1))
                ch = recon.freq_to_channel(freq)
                cur = {'freq': freq, 'ch': ch,
                       'band': recon.freq_to_band(freq), 'in_use': 'in use' in m.group(2),
                       'noise': None, 'active': 0, 'busy': 0, 'rx': 0, 'tx': 0,
                       'busy_pct': 0.0, 'rx_pct': 0.0, 'tx_pct': 0.0}
                continue
            if cur is None:
                continue
            m = re.match(r'noise:\s+(-?\d+)', s)
            if m:
                cur['noise'] = int(m.group(1))
                continue
            m = re.match(r'channel active time:\s+(\d+)', s)
            if m:
                cur['active'] = int(m.group(1))
                continue
            m = re.match(r'channel busy time:\s+(\d+)', s)
            if m:
                cur['busy'] = int(m.group(1))
                continue
            m = re.match(r'channel receive time:\s+(\d+)', s)
            if m and not cur['rx']:
                cur['rx'] = int(m.group(1))
                continue
            m = re.match(r'channel transmit time:\s+(\d+)', s)
            if m:
                cur['tx'] = int(m.group(1))
                continue
        if cur:
            out.append(cur)
        for e in out:
            active = e['active'] or 0
            if active > 0:
                e['busy_pct'] = round(100.0 * e['busy'] / active, 1)
                e['rx_pct'] = round(100.0 * e['rx'] / active, 1)
                e['tx_pct'] = round(100.0 * e['tx'] / active, 1)
        return out

    def _phy_details(self, iface, phy):
        detail = {}
        if linuxutil.have('ethtool'):
            r = linuxutil.run(['ethtool', '-i', iface], timeout=4)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if ':' not in line:
                        continue
                    k, v = line.split(':', 1)
                    detail[k.strip()] = v.strip()
        if phy:
            r = linuxutil.run(['iw', 'phy', phy, 'info'], timeout=5)
            if r.returncode == 0:
                bands = []
                cur = None
                for line in r.stdout.splitlines():
                    if re.match(r'^Band \d+:', line.strip()):
                        cur = {'band': '', 'channels': [], 'max_txpower': None}
                        bands.append(cur)
                        continue
                    if cur is None:
                        continue
                    m = re.match(r'\*\s+(\d+)\s+MHz\s+\[(\d+)\]\s+'
                                 r'(?:\(([\d.]+)\s+dBm\))?', line.strip())
                    if m:
                        freq = int(m.group(1))
                        cur['band'] = cur['band'] or recon.freq_to_band(freq)
                        cur['channels'].append(int(m.group(2)))
                        if m.group(3):
                            tx = float(m.group(3))
                            if cur['max_txpower'] is None or tx > cur['max_txpower']:
                                cur['max_txpower'] = tx
                detail['bands'] = bands
                m = re.search(r'Supported interface modes:\n((?:\s+\*\s*\S+\n)+)',
                              r.stdout)
                if m:
                    detail['modes'] = re.findall(r'\*\s*(\S+)', m.group(1))
        return detail

    # --- snapshot ----------------------------------------------------------
    def snapshot(self):
        now = time.time()
        with self._lock:
            tot = self._totals()
            end = int(now)
            start = end - (SERIES_POINTS - 1)
            series = {'times': list(range(start, end + 1)),
                      'total': [], 'mgmt': [], 'ctrl': [], 'data': [],
                      'events': [], 'retry': [], 'deauth': [],
                      'disassoc': [], 'auth': [], 'assoc': [], 'probe': []}
            for sec in series['times']:
                b = self._buckets.get(sec)
                if b is None:
                    for k in series:
                        if k != 'times':
                            series[k].append(0)
                    continue
                for k in series:
                    if k == 'times':
                        continue
                    series[k].append(int(b.get(k, 0)))
            # 3-second moving average for the headline counters
            def _avg(key, n=3):
                vals = series[key][-n:]
                return round(sum(vals) / float(n), 1) if vals else 0.0
            # Build channel list including ALL channels from hop plan
            hop_channels = config.RADAR_HOP_CHANNELS or config.KARMA_HOP_CHANNELS or \
                list(recon_hop_channels())
            channels = []
            for ch_str in hop_channels:
                try:
                    ch = int(ch_str)
                except (TypeError, ValueError):
                    continue
                ci = self._channels.get(ch, {'total': 0, 'last': 0})
                hist = []
                for sec in range(end - CHANNEL_HIST + 1, end + 1):
                    b = self._buckets.get(sec)
                    hist.append(int((b or {}).get('ch', {}).get(ch, 0)))
                pps = round(sum(hist[-3:]) / 3.0, 1)
                channels.append({
                    'ch': ch, 'band': self._ch_band.get(ch, '') or _band_of_channel(ch),
                    'total': ci['total'], 'pps': pps,
                    'hist': hist, 'last': int(ci['last']),
                })
            channels.sort(key=lambda c: c['ch'])

            aps = []
            for ap in self._aps.values():
                aps.append({
                    'bssid': ap['bssid'],
                    'ssid': ap['ssid'] or '[hidden]',
                    'hidden': not bool(ap['ssid']),
                    'vendor': ap['vendor'],
                    'channel': ap['channel'], 'band': ap['band'],
                    'signal': ap['signal'], 'security': ap['security'],
                    'wps': ap['wps'], 'beacons': ap['beacons'],
                    'frames': ap['frames'],
                    'clients': len(ap['clients']),
                    'age': int(now - ap['last_ts']),
                    'first_seen': _clock(ap['first_ts']),
                    'last_seen': _clock(ap['last_ts']),
                })
            aps.sort(key=lambda a: (a['signal'] if a['signal'] is not None
                                    else -1000), reverse=True)

            clients = []
            for c in self._clients.values():
                ap = self._aps.get(c['bssid']) or {}
                clients.append({
                    'mac': c['mac'], 'vendor': c['vendor'],
                    'randomized': c['randomized'],
                    'bssid': c['bssid'],
                    'ssid': ap.get('ssid') or '',
                    'channel': c['channel'], 'band': c['band'],
                    'signal': c['signal'], 'frames': c['frames'],
                    'data': c['data'], 'probes': list(c['probes']),
                    'age': int(now - c['last_ts']),
                    'first_seen': _clock(c['first_ts']),
                    'last_seen': _clock(c['last_ts']),
                })
            clients.sort(key=lambda c: c['frames'], reverse=True)

            probes = []
            for p in sorted(self._probes.values(),
                            key=lambda x: x['last_ts'], reverse=True)[:60]:
                probes.append({
                    'ssid': p['ssid'], 'count': p['count'],
                    'clients': len(p['clients']), 'channel': p['channel'],
                    'age': int(now - p['last_ts']),
                })

            events = list(self._events)[:80]
            survey = [dict(e) for e in self._survey]
            sh = list(self._survey_hist)

            breakdown = self._breakdown(aps, clients, series)
            radio = dict(self._radio)
            radio['iface'] = radio.get('iface') or self._bound or self._iface
            radio['error'] = self._error if not self._bound else ''

            return {
                'ok': 1,
                'active': bool(self._cmd.get('active')),
                'running': bool(self._thread and self._thread.is_alive()
                                and self._bound),
                'bound': self._bound or '',
                'iface': self._bound or self._iface or radio.get('iface', ''),
                'error': self._error,
                'armed': bool(self._cmd.get('armed')),
                'hop': bool(self._cmd.get('hop')),
                'dwell': self._cmd.get('dwell', config.RADAR_DWELL),
                'uptime': int(now - self._started) if self._started else 0,
                'last_frame': int(self._last_frame),
                'rate': {'packets': _avg('total'), 'events': _avg('events')},
                'counts': {
                    'devices': len(self._clients) + len(self._aps),
                    'aps': len(self._aps),
                    'clients': len(self._clients),
                    'probes': len(self._probes),
                    'events': len(self._events),
                    'frames': tot['frames'],
                    'bytes': tot['bytes'],
                    'eapol': tot['eapol'],
                    'deauth': tot['deauth'],
                    'errors': tot['errors'],
                },
                'series': series,
                'channels': channels[:40],
                'aps': aps[:200],
                'clients': clients[:250],
                'probes': probes,
                'events': events,
                'survey': survey,
                'survey_series': {
                    'busy': [e['busy'] for e in sh],
                    'rx': [e['rx'] for e in sh],
                    'tx': [e['tx'] for e in sh],
                    'noise': [e['noise'] for e in sh],
                    'ch': [e['ch'] for e in sh],
                },
                'radio': radio,
                'breakdown': breakdown,
            }

    def _breakdown(self, aps, clients, series):
        bands = {}
        sec = {}
        for ap in aps:
            bands[ap['band'] or '?'] = bands.get(ap['band'] or '?', 0) + 1
            sec[ap['security'] or '?'] = sec.get(ap['security'] or '?', 0) + 1
        vendors = {}
        for c in clients:
            if c['vendor']:
                vendors[c['vendor']] = vendors.get(c['vendor'], 0) + 1
        top_vendors = [{'name': k, 'count': v} for k, v in
                       sorted(vendors.items(), key=lambda kv: -kv[1])[:8]]
        recent = {k: sum(series[k][-30:]) for k in
                  ('mgmt', 'ctrl', 'data', 'retry', 'deauth', 'probe')}
        return {
            'bands': bands, 'security': sec, 'vendors': top_vendors,
            'randomized': sum(1 for c in clients if c['randomized']),
            'hidden': sum(1 for a in aps if a['hidden']),
            'wps': sum(1 for a in aps if a['wps']),
            'open': sum(1 for a in aps if a['security'] == 'OPEN'),
            'wpa3': sum(1 for a in aps if a['security'].startswith('WPA3')),
            'frame_mix': recent,
        }


# --- helpers -----------------------------------------------------------------

def _reason(code):
    if code is None:
        return 'reason ?'
    return REASONS.get(int(code), 'reason %d' % code)


def _clock(ts):
    return time.strftime('%H:%M:%S', time.localtime(ts))


def _band_of_channel(ch):
    try:
        ch = int(ch)
    except (TypeError, ValueError):
        return ''
    if 1 <= ch <= 14:
        return '2.4 GHz'
    if 32 <= ch <= 177:
        return '5 GHz'
    return ''


def _kernel():
    try:
        return os.uname().release
    except (AttributeError, OSError):
        return ''


def recon_hop_channels():
    return ['%d' % c for c in range(1, 14)] + [
        '36', '40', '44', '48', '52', '56', '60', '64',
        '100', '104', '108', '112', '116', '120', '124', '128',
        '132', '136', '140', '144', '149', '153', '157', '161', '165',
    ]
