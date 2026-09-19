"""Low-level Linux tooling: subprocess helpers, iw/ip netlink glue.

Replaces the OpenWrt `uci`/`wifi`/`fw4` primitives the old payload used.
Everything here is best-effort and returns sensible defaults on failure so the
app can degrade gracefully on drivers that don't support virtual interfaces.
"""

import os
import re
import subprocess
import threading
import time

from . import config


def run(argv, timeout=10):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        r = subprocess.CompletedProcess(argv, 1, '', str(exc))
        return r


def run_bg(argv, log=None):
    """Detached Popen; when `log` is a path, stdout+stderr append to it.

    The child must never inherit our stdio (a wedged radio tool would
    otherwise fill the journal), but its output IS the only honest failure
    diagnostic we have — hostapd config-parse errors die before any pidfile
    exists and were previously invisible ("no hostapd log").
    """
    out = None
    if log:
        try:
            out = open(log, 'ab')
        except OSError:
            out = None
    try:
        return subprocess.Popen(
            argv,
            stdout=out if out else subprocess.DEVNULL,
            stderr=subprocess.STDOUT if out else subprocess.DEVNULL,
            stdin=subprocess.DEVNULL)
    finally:
        if out:
            try:
                out.close()
            except OSError:
                pass


def have(name):
    for d in ('/usr/sbin', '/usr/bin', '/sbin', '/bin'):
        if os.path.exists(os.path.join(d, name)):
            return True
    return False


def netdev_exists(name):
    return os.path.exists('/sys/class/net/' + name)


def iface_mode(iface):
    """802.11 netdev type ('AP', 'managed', 'monitor', ...) or '' on failure."""
    if not netdev_exists(iface):
        return ''
    r = run(['iw', 'dev', iface, 'info'], timeout=5)
    if r.returncode != 0:
        return ''
    m = re.search(r'^\s*type\s+(\S+)', r.stdout, re.M)
    return m.group(1) if m else ''


def station_clients(iface):
    """MACs currently associated with an AP interface (uppercase set)."""
    if not netdev_exists(iface):
        return set()
    r = run(['iw', 'dev', iface, 'station', 'dump'], timeout=6)
    if r.returncode != 0:
        return set()
    return {m.upper() for m in
            re.findall(r'(?im)^\s*Station\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b',
                       r.stdout)}


def phy_of(name):
    try:
        return os.path.basename(os.readlink('/sys/class/net/%s/phy80211' % name))
    except OSError:
        return None


def iface_mac(name):
    try:
        with open('/sys/class/net/%s/address' % name) as fh:
            return fh.read().strip().upper()
    except IOError:
        return ''


def list_phys():
    try:
        return sorted(os.listdir('/sys/class/ieee80211'))
    except OSError:
        return []


def scan_phys():
    """Return [{'phy':..., 'iface':..., 'dev':...}] for wifi-capable netdevs."""
    out = []
    for dev in os.listdir('/sys/class/net'):
        phy = phy_of(dev)
        if not phy:
            continue
        addrs = os.path.join('/sys/class/net', dev, 'address')
        mac = ''
        try:
            with open(addrs) as fh:
                mac = fh.read().strip()
        except IOError:
            pass
        out.append({'phy': phy, 'iface': dev, 'mac': mac})
    return out


def preferred_wlan_dev():
    """Physical wifi device chosen by the operator (env or settings) — '' = auto."""
    dev = config.WLAN_DEV
    if not dev:
        try:
            with open(os.path.join(config.STATE_DIR, 'settings.json')) as fh:
                import json as _json
                dev = (_json.load(fh).get('wlan_dev') or '').strip()
        except (IOError, ValueError):
            pass
    return dev


def ordered_phys():
    """phy names ordered with the operator-chosen radio first (empty = natural order)."""
    pref = preferred_wlan_dev()
    if pref and netdev_exists(pref):
        p = phy_of(pref)
        if p:
            return [p] + [d['phy'] for d in scan_phys() if d['phy'] != p]
    return [d['phy'] for d in scan_phys()]


def ordered_devices():
    """wifi devices ordered with the operator-chosen radio first."""
    order = ordered_phys()
    by = {}
    for d in scan_phys():
        by.setdefault(d['phy'], []).append(d)
    out = []
    for p in order:
        out.extend(by.pop(p, []))
    for rest in by.values():
        out.extend(rest)
    return out


def add_vif(phy, name, devtype):
    r = run(['iw', 'phy', phy, 'interface', 'add', name, 'type', devtype])
    return r.returncode == 0 and netdev_exists(name)


def del_vif(name):
    if netdev_exists(name):
        run(['iw', 'dev', name, 'del'], timeout=5)


_created_by_us = set()

_vif_last_try = {}
_vif_try_lock = threading.Lock()


def _vif_try_gate(phy, name):
    """Return True when a recent add_vif attempt should be skipped.

    A radio that rejects a virtual interface (rtl8xxxu can only carry a couple,
    and never while hostapd holds it) will otherwise be hammered with iw-phy-add
    every engine poll. Throttle re-attempts to once per VIF_RETRY_GAP.
    """
    now = time.time()
    with _vif_try_lock:
        last = _vif_last_try.get((phy, name), 0.0)
        if now - last < config.VIF_RETRY_GAP:
            return True
        _vif_last_try[(phy, name)] = now
        return False


def ensure_monitor_iface():
    """Create monitor vif if none configured/exists. Returns name or None.

    Never flips an internet-uplink radio into monitor mode — that drops the
    box's link and (on USB adapters) can hang the system. Also refuses to
    create or reuse a vif on a driver that wedges the whole Pi (88xxau USB
    Realteks). If no spare radio exists we return None and let the engines
    degrade gracefully.
    """
    if config.MON_IFACE:
        return config.MON_IFACE if netdev_exists(config.MON_IFACE) else None
    name = config.MON_VIF_NAME
    if netdev_exists(name):
        if phy_banned(phy_of(name)):
            # A vif from a previous wedged run must never be resurrected on a
            # radio that hangs the box — tear it down instead of reusing it.
            del_vif(name)
        else:
            return name
    uplinks = set(uplink_ifaces())
    for dev in ordered_devices():
        if dev['iface'] in uplinks:
            continue
        if phy_banned(dev['phy']):
            continue
        if 'monitor' not in phy_modes(dev['phy']):
            continue
        if _vif_try_gate(dev['phy'], name):
            continue
        if add_vif(dev['phy'], name, 'monitor'):
            iface_up(name)
            _created_by_us.add(name)
            return name
    return None


def cleanup_created_vifs():
    """Remove radio vifs the app created (monitor + AP) on teardown."""
    for name in list(_created_by_us):
        try:
            del_vif(name)
        finally:
            _created_by_us.discard(name)


def phy_driver(phy):
    """Driver module name owning a phy (e.g. '8821au', 'brcmfmac'), lowercased.

    Resolved through the phy's own device link first, falling back to any
    netdev on that phy.
    """
    try:
        return os.path.basename(os.readlink(
            '/sys/class/ieee80211/%s/device/driver' % phy)).lower()
    except OSError:
        pass
    for dev in scan_phys():
        if dev['phy'] != phy:
            continue
        try:
            return os.path.basename(os.readlink(
                '/sys/class/net/%s/device/driver' % dev['iface'])).lower()
        except OSError:
            continue
    return ''


def driver_banned(driver):
    """True when virtual-interface creation on this driver is known to hang a Pi."""
    return (driver or '').lower() in config.DANGEROUS_VIF_DRIVERS


def phy_banned(phy):
    return bool(phy) and driver_banned(phy_driver(phy))


def banned_ifaces():
    """Wifi interfaces on drivers blacklisted for vif creation (for alerts)."""
    return [d['iface'] for d in scan_phys() if phy_banned(d['phy'])]


def phy_modes(phy):
    """Set of interface modes a physical radio supports (e.g. {'AP','monitor'}).

    Some "spare" USB dongles (Realtek rtl8xxxu) only support managed+monitor
    and physically cannot serve an AP — they must never be chosen for the
    rogue AP.
    """
    r = run(['iw', 'phy', phy, 'info'], timeout=6)
    if r.returncode != 0:
        return set()
    m = re.search(r'Supported interface modes:\n((?:\s+\*\s*\S+\n)+)', r.stdout)
    if not m:
        return set()
    return set(re.findall(r'\*\s*(\S+)', m.group(1)))


def phy_vht(phy):
    """True when the radio advertises 802.11ac (VHT) capabilities.

    hostapd refuses `ieee80211ac=1` outright on cards without VHT support,
    which would kill the rogue AP at config init — so the conf only gains the
    flag when the phy actually has the capability.
    """
    if not phy:
        return False
    r = run(['iw', 'phy', phy, 'info'], timeout=6)
    return r.returncode == 0 and 'VHT' in r.stdout


def regdom():
    """Current regulatory domain (two-letter country code) or ''."""
    r = run(['iw', 'reg', 'get'], timeout=5)
    if r.returncode == 0:
        m = re.search(r'country\s+([A-Z]{2})\b', r.stdout)
        if m:
            return m.group(1)
    return ''


def set_mac(name, mac):
    if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', str(mac)):
        return False
    r = run(['ip', 'link', 'set', name, 'address', mac.lower()], timeout=5)
    return r.returncode == 0


def iface_up(name, up=True):
    r = run(['ip', 'link', 'set', name, ('up' if up else 'down')], timeout=5)
    return r.returncode == 0


def add_addr(name, ip, prefix=24):
    r = run(['ip', 'addr', 'add', '%s/%d' % (ip, prefix), 'dev', name], timeout=5)
    return r.returncode == 0


def del_addr(name, ip, prefix=24):
    r = run(['ip', 'addr', 'del', '%s/%d' % (ip, prefix), 'dev', name], timeout=5)
    return r.returncode == 0


def flush_uplink_config(name):
    """Strip stale DHCP address + routes from a sacrificed uplink interface.

    When an active internet uplink (e.g. wlan1) is reused as the rogue AP,
    NetworkManager's disconnect does not always flush the old leased address
    or the default route via that interface. The leftover 192.168.x address
    can confuse hostapd/DHCP and make clients fail to get a clean portal
    subnet. This is best-effort: ignore errors if the interface is already
    clean.
    """
    run(['ip', '-4', 'addr', 'flush', 'dev', name], timeout=5)
    run(['ip', 'route', 'flush', 'dev', name], timeout=5)
    return True


def set_channel(name, channel):
    channel = str(channel)
    if not channel.isdigit():
        return False
    r = run(['iw', 'dev', name, 'set', 'channel', channel], timeout=5)
    return r.returncode == 0


def default_route_iface():
    r = run(['ip', 'route', 'show', 'default'], timeout=5)
    if r.returncode == 0:
        m = re.search(r'dev\s+(\S+)', r.stdout)
        if m:
            return m.group(1)
    return None


def uplink_ifaces():
    """Every interface carrying a default route (the machine's own uplinks).

    The rogue-AP / monitor vifs must never be carved from, or switch into
    monitor mode on, one of these radios — doing so drops the box's internet
    link and, on USB wifi adapters (Raspberry Pi), can wedge the driver and
    hang the whole system.
    """
    r = run(['ip', 'route', 'show', 'default'], timeout=5)
    if r.returncode == 0:
        return list(dict.fromkeys(re.findall(r'dev\s+(\S+)', r.stdout)))
    return []


def iface_ipv4(name):
    """First IPv4 address assigned to the named interface."""
    r = run(['ip', '-4', '-o', 'addr', 'show', 'dev', name], timeout=5)
    if r.returncode == 0:
        m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
        if m:
            return m.group(1)
    return None


def iface_ipv4_cidr(name):
    """First IPv4 address WITH prefix length (e.g. '192.168.1.5/24').

    Used to scope client-isolation FORWARD DROPs to the subnets behind the
    box's other interfaces — public-internet passthrough must never be
    caught by an isolation rule anchored to a private prefix.
    """
    r = run(['ip', '-4', '-o', 'addr', 'show', 'dev', name], timeout=5)
    if r.returncode == 0:
        m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', r.stdout)
        if m:
            return m.group(1)
    return None


def uplink_namespace():
    """Real upstream DNS server for passthrough of whitelisted clients.

    Skips loopback resolvers (systemd-resolved's 127.0.0.53 stub etc.) — a
    whitelisted client sits on the rogue subnet, so pointing it at the local
    stub would dead-end its DNS queries.
    """
    try:
        with open('/etc/resolv.conf') as fh:
            for line in fh:
                m = re.match(r'^\s*nameserver\s+(\S+)', line)
                if m:
                    ns = m.group(1)
                    if ns.startswith('127.') or ns == '::1' or ns == '0.0.0.0':
                        continue
                    return ns
    except IOError:
        pass
    return None


def plan_ap_iface():
    """Resolve the AP interface name without touching the radio."""
    if config.AP_IFACE:
        return config.AP_IFACE, False
    # The operator's attack-radio choice (dashboard setting or MALSTROM_WLAN_DEV)
    # is an explicit opt-in, exactly like MALSTROM_AP_IFACE: the picked card may
    # be an active internet uplink — hostapd then takes it over directly,
    # dropping that link for the engagement (NM re-connects it on teardown) —
    # or a spare. Either way the card is used AS-IS, no vif creation: several
    # Realtek builds (rtw_8821au with a live p2p-dev iface) refuse `iw phy ..
    # interface add .. type ap` outright while happily letting hostapd flip the
    # managed interface into AP mode.
    dev = preferred_wlan_dev()
    if dev and netdev_exists(dev):
        phy = phy_of(dev)
        if phy and not phy_banned(phy) and 'AP' in phy_modes(phy):
            return dev, False
    if netdev_exists(config.AP_VIF_NAME):
        if phy_banned(phy_of(config.AP_VIF_NAME)):
            # stale ap0 resurrected from a wedged run: never serve hostapd on a
            # radio that hangs the box; tear it down so plan is genuinely free.
            del_vif(config.AP_VIF_NAME)
        else:
            return config.AP_VIF_NAME, False
    uplinks = set(uplink_ifaces())
    devices = scan_phys()
    # Auto-create an AP vif only on a radio that is BOTH not an uplink AND
    # actually capable of serving an AP AND not blacklisted for wedging the
    # whole system. Creating an AP vif on a radio that is an active uplink
    # drops the box's connection and can wedge a USB wifi adapter (a Raspberry
    # Pi hangs entirely) — so we refuse instead; that sacrifice is what the
    # attack-radio choice above is for.
    free = [d for d in devices
            if d['iface'] not in uplinks and not phy_banned(d['phy'])
            and 'AP' in phy_modes(d['phy'])]
    if free:
        return config.AP_VIF_NAME, True
    # No AP-capable spare. Never sacrifice an uplink automatically — that
    # requires the operator to opt in via the attack-radio setting /
    # MALSTROM_AP_IFACE / MALSTROM_WLAN_DEV.
    return config.AP_VIF_NAME, False


def ap_capable_uplinks():
    """AP-capable wifi cards that currently carry the box's internet uplink.

    Surfaced in alert text so the operator can deliberately sacrifice one by
    setting MALSTROM_AP_IFACE / MALSTROM_WLAN_DEV when no spare radio can
    serve an AP. Driver-blacklisted cards are excluded — sacrificing one would
    just wedge the system again.
    """
    uplinks = set(uplink_ifaces())
    return [d['iface'] for d in scan_phys()
            if d['iface'] in uplinks and 'AP' in phy_modes(d['phy'])
            and not phy_banned(d['phy'])]


def plan_monitor_iface():
    """Resolve the monitor-interface name without touching the radio."""
    if config.MON_IFACE:
        return config.MON_IFACE if netdev_exists(config.MON_IFACE) else None
    if netdev_exists(config.MON_VIF_NAME):
        if phy_banned(phy_of(config.MON_VIF_NAME)):
            del_vif(config.MON_VIF_NAME)
        else:
            return config.MON_VIF_NAME
    # A monitor vif can only be created on a radio that isn't an uplink, isn't
    # a driver known to wedge the whole system, and actually supports monitor
    # mode — several spare USB dongles (rtl8xxxu AP-only builds) would
    # otherwise have the check report a monitor that can never come up.
    uplinks = set(uplink_ifaces())
    for dev in scan_phys():
        if dev['iface'] in uplinks or phy_banned(dev['phy']):
            continue
        if 'monitor' not in phy_modes(dev['phy']):
            continue
        return config.MON_VIF_NAME
    return None


def ensure_ap_iface():
    """Drive hostapd on the resolved AP interface, creating a vif when safe.

    A vif is created only on a radio that is not serving as an internet uplink
    AND that supports AP mode.
    """
    name, want_create = plan_ap_iface()
    if not want_create:
        return name, False
    uplinks = set(uplink_ifaces())
    for dev in ordered_devices():
        if dev['iface'] in uplinks:
            continue
        if phy_banned(dev['phy']):
            continue
        if 'AP' not in phy_modes(dev['phy']):
            continue
        if _vif_try_gate(dev['phy'], name):
            continue
        if add_vif(dev['phy'], name, 'ap'):
            return name, True
    return name, False


def hostapd_ok():
    return have('hostapd')


def iptables(args):
    return run(['iptables'] + args, timeout=8)


def ip6tables(args):
    return run(['ip6tables'] + args, timeout=8)


def nft(args):
    return run(['nft'] + args, timeout=8)


def fw_backend(pref=None):
    """Resolve which firewall backend to drive.

    Modern distros default to nftables; some minimal imager/container builds
    then ship `nft` with NO `iptables` binary, which used to leave the whole
    redirect/isolation layer silently absent while ip_forward stayed on.
    Preference: `iptables` when present (legacy and nft-variant accept the
    same CLI), `nft` otherwise. `pref` (config.MALSTROM_FIREWALL) can force
    either; 'auto' (default) probes.
    """
    if pref in ('iptables', 'nft'):
        return pref if have(pref) else None
    for tool in ('iptables', 'nft'):
        if have(tool):
            return tool
    return None


def ipv6_forward_paths(iface):
    """Sysctl paths that govern IPv6 forwarding for this interface.

    Returns writable paths that exist on the live box and the (best-effort)
    snapshot values to restore at teardown. `all.forwarding` is reported for
    the same reason `net.ipv4.ip_forward` is: a host with v6 forwarding on
    elsewhere must not silently gain a v6 bridge through the rogue segment.
    """
    paths = []
    for name in ('net/ipv6/conf/%s/forwarding' % iface,
                 'net/ipv6/conf/all/forwarding'):
        p = '/proc/sys/' + name
        try:
            with open(p) as fh:
                paths.append((p, fh.read().strip()))
        except (IOError, OSError):
            pass
    return paths


def set_ipv6_forward(paths, value):
    """Best-effort sysctl write; returns the number actually written."""
    n = 0
    for p, _ in paths:
        try:
            with open(p, 'w') as fh:
                fh.write(value)
            n += 1
        except (IOError, OSError):
            pass
    return n


def restore_ipv6_forward(paths):
    """Restore each snapshot's prior value; purely best-effort."""
    for p, value in paths:
        try:
            with open(p, 'w') as fh:
                fh.write(value)
        except (IOError, OSError):
            pass


def wpa_pkill_pattern(iface):
    """Scoped POSIX ERE for pkill -f against a stale wpa_supplicant.

    `\\s` is a PCRE-ism that GNU pkill (POSIX ERE) silently never matches, so
    it must be a class + explicit boundaries. The match is scoped to the exact
    interface so a neighbouring radio's wpa_supplicant is never touched.
    """
    return ('wpa_supplicant.*[[:space:]]-i[[:space:]]+%s([[:space:]]|$)'
            % re.escape(iface))


def nm_managed(iface, on=False):
    """Tear NetworkManager control away from a radio we need to reconfigure.

    On Kali the NM daemon fights hostapd/airmon-style AP modes: it reassociates
    the interface, flushes any address we assign (172.16.52.1), and kills the
    rogue AP. Marking the interface unmanaged (and disconnecting it) is the
    same step mature Kali AP tools take. Best-effort: nothing when NM is absent.
    """
    if not have('nmcli'):
        return
    if on:
        run(['nmcli', 'device', 'set', iface, 'managed', 'yes'], timeout=10)
        return
    run(['nmcli', 'device', 'set', iface, 'managed', 'no'], timeout=10)
    run(['nmcli', 'device', 'disconnect', iface], timeout=10)
    # don't let a stale wpa_supplicant keep a claim on the interface (see
    # wpa_pkill_pattern for why the regex is written the way it is).
    run(['pkill', '-f', wpa_pkill_pattern(iface)], timeout=5)


def networkd_managed(iface, on=False):
    """Tell systemd-networkd to (un)manage an interface.

    systemd-networkd can also reclaim a sacrificed Wi-Fi interface and
    re-request the old DHCP lease while hostapd is trying to serve the rogue
    AP. Drop a transient .network file so networkd leaves the interface alone
    during the engagement, and remove it on cleanup so normal networking
    resumes.
    """
    conf = '/etc/systemd/network/99-malstrom-%s.network' % iface
    if on:
        try:
            os.remove(conf)
        except OSError:
            pass
    else:
        try:
            os.makedirs('/etc/systemd/network', exist_ok=True)
        except OSError:
            return
        try:
            with open(conf, 'w') as fh:
                # KeepConfiguration=yes prevents networkd from flushing the
                # portal address when it (re)loads the unmanaged profile.
                fh.write('[Match]\nName=%s\n\n[Network]\nUnmanaged=true\n'
                         'KeepConfiguration=yes\n' % iface)
        except OSError:
            return
    if have('networkctl'):
        # reconfigure applies the change to this specific interface and lets
        # any flush happen before MALSTROM assigns the portal address.
        run(['networkctl', 'reconfigure', iface], timeout=10)
