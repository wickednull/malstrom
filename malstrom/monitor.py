"""Client / activity monitor.

Watches DHCP leases + the ARP table, emits CLIENT/CLIENT_LEAVE/ARP-alert
events, and tracks new credential entries so the engine can stream them.
"""

import time

from . import config
from . import state


def read_dhcp_leases():
    result = {}
    try:
        with open(config.DHCP_LEASE_FILE) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 5:
                    _, mac, ip, name = parts[0], parts[1], parts[2], parts[3]
                    result[ip] = {'mac': mac.upper(), 'name': name}
    except IOError:
        pass
    return result


def read_arp_table():
    result = {}
    try:
        with open('/proc/net/arp') as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != '00:00:00:00:00:00' \
                        and 'incomplete' not in line.lower():
                    ip, mac = parts[0], parts[3]
                    if mac != '00:00:00:00:00:00':
                        result[ip] = {'mac': mac.upper(),
                                      'dev': parts[5] if len(parts) > 5 else ''}
    except IOError:
        pass
    return result


def _in_portal_net(ip):
    """True when ip lives on the rogue-AP subnet (172.16.52.0/24 by default)."""
    prefix = '.'.join(str(config.PORTAL_NET).split('.')[:3]) + '.'
    return str(ip).startswith(prefix)


class Monitor(object):
    def __init__(self):
        self.clients = {}
        self.arp_map = {}
        self._arp_warned = set()

    def cycle(self):
        now = time.time()
        leases = read_dhcp_leases()
        arp = read_arp_table()
        merged = {}
        for ip, info in arp.items():
            if ip == config.PORTAL_IP or not _in_portal_net(ip):
                continue
            merged[ip] = {'mac': info['mac'],
                          'name': leases.get(ip, {}).get('name', '')}
        for ip, info in leases.items():
            if ip not in merged and ip != config.PORTAL_IP \
                    and _in_portal_net(ip):
                merged[ip] = {'mac': info['mac'], 'name': info['name']}

        for ip, info in arp.items():
            if not _in_portal_net(ip):
                continue
            prev = self.arp_map.get(ip)
            if prev and prev != info['mac']:
                key = (ip, info['mac'])
                if key not in self._arp_warned:
                    state.emit('ALERT', 'ARP entity change: %s now claims MAC %s (was %s)'
                               % (ip, info['mac'], prev))
                    self._arp_warned.add(key)
            self.arp_map[ip] = info['mac']

        for ip, info in merged.items():
            if ip not in self.clients:
                self.clients[ip] = {'mac': info['mac'], 'name': info['name'],
                                    'first_seen': now, 'last_seen': now}
                state.emit('CLIENT', '%s (%s) associated'
                           % (info['name'] or ip, info['mac']))
                state.upsert_device(info['mac'], ip=ip,
                                    hostname=info['name'] or '')
            else:
                self.clients[ip]['last_seen'] = now
                if info['name'] and not self.clients[ip]['name']:
                    self.clients[ip]['name'] = info['name']

        gone = [ip for ip, c in self.clients.items()
                if now - c['last_seen'] > max(15, 3 * config.MONITOR_INTERVAL)]
        for ip in gone:
            c = self.clients.pop(ip, None)
            if c:
                state.emit('CLIENT_LEAVE', '%s (%s) disconnected'
                           % (c['name'] or ip, c['mac']))

        active = set(merged.keys())
        for ip in [ip for ip in self.arp_map if ip not in active]:
            self.arp_map.pop(ip, None)
        self._arp_warned = {(ip, m) for ip, m in self._arp_warned
                            if ip in active}
        return merged