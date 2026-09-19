"""Post-ex recon engine: host discovery + port scans over any CIDR.

Runs nmap in the background (daemon is root), parses grepable output, enriches
hosts with the local ARP table, and persists results into the shared scans
store so the dashboard can poll them.
"""

import os
import re
import shutil
import subprocess
import threading
import time

from . import config
from . import state

PORT_NAMES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
    143: 'imap', 389: 'ldap', 443: 'https', 445: 'smb',
    636: 'ldaps', 993: 'imaps', 995: 'pop3s', 1433: 'mssql',
    1521: 'oracle', 3306: 'mysql', 3389: 'rdp', 5432: 'postgres',
    5900: 'vnc', 5985: 'winrm', 6379: 'redis', 8000: 'http-alt',
    8080: 'http-proxy', 8443: 'https-alt', 9200: 'elastic', 27017: 'mongodb',
}

_HOST_RE = re.compile(
    r'Host:\s+([0-9.]+)(?:\s+\(([^)]*)\))?'
    r'(?:\s+Status:\s+(Up|Down))?(?:\s+Ports:(.*))?')
_PORT_RE = re.compile(
    r'([0-9]+)/(open|closed|filtered|open\|filtered)/(tcp|udp)//([^/]*)/+')


def _arp_lookup(ips):
    macs = {}
    try:
        with open('/proc/net/arp') as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[0] in ips \
                        and parts[3] != '00:00:00:00:00:00':
                    macs[parts[0]] = parts[3]
    except IOError:
        pass
    return macs


def _run_bin(args, timeout=120):
    try:
        proc = subprocess.run([config.SCAN_BIN] + args,
                              capture_output=True, text=True,
                              timeout=timeout, stdin=subprocess.DEVNULL)
        return proc, ''
    except Exception as exc:
        return None, str(exc)


_PORT_KINDS = ('ports', 'svc')


def _parse_gnmap(text, kind):
    out = {'hosts': [], 'ports': {}}
    macs = {}
    if kind in _PORT_KINDS:
        ips = [m.group(1) for m in _HOST_RE.finditer(text)]
        macs = _arp_lookup(set(ips))
    for m in _HOST_RE.finditer(text):
        status = m.group(3) or ''
        ports_text = m.group(4) or ''
        if status == 'Down' and not ports_text.strip():
            continue
        if not status.startswith('Up') and not ports_text.strip():
            continue
        ip = m.group(1)
        host = {'ip': ip, 'hostname': m.group(2) or '',
                'mac': macs.get(ip, '')}
        if not any(h['ip'] == ip for h in out['hosts']):
            out['hosts'].append(host)
        elif not ports_text.strip():
            out['ports'][ip] = out['ports'].get(ip, [])
        if kind in _PORT_KINDS and ports_text.strip():
            plist = []
            for pm in _PORT_RE.finditer(ports_text):
                port = int(pm.group(1))
                if pm.group(2) in ('open', 'open|filtered'):
                    svc = pm.group(4) or PORT_NAMES.get(port, '')
                    plist.append({'port': port, 'proto': pm.group(3),
                                  'svc': svc})
            if plist:
                out['ports'][ip] = plist
    return out


class ScanEngine(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._running = None

    def running(self):
        with self._lock:
            return self._running

    def has_scan_bin(self):
        return bool(shutil.which(config.SCAN_BIN))

    def start_job(self, kind, target, opts):
        kind = kind or 'ports'
        if kind not in ('ping', 'ports', 'svc'):
            kind = 'ports'
        if not target:
            return {'ok': 0, 'error': 'target required'}
        with self._lock:
            if self._running:
                return {'ok': 0, 'error': 'scan already running'}
            job = {
                'id': '%s-%s' % (time.strftime('%H%M%S'), os.getpid()),
                'kind': kind,
                'target': target,
                'targets': ' '.join(opts.get('targets', [])),
                'range': opts.get('range', config.SCAN_PORT_RANGE),
                'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'started': time.time(),
                'status': 'running',
                'cmd': '',
                'error': '',
            }
            self._running = job['id']
        state.put_scan(job)
        t = threading.Thread(target=self._worker, args=(job,), daemon=True)
        t.start()
        return {'ok': 1, 'id': job['id']}

    def _worker(self, job):
        try:
            if job['kind'] == 'ping':
                cmd = ['-sn', '-n', '-oG', '-', job['target']]
                result = _run_bin(cmd, timeout=300)
            elif job['kind'] == 'svc':
                # Service/version detection: turns the port table into an
                # actual service picture (http, ssh, smb versions, ...).
                cmd = ['-sS', '-sV', '-Pn', '-n', '-T4', '--open',
                       '-p', job['range'], '-oG', '-', job['target']]
                result = _run_bin(cmd, timeout=600)
            else:
                cmd = ['-sS', '-Pn', '-n', '-T4', '--open',
                       '-p', job['range'], '-oG', '-', job['target']]
                result = _run_bin(cmd, timeout=300)
            job['cmd'] = '%s %s' % (config.SCAN_BIN, ' '.join(cmd))
            self._finish_job(job, result)
        except Exception as exc:
            job['status'] = 'error'
            job['error'] = str(exc)
        job['finished'] = time.time()
        with self._lock:
            self._running = None
        state.put_scan(job)
        state.mirror_loot()

    def _finish_job(self, job, result):
        if result is None:
            job['status'] = 'error'
            job['error'] = '%s not available' % config.SCAN_BIN
            return
        proc, err = result
        if proc.returncode != 0 and not (proc.stdout or '').strip():
            job['status'] = 'error'
            job['error'] = err or proc.stderr.strip()[:300] or 'nmap failed'
            return
        parsed = _parse_gnmap(proc.stdout or '', job['kind'])
        job.update(parsed)
        job['status'] = 'done'
        state.emit('SCAN', 'scan %s complete: %s -> %d hosts' % (
            job['kind'], job['target'], len(parsed['hosts'])))