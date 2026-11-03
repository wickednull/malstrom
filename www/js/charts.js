/* DarkSec MALSTROM — dependency-free canvas charts.
 *
 * Plain 2D canvas primitives styled for the dashboard theme. Every chart
 * re-reads its element size on draw so it survives view switches / resizes.
 */
(function (global) {
  'use strict';

  var COLORS = {
    red: '#ff5c5c',
    rose: '#ff8a8a',
    amber: '#ffb454',
    cyan: '#5fd0ff',
    blue: '#6ea8ff',
    violet: '#c084fc',
    green: '#7cffb2',
    lime: '#c6ff6e',
    dim: '#6d6065',
    text: '#d5cdd0',
    grid: 'rgba(255,255,255,0.055)',
    axis: 'rgba(255,255,255,0.13)'
  };

  var FONT = '9px "JetBrains Mono","Fira Code",Consolas,monospace';

  function surface(cv, fixedH) {
    var dpr = global.devicePixelRatio || 1;
    var w = cv.clientWidth || (cv.parentNode && cv.parentNode.clientWidth) || 320;
    var h = fixedH || cv.clientHeight || 180;
    cv.width = Math.max(1, Math.round(w * dpr));
    cv.height = Math.max(1, Math.round(h * dpr));
    var g = cv.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, h);
    return { g: g, w: w, h: h };
  }

  function niceMax(v) {
    if (!v || v <= 0) return 1;
    if (v <= 5) return 5;
    var exp = Math.pow(10, Math.floor(Math.log(v) / Math.LN10));
    var f = v / exp;
    var n = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
    return n * exp;
  }

  function rounded(g, x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2);
    g.beginPath();
    g.moveTo(x + r, y);
    g.lineTo(x + w - r, y);
    g.quadraticCurveTo(x + w, y, x + w, y + r);
    g.lineTo(x + w, y + h - r);
    g.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    g.lineTo(x + r, y + h);
    g.quadraticCurveTo(x, y + h, x, y + h - r);
    g.lineTo(x, y + r);
    g.quadraticCurveTo(x, y, x + r, y);
    g.closePath();
  }

  function withAlpha(hex, a) {
    var h = String(hex || '').replace('#', '');
    if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
    var n = parseInt(h, 16);
    if (isNaN(n)) return 'rgba(255,92,92,' + a + ')';
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }

  function fmtClock(sec) {
    var d = new Date(sec * 1000);
    if (isNaN(d.getTime())) return '';
    return ('0' + d.getHours()).slice(-2) + ':' +
           ('0' + d.getMinutes()).slice(-2) + ':' +
           ('0' + d.getSeconds()).slice(-2);
  }

  function fmtCompact(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'k';
    return String(Math.round(n));
  }

  function gridY(g, x, y, w, h, max, color) {
    g.strokeStyle = color || COLORS.grid;
    g.lineWidth = 1;
    g.font = FONT;
    g.textAlign = 'right';
    g.textBaseline = 'middle';
    g.fillStyle = COLORS.dim;
    var small = max <= 12;
    var steps;
    if (small) steps = Math.max(1, Math.round(max));
    else steps = (max % 5 === 0) ? 5 : 4;
    for (var i = 0; i <= steps; i++) {
      var yy = Math.round(y + (h * i / steps)) + 0.5;
      g.beginPath();
      g.moveTo(x, yy);
      g.lineTo(x + w, yy);
      g.stroke();
      var val = max * (steps - i) / steps;
      g.fillText(small ? String(Math.round(val)) : fmtCompact(val), x - 7, yy);
    }
  }

  /* Multi-series line chart.
   * opts: { series:[{name,color,data,width,fill,glow}], labels:[epochSec],
   *         max, min, unit, legend:false }
   */
  function line(cv, opts) {
    var s = surface(cv, opts.height);
    var g = s.g, w = s.w, h = s.h;
    var padL = opts.padL || 38, padR = 10, padT = 10, padB = 21;
    var pw = Math.max(1, w - padL - padR);
    var ph = Math.max(1, h - padT - padB);
    var series = (opts.series || []).filter(function (x) { return x && x.data; });
    cv._series = series;
    cv._labels = opts.labels || [];
    var n = 1;
    series.forEach(function (x) { n = Math.max(n, x.data.length); });
    var max = opts.max, min = opts.min || 0;
    var rawMax = 0;
    if (!max) {
      max = 0;
      series.forEach(function (x) {
        x.data.forEach(function (v) { if (v > max) max = v; });
      });
      rawMax = max;
      max = niceMax(max);
    }
    var range = Math.max(0.0001, max - min);

    gridY(g, padL, padT, pw, ph, max);

    // x-axis time labels
    if (opts.labels && opts.labels.length) {
      g.font = FONT;
      g.fillStyle = COLORS.dim;
      g.textBaseline = 'top';
      var ticks = [0, 0.33, 0.66, 1];
      ticks.forEach(function (t) {
        var idx = Math.round((opts.labels.length - 1) * t);
        var x = padL + pw * t;
        g.textAlign = t === 0 ? 'left' : (t === 1 ? 'right' : 'center');
        g.fillText(fmtClock(opts.labels[idx]), x, padT + ph + 6);
      });
    }

    series.forEach(function (sr) {
      var data = sr.data;
      if (!data.length) return;
      var color = sr.color || COLORS.red;
      var step = data.length > 1 ? pw / (data.length - 1) : pw;
      function px(i) { return padL + i * step; }
      function py(v) { return padT + ph - ((v - min) / range) * ph; }

      if (sr.fill) {
        g.save();
        var grad = g.createLinearGradient(0, padT, 0, padT + ph);
        grad.addColorStop(0, withAlpha(color, 0.22));
        grad.addColorStop(1, withAlpha(color, 0.0));
        g.beginPath();
        g.moveTo(px(0), padT + ph);
        data.forEach(function (v, i) { g.lineTo(px(i), py(v)); });
        g.lineTo(px(data.length - 1), padT + ph);
        g.closePath();
        g.fillStyle = grad;
        g.fill();
        g.restore();
      }

      if (sr.glow) {
        g.save();
        g.shadowColor = color;
        g.shadowBlur = 9;
      }
      g.beginPath();
      data.forEach(function (v, i) {
        if (i === 0) g.moveTo(px(i), py(v));
        else g.lineTo(px(i), py(v));
      });
      g.strokeStyle = color;
      g.lineWidth = sr.width || 1.6;
      g.lineJoin = 'round';
      g.lineCap = 'round';
      g.stroke();
      if (sr.glow) g.restore();

      // live end-point marker
      var lx = px(data.length - 1), ly = py(data[data.length - 1]);
      g.fillStyle = color;
      g.beginPath();
      g.arc(lx, ly, 2.4, 0, Math.PI * 2);
      g.fill();
    });

    if (!rawMax) {
      g.fillStyle = COLORS.dim;
      g.font = FONT;
      g.textAlign = 'center';
      g.textBaseline = 'middle';
      g.fillText(opts.emptyText || 'no samples yet', padL + pw / 2, padT + ph / 2);
    }
  }

  /* Vertical bars: opts { labels, values, colors|color, max, unit, logScale } */
  function bars(cv, opts) {
    var s = surface(cv, opts.height);
    var g = s.g, w = s.w, h = s.h;
    var padL = opts.padL || 38, padR = 10, padT = 12, padB = 20;
    var pw = Math.max(1, w - padL - padR);
    var ph = Math.max(1, h - padT - padB);
    var vals = opts.values || [];
    var max = opts.max;
    var useLog = opts.logScale && vals.length > 0;
    
    if (useLog) {
      // For log scale, find max and use log10 for scaling
      var maxVal = 0;
      vals.forEach(function (v) { if (v > maxVal) maxVal = v; });
      // keep a sane floor so an all-zero chart still has a usable scale
      var logMax = Math.log10(Math.max(10, maxVal));

      // Draw log scale grid
      g.strokeStyle = COLORS.grid;
      g.lineWidth = 1;
      g.font = FONT;
      g.textAlign = 'right';
      g.textBaseline = 'middle';
      g.fillStyle = COLORS.dim;

      var logSteps = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000];
      for (var i = 0; i < logSteps.length; i++) {
        if (logSteps[i] > Math.pow(10, logMax)) break;
        var logPos = Math.log10(logSteps[i]) / logMax;
        var yy = Math.round(padT + ph - (logPos * ph)) + 0.5;
        g.beginPath();
        g.moveTo(padL, yy);
        g.lineTo(padL + pw, yy);
        g.stroke();
        g.fillText(fmtCompact(logSteps[i]), padL - 7, yy);
      }
    } else {
      if (!max) {
        max = 1;
        vals.forEach(function (v) { if (v > max) max = v; });
        max = niceMax(max);
      }
      gridY(g, padL, padT, pw, ph, max);
    }

    var n = vals.length || 1;
    var slot = pw / n;
    var bw = Math.max(2, Math.min(30, slot * 0.64));
    g.font = FONT;
    g.textAlign = 'center';
    g.textBaseline = 'top';

    if (opts.highlight !== undefined && opts.highlight >= 0 && opts.highlight < n) {
      var hx = padL + slot * opts.highlight;
      g.fillStyle = 'rgba(255,26,33,0.07)';
      g.fillRect(hx, padT, slot, ph);
      g.fillStyle = 'rgba(255,26,33,0.55)';
      g.fillRect(hx, padT + ph - 1, slot, 1.5);
    }

    for (var i = 0; i < n; i++) {
      var v = vals[i];
      var cx = padL + slot * (i + 0.5);
      var bh;
      
      if (useLog) {
        // Logarithmic scaling
        var logVal = v > 0 ? Math.log10(v) : 0;
        var logPos = logVal / logMax;
        bh = Math.max(v > 0 ? 2 : 0, logPos * ph);
      } else {
        bh = Math.max(v > 0 ? 2 : 0, (v / max) * ph);
      }
      
      var color = (opts.colors && opts.colors[i]) || opts.color || COLORS.red;
      var hot = i === opts.highlight;
      var y = padT + ph - bh;
      if (bh > 0) {
        var grad = g.createLinearGradient(0, y, 0, padT + ph);
        grad.addColorStop(0, color);
        grad.addColorStop(1, withAlpha(color, hot ? 0.4 : 0.18));
        g.fillStyle = grad;
        rounded(g, cx - bw / 2, y, bw, bh, 2);
        g.fill();
        g.fillStyle = hot ? '#ffffff' : withAlpha(color, 0.9);
        g.fillRect(cx - bw / 2, y, bw, hot ? 2 : 1.4);
      }
      var every = Math.max(1, Math.ceil(n / Math.max(4, Math.floor(pw / 34))));
      if (i % every === 0 || (i === n - 1 && (n - 1) % every >= Math.ceil(every / 2))) {
        g.fillStyle = COLORS.dim;
        g.fillText(String(opts.labels ? opts.labels[i] : i + 1), cx, padT + ph + 5);
      }
      if (opts.showValues && n <= 14 && v > 0) {
        g.fillStyle = color;
        g.textBaseline = 'bottom';
        g.fillText(fmtCompact(v), cx, y - 2);
        g.textBaseline = 'top';
      }
    }
  }

  /* Donut: opts { segments:[{label,value,color}], center, sub } */
  function donut(cv, opts) {
    var s = surface(cv, opts.height);
    var g = s.g, w = s.w, h = s.h;
    var segs = (opts.segments || []).filter(function (x) { return x.value > 0; });
    var total = segs.reduce(function (a, b) { return a + b.value; }, 0);
    var cx = w / 2, cy = h / 2;
    var r = Math.max(12, Math.min(w, h) / 2 - 12);
    var lw = Math.max(8, Math.min(16, r * 0.32));
    g.lineWidth = lw;
    g.lineCap = 'butt';
    if (!total) {
      g.strokeStyle = 'rgba(255,255,255,0.07)';
      g.beginPath();
      g.arc(cx, cy, r - lw / 2, 0, Math.PI * 2);
      g.stroke();
    } else {
      var a0 = -Math.PI / 2;
      segs.forEach(function (sg) {
        var a1 = a0 + (sg.value / total) * Math.PI * 2;
        g.strokeStyle = sg.color;
        g.beginPath();
        g.arc(cx, cy, r - lw / 2, a0, a1);
        g.stroke();
        a0 = a1;
      });
    }
    g.textAlign = 'center';
    g.textBaseline = 'middle';
    g.fillStyle = COLORS.text;
    g.font = '700 17px "JetBrains Mono",Consolas,monospace';
    g.fillText(String(opts.center != null ? opts.center : total), cx, cy - 4);
    g.fillStyle = COLORS.dim;
    g.font = FONT;
    g.fillText(opts.sub || '', cx, cy + 12);
  }

  /* Horizontal rank bars: opts { rows:[{name,value,color}], max } */
  function rank(cv, opts) {
    var s = surface(cv, opts.height);
    var g = s.g, w = s.w, h = s.h;
    var rows = (opts.rows || []).slice(0, opts.limit || 7);
    if (!rows.length) {
      g.fillStyle = COLORS.dim;
      g.font = FONT;
      g.textAlign = 'center';
      g.textBaseline = 'middle';
      g.fillText('no data yet', w / 2, h / 2);
      return;
    }
    var max = opts.max || 1;
    rows.forEach(function (r) { if (r.value > max) max = r.value; });
    var rowH = Math.min(22, h / rows.length);
    var labelW = Math.min(112, Math.max(60, w * 0.32));
    var barX = labelW + 6;
    var barW = Math.max(10, w - barX - 32);
    g.font = FONT;
    rows.forEach(function (r, i) {
      var y = i * rowH + (rowH - 7) / 2;
      g.textAlign = 'left';
      g.textBaseline = 'middle';
      g.fillStyle = COLORS.dim;
      var name = String(r.name || '?');
      if (name.length > 17) name = name.slice(0, 16) + '\u2026';
      g.fillText(name, 0, y + 3.5);
      var bw = Math.max(2, (r.value / max) * barW);
      g.fillStyle = withAlpha(r.color || COLORS.red, 0.18);
      rounded(g, barX, y, barW, 7, 3.5);
      g.fill();
      g.fillStyle = r.color || COLORS.red;
      rounded(g, barX, y, bw, 7, 3.5);
      g.fill();
      g.fillStyle = COLORS.text;
      g.textAlign = 'right';
      g.fillText(fmtCompact(r.value), w, y + 3.5);
    });
  }

  global.MChart = {
    COLORS: COLORS,
    line: line,
    bars: bars,
    donut: donut,
    rank: rank,
    fmtCompact: fmtCompact,
    withAlpha: withAlpha
  };
})(window);
