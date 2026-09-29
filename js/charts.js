/**
 * SOCNeon — charts.js
 * Pure Canvas-based charts. Zero dependencies.
 * Exports: window.SOCNeonCharts
 */
'use strict';

window.SOCNeonCharts = (() => {

  const C = {
    critical: '#ff3860', high: '#ff8c00', medium: '#ffd700',
    low: '#00e5ff', info: '#8892b0',
    accent: '#00e5ff', accent2: '#7b2fff', accent3: '#00ff9d',
    grid: '#1e2d4a', text: '#8892b0', textBright: '#e2e8f5', bg: '#0d1626',
  };

  function isDark() { return !document.body.classList.contains('light-mode'); }
  function gridColor() { return isDark() ? '#1e2d4a' : '#e2e8f0'; }
  function textColor() { return isDark() ? '#8892b0' : '#4a5568'; }
  function bgColor()   { return isDark() ? '#0d1626' : '#f7fafc'; }

  function setupCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width  = rect.width  * dpr;
    canvas.height = canvas.height || (200 * dpr);
    canvas.style.width  = rect.width + 'px';
    canvas.style.height = (canvas.height / dpr) + 'px';
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    return { ctx, w: rect.width, h: canvas.height / dpr, dpr };
  }

  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  /* ─── Timeline Chart ──────────────────────────────────────────────────── */
  function drawTimeline(canvasId, events, findings) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    canvas.height = 220 * (window.devicePixelRatio || 1);
    const { ctx, w, h } = setupCanvas(canvas);
    ctx.clearRect(0, 0, w, h);

    const datedEvents = events.filter(e => e._ts instanceof Date);
    if (datedEvents.length < 2) {
      ctx.fillStyle = textColor();
      ctx.font = '13px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Not enough timestamped events for timeline', w / 2, h / 2);
      return;
    }

    // Determine time range and bucket size
    const times = datedEvents.map(e => e._ts.getTime());
    const minT  = Math.min(...times);
    const maxT  = Math.max(...times);
    const range = maxT - minT;
    const BUCKETS = Math.min(50, Math.max(10, Math.floor(w / 20)));
    const bucketMs = range / BUCKETS || 60000;

    // Count events per bucket
    const counts   = new Array(BUCKETS).fill(0);
    const flagged  = new Array(BUCKETS).fill(0);
    const findingTs = new Set(findings.map(f => f.event?._ts?.getTime()).filter(Boolean));

    datedEvents.forEach(e => {
      const idx = Math.min(BUCKETS - 1, Math.floor((e._ts.getTime() - minT) / bucketMs));
      counts[idx]++;
      if (findingTs.has(e._ts.getTime())) flagged[idx]++;
    });

    const maxCount = Math.max(...counts, 1);
    const pad = { t: 20, r: 20, b: 40, l: 45 };
    const cw = w - pad.l - pad.r;
    const ch = h - pad.t - pad.b;
    const barW = cw / BUCKETS;

    // Grid lines
    ctx.strokeStyle = gridColor();
    ctx.lineWidth = 0.5;
    for (let i = 0; i <= 4; i++) {
      const y = pad.t + ch - (ch * i / 4);
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + cw, y);
      ctx.stroke();
      ctx.fillStyle = textColor();
      ctx.font = '10px Inter, sans-serif';
      ctx.textAlign = 'right';
      ctx.fillText(Math.round(maxCount * i / 4), pad.l - 6, y + 4);
    }

    // Bars (animate via progress)
    counts.forEach((count, i) => {
      const x = pad.l + i * barW;
      const barH = (count / maxCount) * ch;
      const y = pad.t + ch - barH;

      // Base bar gradient
      const grad = ctx.createLinearGradient(0, y, 0, y + barH);
      grad.addColorStop(0, C.accent + 'cc');
      grad.addColorStop(1, C.accent2 + '66');
      ctx.fillStyle = grad;
      roundRect(ctx, x + 1, y, barW - 2, barH, 2);
      ctx.fill();

      // Flagged overlay
      if (flagged[i] > 0) {
        const fH = (flagged[i] / count) * barH;
        ctx.fillStyle = C.critical + 'bb';
        roundRect(ctx, x + 1, y, barW - 2, fH, 2);
        ctx.fill();
      }
    });

    // X-axis time labels
    ctx.fillStyle = textColor();
    ctx.font = '9px Inter, sans-serif';
    ctx.textAlign = 'center';
    const labelCount = Math.min(6, BUCKETS);
    for (let i = 0; i <= labelCount; i++) {
      const idx = Math.round(i * (BUCKETS - 1) / labelCount);
      const t   = new Date(minT + idx * bucketMs);
      const x   = pad.l + idx * barW + barW / 2;
      let label;
      if (range < 3600000)       label = t.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
      else if (range < 86400000) label = t.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
      else                       label = t.toLocaleDateString([], {month:'short',day:'numeric',hour:'2-digit'});
      ctx.fillText(label, x, h - 8);
    }

    // Legend
    ctx.fillStyle = C.accent + 'cc';
    ctx.fillRect(pad.l, 4, 12, 8);
    ctx.fillStyle = textColor();
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText('Events', pad.l + 16, 12);

    ctx.fillStyle = C.critical + 'bb';
    ctx.fillRect(pad.l + 75, 4, 12, 8);
    ctx.fillText('Flagged', pad.l + 91, 12);
  }

  /* ─── Severity Donut ──────────────────────────────────────────────────── */
  function drawDonut(canvasId, counts) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    canvas.height = 200 * (window.devicePixelRatio || 1);
    const { ctx, w, h } = setupCanvas(canvas);
    ctx.clearRect(0, 0, w, h);

    const data = [
      { label: 'Critical', value: counts.critical || 0, color: C.critical },
      { label: 'High',     value: counts.high || 0,     color: C.high },
      { label: 'Medium',   value: counts.medium || 0,   color: C.medium },
      { label: 'Low',      value: counts.low || 0,      color: C.low },
      { label: 'Info',     value: counts.info || 0,     color: C.info },
    ].filter(d => d.value > 0);

    const total = data.reduce((s, d) => s + d.value, 0);
    if (total === 0) {
      ctx.fillStyle = textColor();
      ctx.font = '13px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No findings', w / 2, h / 2);
      return;
    }

    const cx = w * 0.38, cy = h / 2, outerR = Math.min(cx, cy) - 10, innerR = outerR * 0.58;
    let angle = -Math.PI / 2;

    data.forEach(d => {
      const slice = (d.value / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, outerR, angle, angle + slice);
      ctx.closePath();
      ctx.fillStyle = d.color;
      ctx.fill();
      ctx.strokeStyle = bgColor();
      ctx.lineWidth = 2;
      ctx.stroke();
      angle += slice;
    });

    // Donut hole
    ctx.beginPath();
    ctx.arc(cx, cy, innerR, 0, 2 * Math.PI);
    ctx.fillStyle = bgColor();
    ctx.fill();

    // Center text
    ctx.textAlign = 'center';
    ctx.fillStyle = C.accent;
    ctx.font = `bold ${Math.round(innerR * 0.55)}px Orbitron, sans-serif`;
    ctx.fillText(total, cx, cy + 4);
    ctx.fillStyle = textColor();
    ctx.font = `10px Inter, sans-serif`;
    ctx.fillText('findings', cx, cy + 18);

    // Legend
    const lx = w * 0.65, ly = 20;
    data.forEach((d, i) => {
      const y = ly + i * 28;
      ctx.fillStyle = d.color;
      roundRect(ctx, lx, y, 12, 12, 3);
      ctx.fill();
      ctx.fillStyle = C.textBright;
      ctx.font = '12px Inter, sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(d.label, lx + 18, y + 10);
      ctx.fillStyle = textColor();
      ctx.font = '11px Inter, sans-serif';
      ctx.textAlign = 'right';
      ctx.fillText(d.value, w - 10, y + 10);
    });
  }

  /* ─── Horizontal Bar Chart ────────────────────────────────────────────── */
  function drawHBar(canvasId, data, opts = {}) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const itemH = 30, pad = { t: 10, r: 80, b: 20, l: 140 };
    canvas.height = Math.max(120, (data.length * itemH + pad.t + pad.b)) * (window.devicePixelRatio || 1);
    const { ctx, w, h } = setupCanvas(canvas);
    ctx.clearRect(0, 0, w, h);

    if (!data.length) {
      ctx.fillStyle = textColor();
      ctx.font = '12px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No data', w / 2, h / 2);
      return;
    }

    const maxVal = Math.max(...data.map(d => d.value), 1);
    const cw = w - pad.l - pad.r;

    data.forEach((d, i) => {
      const y   = pad.t + i * itemH;
      const barW = (d.value / maxVal) * cw;
      const barH = itemH - 6;

      const grad = ctx.createLinearGradient(pad.l, 0, pad.l + barW, 0);
      grad.addColorStop(0, (d.color || C.accent) + 'dd');
      grad.addColorStop(1, (d.color || C.accent2) + '88');
      ctx.fillStyle = grad;
      roundRect(ctx, pad.l, y + 3, barW, barH, 3);
      ctx.fill();

      // Label
      ctx.fillStyle = textColor();
      ctx.font = '11px Inter, sans-serif';
      ctx.textAlign = 'right';
      const label = String(d.label).slice(0, 18);
      ctx.fillText(label, pad.l - 8, y + barH / 2 + 3 + 3);

      // Value
      ctx.fillStyle = d.color || C.accent;
      ctx.font = 'bold 11px Inter, sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(d.value, pad.l + barW + 6, y + barH / 2 + 3 + 3);
    });
  }

  /* ─── 24h Activity Heatmap ────────────────────────────────────────────── */
  function drawHeatmap(canvasId, events) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    canvas.height = 140 * (window.devicePixelRatio || 1);
    const { ctx, w, h } = setupCanvas(canvas);
    ctx.clearRect(0, 0, w, h);

    // Count events per hour
    const hourly = new Array(24).fill(0);
    events.forEach(e => {
      if (e._ts instanceof Date) hourly[e._ts.getHours()]++;
    });

    const maxVal = Math.max(...hourly, 1);
    const pad    = { t: 30, r: 15, b: 25, l: 15 };
    const cw     = w - pad.l - pad.r;
    const ch     = h - pad.t - pad.b;
    const cellW  = cw / 24;

    // Draw title
    ctx.fillStyle = textColor();
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Events by Hour of Day', w / 2, 14);

    hourly.forEach((count, hour) => {
      const x        = pad.l + hour * cellW;
      const intensity = count / maxVal;
      const isRisk    = hour >= 0 && hour < 5;

      // Cell background
      const baseColor = isRisk ? C.critical : C.accent;
      ctx.fillStyle = baseColor + Math.round(intensity * 200 + 15).toString(16).padStart(2, '0');
      roundRect(ctx, x + 1, pad.t, cellW - 2, ch, 3);
      ctx.fill();

      // Hour label
      ctx.fillStyle = intensity > 0.5 ? '#fff' : textColor();
      ctx.font = '9px Inter, sans-serif';
      ctx.textAlign = 'center';
      if (hour % 3 === 0) ctx.fillText(`${hour}h`, x + cellW / 2, h - 8);

      // Count on top
      if (count > 0) {
        ctx.fillStyle = intensity > 0.3 ? '#fff' : (baseColor + 'ff');
        ctx.font = `bold ${Math.max(8, Math.min(11, cellW * 0.5))}px Inter, sans-serif`;
        ctx.fillText(count > 99 ? '99+' : String(count), x + cellW / 2, pad.t + ch / 2 + 4);
      }
    });

    // Risk zone label
    ctx.fillStyle = C.critical + 'aa';
    ctx.font = '9px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText('▲ off-hours risk zone (0–5h)', pad.l, pad.t - 8);
  }

  /* ─── Threat Score Gauge ──────────────────────────────────────────────── */
  function drawGauge(canvasId, score, label = '') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    canvas.height = 180 * (window.devicePixelRatio || 1);
    const { ctx, w, h } = setupCanvas(canvas);
    ctx.clearRect(0, 0, w, h);

    const cx = w / 2, cy = h * 0.65;
    const r  = Math.min(w, h) * 0.38;
    const startA = Math.PI * 0.8, endA = Math.PI * 0.2 + Math.PI;
    const progress = Math.max(0, Math.min(100, score)) / 100;

    // Background arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, startA, endA + Math.PI * 1.4);
    ctx.strokeStyle = gridColor();
    ctx.lineWidth = 18;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Color stops based on score
    const scoreColor = score >= 80 ? C.critical
                     : score >= 60 ? C.high
                     : score >= 40 ? C.medium
                     : score >= 20 ? C.low
                     : C.info;

    // Filled arc
    const arcEnd = startA + progress * Math.PI * 1.4;
    const grad = ctx.createLinearGradient(cx - r, cy, cx + r, cy);
    grad.addColorStop(0, C.accent3);
    grad.addColorStop(0.5, C.medium);
    grad.addColorStop(1, C.critical);

    ctx.beginPath();
    ctx.arc(cx, cy, r, startA, arcEnd);
    ctx.strokeStyle = grad;
    ctx.lineWidth = 18;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Score text
    ctx.fillStyle = scoreColor;
    ctx.font = `bold ${Math.round(r * 0.55)}px Orbitron, sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText(score, cx, cy + 8);

    ctx.fillStyle = textColor();
    ctx.font = '11px Inter, sans-serif';
    ctx.fillText('/ 100', cx, cy + 26);

    if (label) {
      ctx.fillStyle = scoreColor;
      ctx.font = 'bold 13px Inter, sans-serif';
      ctx.fillText(label, cx, cy - r * 0.55);
    }

    // Tick marks
    for (let i = 0; i <= 10; i++) {
      const a = startA + (i / 10) * Math.PI * 1.4;
      const inner = r - 14, outer = r + 4;
      ctx.beginPath();
      ctx.moveTo(cx + inner * Math.cos(a), cy + inner * Math.sin(a));
      ctx.lineTo(cx + outer * Math.cos(a), cy + outer * Math.sin(a));
      ctx.strokeStyle = gridColor();
      ctx.lineWidth = i % 5 === 0 ? 2 : 1;
      ctx.stroke();
    }
  }

  /* ─── Mini Sparkline ──────────────────────────────────────────────────── */
  function drawSparkline(canvasId, values, color = C.accent) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || values.length < 2) return;
    const { ctx, w, h } = setupCanvas(canvas);
    ctx.clearRect(0, 0, w, h);
    const max = Math.max(...values, 1);
    const step = w / (values.length - 1);
    ctx.beginPath();
    values.forEach((v, i) => {
      const x = i * step, y = h - (v / max) * h * 0.85 - 2;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.stroke();

    // Fill under line
    ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, color + '44');
    grad.addColorStop(1, color + '00');
    ctx.fillStyle = grad;
    ctx.fill();
  }

  return { drawTimeline, drawDonut, drawHBar, drawHeatmap, drawGauge, drawSparkline, COLORS: C };
})();
