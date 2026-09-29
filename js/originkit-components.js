/**
 * SOCNeon — originkit-components.js
 * Animated UI components inspired by Originkit.dev:
 * 1. AsciiRadar: Interactive scanning threat radar with threat blips
 * 2. AsciiStream: Background ambient telemetry stream / digital rain
 * 3. KineticScramble: Cyber glyph text reveal animation
 * 4. HudCrosshair: Subtle analyst coordinate cursor tracker
 * 5. BeamSweep: Interactive card border spotlight / hover beam
 */
'use strict';

window.SOCNeonVisuals = (() => {

  /* ═══════════════════════════════════════════════════════════════════════════
     1. ASCII / CANVAS THREAT RADAR (Originkit ascii-radar inspired)
     ═══════════════════════════════════════════════════════════════════════════ */
  class ThreatRadar {
    constructor(canvasId, options = {}) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;
      this.ctx = this.canvas.getContext('2d');
      this.options = Object.assign({
        speed: 0.025,
        beamColor: 'rgba(201, 165, 90, 0.75)',     // Amber candle gold
        trailColor: 'rgba(201, 165, 90, 0.08)',
        gridColor: 'rgba(42, 37, 69, 0.85)',
        textColor: '#6b6490',
        interactive: true
      }, options);

      this.angle = 0;
      this.blips = [];
      this.hoveredBlip = null;
      this.animationId = null;
      this.active = true;

      this.init();
    }

    init() {
      this.resize();
      window.addEventListener('resize', () => this.resize());

      if (this.options.interactive) {
        this.canvas.addEventListener('mousemove', e => this.handleMouseMove(e));
        this.canvas.addEventListener('mouseleave', () => { this.hoveredBlip = null; });
        this.canvas.addEventListener('click', () => {
          if (this.hoveredBlip && this.hoveredBlip.onClick) {
            this.hoveredBlip.onClick(this.hoveredBlip);
          }
        });
      }

      this.start();
    }

    resize() {
      if (!this.canvas) return;
      const rect = this.canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.w = rect.width;
      this.h = rect.height;
      this.canvas.width = this.w * dpr;
      this.canvas.height = this.h * dpr;
      this.ctx.scale(dpr, dpr);
      this.cx = this.w / 2;
      this.cy = this.h / 2;
      this.radius = Math.min(this.cx, this.cy) - 20;
    }

    setFindings(findings) {
      // Convert security findings to radar blips plotted by severity & hash
      if (!findings || !findings.length) {
        // Generate a few ambient surveillance points
        this.blips = [
          { r: 0.35, theta: 0.8, sev: 'low', label: '192.168.1.1', rule: 'DNS-LOOKUP', ping: 0 },
          { r: 0.65, theta: 2.4, sev: 'info', label: 'Internal Gateway', rule: 'HEARTBEAT', ping: 0 },
          { r: 0.85, theta: 4.1, sev: 'medium', label: 'External Node', rule: 'ROUTING', ping: 0 }
        ];
        return;
      }

      const sevWeights = { critical: 0.28, high: 0.48, medium: 0.68, low: 0.82, info: 0.92 };
      const sevColors = {
        critical: '#c9504a',
        high:     '#c47c2e',
        medium:   '#a8943c',
        low:      '#6aaa89',
        info:     '#7a75a0'
      };

      this.blips = findings.slice(0, 36).map((f, i) => {
        // deterministic pseudo-random theta based on finding id
        let hash = 0;
        const idStr = String(f.id || f.title || i);
        for (let j = 0; j < idStr.length; j++) hash = (hash * 31 + idStr.charCodeAt(j)) & 0xffffffff;
        const theta = Math.abs(hash % 628) / 100;
        const baseR = sevWeights[f.severity] || 0.6;
        const jitter = ((Math.abs(hash >> 3) % 20) - 10) / 100;
        const r = Math.max(0.18, Math.min(0.92, baseR + jitter));

        return {
          r,
          theta,
          sev: f.severity,
          color: sevColors[f.severity] || '#c9a55a',
          label: f.event?.src_ip || f.event?.username || f.event?.process || f.ruleId,
          title: f.title,
          confidence: f.confidence,
          ping: 0,
          rawFinding: f,
          onClick: (b) => {
            // Highlight alert or filter in dashboard
            if (typeof window.SOCNeonFilterByFinding === 'function') {
              window.SOCNeonFilterByFinding(b.rawFinding);
            }
          }
        };
      });
    }

    handleMouseMove(e) {
      const rect = this.canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      let found = null;
      for (const b of this.blips) {
        const bx = this.cx + Math.cos(b.theta) * (this.radius * b.r);
        const by = this.cy + Math.sin(b.theta) * (this.radius * b.r);
        const dist = Math.hypot(x - bx, y - by);
        if (dist < 12) {
          found = Object.assign({}, b, { x: bx, y: by });
          break;
        }
      }
      this.hoveredBlip = found;
      this.canvas.style.cursor = found ? 'pointer' : 'default';
    }

    start() {
      const loop = () => {
        if (!this.active) return;
        this.render();
        this.animationId = requestAnimationFrame(loop);
      };
      this.animationId = requestAnimationFrame(loop);
    }

    stop() {
      this.active = false;
      if (this.animationId) cancelAnimationFrame(this.animationId);
    }

    render() {
      const ctx = this.ctx;
      if (!ctx || this.w <= 0 || this.h <= 0) return;

      // Dark background
      ctx.fillStyle = 'rgba(9, 7, 26, 0.28)';
      ctx.fillRect(0, 0, this.w, this.h);

      const cx = this.cx, cy = this.cy, R = this.radius;

      // ── Radar Rings ──
      ctx.lineWidth = 1;
      ctx.strokeStyle = this.options.gridColor;

      [0.25, 0.5, 0.75, 1.0].forEach((ratio, idx) => {
        ctx.beginPath();
        ctx.arc(cx, cy, R * ratio, 0, Math.PI * 2);
        ctx.stroke();

        // Range markings
        ctx.fillStyle = this.options.textColor;
        ctx.font = '9px JetBrains Mono, monospace';
        ctx.textAlign = 'left';
        ctx.fillText(`${(ratio * 100).toFixed(0)}%`, cx + 4, cy - R * ratio + 10);
      });

      // ── Crosshair grid lines ──
      ctx.beginPath();
      ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy);
      ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R);
      ctx.stroke();

      // Cardinal labels (HUD style)
      ctx.fillStyle = '#6b6490';
      ctx.font = '9px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText('000° SEC', cx, cy - R - 6);
      ctx.fillText('180° PER', cx, cy + R + 14);
      ctx.fillText('270° INT', cx - R - 16, cy + 3);
      ctx.fillText('090° EXT', cx + R + 16, cy + 3);

      // ── Sweep Beam ──
      this.angle = (this.angle + this.options.speed) % (Math.PI * 2);

      // Trailing gradient wedge
      const trailAngle = 0.55;
      const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, R);
      grad.addColorStop(0, 'rgba(201, 165, 90, 0.2)');
      grad.addColorStop(1, 'rgba(201, 165, 90, 0.01)');

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, R, this.angle - trailAngle, this.angle, false);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.restore();

      // Main sweep vector line
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(this.angle) * R, cy + Math.sin(this.angle) * R);
      ctx.strokeStyle = this.options.beamColor;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // ── Render Blips ──
      const now = performance.now();
      for (const b of this.blips) {
        const bx = cx + Math.cos(b.theta) * (R * b.r);
        const by = cy + Math.sin(b.theta) * (R * b.r);

        // Check if radar beam just crossed this blip
        let diff = (this.angle - b.theta) % (Math.PI * 2);
        if (diff < 0) diff += Math.PI * 2;
        if (diff < 0.15) b.ping = now; // trigger illuminated ping

        const timeSincePing = (now - b.ping) / 1000;
        let brightness = 0.35;
        if (timeSincePing < 1.8) {
          brightness = Math.max(0.35, 1 - (timeSincePing / 1.8));
          // expanding pulse ring
          const pulseR = (timeSincePing * 16);
          ctx.beginPath();
          ctx.arc(bx, by, pulseR, 0, Math.PI * 2);
          ctx.strokeStyle = b.color;
          ctx.globalAlpha = Math.max(0, 0.6 - timeSincePing * 0.3);
          ctx.lineWidth = 1;
          ctx.stroke();
          ctx.globalAlpha = 1.0;
        }

        // Draw blip core
        ctx.beginPath();
        ctx.arc(bx, by, b.sev === 'critical' ? 4.5 : 3.5, 0, Math.PI * 2);
        ctx.fillStyle = b.color;
        ctx.globalAlpha = brightness;
        ctx.fill();

        // Inner glowing dot
        ctx.beginPath();
        ctx.arc(bx, by, 1.5, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.fill();
        ctx.globalAlpha = 1.0;
      }

      // ── Hovered Tooltip HUD ──
      if (this.hoveredBlip) {
        const hb = this.hoveredBlip;
        ctx.save();
        ctx.fillStyle = 'rgba(16, 13, 34, 0.95)';
        ctx.strokeStyle = hb.color;
        ctx.lineWidth = 1;

        const pad = 8;
        const text1 = `[${hb.sev.toUpperCase()}] ${hb.label || 'Unknown'}`;
        const text2 = hb.title ? hb.title.slice(0, 36) : '';
        ctx.font = '10px JetBrains Mono, monospace';
        const w1 = ctx.measureText(text1).width;
        const w2 = ctx.measureText(text2).width;
        const boxW = Math.max(w1, w2) + pad * 2;
        const boxH = text2 ? 34 : 20;

        let tx = hb.x + 12;
        let ty = hb.y - 12;
        if (tx + boxW > this.w) tx = hb.x - boxW - 12;
        if (ty - boxH < 0) ty = hb.y + 20;

        ctx.fillRect(tx, ty - boxH, boxW, boxH);
        ctx.strokeRect(tx, ty - boxH, boxW, boxH);

        ctx.fillStyle = hb.color;
        ctx.fillText(text1, tx + pad, ty - boxH + 13);
        if (text2) {
          ctx.fillStyle = '#b8b0d0';
          ctx.fillText(text2, tx + pad, ty - boxH + 26);
        }
        ctx.restore();
      }
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     2. ASCII RAIN / BACKGROUND TELEMETRY (Originkit ascii-rain inspired)
     ═══════════════════════════════════════════════════════════════════════════ */
  class AsciiTelemetryStream {
    constructor(canvasId) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;
      this.ctx = this.canvas.getContext('2d');
      this.chars = '0123456789ABCDEF!@#$%^&*<>/:;{}[]|~+=—';
      this.columns = [];
      this.fontSize = 13;
      this.active = true;
      this.init();
    }

    init() {
      this.resize();
      window.addEventListener('resize', () => this.resize());
      this.loop();
    }

    resize() {
      if (!this.canvas) return;
      const rect = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.w = rect.width;
      this.h = rect.height;
      this.canvas.width = this.w * dpr;
      this.canvas.height = this.h * dpr;
      this.ctx.scale(dpr, dpr);

      const colCount = Math.floor(this.w / this.fontSize);
      this.columns = [];
      for (let i = 0; i < colCount; i++) {
        this.columns.push({
          y: Math.random() * -100,
          speed: 0.6 + Math.random() * 1.4,
          opacity: 0.08 + Math.random() * 0.18
        });
      }
    }

    loop() {
      if (!this.active) return;
      const ctx = this.ctx;
      ctx.fillStyle = 'rgba(9, 7, 26, 0.14)';
      ctx.fillRect(0, 0, this.w, this.h);

      ctx.font = `${this.fontSize}px JetBrains Mono, monospace`;
      for (let i = 0; i < this.columns.length; i++) {
        const col = this.columns[i];
        const char = this.chars[Math.floor(Math.random() * this.chars.length)];
        const x = i * this.fontSize;

        // Occasional golden glimmer, mostly subtle deep violet
        const isGold = Math.random() < 0.04;
        ctx.fillStyle = isGold ? `rgba(201, 165, 90, ${col.opacity * 2.5})` : `rgba(139, 111, 212, ${col.opacity})`;
        ctx.fillText(char, x, col.y);

        col.y += col.speed * this.fontSize;
        if (col.y > this.h + 50) {
          col.y = Math.random() * -60;
          col.speed = 0.6 + Math.random() * 1.4;
        }
      }
      requestAnimationFrame(() => this.loop());
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     3. KINETIC TEXT SCRAMBLE (Originkit appear-text / block-text inspired)
     ═══════════════════════════════════════════════════════════════════════════ */
  class KineticScramble {
    static scramble(element, finalString, duration = 800) {
      if (!element) return;
      const glyphs = 'ABCDEF0123456789!<>-_\\/[]{}—=+*^?#';
      const fps = 30;
      const totalFrames = Math.round((duration / 1000) * fps);
      let frame = 0;
      const target = finalString || element.getAttribute('data-scramble') || element.textContent;

      const timer = setInterval(() => {
        frame++;
        const progress = frame / totalFrames;
        const revealedChars = Math.floor(progress * target.length);

        let output = '';
        for (let i = 0; i < target.length; i++) {
          if (target[i] === ' ') {
            output += ' ';
          } else if (i < revealedChars) {
            output += target[i];
          } else {
            output += glyphs[Math.floor(Math.random() * glyphs.length)];
          }
        }
        element.textContent = output;

        if (frame >= totalFrames) {
          clearInterval(timer);
          element.textContent = target;
        }
      }, 1000 / fps);
    }

    static attachAll(selector = '[data-scramble-hover]') {
      document.querySelectorAll(selector).forEach(el => {
        el.addEventListener('mouseenter', () => {
          KineticScramble.scramble(el, el.getAttribute('data-scramble') || el.textContent, 500);
        });
      });
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     4. HUD ANALYST CROSSHAIR (Originkit axis-cursor inspired)
     ═══════════════════════════════════════════════════════════════════════════ */
  class HudCrosshair {
    constructor() {
      this.el = document.createElement('div');
      this.el.className = 'hud-crosshair';
      this.el.innerHTML = '<span class="hud-coords">SEC-HUD: 000,000</span>';
      document.body.appendChild(this.el);

      this.coordText = this.el.querySelector('.hud-coords');
      this.visible = false;

      window.addEventListener('mousemove', e => {
        this.el.style.transform = `translate3d(${e.clientX + 14}px, ${e.clientY + 14}px, 0)`;
        if (this.coordText) {
          this.coordText.textContent = `HEX:${e.clientX.toString(16).toUpperCase()}:${e.clientY.toString(16).toUpperCase()} · UTC`;
        }
      });

      // Show only when hovering interactive analyst visualizer zones
      document.addEventListener('mouseover', e => {
        if (e.target.closest('.interactive-hud-zone, .drop-zone, .radar-container, .stat-card')) {
          this.el.classList.add('active');
        } else {
          this.el.classList.remove('active');
        }
      });
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     5. BEAM SWEEP SPOTLIGHT (Originkit beam-sweep inspired)
     ═══════════════════════════════════════════════════════════════════════════ */
  function initBeamSweeps() {
    document.querySelectorAll('.beam-card, .feat-card, .drop-zone').forEach(card => {
      card.addEventListener('mousemove', e => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        card.style.setProperty('--mouse-x', `${x}px`);
        card.style.setProperty('--mouse-y', `${y}px`);
      });
    });
  }

  return {
    ThreatRadar,
    AsciiTelemetryStream,
    KineticScramble,
    HudCrosshair,
    initBeamSweeps
  };
})();
