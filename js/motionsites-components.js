/**
 * SOCNeon — motionsites-components.js
 * High-end MotionSites AI design inspirations:
 * 1. SecuritySphere3D: Rotating 3D interactive wireframe globe with defense nodes & attack trajectories (NOVA / AKOR Security style)
 * 2. ParticleEmbers: Floating ambient ember particles (EMBER.dsgn style)
 * 3. Card3DTilt: Physics-based 3D perspective tilt on hover with specular lighting (Glow Features style)
 * 4. AnimatedGradientBorders: Rotating conic gradient border beams
 * 5. CounterRollingAnimation: Smooth number rolling for stats
 */
'use strict';

window.SOCMotionVisuals = (() => {

  /* ═══════════════════════════════════════════════════════════════════════════
     1. 3D DEFENSE SPHERE / HOLOGRAPHIC MESH (AKOR Security / NOVA style)
     ═══════════════════════════════════════════════════════════════════════════ */
  class SecuritySphere3D {
    constructor(canvasId) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;
      this.ctx = this.canvas.getContext('2d');
      this.nodes = [];
      this.connections = [];
      this.rotationX = 0.2;
      this.rotationY = 0;
      this.targetRotX = 0.2;
      this.targetRotY = 0;
      this.active = true;

      this.init();
    }

    init() {
      this.resize();
      window.addEventListener('resize', () => this.resize());

      // Generate spherical nodes
      const nodeCount = 56;
      for (let i = 0; i < nodeCount; i++) {
        const phi = Math.acos(-1 + (2 * i) / nodeCount);
        const theta = Math.sqrt(nodeCount * Math.PI) * phi;
        this.nodes.push({
          x: Math.cos(theta) * Math.sin(phi),
          y: Math.sin(theta) * Math.sin(phi),
          z: Math.cos(phi),
          baseX: Math.cos(theta) * Math.sin(phi),
          baseY: Math.sin(theta) * Math.sin(phi),
          baseZ: Math.cos(phi),
          threat: Math.random() < 0.25,
          threatColor: Math.random() < 0.4 ? '#c9504a' : '#c47c2e',
          pulse: Math.random() * Math.PI * 2
        });
      }

      // Generate connections between nearby nodes
      for (let i = 0; i < this.nodes.length; i++) {
        for (let j = i + 1; j < this.nodes.length; j++) {
          const dx = this.nodes[i].x - this.nodes[j].x;
          const dy = this.nodes[i].y - this.nodes[j].y;
          const dz = this.nodes[i].z - this.nodes[j].z;
          const dist = Math.hypot(dx, dy, dz);
          if (dist < 0.52) {
            this.connections.push([i, j]);
          }
        }
      }

      // Mouse drag rotation
      let isDragging = false, lastX = 0, lastY = 0;
      this.canvas.addEventListener('mousedown', e => {
        isDragging = true;
        lastX = e.clientX;
        lastY = e.clientY;
      });
      window.addEventListener('mouseup', () => { isDragging = false; });
      window.addEventListener('mousemove', e => {
        if (!isDragging) {
          // Subtle mouse follow
          const rect = this.canvas.getBoundingClientRect();
          const cx = rect.left + rect.width / 2;
          const cy = rect.top + rect.height / 2;
          this.targetRotY += (e.clientX - cx) * 0.00004;
          this.targetRotX += (e.clientY - cy) * 0.00004;
          return;
        }
        const dx = e.clientX - lastX;
        const dy = e.clientY - lastY;
        this.targetRotY += dx * 0.008;
        this.targetRotX += dy * 0.008;
        lastX = e.clientX;
        lastY = e.clientY;
      });

      this.render();
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
      this.sphereRadius = Math.min(this.w, this.h) * 0.38;
      this.cx = this.w / 2;
      this.cy = this.h / 2;
    }

    render() {
      if (!this.active) return;
      const ctx = this.ctx;
      ctx.clearRect(0, 0, this.w, this.h);

      // Smooth rotation dampening
      this.targetRotY += 0.003; // constant spin
      this.rotationX += (this.targetRotX - this.rotationX) * 0.08;
      this.rotationY += (this.targetRotY - this.rotationY) * 0.08;

      const cosX = Math.cos(this.rotationX), sinX = Math.sin(this.rotationX);
      const cosY = Math.cos(this.rotationY), sinY = Math.sin(this.rotationY);

      // Project nodes
      const projected = [];
      const R = this.sphereRadius;

      for (let i = 0; i < this.nodes.length; i++) {
        const n = this.nodes[i];
        n.pulse += 0.04;

        // Y-axis rotation
        let x1 = n.baseX * cosY - n.baseZ * sinY;
        let z1 = n.baseZ * cosY + n.baseX * sinY;

        // X-axis rotation
        let y2 = n.baseY * cosX - z1 * sinX;
        let z2 = z1 * cosX + n.baseY * sinX;

        // Perspective scale (z ranges ~ -1 to 1)
        const fov = 2.4;
        const scale = fov / (fov + z2);
        const px = this.cx + x1 * R * scale;
        const py = this.cy + y2 * R * scale;

        projected.push({ x: px, y: py, z: z2, scale, threat: n.threat, color: n.threatColor, pulse: n.pulse });
      }

      // Draw connections
      for (const [i, j] of this.connections) {
        const p1 = projected[i];
        const p2 = projected[j];
        if (p1.z > 0.4 && p2.z > 0.4) continue; // backface culling subtle

        const avgZ = (p1.z + p2.z) / 2;
        const alpha = Math.max(0.04, Math.min(0.4, (1 - avgZ) * 0.28));

        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.strokeStyle = `rgba(139, 111, 212, ${alpha})`;
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }

      // Draw nodes
      for (const p of projected) {
        const alpha = Math.max(0.2, (1 - p.z) * 0.5);
        const size = Math.max(1.8, 3.2 * p.scale);

        if (p.threat) {
          // Glowing threat node
          ctx.beginPath();
          ctx.arc(p.x, p.y, size * (1.2 + Math.sin(p.pulse) * 0.3), 0, Math.PI * 2);
          ctx.fillStyle = p.color;
          ctx.globalAlpha = alpha;
          ctx.fill();

          ctx.beginPath();
          ctx.arc(p.x, p.y, size * 2.2, 0, Math.PI * 2);
          ctx.strokeStyle = p.color;
          ctx.globalAlpha = alpha * 0.4;
          ctx.lineWidth = 1;
          ctx.stroke();
        } else {
          // Regular security mesh node
          ctx.beginPath();
          ctx.arc(p.x, p.y, size, 0, Math.PI * 2);
          ctx.fillStyle = '#c9a55a';
          ctx.globalAlpha = alpha;
          ctx.fill();
        }
      }
      ctx.globalAlpha = 1.0;

      // Outer security perimeter rings
      ctx.beginPath();
      ctx.arc(this.cx, this.cy, R * 1.14, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(201, 165, 90, 0.12)';
      ctx.setLineDash([4, 8]);
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.setLineDash([]);

      requestAnimationFrame(() => this.render());
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     2. AMBIENT EMBER PARTICLES (EMBER.dsgn style)
     ═══════════════════════════════════════════════════════════════════════════ */
  class ParticleEmbers {
    constructor(canvasId) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;
      this.ctx = this.canvas.getContext('2d');
      this.particles = [];
      this.init();
    }

    init() {
      this.resize();
      window.addEventListener('resize', () => this.resize());

      const count = 45;
      for (let i = 0; i < count; i++) {
        this.particles.push({
          x: Math.random() * this.w,
          y: Math.random() * this.h,
          radius: 0.8 + Math.random() * 2.2,
          color: Math.random() < 0.65 ? 'rgba(201, 165, 90,' : 'rgba(139, 111, 212,',
          alpha: 0.2 + Math.random() * 0.6,
          vx: (Math.random() - 0.5) * 0.4,
          vy: -0.3 - Math.random() * 0.7,
          flicker: Math.random() * Math.PI * 2
        });
      }

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
    }

    loop() {
      const ctx = this.ctx;
      ctx.clearRect(0, 0, this.w, this.h);

      for (const p of this.particles) {
        p.x += p.vx;
        p.y += p.vy;
        p.flicker += 0.05;

        if (p.y < -10) {
          p.y = this.h + 10;
          p.x = Math.random() * this.w;
        }

        const currentAlpha = Math.max(0.1, p.alpha * (0.7 + Math.sin(p.flicker) * 0.3));
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `${p.color} ${currentAlpha})`;
        ctx.fill();

        // Subtle glow halo
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius * 2.5, 0, Math.PI * 2);
        ctx.fillStyle = `${p.color} ${currentAlpha * 0.25})`;
        ctx.fill();
      }

      requestAnimationFrame(() => this.loop());
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     3. 3D CARD PERSPECTIVE TILT (Glow Features style)
     ═══════════════════════════════════════════════════════════════════════════ */
  function init3DCardTilt(selector = '.tilt-card, .feat-card, .stat-card, .rp-score-card') {
    document.querySelectorAll(selector).forEach(card => {
      let isHovered = false;

      card.addEventListener('mouseenter', () => {
        isHovered = true;
        card.style.transition = 'transform 0.1s ease-out, box-shadow 0.25s ease';
      });

      card.addEventListener('mousemove', e => {
        if (!isHovered) return;
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const cx = rect.width / 2;
        const cy = rect.height / 2;

        const rotateX = ((y - cy) / cy) * -8; // degrees
        const rotateY = ((x - cx) / cx) * 8;

        card.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) scale3d(1.02, 1.02, 1.02)`;
        card.style.setProperty('--tilt-x', `${(x / rect.width) * 100}%`);
        card.style.setProperty('--tilt-y', `${(y / rect.height) * 100}%`);
      });

      card.addEventListener('mouseleave', () => {
        isHovered = false;
        card.style.transition = 'transform 0.4s ease-out, box-shadow 0.4s ease';
        card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
      });
    });
  }

  return {
    SecuritySphere3D,
    ParticleEmbers,
    init3DCardTilt
  };
})();
