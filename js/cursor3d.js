// ─── SOCNeon 3D Interactive Cyber Cursor & Kinetic Text (OriginKit/MotionSites) ───
(function () {
  'use strict';

  // Only enable custom 3D cursor on desktop pointers
  if (window.matchMedia('(pointer: coarse)').matches) return;

  var dot = document.createElement('div');
  dot.id = 'cyber-cursor-dot';
  document.body.appendChild(dot);

  var ring = document.createElement('div');
  ring.id = 'cyber-cursor-ring';
  document.body.appendChild(ring);

  var mouseX = -100, mouseY = -100;
  var ringX = -100, ringY = -100;
  var isHovered = false;

  window.addEventListener('mousemove', function (e) {
    mouseX = e.clientX;
    mouseY = e.clientY;
    dot.style.transform = 'translate3d(' + mouseX + 'px, ' + mouseY + 'px, 0)';
  });

  function renderCursor() {
    ringX += (mouseX - ringX) * 0.18;
    ringY += (mouseY - ringY) * 0.18;

    var scale = isHovered ? ' scale(1.6)' : ' scale(1)';
    ring.style.transform = 'translate3d(' + ringX + 'px, ' + ringY + 'px, 0)' + scale;

    requestAnimationFrame(renderCursor);
  }
  requestAnimationFrame(renderCursor);

  // Attach hover expand states to all interactive elements
  function attachHoverTargets() {
    var targets = document.querySelectorAll('button, a, input, select, textarea, .drop-zone, .tab-btn, .feature-pill, .demo-btn, .stat-card, [role="button"]');
    targets.forEach(function (el) {
      el.addEventListener('mouseenter', function () {
        isHovered = true;
        ring.classList.add('cursor-hover');
      });
      el.addEventListener('mouseleave', function () {
        isHovered = false;
        ring.classList.remove('cursor-hover');
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attachHoverTargets);
  } else {
    attachHoverTargets();
  }

  // Observer to re-attach hover on dynamically rendered tab panels
  var observer = new MutationObserver(function () {
    attachHoverTargets();
  });
  var main = document.querySelector('.app-main');
  if (main) {
    observer.observe(main, { childList: true, subtree: true });
  }

})();
