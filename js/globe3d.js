// ─── SOCNeon 3D Interactive Cyber Globe & Mesh ───────────────────────────
(function () {
  'use strict';

  var container = document.getElementById('globe-3d-container');
  if (!container || typeof THREE === 'undefined') return;

  var scene, camera, renderer, globeGroup;
  var spherePoints, wireSphere, ringGroup;
  var raycaster, mouse, INTERSECTED;
  var mouseX = 0, mouseY = 0;
  var targetRotationX = 0, targetRotationY = 0;
  var isMouseDown = false, prevMouseX = 0, prevMouseY = 0;
  var nodes = [];
  var arcs = [];
  var animId;

  var width = container.clientWidth || 400;
  var height = container.clientHeight || 400;

  function init() {
    scene = new THREE.Scene();

    camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 240;

    renderer = new THREE.WebGLRenderer({
      canvas: document.getElementById('globe-3d-canvas'),
      alpha: true,
      antialias: true
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(width, height);

    globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // 1. Inner glowing core
    var coreGeo = new THREE.SphereGeometry(62, 32, 32);
    var coreMat = new THREE.MeshBasicMaterial({
      color: 0x07111e,
      transparent: true,
      opacity: 0.85
    });
    var core = new THREE.Mesh(coreGeo, coreMat);
    globeGroup.add(core);

    // 2. Wireframe / latitude longitude grid
    var wireGeo = new THREE.SphereGeometry(65, 24, 24);
    var wireMat = new THREE.MeshBasicMaterial({
      color: 0x00e5ff,
      wireframe: true,
      transparent: true,
      opacity: 0.12
    });
    wireSphere = new THREE.Mesh(wireGeo, wireMat);
    globeGroup.add(wireSphere);

    // 3. Dot matrix sphere surface
    var pointCount = 1200;
    var pointGeo = new THREE.BufferGeometry();
    var positions = new Float32Array(pointCount * 3);
    var colors = new Float32Array(pointCount * 3);
    var radius = 66;

    for (var i = 0; i < pointCount; i++) {
      var phi = Math.acos(-1 + (2 * i) / pointCount);
      var theta = Math.sqrt(pointCount * Math.PI) * phi;

      var x = radius * Math.cos(theta) * Math.sin(phi);
      var y = radius * Math.sin(theta) * Math.sin(phi);
      var z = radius * Math.cos(phi);

      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;

      // Color variation between cyan and neon violet
      if (Math.random() > 0.3) {
        colors[i * 3] = 0.0;
        colors[i * 3 + 1] = 0.898;
        colors[i * 3 + 2] = 1.0;
      } else {
        colors[i * 3] = 0.482;
        colors[i * 3 + 1] = 0.184;
        colors[i * 3 + 2] = 1.0;
      }
    }

    pointGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    pointGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    var pointMat = new THREE.PointsMaterial({
      size: 1.8,
      vertexColors: true,
      transparent: true,
      opacity: 0.65
    });

    spherePoints = new THREE.Points(pointGeo, pointMat);
    globeGroup.add(spherePoints);

    // 4. Interactive Threat Alert Nodes on Globe
    var threatSites = [
      { name: 'US-East (SIEM Primary)', lat: 38.9, lon: -77.0, sev: 'critical', color: 0xff3860 },
      { name: 'Frankfurt (IDS Node)', lat: 50.1, lon: 8.6, sev: 'high', color: 0xff7f00 },
      { name: 'Tokyo (Edge Sensor)', lat: 35.6, lon: 139.6, sev: 'medium', color: 0xffd700 },
      { name: 'Sydney (WAF Cluster)', lat: -33.8, lon: 151.2, sev: 'low', color: 0x00e5ff },
      { name: 'São Paulo (Log Collector)', lat: -23.5, lon: -46.6, sev: 'high', color: 0xff7f00 },
      { name: 'Singapore (Proxy Relay)', lat: 1.35, lon: 103.8, sev: 'critical', color: 0xff3860 },
      { name: 'London (Core Gateway)', lat: 51.5, lon: -0.12, sev: 'info', color: 0x00ff9d }
    ];

    threatSites.forEach(function (site) {
      var coords = latLonToVector3(site.lat, site.lon, 66.5);
      var nodeGeo = new THREE.SphereGeometry(2.4, 16, 16);
      var nodeMat = new THREE.MeshBasicMaterial({
        color: site.color,
        transparent: true,
        opacity: 0.95
      });
      var nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
      nodeMesh.position.copy(coords);
      nodeMesh.userData = site;
      globeGroup.add(nodeMesh);
      nodes.push(nodeMesh);

      // Pulsing beacon ring around each node
      var beaconGeo = new THREE.RingGeometry(2.8, 3.8, 32);
      var beaconMat = new THREE.MeshBasicMaterial({
        color: site.color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.7
      });
      var beacon = new THREE.Mesh(beaconGeo, beaconMat);
      beacon.position.copy(coords);
      beacon.lookAt(new THREE.Vector3(0, 0, 0));
      beacon.userData = { initialScale: 1, maxScale: 2.5, speed: 0.03 };
      globeGroup.add(beacon);
      site.beacon = beacon;
    });

    // 5. Connect threat nodes with 3D Bezier Cyber Attack Arcs
    createArcs();

    // 6. Orbital HUD Rings
    ringGroup = new THREE.Group();
    var orbitRingGeo = new THREE.RingGeometry(85, 85.8, 64);
    var orbitRingMat = new THREE.MeshBasicMaterial({
      color: 0x00e5ff,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.25
    });
    var orbitRing = new THREE.Mesh(orbitRingGeo, orbitRingMat);
    orbitRing.rotation.x = Math.PI / 2.3;
    ringGroup.add(orbitRing);

    var orbitRing2 = new THREE.Mesh(
      new THREE.RingGeometry(100, 100.5, 64),
      new THREE.MeshBasicMaterial({
        color: 0x7b2fff,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.18
      })
    );
    orbitRing2.rotation.y = Math.PI / 3;
    orbitRing2.rotation.x = Math.PI / 4;
    ringGroup.add(orbitRing2);

    globeGroup.add(ringGroup);

    // Event Listeners
    setupInteractions();
    window.addEventListener('resize', onWindowResize);
  }

  function latLonToVector3(lat, lon, r) {
    var phi = (90 - lat) * (Math.PI / 180);
    var theta = (lon + 180) * (Math.PI / 180);
    return new THREE.Vector3(
      -(r * Math.sin(phi) * Math.cos(theta)),
      r * Math.cos(phi),
      r * Math.sin(phi) * Math.sin(theta)
    );
  }

  function createArcs() {
    if (nodes.length < 2) return;
    for (var i = 0; i < nodes.length - 1; i++) {
      var v1 = nodes[i].position;
      var v2 = nodes[i + 1].position;

      // Arc midpoint elevated from globe
      var mid = v1.clone().add(v2).multiplyScalar(0.5);
      var distance = v1.distanceTo(v2);
      mid.normalize().multiplyScalar(66 + distance * 0.25);

      var curve = new THREE.QuadraticBezierCurve3(v1, mid, v2);
      var points = curve.getPoints(50);
      var arcGeo = new THREE.BufferGeometry().setFromPoints(points);
      var arcMat = new THREE.LineBasicMaterial({
        color: i % 2 === 0 ? 0x00e5ff : 0xff3860,
        transparent: true,
        opacity: 0.45,
        linewidth: 1.5
      });
      var arcLine = new THREE.Line(arcGeo, arcMat);
      globeGroup.add(arcLine);
      arcs.push(arcLine);
    }
  }

  function setupInteractions() {
    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    var canvas = renderer.domElement;

    // Mouse drag to rotate
    canvas.addEventListener('mousedown', function (e) {
      isMouseDown = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    });

    window.addEventListener('mouseup', function () {
      isMouseDown = false;
    });

    window.addEventListener('mousemove', function (e) {
      var rect = canvas.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      if (isMouseDown) {
        var deltaX = e.clientX - prevMouseX;
        var deltaY = e.clientY - prevMouseY;
        targetRotationY += deltaX * 0.005;
        targetRotationX += deltaY * 0.005;
        prevMouseX = e.clientX;
        prevMouseY = e.clientY;
      }
    });

    // Touch support for mobile devices
    canvas.addEventListener('touchstart', function (e) {
      if (e.touches.length === 1) {
        isMouseDown = true;
        prevMouseX = e.touches[0].clientX;
        prevMouseY = e.touches[0].clientY;
      }
    }, { passive: true });

    window.addEventListener('touchend', function () {
      isMouseDown = false;
    });

    window.addEventListener('touchmove', function (e) {
      if (isMouseDown && e.touches.length === 1) {
        var deltaX = e.touches[0].clientX - prevMouseX;
        var deltaY = e.touches[0].clientY - prevMouseY;
        targetRotationY += deltaX * 0.007;
        targetRotationX += deltaY * 0.007;
        prevMouseX = e.touches[0].clientX;
        prevMouseY = e.touches[0].clientY;
      }
    }, { passive: true });

    // Hover tooltip for threat nodes
    var tooltip = document.getElementById('globe-tooltip');
    canvas.addEventListener('mousemove', function () {
      raycaster.setFromCamera(mouse, camera);
      var intersects = raycaster.intersectObjects(nodes);

      if (intersects.length > 0) {
        canvas.style.cursor = 'pointer';
        var obj = intersects[0].object;
        if (tooltip && obj.userData) {
          tooltip.style.display = 'block';
          tooltip.innerHTML = '<strong>' + obj.userData.name + '</strong><br>' +
            '<span style="color:' + (obj.userData.sev === 'critical' ? '#ff3860' : '#00e5ff') + '">' +
            '● Alert Level: ' + obj.userData.sev.toUpperCase() + '</span>';
          tooltip.style.left = (event.clientX + 12) + 'px';
          tooltip.style.top = (event.clientY + 12) + 'px';
        }
      } else {
        canvas.style.cursor = 'grab';
        if (tooltip) tooltip.style.display = 'none';
      }
    });
  }

  function onWindowResize() {
    if (!container) return;
    width = container.clientWidth || 400;
    height = container.clientHeight || 400;
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height);
  }

  function animate() {
    animId = requestAnimationFrame(animate);

    // Auto spin when not dragging
    if (!isMouseDown) {
      targetRotationY += 0.002;
    }

    // Smooth inertia interpolation
    globeGroup.rotation.y += (targetRotationY - globeGroup.rotation.y) * 0.08;
    globeGroup.rotation.x += (targetRotationX - globeGroup.rotation.x) * 0.08;

    // Counter-rotate HUD rings
    if (ringGroup) {
      ringGroup.rotation.z += 0.004;
    }

    // Pulse node beacons
    nodes.forEach(function (n) {
      if (n.userData && n.userData.beacon) {
        var b = n.userData.beacon;
        b.scale.x += 0.015;
        b.scale.y += 0.015;
        b.material.opacity = Math.max(0, 0.8 - (b.scale.x - 1) * 0.5);
        if (b.scale.x > 2.2) {
          b.scale.set(1, 1, 1);
          b.material.opacity = 0.8;
        }
      }
    });

    renderer.render(scene, camera);
  }

  // ─── Interactive 3D Card Tilt for Dropzone & Demo Cards ─────────────────────
  function setup3DCardTilt() {
    var cards = document.querySelectorAll('.tilt-3d-card, .drop-zone, .demo-btn');
    cards.forEach(function (card) {
      card.addEventListener('mousemove', function (e) {
        var rect = card.getBoundingClientRect();
        var x = e.clientX - rect.left;
        var y = e.clientY - rect.top;
        var centerX = rect.width / 2;
        var centerY = rect.height / 2;

        var rotateX = ((y - centerY) / centerY) * -12;
        var rotateY = ((x - centerX) / centerX) * 12;

        card.style.transform = 'perspective(1000px) rotateX(' + rotateX.toFixed(2) + 'deg) rotateY(' + rotateY.toFixed(2) + 'deg) scale3d(1.02, 1.02, 1.02)';
      });

      card.addEventListener('mouseleave', function () {
        card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
      });
    });
  }

  // Initialize
  init();
  animate();
  setup3DCardTilt();

})();
