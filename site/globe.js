/* Elara — hero globe. A rotating point-sphere with traveling great-circle
   arcs. Vanilla canvas, no dependencies, honors prefers-reduced-motion. */
(function () {
  "use strict";
  var canvas = document.getElementById("globe");
  if (!canvas) return;
  var ctx = canvas.getContext("2d");
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var DPR = Math.min(window.devicePixelRatio || 1, 2);

  var W = 0, H = 0, CX = 0, CY = 0, R = 0;
  var rotY = 0, tilt = -0.32;
  var tmx = 0, mx = 0;

  /* ── geometry ── */
  var N = 950, pts = [];
  (function fib() {
    var ga = Math.PI * (3 - Math.sqrt(5));
    for (var i = 0; i < N; i++) {
      var y = 1 - (i / (N - 1)) * 2;
      var r = Math.sqrt(1 - y * y);
      var th = ga * i;
      pts.push([Math.cos(th) * r, y, Math.sin(th) * r]);
    }
  })();

  function rot(p, ry) {
    var x = p[0], y = p[1], z = p[2];
    var cy = Math.cos(ry), sy = Math.sin(ry);
    var x1 = x * cy - z * sy, z1 = x * sy + z * cy;
    var ct = Math.cos(tilt), st = Math.sin(tilt);
    var y2 = y * ct - z1 * st, z2 = y * st + z1 * ct;
    return [x1, y2, z2];
  }
  function proj(p) {
    var f = 2.4 / (2.4 + p[2]); // perspective
    return [CX + p[0] * R * f, CY + p[1] * R * f, f, p[2]];
  }

  /* ── arcs ── */
  function rndPt() { return pts[(Math.random() * pts.length) | 0]; }
  function slerp(a, b, t) {
    var d = a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
    d = Math.max(-1, Math.min(1, d));
    var om = Math.acos(d);
    if (om < 1e-4) return a.slice();
    var so = Math.sin(om);
    var ka = Math.sin((1 - t) * om) / so, kb = Math.sin(t * om) / so;
    return [a[0] * ka + b[0] * kb, a[1] * ka + b[1] * kb, a[2] * ka + b[2] * kb];
  }
  var arcs = [];
  function spawnArc() {
    var a = rndPt(), b = rndPt();
    var d = a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
    if (d > 0.55 || d < -0.92) return; // too close / antipodal = ugly
    arcs.push({ a: a, b: b, t: 0, v: 0.004 + Math.random() * 0.004, burst: 0 });
  }
  function arcPoint(arc, t) {
    var p = slerp(arc.a, arc.b, t);
    var lift = 1 + Math.sin(t * Math.PI) * 0.22;
    return [p[0] * lift, p[1] * lift, p[2] * lift];
  }

  /* ── render ── */
  function resize() {
    var rect = canvas.getBoundingClientRect();
    W = rect.width; H = rect.height;
    canvas.width = W * DPR; canvas.height = H * DPR;
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    CX = W * 0.5; CY = H * 0.5;
    R = Math.min(W, H) * 0.40;
  }

  function ring(lat) {
    ctx.beginPath();
    var first = true;
    for (var i = 0; i <= 90; i++) {
      var lon = (i / 90) * Math.PI * 2;
      var p = rot([Math.cos(lon) * Math.cos(lat), Math.sin(lat), Math.sin(lon) * Math.cos(lat)], rotY);
      var q = proj(p);
      if (p[2] > 0.25) { first = true; continue; } // hide far side
      if (first) { ctx.moveTo(q[0], q[1]); first = false; }
      else ctx.lineTo(q[0], q[1]);
    }
    ctx.stroke();
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    mx += (tmx - mx) * 0.03;
    var ry = rotY + mx * 0.5;

    // back glow
    var g = ctx.createRadialGradient(CX, CY, R * 0.1, CX, CY, R * 1.45);
    g.addColorStop(0, "rgba(54,226,196,0.075)");
    g.addColorStop(0.65, "rgba(79,157,255,0.035)");
    g.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, W, H);

    // latitude rings
    ctx.strokeStyle = "rgba(150,170,190,0.10)";
    ctx.lineWidth = 1;
    var save = rotY; rotY = ry;
    ring(0); ring(0.5); ring(-0.5); ring(1.0); ring(-1.0);
    rotY = save;

    // points
    for (var i = 0; i < pts.length; i++) {
      var p = rot(pts[i], ry), q = proj(p);
      var front = p[2] < 0;
      var a = front ? 0.22 + (-p[2]) * 0.6 : 0.05;
      var r = (front ? 1.15 : 0.7) * q[2];
      ctx.fillStyle = front
        ? "rgba(178,204,222," + a.toFixed(3) + ")"
        : "rgba(120,140,160," + a.toFixed(3) + ")";
      ctx.beginPath(); ctx.arc(q[0], q[1], r, 0, 6.2832); ctx.fill();
    }

    // arcs
    for (var k = arcs.length - 1; k >= 0; k--) {
      var arc = arcs[k];
      arc.t += arc.v;
      if (arc.t >= 1 && arc.burst === 0) arc.burst = 0.01;
      // trail
      var T0 = Math.max(0, arc.t - 0.30), T1 = Math.min(arc.t, 1);
      if (T1 > T0) {
        ctx.lineWidth = 1.6;
        var steps = 22;
        for (var s = 0; s < steps; s++) {
          var ta = T0 + ((T1 - T0) * s) / steps;
          var tb = T0 + ((T1 - T0) * (s + 1)) / steps;
          var pa = rot(arcPoint(arc, ta), ry), pb = rot(arcPoint(arc, tb), ry);
          if (pa[2] > 0.45 && pb[2] > 0.45) continue;
          var qa = proj(pa), qb = proj(pb);
          var fade = (s / steps) * 0.85;
          ctx.strokeStyle = "rgba(54,226,196," + (fade * 0.8).toFixed(3) + ")";
          ctx.beginPath(); ctx.moveTo(qa[0], qa[1]); ctx.lineTo(qb[0], qb[1]); ctx.stroke();
        }
        // head
        if (arc.t <= 1) {
          var hp = rot(arcPoint(arc, T1), ry);
          if (hp[2] < 0.45) {
            var hq = proj(hp);
            var hg = ctx.createRadialGradient(hq[0], hq[1], 0, hq[0], hq[1], 10);
            hg.addColorStop(0, "rgba(157,246,228,0.95)");
            hg.addColorStop(1, "rgba(54,226,196,0)");
            ctx.fillStyle = hg;
            ctx.beginPath(); ctx.arc(hq[0], hq[1], 10, 0, 6.2832); ctx.fill();
            ctx.fillStyle = "#d9fff6";
            ctx.beginPath(); ctx.arc(hq[0], hq[1], 1.9, 0, 6.2832); ctx.fill();
          }
        }
      }
      // arrival burst
      if (arc.burst > 0) {
        arc.burst += 0.05;
        var bp = rot(arc.b, ry);
        if (bp[2] < 0.45) {
          var bq = proj(bp);
          ctx.strokeStyle = "rgba(54,226,196," + (Math.max(0, 1 - arc.burst) * 0.7).toFixed(3) + ")";
          ctx.lineWidth = 1.4;
          ctx.beginPath(); ctx.arc(bq[0], bq[1], arc.burst * 16, 0, 6.2832); ctx.stroke();
        }
        if (arc.burst >= 1) arcs.splice(k, 1);
      }
    }

    // rim light
    ctx.strokeStyle = "rgba(54,226,196,0.10)";
    ctx.lineWidth = 1.2;
    ctx.beginPath(); ctx.arc(CX, CY, R * 1.005, 0, 6.2832); ctx.stroke();
  }

  var spawnT = 0;
  function loop() {
    rotY += 0.0016;
    if (++spawnT > 70) { spawnT = 0; if (arcs.length < 7) spawnArc(); }
    draw();
    requestAnimationFrame(loop);
  }

  window.addEventListener("resize", resize);
  window.addEventListener("pointermove", function (e) {
    tmx = (e.clientX / window.innerWidth - 0.5) * 2;
  }, { passive: true });

  resize();
  spawnArc(); spawnArc(); spawnArc();
  if (reduced) { draw(); return; }
  requestAnimationFrame(loop);
})();
