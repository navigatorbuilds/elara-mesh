/* Elara — hero mesh animation. Vanilla canvas, no deps.
   Nodes drift; nearby nodes link; record-packets hop the mesh;
   a seal-wave periodically sweeps. Honors prefers-reduced-motion. */
(function () {
  "use strict";
  var canvas = document.getElementById("mesh");
  if (!canvas) return;
  var ctx = canvas.getContext("2d");
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var W = 0, H = 0, DPR = Math.min(window.devicePixelRatio || 1, 2);
  var nodes = [], packets = [], wave = null;
  var LINK_D = 150;

  function resize() {
    var r = canvas.getBoundingClientRect();
    W = r.width; H = r.height;
    canvas.width = W * DPR; canvas.height = H * DPR;
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    seed();
  }

  var mx = 0, my = 0, tmx = 0, tmy = 0; // mouse parallax (eased)

  function seed() {
    var count = Math.max(36, Math.min(110, Math.round((W * H) / 16000)));
    nodes = [];
    for (var i = 0; i < count; i++) {
      var z = 0.45 + Math.random(); // depth: far (small/slow/dim) → near (big/fast/bright)
      nodes.push({
        x: Math.random() * W, y: Math.random() * H,
        vx: (Math.random() - 0.5) * 0.16 * z, vy: (Math.random() - 0.5) * 0.16 * z,
        r: (0.9 + Math.random() * 1.5) * z,
        z: z
      });
    }
  }

  function neighbors(i) {
    var out = [], a = nodes[i];
    for (var j = 0; j < nodes.length; j++) {
      if (j === i) continue;
      var b = nodes[j], dx = a.x - b.x, dy = a.y - b.y;
      if (dx * dx + dy * dy < LINK_D * LINK_D) out.push(j);
    }
    return out;
  }

  function spawnPacket() {
    var i = (Math.random() * nodes.length) | 0;
    packets.push({ from: i, to: -1, t: 1, hops: 3 + ((Math.random() * 3) | 0) });
  }

  function step() {
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      n.x += n.vx; n.y += n.vy;
      if (n.x < -20) n.x = W + 20; if (n.x > W + 20) n.x = -20;
      if (n.y < -20) n.y = H + 20; if (n.y > H + 20) n.y = -20;
    }
    for (var p = packets.length - 1; p >= 0; p--) {
      var k = packets[p];
      if (k.t >= 1) {
        if (k.hops-- <= 0) { packets.splice(p, 1); continue; }
        var ns = neighbors(k.from);
        if (!ns.length) { packets.splice(p, 1); continue; }
        k.to = ns[(Math.random() * ns.length) | 0];
        k.t = 0;
      } else {
        k.t += 0.035;
        if (k.t >= 1) { k.from = k.to; }
      }
    }
    if (wave) {
      wave.r += 2.6;
      if (wave.r > wave.max) wave = null;
    }
  }

  function px(n) { return n.x + mx * 16 * (n.z - 0.95); }
  function py(n) { return n.y + my * 12 * (n.z - 0.95); }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    // eased parallax follow
    mx += (tmx - mx) * 0.04; my += (tmy - my) * 0.04;
    // links
    for (var i = 0; i < nodes.length; i++) {
      var a = nodes[i];
      for (var j = i + 1; j < nodes.length; j++) {
        var b = nodes[j];
        var dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
        if (d2 > LINK_D * LINK_D) continue;
        var d = Math.sqrt(d2);
        var depth = (a.z + b.z) / 2;
        var alpha = (1 - d / LINK_D) * 0.17 * depth;
        if (wave) {
          var wx = (a.x + b.x) / 2 - wave.x, wy = (a.y + b.y) / 2 - wave.y;
          var wd = Math.abs(Math.sqrt(wx * wx + wy * wy) - wave.r);
          if (wd < 40) alpha += (1 - wd / 40) * 0.4 * depth;
        }
        ctx.strokeStyle = "rgba(54,226,196," + alpha.toFixed(3) + ")";
        ctx.lineWidth = depth > 1.05 ? 1.2 : 0.8;
        ctx.beginPath(); ctx.moveTo(px(a), py(a)); ctx.lineTo(px(b), py(b)); ctx.stroke();
      }
    }
    // nodes (far dimmer, near brighter with halo)
    for (var q = 0; q < nodes.length; q++) {
      var n = nodes[q];
      var na = 0.28 + n.z * 0.3;
      ctx.fillStyle = "rgba(154,167,180," + na.toFixed(3) + ")";
      ctx.beginPath(); ctx.arc(px(n), py(n), n.r, 0, 6.2832); ctx.fill();
      if (n.z > 1.18) {
        ctx.fillStyle = "rgba(54,226,196,0.10)";
        ctx.beginPath(); ctx.arc(px(n), py(n), n.r * 3.4, 0, 6.2832); ctx.fill();
      }
    }
    // packets
    for (var p = 0; p < packets.length; p++) {
      var k = packets[p];
      if (k.to < 0) continue;
      var f = nodes[k.from], t = nodes[k.to];
      var x = px(f) + (px(t) - px(f)) * k.t, y = py(f) + (py(t) - py(f)) * k.t;
      var g = ctx.createRadialGradient(x, y, 0, x, y, 12);
      g.addColorStop(0, "rgba(54,226,196,0.9)");
      g.addColorStop(1, "rgba(54,226,196,0)");
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(x, y, 12, 0, 6.2832); ctx.fill();
      ctx.fillStyle = "#bdfff1";
      ctx.beginPath(); ctx.arc(x, y, 2.2, 0, 6.2832); ctx.fill();
    }
  }

  var pTimer = 0, wTimer = 0;
  function loop() {
    step(); draw();
    if (++pTimer > 95) { pTimer = 0; spawnPacket(); }
    if (++wTimer > 560) {
      wTimer = 0;
      var c = nodes[(Math.random() * nodes.length) | 0];
      wave = { x: c.x, y: c.y, r: 0, max: Math.max(W, H) * 0.55 };
    }
    requestAnimationFrame(loop);
  }

  window.addEventListener("resize", resize);
  window.addEventListener("pointermove", function (e) {
    tmx = (e.clientX / window.innerWidth - 0.5) * 2;
    tmy = (e.clientY / window.innerHeight - 0.5) * 2;
  }, { passive: true });
  resize();
  if (reduced) { spawnPacket(); step(); draw(); return; }
  spawnPacket(); spawnPacket();
  requestAnimationFrame(loop);
})();
