/* Elara — scroll reveal. Auto-tags key blocks, staggers siblings. No deps. */
(function () {
  "use strict";
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  var sel = [
    ".block h2", ".block .cols .col", ".step", ".paper", ".uc-card",
    ".status-lead", ".status-table", ".code", ".start-note",
    ".uc-text", ".uc-anim", ".stage-row", ".hero-strip div", ".page-head > *"
  ].join(",");
  var els = Array.prototype.slice.call(document.querySelectorAll(sel));
  var groups = new Map();
  els.forEach(function (el) {
    el.classList.add("rv");
    var p = el.parentElement;
    if (!groups.has(p)) groups.set(p, 0);
    var i = groups.get(p);
    el.style.transitionDelay = Math.min(i * 90, 450) + "ms";
    groups.set(p, i + 1);
  });
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) { e.target.classList.add("rv-in"); io.unobserve(e.target); }
    });
  }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
  els.forEach(function (el) { io.observe(el); });
})();
