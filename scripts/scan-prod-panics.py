#!/usr/bin/env python3
"""Measure the *production* panic surface of src/ + crates/ — the real Lane-2 metric.

A naive `grep -c unwrap src/` reports ~8000 hits and is useless: the
overwhelming majority are inside `#[cfg(test)]` modules. This tool excludes
test code with a Rust-aware mini-lexer (line/block comments, string, raw-string
and char literals all carried correctly across lines) and reports only the
panic points that can actually abort a running node:

  * non-lock  .unwrap() / .expect()      — the Byzantine-record crash class
  * lock      .read()/.write()/.lock().unwrap()  — std-lock poison cascade
  * panic! / unreachable! / todo! / unimplemented!

NOT covered (a separate, harder audit): slice indexing `b[i]`, arithmetic
overflow, division by zero. Those are the genuine remaining hot-path surface
once explicit panics hit zero — `from_wire_bytes`-style decoders must keep
their `data.len() < N` guards.

Self-validation: the scanner first asserts a baseline set of hot-path files
that are KNOWN to contain zero production non-lock unwraps. If the parser ever
regresses (e.g. a new multi-line-literal shape desyncs brace counting), the
baseline trips and the run aborts rather than reporting a false zero.

Usage:
  scripts/scan-prod-panics.py                 # report the full surface
  scripts/scan-prod-panics.py --check         # exit 1 if surface is non-empty
  scripts/scan-prod-panics.py --locks         # also list production lock-unwraps
  scripts/scan-prod-panics.py --show FILE     # dump every hit + line in one file
"""
import os
import re
import sys
import glob

# 2026-07-18 (audit robustness rec): `.unwrap_err()`/`.expect_err()` added —
# the inverse-unwrap panics on Ok exactly like unwrap panics on Err; the
# production surface was verified 0 at the time, so the gate extends green.
HIT = re.compile(r"\.unwrap\(\)|\.expect\(|\.unwrap_err\(\)|\.expect_err\(")
LOCK = re.compile(r"\.(read|write|lock)\(\)\.(unwrap|expect)\(")
PANIC = re.compile(r"\bpanic!|\bunreachable!|\btodo!|\bunimplemented!")
# matches #[cfg(test)] and #[cfg(all(test, ...))] / #[cfg(any(test, ...))]
CFGTEST = re.compile(r"^\s*#\[cfg\([^]]*\btest\b")
# A separate-FILE test module — `#[cfg(test)] mod NAME;` (trailing ';', no
# inline `{ ... }` block). scan()'s brace tracker only catches INLINE
# `#[cfg(test)] mod tests { ... }`; without resolving these declarations to
# their child files, the WHOLE contents of a lifted `tests.rs` count as
# production code — exactly what the god-file → mod-dir split produced
# (explorer.rs's inline `mod tests` became explorer/tests.rs, declared
# `#[cfg(test)] mod tests;` in explorer/mod.rs).
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;")
INLINE_CFGTEST_MOD = re.compile(
    r"^\s*#\[cfg\([^]]*\btest\b[^]]*\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
)

# --ip-scan: a dotted-quad literal, and the ranges that are EXPECTED noise in a
# public mirror (loopback, RFC-1918 private, CGNAT 100.64/10, link-local,
# RFC-5737 documentation blocks, well-known public DNS, multicast, the
# all-zeros/all-ones edges). Mirrors the inline filter in build-public-mirror.sh
# so the script and this scanner agree on what "unexpected" means. The scanner's
# job on top of the bash filter is CONTEXT: only flag a dotted-quad that survives
# in production (non-test, non-comment) code, where a leaked endpoint would hide.
IP = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
BENIGN_IP = re.compile(
    r"^(?:127\.|0\.0\.0\.0|255\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\."
    r"|169\.254\.|100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\."
    r"|203\.0\.113\.|198\.51\.100\.|192\.0\.2\."
    r"|1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9|239\.)"
)

# Hot-path files manually verified to contain zero production non-lock unwraps.
# If any of these reports a hit, the parser has regressed — abort, don't lie.
BASELINE_CLEAN = [
    "src/network/consensus.rs",
    "src/network/epoch.rs",
    "src/network/gossip.rs",
    "src/network/sync.rs",
    "src/accounting/cross_zone.rs",
    "src/accounting/governance.rs",
    "src/network/fisherman.rs",
    "src/light_verify.rs",
]


def code_views(line, st):
    """De-literalise one Rust source line two ways in a single lexer pass.

    Returns ``(stripped, kept)``:

      * ``stripped`` — comments AND string/char literals removed. This is the
        original ``code_only`` view; brace counting on it is reliable because a
        ``{`` inside a string or comment never survives.
      * ``kept`` — comments removed but string / raw-string CONTENT preserved
        (space-padded), so a value that lives *inside* a literal — an IP
        address, a URL host — survives for content scanning while a value that
        lives in a ``//`` or ``/* */`` comment does NOT. This is what lets the
        IP scan distinguish a real endpoint hard-coded as `"203.0.113.5"` from
        the same digits sitting in an explanatory comment. Crucially it gets
        `"http://1.2.3.4"` right — the inner `//` is string content, not a
        comment — which a naive `//`-position heuristic would mis-classify and
        under-warn on (the one failure mode a leak gate must never have).

    `st` carries multi-line state (block-comment depth, open raw-string hash
    count, open plain-string) across calls — identical for both views, since
    only the emitted text differs, never the lexer transitions.
    """
    out = []   # stripped: comments + literals removed
    keep = []  # kept: comments removed, string content preserved
    i = 0
    n = len(line)
    while i < n:
        if st["block"] > 0:  # inside /* ... */ — emit nothing in either view
            if line[i] == "*" and i + 1 < n and line[i + 1] == "/":
                st["block"] -= 1
                i += 2
                continue
            if line[i] == "/" and i + 1 < n and line[i + 1] == "*":
                st["block"] += 1
                i += 2
                continue
            i += 1
            continue
        if st["raw"] is not None:  # inside r#"..."#
            term = '"' + "#" * st["raw"]
            end = line.find(term, i)
            if end == -1:
                keep.append(" " + line[i:] + " ")
                return "".join(out), "".join(keep)
            keep.append(" " + line[i:end] + " ")
            i = end + len(term)
            st["raw"] = None
            out.append('""')
            continue
        if st["str"]:  # inside a plain "..." that wrapped a line
            j = i
            while j < n:
                if line[j] == "\\":
                    j += 2
                    continue
                if line[j] == '"':
                    break
                j += 1
            if j >= n:
                keep.append(" " + line[i:] + " ")
                return "".join(out), "".join(keep)
            keep.append(" " + line[i:j] + " ")
            i = j + 1
            st["str"] = False
            out.append('""')
            continue
        c = line[i]
        if c == "/" and i + 1 < n and line[i + 1] == "*":
            st["block"] += 1
            i += 2
            continue
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            break
        if c == "r" and i + 1 < n and line[i + 1] in '"#':
            j = i + 1
            h = 0
            while j < n and line[j] == "#":
                h += 1
                j += 1
            if j < n and line[j] == '"':
                term = '"' + "#" * h
                end = line.find(term, j + 1)
                if end == -1:
                    st["raw"] = h
                    out.append('""')
                    keep.append(" " + line[j + 1:] + " ")
                    return "".join(out), "".join(keep)
                keep.append(" " + line[j + 1:end] + " ")
                i = end + len(term)
                out.append('""')
                continue
        if c == '"':
            j = i + 1
            while j < n:
                if line[j] == "\\":
                    j += 2
                    continue
                if line[j] == '"':
                    break
                j += 1
            if j >= n:
                st["str"] = True
                out.append('""')
                keep.append(" " + line[i + 1:] + " ")
                return "".join(out), "".join(keep)
            keep.append(" " + line[i + 1:j] + " ")
            i = j + 1
            out.append('""')
            continue
        if c == "'":
            # char literal '\n' / 'x' — distinguished from a lifetime 'a
            if i + 1 < n and line[i + 1] == "\\":
                k = line.find("'", i + 2)
                if k != -1 and k - i <= 5:
                    i = k + 1
                    out.append("'C'")
                    keep.append("'C'")
                    continue
            elif i + 2 < n and line[i + 2] == "'":
                i += 3
                out.append("'C'")
                keep.append("'C'")
                continue
            out.append(c)
            keep.append(c)
            i += 1
            continue
        out.append(c)
        keep.append(c)
        i += 1
    return "".join(out), "".join(keep)


def code_only(line, st):
    """Comments + string/char literals stripped (see code_views). Thin wrapper
    so there is exactly ONE lexer — the panic gate and the IP scan can never
    desync on Rust tokenisation."""
    return code_views(line, st)[0]


def _child_module_paths(parent, name):
    """Candidate file paths Rust resolves `mod name;` to, declared in `parent`.

    `mod foo;` resolves to either `<dir>/foo.rs` or `<dir>/foo/mod.rs`, where
    <dir> is the parent's own directory for mod.rs/lib.rs/main.rs, else the
    directory named after the parent file (`bar.rs` → `bar/`)."""
    d = os.path.dirname(parent)
    base = os.path.basename(parent)
    moddir = d if base in ("mod.rs", "lib.rs", "main.rs") else os.path.join(d, base[:-3])
    return {
        os.path.normpath(os.path.join(moddir, name + ".rs")),
        os.path.normpath(os.path.join(moddir, name, "mod.rs")),
    }


def _module_children(path):
    """(test_gated, plain) child-module file paths declared in one file.

    Reuses the comment/string-aware lexer so a `mod x;` inside a comment or
    string literal cannot spoof an exclusion. A `#[cfg(test)] mod x;` (two-line
    or single-line) flags x as test-gated; a bare `mod x;` flags it plain."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return set(), set()
    st = {"block": 0, "raw": None, "str": False}
    pend = False
    test_kids, plain_kids = set(), set()
    for raw in lines:
        clean = st["block"] == 0 and st["raw"] is None and not st["str"]
        code = code_only(raw, st)  # also advances multi-line lexer state
        if clean:
            inl = INLINE_CFGTEST_MOD.match(code)
            if inl:
                test_kids |= _child_module_paths(path, inl.group(1))
                pend = False
                continue
            if CFGTEST.match(raw):
                pend = True
                continue
        m = MOD_DECL.match(code)
        if m:
            (test_kids if pend else plain_kids).update(
                _child_module_paths(path, m.group(1))
            )
            pend = False
            continue
        # A pending #[cfg(test)] survives stacked attribute / blank / comment
        # lines; any other real code line cancels it.
        s = code.strip()
        if s and not s.startswith("#["):
            pend = False
    return test_kids, plain_kids


def compute_cfgtest_files(globs):
    """Normalised paths of every `#[cfg(test)]`-gated module FILE (transitive:
    a sub-module of a test module is itself test-only) under `globs`.

    Soundness: a production file is excluded ONLY if it is reached from a
    `#[cfg(test)] mod ...;` declaration, which by Rust semantics makes it (and
    all its descendants) test code. An under-exclusion instead surfaces loudly
    as a non-zero surface, so the gate never silently lies."""
    test_kids, plain_kids = {}, {}
    for pattern in globs:
        for path in glob.glob(pattern, recursive=True):
            p = os.path.normpath(path)
            test_kids[p], plain_kids[p] = _module_children(p)
    excluded = set()
    frontier = set().union(*test_kids.values()) if test_kids else set()
    while frontier:
        f = frontier.pop()
        if f in excluded:
            continue
        excluded.add(f)
        # every child of an already-excluded test module is also test-only
        frontier |= test_kids.get(f, set()) | plain_kids.get(f, set())
    return excluded


_CFGTEST_FILES = None


def cfgtest_module_files():
    """Cached default-glob (working-tree) `#[cfg(test)]` module-file set. The
    file tree does not change within an invocation, and `scan()` calls this
    once per file, so caching matters for the panic gate."""
    global _CFGTEST_FILES
    if _CFGTEST_FILES is None:
        _CFGTEST_FILES = compute_cfgtest_files(SCAN_GLOBS)
    return _CFGTEST_FILES


def scan(path, pat, exclude=None):
    """Return [(line_no, text)] for `pat` matches in production (non-test) code."""
    if os.path.normpath(path) in cfgtest_module_files():
        return []  # separate-file #[cfg(test)] module — entirely test code
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    st = {"block": 0, "raw": None, "str": False}
    depth = 0
    in_test = False
    test_depth = 0
    pending = False
    hits = []
    for i, raw in enumerate(lines, 1):
        clean = st["block"] == 0 and st["raw"] is None and not st["str"]
        if clean and CFGTEST.match(raw):
            pending = True
        code = code_only(raw, st)
        opens = code.count("{")
        closes = code.count("}")
        if pending and opens > 0 and not in_test:
            in_test = True
            test_depth = depth
            pending = False
        if not in_test and pat.search(code) and (exclude is None or not exclude.search(code)):
            hits.append((i, raw.strip()[:100]))
        depth += opens - closes
        if in_test and depth <= test_depth:
            in_test = False
    return hits


def scan_ips(path, cfgtest_set):
    """Return [(line_no, ip)] for non-benign dotted-quad literals that appear in
    PRODUCTION code in `path` — i.e. outside `#[cfg(test)]` blocks/modules and
    outside comments. Same brace tracker as scan(), but matched against the
    string-content-preserving `kept` view so an IP inside a literal still
    counts while one inside a comment does not."""
    if os.path.normpath(path) in cfgtest_set:
        return []  # separate-file #[cfg(test)] module — entirely test code
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    st = {"block": 0, "raw": None, "str": False}
    depth = 0
    in_test = False
    test_depth = 0
    pending = False
    hits = []
    for i, raw in enumerate(lines, 1):
        clean = st["block"] == 0 and st["raw"] is None and not st["str"]
        if clean and CFGTEST.match(raw):
            pending = True
        stripped, kept = code_views(raw, st)
        opens = stripped.count("{")
        closes = stripped.count("}")
        if pending and opens > 0 and not in_test:
            in_test = True
            test_depth = depth
            pending = False
        if not in_test:
            for m in IP.finditer(kept):
                if not BENIGN_IP.match(m.group(0)):
                    hits.append((i, m.group(0)))
        depth += opens - closes
        if in_test and depth <= test_depth:
            in_test = False
    return hits


def ip_surface(root):
    """{relpath: [(line, ip), ...]} of production-code dotted-quads under `root`
    (its src/ + crates/*/src/). `root` is a mirror-output dir (or '.')."""
    globs = (
        os.path.join(root, "src/**/*.rs"),
        os.path.join(root, "crates/*/src/**/*.rs"),
    )
    cfgtest_set = compute_cfgtest_files(globs)
    res = {}
    for pattern in globs:
        for path in glob.glob(pattern, recursive=True):
            h = scan_ips(path, cfgtest_set)
            if h:
                rel = os.path.relpath(path, root)
                res[rel] = h
    return res


def selftest():
    """Lock the two-view lexer against regressions — the IP gate's analogue of
    validate(). A desync here (e.g. the kept view starts swallowing a literal,
    or the stripped view miscounts a brace) would make the IP gate either miss a
    leak or fire falsely, so assert the tricky cases explicitly: a `//` inside a
    string is content not a comment, a brace inside a string is not a brace, a
    line comment is dropped, and a string that wraps a line stays scannable."""
    # (line, must-be-in-kept, must-NOT-be-in-kept, net-brace-delta-of-stripped)
    cases = [
        ('let s = "203.0.55.7";', ["203.0.55.7"], [], 0),
        ('let u = "http://5.4.3.2/x";', ["5.4.3.2"], [], 0),
        ('let _ = ip; // seed 198.18.0.1 here', [], ["198.18.0.1"], 0),
        ('let m = "{not a brace}";', ["not a brace"], [], 0),
        ('fn f() { g(); }', [], [], 0),
        ('let r = r#"raw 9.9.1.1"#;', ["9.9.1.1"], [], 0),
        ('open_brace_in_str("{");', [], [], 0),
    ]
    fail = []
    for line, must, mustnot, brace_delta in cases:
        st = {"block": 0, "raw": None, "str": False}
        strip, keep = code_views(line, st)
        for w in must:
            if w not in keep:
                fail.append(f"{line!r}: kept view missing {w!r}")
        for w in mustnot:
            if w in keep:
                fail.append(f"{line!r}: kept view leaked comment {w!r}")
        got = strip.count("{") - strip.count("}")
        if got != brace_delta:
            fail.append(f"{line!r}: stripped brace delta {got} != {brace_delta}")
    # A plain string that wraps a line must keep its content on BOTH lines.
    st = {"block": 0, "raw": None, "str": False}
    _, k1 = code_views('let s = "host', st)
    _, k2 = code_views('  10.20.30.40";', st)
    if "host" not in k1 or "10.20.30.40" not in k2:
        fail.append("wrapped-string content not preserved across lines")
    if fail:
        print("IP-SCAN SELFTEST FAILED — lexer regressed:", file=sys.stderr)
        for f in fail:
            print("  " + f, file=sys.stderr)
        sys.exit(2)


def validate():
    bad = []
    for f in BASELINE_CLEAN:
        h = scan(f, HIT, exclude=LOCK)
        if h:
            bad.append((f, h[0]))
    if bad:
        print("PARSER REGRESSION — baseline-clean files report hits:", file=sys.stderr)
        for f, (ln, txt) in bad:
            print(f"  {f}:{ln}: {txt}", file=sys.stderr)
        sys.exit(2)


# Scan roots: the node tree plus every extracted crate's src/. Without the
# crates/ glob, code that moved into a public crate would silently escape the
# Lane-2 panic gate.
SCAN_GLOBS = ("src/**/*.rs", "crates/*/src/**/*.rs")


def surface(pat, exclude=None):
    res = {}
    total = 0
    for pattern in SCAN_GLOBS:
        for path in glob.glob(pattern, recursive=True):
            h = scan(path, pat, exclude)
            if h:
                res[path] = h
                total += len(h)
    return total, res


def main():
    args = sys.argv[1:]
    if "--show" in args:
        path = args[args.index("--show") + 1]
        for pat, name in ((HIT, "unwrap/expect"), (PANIC, "panic-macro")):
            ex = LOCK if pat is HIT else None
            for ln, txt in scan(path, pat, ex):
                print(f"{name:14s} {path}:{ln}: {txt}")
        return
    if "--selftest" in args:
        selftest()
        print("OK: ip-scan lexer selftest passed")
        return
    if "--ip-scan" in args:
        # Production-code dotted-quad literals under a mirror root (test blocks
        # and comments excluded). Exit 0 with the per-file list; the caller
        # (build-public-mirror.sh) decides how loud to be. A root arg may follow
        # --ip-scan; default '.'.
        selftest()  # abort rather than silently miss a leak if the lexer regressed
        idx = args.index("--ip-scan")
        root = args[idx + 1] if idx + 1 < len(args) else "."
        res = ip_surface(root)
        total = sum(len(v) for v in res.values())
        for rel in sorted(res):
            for ln, ip in res[rel]:
                print(f"{rel}:{ln}: {ip}")
        if total == 0:
            print("OK: no production-code IPv4 literals (test/comment excluded)")
        return
    validate()
    nonlock, r1 = surface(HIT, exclude=LOCK)
    locks, r2 = surface(LOCK)
    panics, r3 = surface(PANIC)
    print("Production panic surface (src/ + crates/*/src/, #[cfg(test)] excluded):")
    print(f"  non-lock unwrap/expect : {nonlock}")
    print(f"  lock unwrap/expect     : {locks}")
    print(f"  panic!/unreachable!/.. : {panics}")
    if "--locks" in args:
        for p, h in sorted(r2.items(), key=lambda kv: -len(kv[1])):
            print(f"    {len(h):3d}  {p}")
    for label, res in (("unwrap", r1), ("panic", r3)):
        for p, h in sorted(res.items(), key=lambda kv: -len(kv[1])):
            print(f"  [{label}] {len(h):3d}  {p}")
    if "--check" in args:
        if nonlock or locks or panics:
            print("FAIL: production panic surface is non-empty", file=sys.stderr)
            sys.exit(1)
        print("OK: zero production explicit-panic points")


if __name__ == "__main__":
    main()
