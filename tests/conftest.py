"""Session header: say WHAT these suites are actually testing, and when it was built.

Why this exists (2026-09-07). The five `tests/test_*.py` suites import
`elara_runtime`, whose native half is `python/elara_runtime/_native.<abi>.so` — a
file **no gate builds** and **git does not track**. On the day this was written it
was dated Jun 29, ten weeks stale, and running the suites for the first time in
months produced eight failures. Two were a genuine stale-test bug; the rest looked
like a severe wire-codec defect ("no non-empty metadata survives to_bytes →
from_bytes"), which would have been filed against shipped code. It was not shipped
code: `cargo test -p elara-record --lib` was 119/0 on the same tree, including two
metadata round-trip tests. The failures belonged to the artifact.

A suite whose subject is a stale local build is not evidence in either direction —
green proves nothing about HEAD and red accuses the wrong code. This header does
not fix that; the fix is a ruling (build the extension in a gate, or skip on
staleness) that is deliberately still open. It removes the *trap*: nobody should
have to think to run `ls` before believing a result.

Deliberately non-gating: it prints, never fails. A header that could abort the run
would be a policy decision wearing a diagnostic's clothes.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path


def _native_provenance() -> list[str]:
    try:
        import elara_runtime  # noqa: PLC0415  (import here: a missing module is a valid answer)
    except Exception as exc:  # pragma: no cover - reported, never raised
        return [f"elara_runtime: NOT IMPORTABLE ({exc.__class__.__name__}: {exc})"]

    lines = [f"elara_runtime: {getattr(elara_runtime, '__file__', '<no __file__>')}"]
    native = getattr(elara_runtime, "_native", None)
    so = getattr(native, "__file__", None) if native is not None else None
    if so is None:
        lines.append("  native extension: ABSENT — suites gated on NATIVE_AVAILABLE will skip")
        return lines

    path = Path(so)
    try:
        age_days = (time.time() - path.stat().st_mtime) / 86400.0
    except OSError as exc:  # pragma: no cover
        return lines + [f"  native extension: {so} (stat failed: {exc})"]

    # Tracked-ness is the other half of the question: an untracked artifact has no
    # commit describing it, so its age is the ONLY provenance available.
    try:
        rc = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(path)],
            cwd=path.parent,
            capture_output=True,
            timeout=10,
        ).returncode
        tracked = "tracked" if rc == 0 else "UNTRACKED (no commit describes it)"
    except Exception:  # pragma: no cover - git absent is not this file's problem
        tracked = "tracked-ness unknown (git unavailable)"

    lines.append(f"  native extension: {path.name}")
    lines.append(f"    built {age_days:.1f} days ago · {tracked}")
    if age_days >= 7.0:
        lines.append(
            "    ⚠ NOT REBUILT BY ANY GATE. A failure here may belong to this artifact,"
        )
        lines.append(
            "      not to HEAD — cross-check with `cargo test -p elara-record --lib`"
        )
        lines.append("      before filing anything against shipped code.")
    return lines


def pytest_report_header(config):  # noqa: ARG001 - pytest hook signature
    return _native_provenance()


def pytest_terminal_summary(terminalreporter, exitstatus, config):  # noqa: ARG001
    """Repeat the provenance when the run FAILED — including under `-q`.

    `pytest_report_header` above is suppressed by `-q`, which is the invocation
    everyone actually types (it is the one I used all session). So the header was
    blind in exactly the common case — caught by running the new hook both ways
    instead of only the way that showed it working.

    The trap only springs on a failure: that is the moment someone is about to
    decide whether HEAD is broken. So re-emit there, unconditionally of verbosity,
    and stay silent on a green run so a passing suite gains no noise.
    """
    if not terminalreporter.stats.get("failed"):
        return
    terminalreporter.write_sep("-", "what was under test")
    for line in _native_provenance():
        terminalreporter.write_line(line)
