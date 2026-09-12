use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // git_dirty hardening: watching only .git/HEAD, .git/refs/heads, and
    // build.rs fires on HEAD switches, commits, and self-edits, but NOT on
    // `git add` / `git reset` / `git stash`, which mutate the
    // working-tree-vs-index delta that `git status --porcelain` reports.
    // Without .git/index in the watch list, a clean→dirty→clean working-tree
    // transition can leave the binary's embedded BUILD_GIT_DIRTY stamp stale
    // (cargo re-uses the cached value because none of HEAD/refs/build.rs
    // changed). Adding .git/index closes that gap.
    //
    // For purely unstaged edits (no `git add`), .git/index is unchanged, so
    // build.rs still won't re-run; a runtime git_dirty re-check in the deploy
    // script is the second layer.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=build.rs");

    let git_sha = git("rev-parse", &["HEAD"]).unwrap_or_else(|| "unknown".to_string());
    // `rev-parse --abbrev-ref HEAD` returns the literal string "HEAD" on a detached
    // checkout, and it does so by SUCCEEDING — so the unwrap_or fallback can never
    // catch it. Every binary published by release.yml is built from a detached tag
    // checkout (actions/checkout on a `v*` tag push), so every released binary has
    // been stamping git_ref="HEAD": the HELP text promised "branch/tag" and delivered
    // neither. Ask for the exact tag first, fall back to the branch, and name the
    // detached case for what it is rather than letting "HEAD" pass as if it were a ref.
    let git_ref = git("describe", &["--tags", "--exact-match"])
        .or_else(|| git("rev-parse", &["--abbrev-ref", "HEAD"]).filter(|r| r.as_str() != "HEAD"))
        .or_else(|| git("rev-parse", &["--short", "HEAD"]).map(|s| format!("detached-{s}")))
        .unwrap_or_else(|| "unknown".to_string());
    // Deliberately UNSCOPED, and it must stay that way until something derives the
    // scope instead of restating it. This check is over-inclusive: it counts tracked
    // files that no binary compiles (the cron-rewritten ledgers under logs/), so a
    // release build stamps 1 on roughly half of all days while its bytes are identical
    // to a clean tree. That is noise, and the HELP text below now says so instead of
    // promising otherwise. The obvious repair — a hand-written pathspec over src/,
    // crates/ and the manifests — is REFUSED: src/network/server/mod.rs compiles
    // static/explorer.html in via include_str!, so such a list would stamp 0 while the
    // binary genuinely differed from HEAD. A false 0 here is far worse than a false 1:
    // the deploy gate refuses on 1 and proceeds on 0. Over-inclusive is fail-safe;
    // under-inclusive is fail-dangerous. Any future scoping must derive its list from
    // the actual compile graph (include_str!/include_bytes! targets included), the way
    // scripts/check-deploy-staleness.sh derives build_graph_pathspec.
    let git_dirty = match Command::new("git").args(["status", "--porcelain"]).output() {
        Ok(out) if out.status.success() => !out.stdout.is_empty(),
        _ => false,
    };

    let build_ts_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("cargo:rustc-env=BUILD_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=BUILD_GIT_REF={git_ref}");
    println!("cargo:rustc-env=BUILD_GIT_DIRTY={}", if git_dirty { "1" } else { "0" });
    println!("cargo:rustc-env=BUILD_TS_SECS={build_ts_secs}");
}

fn git(subcmd: &str, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.arg(subcmd);
    for a in args {
        cmd.arg(a);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
