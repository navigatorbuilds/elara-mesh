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
    let git_ref = git("rev-parse", &["--abbrev-ref", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
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
