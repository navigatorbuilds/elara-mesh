//! `elara-verify` — the offline verifier CLI, built from this crate alone
//! (`cargo build -p elara-verify --features cli --bin elara-verify`, or via
//! `cargo install` once published). The node repo's root `[[bin]]` of the same
//! name is an identical delegate to [`elara_verify::cli::run`], so both build
//! paths produce the same verifier; the driver + checks live in the library.

use std::process::ExitCode;

fn main() -> ExitCode {
    elara_verify::cli::run()
}
