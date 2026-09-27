// Copyright (c) 2026 Elara Protocol contributors
// Licensed under AGPL-3.0-only
//
// elara-keygen — Air-gap-friendly Dilithium3 (+ optional SPHINCS+) identity
// toolchain for the mainnet genesis ceremony (see internal design notes
// §3, §6).
//
// Subcommands:
//   gen      — generate a new identity (default if no subcommand given)
//   verify   — read a JSON identity, check structure + PoW, print summary
//   pubkey   — strip secret material from a JSON identity, emit publishable
//              subset (for QR-out / paper-out from an air-gap host)
//   rekey    — rotate the passphrase of an encrypted identity file
//   fips205  — write a copy of an identity holding a fresh FIPS 205 SLH-DSA
//              second-leg key
//
// No network, no database, no tokio runtime. Pure CPU + filesystem.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use elara_runtime::identity::{
    is_encrypted_identity, write_identity_file, CryptoProfile, EntityType, Identity,
    SphincsSuite, MAX_POW_DIFFICULTY,
};

const USAGE: &str = "\
elara-keygen — air-gap identity toolchain (Dilithium3 + optional SPHINCS+)

USAGE:
    elara-keygen [gen] --output <PATH> [--profile A|B|C] [--entity TYPE]
                       [--pow-difficulty N] [--quiet]
    elara-keygen verify <PATH>
    elara-keygen pubkey <PATH> [--output <PUB_PATH>] [--quiet]
    elara-keygen rekey <PATH>       (env: ELARA_OLD_PASSPHRASE, ELARA_NEW_PASSPHRASE)
    elara-keygen fips205 <PATH> --output <NEW_PATH> [--quiet]
                                    (env: ELARA_IDENTITY_PASSPHRASE if PATH is encrypted)
    elara-keygen -h | --help

SUBCOMMANDS:
    gen        Generate a new identity (default when no subcommand given).
    verify     Read a JSON identity, check structure + PoW, print summary.
    pubkey     Read a JSON identity and emit the publishable subset
               (no secret_key / no sphincs_secret_key) — suitable for
               transferring out of an air-gap host via QR or paper.
    rekey      Rotate the passphrase of an encrypted identity file in place.
    fips205    Write a copy of a Profile A identity holding a fresh FIPS 205
               SLH-DSA-SHA2-192f second-leg key, drawn from OS randomness and
               never derived from the old key. The ML-DSA key and identity_hash
               stay as they are; PATH is never changed. NEW_PATH is encrypted,
               under the same passphrase, when PATH is. The new key signs only
               from WIRE_VERSION 8.

GEN OPTIONS:
    --output PATH          Where to write the identity JSON file (0o600).
    --profile A|B|C        Crypto profile. A = Dilithium3 + SPHINCS+ (default),
                           B = Dilithium3 only, C = Dilithium3 only (light).
    --entity TYPE          One of: human, ai, device, organization, composite
                           (default: human).
    --pow-difficulty N     Leading zero bits required on SHA3-256(pk||nonce).
                           0..=32. Default 0 (genesis ceremony — no PoW gate).
                           Use 20 for normal user identities.
    --quiet                Suppress informational stderr; only print
                           identity_hash on stdout.

PUBKEY OPTIONS:
    --output PATH          Write publishable JSON to PATH (0o644). If omitted,
                           the publishable JSON is written to stdout.
    --quiet                Suppress informational stderr.

OUTPUT:
    On `gen`, identity_hash is printed to stdout (one line) so it can be
    piped or captured. The full keypair (including secret_key) is written
    to PATH with mode 0o600. Back this file up to cold storage immediately.

    On `verify`, identity_hash is printed on stdout and a multi-line summary
    on stderr; exit 0 if PoW passes, exit 1 otherwise.

    On `pubkey`, the publishable JSON (public_key, identity_hash,
    entity_type, profile, algorithm, created, pow_nonce, pow_difficulty,
    sphincs_public_key, and sphincs_suite for a FIPS 205 key) is emitted.
    No secret_key, no sphincs_secret_key.

GENESIS USE:
    Run `gen` on an air-gapped machine (Tails live image, factory-fresh
    laptop). Then run `pubkey` on the same machine to extract the file
    you carry out via QR or paper. Verify on co-attendees' machines with
    `verify`. Never expose secret_key.
";

// ─────────────────────────────────────────────────────────────────────────
// gen — generate a new identity
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct GenArgs {
    output: PathBuf,
    profile: CryptoProfile,
    entity: EntityType,
    difficulty: u8,
    quiet: bool,
}

fn parse_gen(rest: Vec<String>) -> std::result::Result<GenArgs, String> {
    let mut output: Option<PathBuf> = None;
    let mut profile = CryptoProfile::ProfileA;
    let mut entity = EntityType::Human;
    let mut difficulty: u8 = 0;
    let mut quiet = false;

    let mut it = rest.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--quiet" => quiet = true,
            "--output" => {
                output = Some(PathBuf::from(
                    it.next().ok_or("--output requires a path".to_string())?,
                ));
            }
            "--profile" => {
                let v = it.next().ok_or("--profile requires A|B|C".to_string())?;
                profile = match v.to_ascii_uppercase().as_str() {
                    "A" => CryptoProfile::ProfileA,
                    "B" => CryptoProfile::ProfileB,
                    "C" => CryptoProfile::ProfileC,
                    other => return Err(format!("unknown profile: {other}")),
                };
            }
            "--entity" => {
                let v = it.next().ok_or("--entity requires a type".to_string())?;
                entity = match v.to_ascii_lowercase().as_str() {
                    "human" => EntityType::Human,
                    "ai" => EntityType::Ai,
                    "device" => EntityType::Device,
                    "organization" | "org" => EntityType::Organization,
                    "composite" => EntityType::Composite,
                    other => return Err(format!("unknown entity type: {other}")),
                };
            }
            "--pow-difficulty" => {
                let v = it
                    .next()
                    .ok_or("--pow-difficulty requires a number".to_string())?;
                difficulty = v
                    .parse::<u8>()
                    .map_err(|e| format!("invalid difficulty: {e}"))?;
                if difficulty > MAX_POW_DIFFICULTY {
                    return Err(format!(
                        "difficulty {difficulty} exceeds max {MAX_POW_DIFFICULTY}"
                    ));
                }
            }
            other => return Err(format!("unknown argument to gen: {other}")),
        }
    }

    Ok(GenArgs {
        output: output.ok_or("--output is required (use -h for help)".to_string())?,
        profile,
        entity,
        difficulty,
        quiet,
    })
}

fn run_gen(args: GenArgs) -> std::result::Result<(), String> {
    if args.output.exists() {
        return Err(format!(
            "refusing to overwrite existing file: {}",
            args.output.display()
        ));
    }

    if !args.quiet {
        eprintln!(
            "elara-keygen gen: profile={:?} entity={:?} pow_difficulty={} output={}",
            args.profile,
            args.entity,
            args.difficulty,
            args.output.display()
        );
        if args.difficulty > 0 {
            eprintln!("elara-keygen gen: mining PoW (this may take a while)...");
        }
    }

    let identity = Identity::generate_with_pow(args.entity, args.profile, args.difficulty)
        .map_err(|e| format!("keygen failed: {e}"))?;

    let json = identity.to_json();
    write_identity_file(&args.output, &json).map_err(|e| format!("write failed: {e}"))?;

    let roundtrip =
        Identity::from_json(&json).map_err(|e| format!("roundtrip from_json failed: {e}"))?;
    if roundtrip.identity_hash != identity.identity_hash {
        return Err(format!(
            "roundtrip identity_hash mismatch: wrote {} read {}",
            identity.identity_hash, roundtrip.identity_hash
        ));
    }
    if !roundtrip.verify_pow() {
        return Err("roundtrip PoW verification failed".to_string());
    }

    if !args.quiet {
        eprintln!(
            "elara-keygen gen: wrote {} ({} bytes pubkey)",
            args.output.display(),
            identity.public_key.len()
        );
        eprintln!(
            "elara-keygen gen: BACK UP {} TO COLD STORAGE NOW.",
            args.output.display()
        );
    }

    println!("{}", identity.identity_hash);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// verify — read JSON, verify PoW, print summary
// ─────────────────────────────────────────────────────────────────────────

fn read_identity_file(path: &Path) -> std::result::Result<BTreeMap<String, serde_json::Value>, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("read {} failed: {e}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {} failed: {e}", path.display()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| format!("{} is not a JSON object", path.display()))?;
    Ok(obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}

fn run_verify(rest: Vec<String>) -> std::result::Result<(), String> {
    let path = match rest.as_slice() {
        [p] => PathBuf::from(p),
        _ => return Err("verify takes exactly one path argument".to_string()),
    };
    let data = read_identity_file(&path)?;
    let identity = Identity::from_json(&data).map_err(|e| format!("invalid identity: {e}"))?;

    let pow_ok = identity.verify_pow();

    eprintln!("elara-keygen verify: file={}", path.display());
    eprintln!("  algorithm:        {}", identity.algorithm);
    eprintln!("  profile:          {:?}", identity.profile);
    eprintln!("  entity_type:      {:?}", identity.entity_type);
    eprintln!("  public_key bytes: {}", identity.public_key.len());
    eprintln!(
        "  sphincs+ bytes:   {}",
        identity
            .sphincs_public_key()
            .map(|v| v.len())
            .unwrap_or(0)
    );
    if identity.sphincs_public_key().is_some() {
        eprintln!("  sphincs_suite:    {}", identity.sphincs_suite().tag());
    }
    eprintln!("  pow_difficulty:   {}", identity.pow_difficulty);
    eprintln!("  pow_nonce:        {}", identity.pow_nonce);
    eprintln!("  pow_valid:        {}", pow_ok);
    eprintln!("  has_secret_key:   {}", identity.has_secret_key());

    println!("{}", identity.identity_hash);

    if !pow_ok {
        return Err("PoW verification failed".to_string());
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// pubkey — strip secret material, emit publishable subset
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct PubkeyArgs {
    input: PathBuf,
    output: Option<PathBuf>,
    quiet: bool,
}

fn parse_pubkey(rest: Vec<String>) -> std::result::Result<PubkeyArgs, String> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut quiet = false;

    let mut it = rest.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--quiet" => quiet = true,
            "--output" => {
                output = Some(PathBuf::from(
                    it.next().ok_or("--output requires a path".to_string())?,
                ));
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown argument to pubkey: {other}"));
            }
            other => {
                if input.is_some() {
                    return Err("pubkey takes one positional path".to_string());
                }
                input = Some(PathBuf::from(other));
            }
        }
    }

    Ok(PubkeyArgs {
        input: input.ok_or("pubkey requires a path argument".to_string())?,
        output,
        quiet,
    })
}

fn run_pubkey(args: PubkeyArgs) -> std::result::Result<(), String> {
    let data = read_identity_file(&args.input)?;
    // Validate via from_json before stripping; refuse to emit anything
    // structurally invalid (so a typo'd file doesn't propagate).
    let identity = Identity::from_json(&data).map_err(|e| format!("invalid identity: {e}"))?;

    // public_identity() strips secret_key + sphincs_secret_key.
    let publishable = identity.public_identity().to_json();

    let json_str = serde_json::to_string_pretty(&publishable)
        .map_err(|e| format!("serialize failed: {e}"))?;

    match &args.output {
        Some(path) => {
            if path.exists() {
                return Err(format!(
                    "refusing to overwrite existing file: {}",
                    path.display()
                ));
            }
            std::fs::write(path, &json_str)
                .map_err(|e| format!("write {} failed: {e}", path.display()))?;
            // 0o644: the public file is meant to be shared.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
                    .map_err(|e| format!("chmod {} failed: {e}", path.display()))?;
            }
            if !args.quiet {
                eprintln!(
                    "elara-keygen pubkey: wrote {} (public fields only)",
                    path.display()
                );
            }
        }
        None => {
            print!("{json_str}");
            if !json_str.ends_with('\n') {
                println!();
            }
        }
    }

    if !args.quiet {
        eprintln!("elara-keygen pubkey: identity_hash={}", identity.identity_hash);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// fips205 — a copy of an identity with a fresh FIPS 205 second-leg key
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Fips205Args {
    input: PathBuf,
    output: PathBuf,
    quiet: bool,
}

fn parse_fips205(rest: Vec<String>) -> std::result::Result<Fips205Args, String> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut quiet = false;

    let mut it = rest.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--quiet" => quiet = true,
            "--output" => {
                output = Some(PathBuf::from(
                    it.next().ok_or("--output requires a path".to_string())?,
                ));
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown argument to fips205: {other}"));
            }
            other => {
                if input.is_some() {
                    return Err("fips205 takes one positional path".to_string());
                }
                input = Some(PathBuf::from(other));
            }
        }
    }

    Ok(Fips205Args {
        input: input.ok_or("fips205 requires a path argument".to_string())?,
        output: output
            .ok_or("fips205 requires --output: the source file is never changed".to_string())?,
        quiet,
    })
}

/// The identity file `data` with a fresh FIPS 205 second-leg key, and its
/// identity hash. The new file is encrypted, under the same passphrase, when
/// `data` is. It is read back and checked in memory before anything is written.
fn fips205_file(
    data: &BTreeMap<String, serde_json::Value>,
    passphrase: Option<&[u8]>,
) -> std::result::Result<(BTreeMap<String, serde_json::Value>, String), String> {
    let passphrase = match (is_encrypted_identity(data), passphrase) {
        (true, None) => {
            return Err("the identity file is encrypted: set ELARA_IDENTITY_PASSPHRASE".to_string())
        }
        (true, pass) => pass,
        (false, _) => None,
    };
    let open = |file: &BTreeMap<String, serde_json::Value>| match passphrase {
        Some(pass) => Identity::from_encrypted_json(file, pass),
        None => Identity::from_json(file),
    };

    let old = open(data).map_err(|e| format!("invalid identity: {e}"))?;
    let new = old
        .with_fresh_fips205_key()
        .map_err(|e| format!("no FIPS 205 key written: {e}"))?;
    let file = match passphrase {
        Some(pass) => new.to_encrypted_json(pass),
        None => Ok(new.to_json()),
    }
    .map_err(|e| format!("serialize failed: {e}"))?;

    let back = open(&file).map_err(|e| format!("read-back failed, nothing written: {e}"))?;
    let unchanged = |id: &Identity| {
        let mut public = id.public_identity().to_json();
        public.remove("sphincs_public_key");
        public.remove("sphincs_suite");
        public
    };
    if unchanged(&back) != unchanged(&old) {
        return Err("read-back changed the identity, nothing written".to_string());
    }
    if back.sphincs_suite() != SphincsSuite::Fips205
        || back.sphincs_public_key() != new.sphincs_public_key()
    {
        return Err("read-back lost the new key, nothing written".to_string());
    }
    let probe = b"elara-keygen fips205 read-back";
    let sig = back
        .sign(probe)
        .map_err(|e| format!("read-back ML-DSA key failed to sign, nothing written: {e}"))?;
    if !Identity::verify(probe, &sig, &back.public_key).unwrap_or(false) {
        return Err("read-back ML-DSA key does not verify, nothing written".to_string());
    }
    back.check_fips205_key()
        .map_err(|e| format!("read-back key check failed, nothing written: {e}"))?;
    Ok((file, back.identity_hash.clone()))
}

/// Write a copy of the identity at `input` holding a fresh FIPS 205 SLH-DSA
/// second-leg key to `output`, a new file. The source is only read.
fn run_fips205(args: Fips205Args) -> std::result::Result<(), String> {
    if args.output.exists() {
        return Err(format!(
            "refusing to overwrite existing file: {}",
            args.output.display()
        ));
    }
    let data = read_identity_file(&args.input)?;
    let passphrase = if is_encrypted_identity(&data) {
        // Read as the node reads it: an empty value counts as unset.
        let pass = std::env::var("ELARA_IDENTITY_PASSPHRASE")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or("the identity file is encrypted: set ELARA_IDENTITY_PASSPHRASE".to_string())?;
        Some(zeroize::Zeroizing::new(pass))
    } else {
        None
    };
    let (file, hash) = fips205_file(&data, passphrase.as_ref().map(|p| p.as_bytes()))?;
    write_identity_file(&args.output, &file).map_err(|e| format!("write failed: {e}"))?;
    if read_identity_file(&args.output)? != file {
        return Err(format!(
            "{} does not read back as written: do not use it",
            args.output.display()
        ));
    }

    if !args.quiet {
        eprintln!("elara-keygen fips205: wrote {}", args.output.display());
        eprintln!("  second leg:       {}", SphincsSuite::Fips205.tag());
        eprintln!("  encrypted:        {}", passphrase.is_some());
        eprintln!("  source untouched: {}", args.input.display());
        eprintln!("  it signs its second leg only from WIRE_VERSION 8");
    }
    println!("{hash}");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// dispatch
// ─────────────────────────────────────────────────────────────────────────

fn run_with_args(mut args: Vec<String>) -> std::result::Result<(), String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(());
    }

    let subcommand = if let Some(first) = args.first() {
        match first.as_str() {
            "gen" | "verify" | "pubkey" | "rekey" | "fips205" => {
                let s = first.clone();
                args.remove(0);
                s
            }
            // Flags (--output, --profile, …) mean the caller omitted the
            // subcommand and wants the default "gen".
            other if other.starts_with('-') => "gen".to_string(),
            other => {
                return Err(format!(
                    "unknown subcommand '{other}' — valid: gen, verify, pubkey, rekey, fips205"
                ));
            }
        }
    } else {
        return Err("no arguments — try `elara-keygen --help`".to_string());
    };

    match subcommand.as_str() {
        "gen" => run_gen(parse_gen(args)?),
        "verify" => run_verify(args),
        "pubkey" => run_pubkey(parse_pubkey(args)?),
        "rekey" => run_rekey(args),
        "fips205" => run_fips205(parse_fips205(args)?),
        _ => Err(format!("unexpected subcommand: {subcommand}")),
    }
}

/// Rotate the passphrase of an ENCRYPTED identity file in place.
///
/// Born 2026-08-20: the authority passphrase touched a conversation transcript
/// during its escrow walk — a secret that touched a transcript gets rotated.
/// Passphrases ride ONLY in env vars (ELARA_OLD_PASSPHRASE / ELARA_NEW_PASSPHRASE)
/// so they never appear in argv (visible in `ps`) or shell-history arguments.
/// Order of operations is fail-safe: decrypt → re-encrypt → ROUND-TRIP VERIFY the
/// new ciphertext in memory → backup the original → atomic tmp+rename replace.
/// Disk is untouched until the round trip proves the new file will load.
fn run_rekey(rest: Vec<String>) -> std::result::Result<(), String> {
    let path = match rest.as_slice() {
        [p] => PathBuf::from(p),
        _ => return Err("rekey takes exactly one path argument".to_string()),
    };
    let old = std::env::var("ELARA_OLD_PASSPHRASE")
        .map_err(|_| "ELARA_OLD_PASSPHRASE not set".to_string())?;
    let new = std::env::var("ELARA_NEW_PASSPHRASE")
        .map_err(|_| "ELARA_NEW_PASSPHRASE not set".to_string())?;
    if new.trim().is_empty() {
        return Err("new passphrase is empty".to_string());
    }
    if old == new {
        return Err("new passphrase equals old — nothing to rotate".to_string());
    }

    let data = read_identity_file(&path)?;
    if !is_encrypted_identity(&data) {
        return Err(
            "identity file is PLAINTEXT — rekey only handles encrypted identities".to_string(),
        );
    }
    let identity = Identity::from_encrypted_json(&data, old.as_bytes())
        .map_err(|e| format!("decrypt with OLD passphrase failed: {e}"))?;
    let reenc = identity
        .to_encrypted_json(new.as_bytes())
        .map_err(|e| format!("re-encrypt failed: {e}"))?;
    let roundtrip = Identity::from_encrypted_json(&reenc, new.as_bytes())
        .map_err(|e| format!("round-trip verify failed — aborting, disk untouched: {e}"))?;
    if roundtrip.identity_hash != identity.identity_hash {
        return Err("round-trip identity hash mismatch — aborting, disk untouched".to_string());
    }

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bak = path.with_extension(format!("bak-rekey-{ts}"));
    std::fs::copy(&path, &bak).map_err(|e| format!("backup failed: {e}"))?;
    write_identity_file(&path, &reenc).map_err(|e| format!("atomic write failed: {e}"))?;

    eprintln!("elara-keygen rekey: OK");
    eprintln!("  file:            {}", path.display());
    eprintln!("  identity_hash:   {}…", &identity.identity_hash[..16]);
    eprintln!("  backup (OLD passphrase — delete after the service restarts clean):");
    eprintln!("                   {}", bak.display());
    Ok(())
}

fn run() -> std::result::Result<(), String> {
    run_with_args(std::env::args().skip(1).collect())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "elara_keygen_test_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ─── parse_gen ────────────────────────────────────────────────────────

    #[test]
    fn parse_gen_requires_output() {
        let err = parse_gen(args(&[])).unwrap_err();
        assert!(err.contains("--output is required"), "{err}");
    }

    #[test]
    fn parse_gen_defaults_when_only_output_given() {
        let g = parse_gen(args(&["--output", "/tmp/x.json"])).unwrap();
        assert_eq!(g.output, PathBuf::from("/tmp/x.json"));
        assert!(matches!(g.profile, CryptoProfile::ProfileA));
        assert!(matches!(g.entity, EntityType::Human));
        assert_eq!(g.difficulty, 0);
        assert!(!g.quiet);
    }

    #[test]
    fn parse_gen_profile_case_insensitive() {
        for (s, want) in [
            ("a", "ProfileA"),
            ("A", "ProfileA"),
            ("b", "ProfileB"),
            ("B", "ProfileB"),
            ("c", "ProfileC"),
            ("C", "ProfileC"),
        ] {
            let g = parse_gen(args(&["--output", "/tmp/x.json", "--profile", s])).unwrap();
            assert_eq!(format!("{:?}", g.profile), want, "profile arg {s}");
        }
    }

    #[test]
    fn parse_gen_entity_all_variants() {
        for (s, want) in [
            ("human", "Human"),
            ("HUMAN", "Human"),
            ("ai", "Ai"),
            ("device", "Device"),
            ("organization", "Organization"),
            ("org", "Organization"),
            ("composite", "Composite"),
        ] {
            let g = parse_gen(args(&["--output", "/tmp/x.json", "--entity", s])).unwrap();
            assert_eq!(format!("{:?}", g.entity), want, "entity arg {s}");
        }
    }

    #[test]
    fn parse_gen_unknown_profile_rejected() {
        let err = parse_gen(args(&["--output", "/tmp/x.json", "--profile", "Z"])).unwrap_err();
        assert!(err.contains("unknown profile"), "{err}");
    }

    #[test]
    fn parse_gen_unknown_entity_rejected() {
        let err =
            parse_gen(args(&["--output", "/tmp/x.json", "--entity", "ghost"])).unwrap_err();
        assert!(err.contains("unknown entity type"), "{err}");
    }

    #[test]
    fn parse_gen_difficulty_above_max_rejected() {
        let too_high = (MAX_POW_DIFFICULTY as u16 + 1).to_string();
        let err = parse_gen(args(&[
            "--output",
            "/tmp/x.json",
            "--pow-difficulty",
            &too_high,
        ]))
        .unwrap_err();
        assert!(err.contains("exceeds max"), "{err}");
    }

    #[test]
    fn parse_gen_difficulty_at_max_accepted() {
        let g = parse_gen(args(&[
            "--output",
            "/tmp/x.json",
            "--pow-difficulty",
            &MAX_POW_DIFFICULTY.to_string(),
        ]))
        .unwrap();
        assert_eq!(g.difficulty, MAX_POW_DIFFICULTY);
    }

    #[test]
    fn parse_gen_difficulty_non_numeric_rejected() {
        let err = parse_gen(args(&[
            "--output",
            "/tmp/x.json",
            "--pow-difficulty",
            "twelve",
        ]))
        .unwrap_err();
        assert!(err.contains("invalid difficulty"), "{err}");
    }

    #[test]
    fn parse_gen_quiet_flag() {
        let g = parse_gen(args(&["--output", "/tmp/x.json", "--quiet"])).unwrap();
        assert!(g.quiet);
    }

    #[test]
    fn parse_gen_unknown_arg_rejected() {
        let err = parse_gen(args(&["--output", "/tmp/x.json", "--bogus"])).unwrap_err();
        assert!(err.contains("unknown argument"), "{err}");
    }

    #[test]
    fn parse_gen_missing_value_for_output() {
        let err = parse_gen(args(&["--output"])).unwrap_err();
        assert!(err.contains("--output requires"), "{err}");
    }

    #[test]
    fn parse_gen_missing_value_for_difficulty() {
        let err = parse_gen(args(&["--output", "/tmp/x.json", "--pow-difficulty"])).unwrap_err();
        assert!(err.contains("--pow-difficulty requires"), "{err}");
    }

    // ─── parse_pubkey ─────────────────────────────────────────────────────

    #[test]
    fn parse_pubkey_requires_input() {
        let err = parse_pubkey(args(&[])).unwrap_err();
        assert!(err.contains("pubkey requires"), "{err}");
    }

    #[test]
    fn parse_pubkey_positional_input() {
        let p = parse_pubkey(args(&["in.json"])).unwrap();
        assert_eq!(p.input, PathBuf::from("in.json"));
        assert!(p.output.is_none());
        assert!(!p.quiet);
    }

    #[test]
    fn parse_pubkey_with_output_and_quiet() {
        let p =
            parse_pubkey(args(&["in.json", "--output", "out.json", "--quiet"])).unwrap();
        assert_eq!(p.input, PathBuf::from("in.json"));
        assert_eq!(p.output, Some(PathBuf::from("out.json")));
        assert!(p.quiet);
    }

    #[test]
    fn parse_pubkey_rejects_two_positionals() {
        let err = parse_pubkey(args(&["in.json", "in2.json"])).unwrap_err();
        assert!(err.contains("one positional path"), "{err}");
    }

    #[test]
    fn parse_pubkey_rejects_unknown_flag() {
        let err = parse_pubkey(args(&["in.json", "--bogus"])).unwrap_err();
        assert!(err.contains("unknown argument"), "{err}");
    }

    // ─── gen → verify roundtrip (Profile B for fast tests) ────────────────

    #[test]
    fn gen_writes_identity_file_then_verify_succeeds() {
        let dir = tmp_dir("gen_verify");
        let id_path = dir.join("ident.json");

        run_gen(GenArgs {
            output: id_path.clone(),
            profile: CryptoProfile::ProfileB,
            entity: EntityType::Human,
            difficulty: 0,
            quiet: true,
        })
        .expect("gen should succeed");

        assert!(id_path.exists(), "identity file must exist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&id_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "identity file must be 0o600, got 0o{:o}", mode);
        }

        run_verify(vec![id_path.to_str().unwrap().to_string()])
            .expect("verify should pass on freshly generated identity");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gen_refuses_to_overwrite_existing_file() {
        let dir = tmp_dir("gen_overwrite");
        let id_path = dir.join("ident.json");
        std::fs::write(&id_path, "{}").unwrap();

        let err = run_gen(GenArgs {
            output: id_path,
            profile: CryptoProfile::ProfileB,
            entity: EntityType::Human,
            difficulty: 0,
            quiet: true,
        })
        .unwrap_err();
        assert!(err.contains("refusing to overwrite"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // ─── pubkey strips secrets (the security-critical invariant) ──────────

    #[test]
    fn rekey_rotates_passphrase_and_refuses_bad_inputs() {
        let dir = tmp_dir("rekey");
        let id_path = dir.join("enc-ident.json");

        // Build an ENCRYPTED identity file under the OLD passphrase (in-code:
        // gen writes plaintext, and rekey must refuse plaintext — tested below).
        let identity =
            Identity::generate_with_pow(EntityType::Device, CryptoProfile::ProfileB, 0)
                .expect("gen identity");
        let enc = identity
            .to_encrypted_json(b"old-passphrase")
            .expect("encrypt");
        write_identity_file(&id_path, &enc).expect("write");

        // Refusal: plaintext file.
        let plain_path = dir.join("plain-ident.json");
        write_identity_file(&plain_path, &identity.to_json()).expect("write plain");
        std::env::set_var("ELARA_OLD_PASSPHRASE", "old-passphrase");
        std::env::set_var("ELARA_NEW_PASSPHRASE", "new-passphrase");
        let err = run_rekey(vec![plain_path.display().to_string()])
            .expect_err("plaintext must refuse");
        assert!(err.contains("PLAINTEXT"), "got: {err}");

        // Refusal: old == new.
        std::env::set_var("ELARA_NEW_PASSPHRASE", "old-passphrase");
        let err =
            run_rekey(vec![id_path.display().to_string()]).expect_err("same pass must refuse");
        assert!(err.contains("nothing to rotate"), "got: {err}");

        // Refusal: wrong old passphrase — disk untouched.
        std::env::set_var("ELARA_OLD_PASSPHRASE", "wrong");
        std::env::set_var("ELARA_NEW_PASSPHRASE", "new-passphrase");
        let err = run_rekey(vec![id_path.display().to_string()])
            .expect_err("wrong old must refuse");
        assert!(err.contains("decrypt with OLD"), "got: {err}");
        let still = read_identity_file(&id_path).expect("read");
        Identity::from_encrypted_json(&still, b"old-passphrase")
            .expect("file must still open with the ORIGINAL passphrase after a refused rekey");

        // The real rotation.
        std::env::set_var("ELARA_OLD_PASSPHRASE", "old-passphrase");
        std::env::set_var("ELARA_NEW_PASSPHRASE", "new-passphrase");
        run_rekey(vec![id_path.display().to_string()]).expect("rekey");
        let rotated = read_identity_file(&id_path).expect("read rotated");
        let opened = Identity::from_encrypted_json(&rotated, b"new-passphrase")
            .expect("opens with NEW passphrase");
        assert_eq!(opened.identity_hash, identity.identity_hash, "same identity");
        assert!(
            Identity::from_encrypted_json(&rotated, b"old-passphrase").is_err(),
            "old passphrase must no longer open the file"
        );
        // A backup with the old encryption exists alongside.
        let baks: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("bak-rekey-"))
            .collect();
        assert_eq!(baks.len(), 1, "exactly one backup");

        std::env::remove_var("ELARA_OLD_PASSPHRASE");
        std::env::remove_var("ELARA_NEW_PASSPHRASE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pubkey_strips_secret_material() {
        let dir = tmp_dir("pubkey_strip");
        let id_path = dir.join("ident.json");
        let pub_path = dir.join("pub.json");

        run_gen(GenArgs {
            output: id_path.clone(),
            profile: CryptoProfile::ProfileB,
            entity: EntityType::Human,
            difficulty: 0,
            quiet: true,
        })
        .expect("gen");

        run_pubkey(PubkeyArgs {
            input: id_path.clone(),
            output: Some(pub_path.clone()),
            quiet: true,
        })
        .expect("pubkey");

        let pub_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&pub_path).unwrap()).unwrap();
        let pub_obj = pub_json.as_object().unwrap();
        assert!(
            !pub_obj.contains_key("secret_key"),
            "publishable JSON must NOT contain secret_key"
        );
        assert!(
            !pub_obj.contains_key("sphincs_secret_key"),
            "publishable JSON must NOT contain sphincs_secret_key"
        );
        assert!(pub_obj.contains_key("public_key"));
        assert!(pub_obj.contains_key("identity_hash"));

        let src_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&id_path).unwrap()).unwrap();
        assert!(
            src_json.as_object().unwrap().contains_key("secret_key"),
            "source identity file must still contain secret_key after pubkey emit"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&pub_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "pub file must be 0o644, got 0o{:o}", mode);
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pubkey_refuses_to_overwrite_output() {
        let dir = tmp_dir("pubkey_overwrite");
        let id_path = dir.join("ident.json");
        let pub_path = dir.join("pub.json");

        run_gen(GenArgs {
            output: id_path.clone(),
            profile: CryptoProfile::ProfileB,
            entity: EntityType::Human,
            difficulty: 0,
            quiet: true,
        })
        .expect("gen");

        std::fs::write(&pub_path, "{}").unwrap();
        let err = run_pubkey(PubkeyArgs {
            input: id_path,
            output: Some(pub_path),
            quiet: true,
        })
        .unwrap_err();
        assert!(err.contains("refusing to overwrite"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // ─── verify negative cases ────────────────────────────────────────────

    #[test]
    fn verify_rejects_unparseable_file() {
        let dir = tmp_dir("verify_bad");
        let bad = dir.join("bad.json");
        std::fs::write(&bad, b"not json at all").unwrap();

        let err = run_verify(vec![bad.to_str().unwrap().to_string()]).unwrap_err();
        assert!(
            err.contains("parse") || err.contains("invalid identity"),
            "expected parse/invalid error, got: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verify_requires_exactly_one_path() {
        let err = run_verify(vec![]).unwrap_err();
        assert!(err.contains("exactly one path"), "{err}");

        let err = run_verify(vec!["a.json".into(), "b.json".into()]).unwrap_err();
        assert!(err.contains("exactly one path"), "{err}");
    }

    #[test]
    fn read_identity_file_rejects_non_object_root() {
        let dir = tmp_dir("read_non_object");
        let p = dir.join("array.json");
        std::fs::write(&p, b"[]").unwrap();

        let err = read_identity_file(&p).unwrap_err();
        assert!(err.contains("not a JSON object"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // ─── fresh axes on parse_gen / parse_pubkey ────

    #[test]
    fn batch_b_parse_gen_combined_flags_in_arbitrary_order_yield_equal_args() {
        // The while-let argument loop is order-independent: each flag sets
        // its own field and falls through. Flip the order; result must match.
        let g1 = parse_gen(args(&[
            "--output", "/tmp/x.json",
            "--profile", "B",
            "--entity", "device",
            "--pow-difficulty", "5",
            "--quiet",
        ]))
        .unwrap();
        let g2 = parse_gen(args(&[
            "--quiet",
            "--pow-difficulty", "5",
            "--entity", "device",
            "--profile", "B",
            "--output", "/tmp/x.json",
        ]))
        .unwrap();
        assert_eq!(g1.output, g2.output);
        assert_eq!(format!("{:?}", g1.profile), format!("{:?}", g2.profile));
        assert_eq!(format!("{:?}", g1.entity), format!("{:?}", g2.entity));
        assert_eq!(g1.difficulty, g2.difficulty);
        assert_eq!(g1.quiet, g2.quiet);
        assert_eq!(g1.difficulty, 5);
        assert!(g1.quiet);
    }

    #[test]
    fn batch_b_parse_gen_duplicate_flag_last_value_wins_across_all_fields() {
        // The parser overwrites each field on every match — no first-wins
        // or "duplicate flag" rejection. Pin this across every overridable
        // field so a future "reject duplicate" refactor that breaks shell
        // pipelines surfaces with a named test.
        let g = parse_gen(args(&[
            "--output", "/tmp/a.json",
            "--output", "/tmp/b.json",
            "--profile", "A",
            "--profile", "C",
            "--entity", "human",
            "--entity", "device",
            "--pow-difficulty", "1",
            "--pow-difficulty", "7",
        ]))
        .unwrap();
        assert_eq!(g.output, PathBuf::from("/tmp/b.json"));
        assert!(matches!(g.profile, CryptoProfile::ProfileC));
        assert!(matches!(g.entity, EntityType::Device));
        assert_eq!(g.difficulty, 7);
    }

    #[test]
    fn batch_b_parse_gen_difficulty_explicit_values_round_trip_across_span() {
        // `parse_gen_difficulty_at_max_accepted` pins MAX. `parse_gen_defaults_when_only_output_given`
        // covers the implicit-default 0. This axis pins the EXPLICIT path
        // across the rest of the span — boundary 0, low, mid, MAX-1 — so a
        // future swap of `parse::<u8>` → `parse::<i8>` or a flip of the
        // comparator from `> MAX` to `>= MAX` is caught.
        for d in [
            0_u8,
            1,
            5,
            MAX_POW_DIFFICULTY / 2,
            MAX_POW_DIFFICULTY.saturating_sub(1),
        ] {
            let g = parse_gen(args(&[
                "--output",
                "/tmp/x.json",
                "--pow-difficulty",
                &d.to_string(),
            ]))
            .unwrap();
            assert_eq!(g.difficulty, d, "explicit --pow-difficulty {d}");
        }
    }

    #[test]
    fn batch_b_parse_pubkey_positional_before_or_after_flags_both_accepted() {
        // The positional arm sits in the catch-all `other =>` after the
        // `--`-prefix arm, so it works regardless of where the positional
        // sits among flags. Pin both orderings — positional-first and
        // positional-last — produce the same struct.
        let p1 = parse_pubkey(args(&["in.json", "--output", "out.json"])).unwrap();
        let p2 = parse_pubkey(args(&["--output", "out.json", "in.json"])).unwrap();
        assert_eq!(p1.input, PathBuf::from("in.json"));
        assert_eq!(p1.output, Some(PathBuf::from("out.json")));
        assert!(!p1.quiet);
        assert_eq!(p2.input, PathBuf::from("in.json"));
        assert_eq!(p2.output, Some(PathBuf::from("out.json")));
        assert!(!p2.quiet);
    }

    #[test]
    fn batch_b_parse_quiet_flag_is_idempotent_under_repetition() {
        // `--quiet` sets a bool; repeating it must not error or flip state.
        // Pin on both parsers so a future migration to a counter (--quiet --quiet
        // = verbosity level 2) breaks visibly here.
        let g = parse_gen(args(&[
            "--output", "/tmp/x.json",
            "--quiet", "--quiet", "--quiet",
        ]))
        .unwrap();
        assert!(g.quiet, "--quiet repeated must remain true: {:?}", g.quiet);

        let p = parse_pubkey(args(&["in.json", "--quiet", "--quiet"])).unwrap();
        assert!(p.quiet, "--quiet repeated on pubkey must remain true");
    }

    #[test]
    fn run_with_args_unknown_subcommand_returns_err() {
        let err = run_with_args(args(&["frobnicate"])).unwrap_err();
        assert!(err.contains("unknown subcommand"), "{err}");
        assert!(err.contains("frobnicate"), "{err}");
    }

    #[test]
    fn run_with_args_flag_without_subcommand_routes_to_gen() {
        // --output missing a path produces a gen parse error, not an unknown-
        // subcommand error — confirming the flag-first path still reaches gen.
        let err = run_with_args(args(&["--output"])).unwrap_err();
        assert!(!err.contains("unknown subcommand"), "{err}");
    }

    // ─── fips205 — a fresh FIPS 205 second-leg key ────────────────────────

    fn profile_a_file(dir: &Path) -> PathBuf {
        let path = dir.join("ident.json");
        run_gen(GenArgs {
            output: path.clone(),
            profile: CryptoProfile::ProfileA,
            entity: EntityType::Device,
            difficulty: 0,
            quiet: true,
        })
        .expect("gen");
        path
    }

    #[test]
    fn fips205_writes_a_new_file_and_leaves_the_source_alone() {
        let dir = tmp_dir("fips205");
        let src = profile_a_file(&dir);
        let before = std::fs::read(&src).unwrap();
        let out = dir.join("fips205.json");

        run_fips205(Fips205Args { input: src.clone(), output: out.clone(), quiet: true })
            .expect("fips205");

        assert_eq!(std::fs::read(&src).unwrap(), before, "the source file is never changed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "identity file must be 0o600, got 0o{mode:o}");
        }
        let old = Identity::from_json(&read_identity_file(&src).unwrap()).unwrap();
        let new = Identity::from_json(&read_identity_file(&out).unwrap()).unwrap();
        assert_eq!(new.identity_hash, old.identity_hash);
        assert_eq!(new.public_key, old.public_key);
        assert_eq!(new.sphincs_suite(), SphincsSuite::Fips205);
        assert_ne!(new.sphincs_public_key(), old.sphincs_public_key());
        new.check_fips205_key().expect("the new key passes the FIPS 205 key check");
        run_verify(vec![out.display().to_string()]).expect("verify reads the new file");

        let err = run_fips205(Fips205Args { input: src, output: out, quiet: true }).unwrap_err();
        assert!(err.contains("refusing to overwrite"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fips205_keeps_an_encrypted_file_encrypted() {
        let id = Identity::generate_with_pow(EntityType::Device, CryptoProfile::ProfileA, 0)
            .expect("gen identity");
        let data = id.to_encrypted_json(b"pass").expect("encrypt");

        let err = fips205_file(&data, None).unwrap_err();
        assert!(err.contains("ELARA_IDENTITY_PASSPHRASE"), "{err}");
        assert!(fips205_file(&data, Some(b"wrong")).is_err());

        let (file, hash) = fips205_file(&data, Some(b"pass")).expect("fips205");
        assert_eq!(hash, id.identity_hash);
        assert!(is_encrypted_identity(&file));
        assert_eq!(file["sphincs_suite"], SphincsSuite::Fips205.tag());
        assert!(!file.contains_key("secret_key"));
        assert!(!file.contains_key("sphincs_secret_key"));
        let back = Identity::from_encrypted_json(&file, b"pass").expect("decrypt");
        back.check_fips205_key().expect("the new key passes the FIPS 205 key check");
    }

    #[test]
    fn fips205_refuses_what_cannot_take_a_second_leg_key() {
        let a = Identity::generate_with_pow(EntityType::Device, CryptoProfile::ProfileA, 0)
            .expect("gen A");
        let b = Identity::generate_with_pow(EntityType::Device, CryptoProfile::ProfileB, 0)
            .expect("gen B");
        let (fresh, _) = fips205_file(&a.to_json(), None).expect("fips205");
        for (data, why) in [
            (b.to_json(), "Profile B"),
            (a.public_identity().to_json(), "a public-only file"),
            (fresh, "a file that already holds a FIPS 205 key"),
        ] {
            let err = fips205_file(&data, None).unwrap_err();
            assert!(err.contains("no FIPS 205 key written"), "{why}: {err}");
        }
    }

    #[test]
    fn parse_fips205_needs_a_path_and_an_output() {
        let err = parse_fips205(args(&["in.json"])).unwrap_err();
        assert!(err.contains("--output"), "{err}");
        let err = parse_fips205(args(&["--output", "out.json"])).unwrap_err();
        assert!(err.contains("path argument"), "{err}");
        let f = parse_fips205(args(&["in.json", "--output", "out.json", "--quiet"])).unwrap();
        assert_eq!(f.input, PathBuf::from("in.json"));
        assert_eq!(f.output, PathBuf::from("out.json"));
        assert!(f.quiet);
        let err = run_with_args(args(&["fips205", "in.json", "--output"])).unwrap_err();
        assert!(err.contains("--output requires a path"), "{err}");
    }
}
