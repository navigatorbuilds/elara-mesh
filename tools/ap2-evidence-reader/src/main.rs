//! ap2-evidence-reader — independent, fail-closed reader for `ap2-evidence-pack/1.0`,
//! written from SPEC_AP2_EVIDENCE.md alone (the reference implementation was never read).
//!
//!   ap2-evidence-reader verify <pack.json> [--policy <x.expected.json>] [--pins <json>]
//!                              [--require-producer] [--require-pq] [--require-anchor]
//!                              [--tsa-root <cert.pem|der>]
//!   ap2-evidence-reader conformance <dir> [--tsa-root <cert>]
//!   ap2-evidence-reader rfc3161 <token.tsr> <digest-hex> [--tsa-root <cert>]

mod der;
mod json;
mod pack;
mod producer;
mod rfc3161;
mod sdjwt;

use json::Value;
use pack::{Policy, NORMATIVE_FIELDS};
use std::path::{Path, PathBuf};
use std::process::exit;

fn usage() -> ! {
    eprintln!(
        "usage:\n  ap2-evidence-reader verify <pack.json> [--policy <expected.json>] [--pins <json>] [--require-producer] [--require-pq] [--require-anchor] [--tsa-root <cert>]\n  ap2-evidence-reader conformance <vectors-dir> [--tsa-root <cert>]\n  ap2-evidence-reader rfc3161 <token.tsr> <digest-hex> [--tsa-root <cert>]"
    );
    exit(2)
}

fn read(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            exit(2)
        }
    }
}

fn read_text(path: &Path) -> String {
    match String::from_utf8(read(path)) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("{} is not UTF-8 (the container MUST be UTF-8)", path.display());
            exit(2)
        }
    }
}

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    if i + 1 >= args.len() {
        usage();
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Some(v)
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == name) {
        args.remove(i);
        true
    } else {
        false
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = if args.is_empty() { usage() } else { args.remove(0) };
    let tsa_root: Option<Vec<u8>> = take_opt(&mut args, "--tsa-root").map(|p| read(Path::new(&p)));
    match cmd.as_str() {
        "verify" => cmd_verify(args, tsa_root.as_deref()),
        "conformance" => cmd_conformance(args, tsa_root.as_deref()),
        "rfc3161" => cmd_rfc3161(args, tsa_root.as_deref()),
        _ => usage(),
    }
}

fn cmd_verify(mut args: Vec<String>, tsa_root: Option<&[u8]>) {
    let mut policy = Policy::default();
    if let Some(p) = take_opt(&mut args, "--policy") {
        let exp = json::parse(&read_text(Path::new(&p))).unwrap_or_else(|e| {
            eprintln!("policy file: {e}");
            exit(2)
        });
        let block = exp.get("policy").unwrap_or(&exp);
        policy = Policy::from_expected(block).unwrap_or_else(|e| {
            eprintln!("policy: {e}");
            exit(2)
        });
    }
    if let Some(p) = take_opt(&mut args, "--pins") {
        let v = json::parse(&read_text(Path::new(&p))).unwrap_or_else(|e| {
            eprintln!("pins file: {e}");
            exit(2)
        });
        policy.pins = Some(pack::parse_pins(&v).unwrap_or_else(|e| {
            eprintln!("pins: {e}");
            exit(2)
        }));
    }
    policy.require_producer |= take_flag(&mut args, "--require-producer");
    policy.require_pq |= take_flag(&mut args, "--require-pq");
    policy.require_anchor |= take_flag(&mut args, "--require-anchor");
    if args.len() != 1 {
        usage();
    }
    let text = read_text(Path::new(&args[0]));
    match pack::verify_pack(&text, &policy, tsa_root) {
        Ok(v) => {
            let out = Value::obj(vec![("normative", v.normative()), ("diagnostics", v.diagnostics())]);
            println!("{}", json::canonical(&out));
            exit(if v.valid { 0 } else { 1 })
        }
        Err(e) => {
            println!(
                "{}",
                json::canonical(&Value::obj(vec![
                    ("normative", Value::obj(vec![("valid", Value::Bool(false))])),
                    ("parse_error", Value::str(&e)),
                ]))
            );
            exit(1)
        }
    }
}

fn cell(v: Option<&Value>) -> String {
    match v {
        Some(Value::Bool(true)) => "true".into(),
        Some(Value::Bool(false)) => "false".into(),
        Some(Value::Null) => "null".into(),
        Some(other) => json::canonical(other),
        None => "—".into(),
    }
}

fn cmd_conformance(args: Vec<String>, tsa_root: Option<&[u8]>) {
    if args.len() != 1 {
        usage();
    }
    let dir = PathBuf::from(&args[0]);
    let mut names: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter_map(|f| f.strip_suffix(".expected.json").map(String::from))
            .collect(),
        Err(e) => {
            eprintln!("cannot list {}: {e}", dir.display());
            exit(2)
        }
    };
    names.sort();
    if names.is_empty() {
        eprintln!("no *.expected.json in {}", dir.display());
        exit(2)
    }
    struct Row {
        name: String,
        expected: Value,
        ours: Value,
        mismatches: Vec<String>,
        requires: Vec<String>,
        reasons: Vec<String>,
    }
    let mut rows: Vec<Row> = Vec::new();
    for name in &names {
        let exp = json::parse(&read_text(&dir.join(format!("{name}.expected.json")))).unwrap_or_else(|e| {
            eprintln!("{name}.expected.json: {e}");
            exit(2)
        });
        let policy = Policy::from_expected(exp.get("policy").unwrap_or(&Value::Obj(vec![]))).unwrap_or_else(|e| {
            eprintln!("{name}: policy: {e}");
            exit(2)
        });
        let requires: Vec<String> = exp
            .get("requires")
            .and_then(Value::as_arr)
            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default();
        let expected = exp.get("normative").cloned().unwrap_or(Value::Obj(vec![]));
        let text = read_text(&dir.join(format!("{name}.json")));
        let (ours, reasons) = match pack::verify_pack(&text, &policy, tsa_root) {
            Ok(v) => (v.normative(), v.reasons.clone()),
            Err(e) => (Value::obj(vec![("valid", Value::Bool(false))]), vec![format!("parse error: {e}")]),
        };
        let mismatches: Vec<String> = NORMATIVE_FIELDS
            .iter()
            .filter(|f| expected.get(f) != ours.get(f))
            .map(|f| format!("{f}: expected {} got {}", cell(expected.get(f)), cell(ours.get(f))))
            .collect();
        rows.push(Row { name: name.clone(), expected, ours, mismatches, requires, reasons });
    }

    let mut all_ok = true;
    println!("### ap2-evidence-pack/1.0 conformance — ap2-evidence-reader (Rust, spec-derived)\n");
    println!("| vector | expected `valid` | ours | fields reproduced | requires | notes |");
    println!("|---|---|---|---|---|---|");
    for r in &rows {
        let n_ok = NORMATIVE_FIELDS.len() - r.mismatches.len();
        if !r.mismatches.is_empty() {
            all_ok = false;
        }
        let verdict = |v: &Value| match v.get("valid") {
            Some(Value::Bool(true)) => "ACCEPT",
            _ => "REJECT",
        };
        let note = if r.mismatches.is_empty() {
            r.reasons
                .iter()
                .find(|s| !s.starts_with("diagnostic"))
                .cloned()
                .unwrap_or_else(|| "—".into())
        } else {
            r.mismatches.join("; ")
        };
        println!(
            "| `{}` | {} | {} | {}/{} {} | {} | {} |",
            r.name,
            verdict(&r.expected),
            verdict(&r.ours),
            n_ok,
            NORMATIVE_FIELDS.len(),
            if r.mismatches.is_empty() { "✓" } else { "✗" },
            if r.requires.is_empty() { "—".to_string() } else { r.requires.join(", ") },
            note.replace('|', "\\|")
        );
    }
    println!("\n<details><summary>All 11 normative fields × {} vectors (ours; ✗ marks a divergence from the expected block)</summary>\n", rows.len());
    print!("| field |");
    for r in &rows {
        print!(" `{}` |", r.name);
    }
    println!();
    print!("|---|");
    for _ in &rows {
        print!("---|");
    }
    println!();
    for f in NORMATIVE_FIELDS {
        print!("| `{f}` |");
        for r in &rows {
            let mine = r.ours.get(f);
            let mark = if r.expected.get(f) == mine { "" } else { " ✗" };
            print!(" {}{mark} |", cell(mine));
        }
        println!();
    }
    println!("\n</details>");
    println!(
        "\n**{}** — {} of {} vectors reproduce every normative field.",
        if all_ok { "CONFORMANT" } else { "DIVERGENT" },
        rows.iter().filter(|r| r.mismatches.is_empty()).count(),
        rows.len()
    );
    exit(if all_ok { 0 } else { 1 })
}

fn cmd_rfc3161(args: Vec<String>, tsa_root: Option<&[u8]>) {
    if args.len() != 2 {
        usage();
    }
    let token = read(Path::new(&args[0]));
    let digest = hex::decode(&args[1]).unwrap_or_else(|e| {
        eprintln!("digest hex: {e}");
        exit(2)
    });
    match rfc3161::verify_token(&token, &digest, tsa_root) {
        rfc3161::Outcome::Verified => {
            println!("VERIFIED: granted, imprint matches, CMS signature valid, signer chains to the supplied root");
            exit(0)
        }
        rfc3161::Outcome::Unverifiable(w) => {
            println!("UNVERIFIABLE (null): {w}");
            exit(3)
        }
        rfc3161::Outcome::Failed(w) => {
            println!("FAILED (false): {w}");
            exit(1)
        }
    }
}
