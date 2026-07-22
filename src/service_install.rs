//! Ship-with-the-code service installation: `elara-node --install-service`
//! registers the node with the operating system so it starts on boot and
//! restarts on failure — no manual unit files, no operator homework.
//!
//! Platform behavior (one flag, per-platform mechanics):
//! - **Linux + systemd**: writes `/etc/systemd/system/elara-node.service`
//!   when root, else a per-user unit under `~/.config/systemd/user` (with a
//!   lingering hint so the user manager outlives logout), then
//!   `daemon-reload` + `enable --now`.
//! - **WSL2 + systemd**: same unit as Linux, PLUS a Windows-side logon wake
//!   entry (a `.bat` in the Windows Startup folder running
//!   `wsl.exe -d <distro> --exec true`) — WSL only boots on first use, so
//!   without the wake entry a reboot leaves the distro (and the node) down.
//! - **Windows (native)**: a logon autostart entry (`.bat` in the Startup
//!   folder launching the exe minimized). Full Service-Control-Manager
//!   integration is roadmap; the autostart entry gives reboot survival today.
//!
//! The installed invocation reproduces the operator's current command line
//! (config/data-dir/listen flags) minus the service-management flags, so the
//! service runs exactly the node that was foregrounded when installed.
//! Everything supports `--service-dry-run`, which prints each action —
//! including full file contents — without executing anything.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::errors::{ElaraError, Result};

pub const UNIT_NAME: &str = "elara-node.service";
const WSL_WAKE_BAT: &str = "elara-wsl-autostart.bat";
#[cfg(windows)] // consumed only by the Platform::WindowsNative install arm
const WIN_START_BAT: &str = "elara-node-autostart.bat";

/// Flags owned by this module: stripped from the re-emitted invocation so the
/// installed service never re-runs the installer.
const SERVICE_FLAGS: &[&str] = &[
    "--install-service",
    "--uninstall-service",
    "--service-status",
    "--service-dry-run",
    "--no-windows-autostart",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    LinuxSystemd,
    Wsl2Systemd,
    WindowsNative,
    Unsupported,
}

pub fn detect_platform() -> Platform {
    if cfg!(windows) {
        return Platform::WindowsNative;
    }
    let wsl = std::env::var_os("WSL_DISTRO_NAME").is_some()
        || std::fs::read_to_string("/proc/version")
            .map(|v| v.to_lowercase().contains("microsoft"))
            .unwrap_or(false);
    let systemd = Path::new("/run/systemd/system").is_dir();
    match (wsl, systemd) {
        (true, true) => Platform::Wsl2Systemd,
        (false, true) => Platform::LinuxSystemd,
        _ => Platform::Unsupported,
    }
}

/// The operator's invocation with service-management flags removed, ready to
/// embed in the unit / autostart entry.
pub fn sanitized_args(raw: impl Iterator<Item = String>) -> Vec<String> {
    raw.filter(|a| {
        let flag = a.split('=').next().unwrap_or(a);
        !SERVICE_FLAGS.contains(&flag)
    })
    .collect()
}

fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| {
            if p.is_empty() || p.chars().any(|c| c.is_whitespace() || "\"'`$\\".contains(c)) {
                format!("\"{}\"", p.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                p.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `ELARA_*` environment of the installing invocation, sorted for
/// deterministic unit output. systemd services do not inherit the operator's
/// shell environment, so env-driven config (the QUICKSTART path) must be
/// snapshotted into the unit explicitly.
pub fn elara_env_snapshot() -> Vec<(String, String)> {
    let mut vars: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| k.starts_with("ELARA_"))
        .collect();
    vars.sort();
    vars
}

/// systemd unit content. Pure function — pinned by unit tests.
pub fn unit_file_content(
    exe: &Path,
    args: &[String],
    env: &[(String, String)],
    workdir: &Path,
    system_mode: bool,
) -> String {
    let exec_start = if args.is_empty() {
        shell_join(&[exe.display().to_string()])
    } else {
        format!(
            "{} {}",
            shell_join(&[exe.display().to_string()]),
            shell_join(args)
        )
    };
    let env_lines: String = env
        .iter()
        .map(|(k, v)| format!("Environment=\"{k}={v}\"\n"))
        .collect();
    let wanted_by = if system_mode {
        "multi-user.target"
    } else {
        "default.target"
    };
    format!(
        "[Unit]\n\
         Description=Elara Protocol node (installed by --install-service)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         # Crash-loop bound for the state_core WorkerPanicAbort guard: interval MUST\n\
         # exceed (StartLimitBurst-1)*RestartSec = 20s or a deterministic worker panic\n\
         # (process::abort) restarts forever instead of paging (systemd default 10s is\n\
         # below that floor). See src/network/state_core.rs.\n\
         StartLimitIntervalSec=30\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         WorkingDirectory={workdir}\n\
         ExecStart={exec_start}\n\
         {env_lines}\
         Restart=on-failure\n\
         RestartSec=5\n\
         # RocksDB SST/WAL fds + the connection-admission DEFAULTS (pq_serve_concurrency\n\
         # 4096 + http_conn_cap 1024, both hardcoded as fractions of 65536 in config.rs)\n\
         # far exceed systemd's default 1024-fd soft limit — without this a fresh node\n\
         # hits EMFILE under fan-in and the gossip layer goes silently deaf. Raise it.\n\
         LimitNOFILE=65536\n\
         \n\
         [Install]\n\
         WantedBy={wanted_by}\n",
        workdir = workdir.display(),
    )
}

/// Windows-side wake entry for WSL2: boots the distro at logon so systemd
/// (and the node unit) come up without a terminal.
pub fn wsl_wake_bat_content(distro: &str) -> String {
    format!("@echo off\r\nwsl.exe -d {distro} --exec true\r\n")
}

/// Native-Windows logon autostart entry.
pub fn windows_start_bat_content(exe: &Path, args: &[String], env: &[(String, String)]) -> String {
    let arg_str = if args.is_empty() {
        String::new()
    } else {
        format!(" {}", shell_join(args))
    };
    let env_lines: String = env
        .iter()
        .map(|(k, v)| format!("set \"{k}={v}\"\r\n"))
        .collect();
    format!(
        "@echo off\r\n{env_lines}start \"elara-node\" /min \"{}\"{arg_str}\r\n",
        exe.display()
    )
}

fn is_root() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(not(unix))]
    false
}

struct Ctx {
    dry_run: bool,
}

impl Ctx {
    fn act(&self, description: &str, f: impl FnOnce() -> Result<()>) -> Result<()> {
        if self.dry_run {
            println!("[dry-run] {description}");
            return Ok(());
        }
        println!("{description}");
        f()
    }

    fn systemctl(&self, user_mode: bool, args: &[&str]) -> Result<()> {
        let mut display = String::from("systemctl ");
        if user_mode {
            display.push_str("--user ");
        }
        display.push_str(&args.join(" "));
        self.act(&format!("run: {display}"), || {
            let mut cmd = Command::new("systemctl");
            if user_mode {
                cmd.arg("--user");
            }
            let out = cmd
                .args(args)
                .output()
                .map_err(|e| ElaraError::Config(format!("failed to run systemctl: {e}")))?;
            if !out.status.success() {
                return Err(ElaraError::Config(format!(
                    "`{display}` failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            Ok(())
        })
    }
}

fn unit_path(system_mode: bool) -> Result<PathBuf> {
    if system_mode {
        Ok(PathBuf::from("/etc/systemd/system").join(UNIT_NAME))
    } else {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| ElaraError::Config("HOME not set; cannot install user unit".into()))?;
        Ok(PathBuf::from(home)
            .join(".config/systemd/user")
            .join(UNIT_NAME))
    }
}

/// Resolve the Windows Startup folder from inside WSL2 via `%APPDATA%`.
/// Best-effort: returns None (with a printed reason) when the boundary
/// cannot be crossed — the systemd install is still complete without it.
fn wsl_windows_startup_dir() -> Option<PathBuf> {
    let out = Command::new("cmd.exe")
        .args(["/c", "echo %APPDATA%"])
        .output()
        .ok()?;
    let appdata_win = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if appdata_win.is_empty() || appdata_win.contains('%') {
        return None;
    }
    let out = Command::new("wslpath").args(["-u", &appdata_win]).output().ok()?;
    let appdata = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if appdata.is_empty() {
        return None;
    }
    let dir = PathBuf::from(appdata).join("Microsoft/Windows/Start Menu/Programs/Startup");
    dir.is_dir().then_some(dir)
}

#[cfg(windows)]
fn native_windows_startup_dir() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    let dir = PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    dir.is_dir().then_some(dir)
}

fn write_file(ctx: &Ctx, path: &Path, content: &str) -> Result<()> {
    ctx.act(
        &format!("write {} ({} bytes):\n---\n{content}---", path.display(), content.len()),
        || {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, content)?;
            Ok(())
        },
    )
}

pub struct ServiceOpts {
    pub dry_run: bool,
    pub windows_autostart: bool,
}

/// `--install-service` entry point. Exits the process' purpose after this —
/// the caller returns immediately.
pub fn install(opts: &ServiceOpts) -> Result<()> {
    let ctx = Ctx { dry_run: opts.dry_run };
    let platform = detect_platform();
    let exe = std::env::current_exe()
        .map_err(|e| ElaraError::Config(format!("cannot resolve own executable path: {e}")))?;
    let workdir = std::env::current_dir()
        .map_err(|e| ElaraError::Config(format!("cannot resolve working directory: {e}")))?;
    let args = sanitized_args(std::env::args().skip(1));
    let env = elara_env_snapshot();
    if !env.is_empty() {
        println!(
            "snapshotting {} ELARA_* environment variable(s) into the service definition",
            env.len()
        );
    }

    println!("platform: {platform:?}");
    match platform {
        Platform::LinuxSystemd | Platform::Wsl2Systemd => {
            let system_mode = is_root();
            let path = unit_path(system_mode)?;
            write_file(
                &ctx,
                &path,
                &unit_file_content(&exe, &args, &env, &workdir, system_mode),
            )?;
            ctx.systemctl(!system_mode, &["daemon-reload"])?;
            ctx.systemctl(!system_mode, &["enable", "--now", UNIT_NAME])?;
            if !system_mode {
                println!(
                    "note: per-user unit installed. To keep it running without an active login \
                     session, run once: sudo loginctl enable-linger $USER"
                );
            }
            if platform == Platform::Wsl2Systemd {
                if opts.windows_autostart {
                    match wsl_windows_startup_dir() {
                        Some(dir) => {
                            let distro = std::env::var("WSL_DISTRO_NAME")
                                .unwrap_or_else(|_| "Ubuntu".to_string());
                            write_file(
                                &ctx,
                                &dir.join(WSL_WAKE_BAT),
                                &wsl_wake_bat_content(&distro),
                            )?;
                            println!(
                                "Windows logon wake entry installed — WSL (and this service) now \
                                 starts at Windows logon."
                            );
                        }
                        None => println!(
                            "warning: could not locate the Windows Startup folder from WSL; the \
                             systemd unit is installed, but WSL itself only boots on first use. \
                             Create a Startup entry running `wsl.exe --exec true` for zero-touch \
                             reboot recovery (or re-run with access to cmd.exe)."
                        ),
                    }
                } else {
                    println!("Windows logon wake entry skipped (--no-windows-autostart).");
                }
            }
            println!("service installed: {}", path.display());
        }
        Platform::WindowsNative => {
            #[cfg(windows)]
            {
                if !opts.windows_autostart {
                    return Err(ElaraError::Config(
                        "--no-windows-autostart leaves nothing to install on native Windows"
                            .into(),
                    ));
                }
                let dir = native_windows_startup_dir().ok_or_else(|| {
                    ElaraError::Config("cannot locate the Windows Startup folder (%APPDATA%)".into())
                })?;
                write_file(
                    &ctx,
                    &dir.join(WIN_START_BAT),
                    &windows_start_bat_content(&exe, &args, &env),
                )?;
                println!(
                    "logon autostart entry installed. Note: this starts the node at logon; full \
                     Windows service integration (start-before-logon) is on the roadmap."
                );
            }
            #[cfg(not(windows))]
            return Err(ElaraError::Config(
                "internal: WindowsNative platform reported on a non-Windows build".into(),
            ));
        }
        Platform::Unsupported => {
            return Err(ElaraError::Config(
                "no supported service manager found (systemd not running). Install manually or \
                 run the node under your init system of choice."
                    .into(),
            ));
        }
    }
    Ok(())
}

/// `--uninstall-service` entry point. Tolerates partial/absent installs.
pub fn uninstall(opts: &ServiceOpts) -> Result<()> {
    let ctx = Ctx { dry_run: opts.dry_run };
    match detect_platform() {
        Platform::LinuxSystemd | Platform::Wsl2Systemd => {
            // SVC-1: probe BOTH scopes like status() does — install() picks one
            // scope by is_root(), but a prior install may have used the other
            // (sudo install then non-root uninstall, or vice-versa). Removing
            // only the is_root()-selected scope while printing "uninstalled"
            // silently leaves the other unit enabled. Attempt each scope whose
            // unit is present; report per-scope; only claim success for what we
            // actually removed, and warn (non-fatal) about any we couldn't.
            let mut removed = 0usize;
            let mut left_behind: Vec<String> = Vec::new();
            for (label, system_mode) in [("system", true), ("user", false)] {
                let path = match unit_path(system_mode) {
                    Ok(p) => p,
                    Err(_) => continue, // e.g. user scope with no HOME
                };
                if !(path.exists() || ctx.dry_run) {
                    continue;
                }
                // Best-effort disable; not fatal if already absent.
                let _ = ctx.systemctl(!system_mode, &["disable", "--now", UNIT_NAME]);
                match ctx.act(&format!("remove {} unit {}", label, path.display()), || {
                    if path.exists() {
                        std::fs::remove_file(&path)?;
                    }
                    Ok(())
                }) {
                    Ok(()) => {
                        removed += 1;
                        let _ = ctx.systemctl(!system_mode, &["daemon-reload"]);
                    }
                    Err(e) => {
                        // Most likely EPERM removing /etc/systemd/system without
                        // root — surface it, do NOT claim success.
                        left_behind.push(format!(
                            "{label} unit {} ({e}) — re-run with sudo to remove it",
                            path.display()
                        ));
                    }
                }
            }
            if detect_platform() == Platform::Wsl2Systemd {
                if let Some(dir) = wsl_windows_startup_dir() {
                    let bat = dir.join(WSL_WAKE_BAT);
                    if bat.exists() || ctx.dry_run {
                        ctx.act(&format!("remove {}", bat.display()), || {
                            std::fs::remove_file(&bat)?;
                            Ok(())
                        })?;
                    }
                }
            }
            if !left_behind.is_empty() {
                for w in &left_behind {
                    eprintln!("WARNING: could not remove {w}");
                }
                return Err(ElaraError::Config(format!(
                    "uninstall incomplete: {} unit(s) still present (see warnings above)",
                    left_behind.len()
                )));
            }
            if removed == 0 && !ctx.dry_run {
                println!("no elara service units found (system or user) — nothing to uninstall.");
            } else {
                println!("service uninstalled ({removed} unit(s) removed).");
            }
        }
        Platform::WindowsNative => {
            #[cfg(windows)]
            {
                if let Some(dir) = native_windows_startup_dir() {
                    let bat = dir.join(WIN_START_BAT);
                    if bat.exists() || ctx.dry_run {
                        ctx.act(&format!("remove {}", bat.display()), || {
                            std::fs::remove_file(&bat)?;
                            Ok(())
                        })?;
                    }
                }
                println!("autostart entry removed (if present).");
            }
        }
        Platform::Unsupported => println!("nothing installed on this platform."),
    }
    Ok(())
}

/// `--service-status` entry point: reports without mutating.
pub fn status() -> Result<()> {
    let platform = detect_platform();
    println!("platform: {platform:?}");
    match platform {
        Platform::LinuxSystemd | Platform::Wsl2Systemd => {
            for (label, system_mode) in [("system", true), ("user", false)] {
                let path = match unit_path(system_mode) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let installed = path.exists();
                println!("{label} unit {}: {}", path.display(), if installed { "installed" } else { "absent" });
                if installed {
                    for verb in ["is-enabled", "is-active"] {
                        let mut cmd = Command::new("systemctl");
                        if !system_mode {
                            cmd.arg("--user");
                        }
                        if let Ok(out) = cmd.args([verb, UNIT_NAME]).output() {
                            println!(
                                "  {verb}: {}",
                                String::from_utf8_lossy(&out.stdout).trim()
                            );
                        }
                    }
                }
            }
            if platform == Platform::Wsl2Systemd {
                match wsl_windows_startup_dir() {
                    Some(dir) if dir.join(WSL_WAKE_BAT).exists() => {
                        println!("Windows logon wake entry: installed");
                    }
                    Some(_) => println!("Windows logon wake entry: absent"),
                    None => println!("Windows logon wake entry: unknown (cannot reach Startup folder)"),
                }
            }
        }
        Platform::WindowsNative => {
            #[cfg(windows)]
            match native_windows_startup_dir() {
                Some(dir) if dir.join(WIN_START_BAT).exists() => {
                    println!("logon autostart entry: installed")
                }
                Some(_) => println!("logon autostart entry: absent"),
                None => println!("logon autostart entry: unknown (%APPDATA% unresolved)"),
            }
        }
        Platform::Unsupported => println!("no supported service manager detected."),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_content_reproduces_invocation_and_restart_policy() {
        let exe = PathBuf::from("/opt/elara/elara-node");
        let args = vec![
            "--config".to_string(),
            "/etc/elara/elara-node.toml".to_string(),
            "--data-dir".to_string(),
            "/var/lib/elara".to_string(),
        ];
        let unit = unit_file_content(&exe, &args, &[], Path::new("/var/lib/elara"), true);
        assert!(unit.contains(
            "ExecStart=/opt/elara/elara-node --config /etc/elara/elara-node.toml --data-dir /var/lib/elara"
        ));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("RestartSec=5"));
        assert!(unit.contains("WorkingDirectory=/var/lib/elara"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        // network-online ordering is only effective when the target is pulled in.
        assert!(unit.contains("Wants=network-online.target"));
        // The node's connection-admission defaults are sized against 65536 fds; the
        // installed unit must raise the limit or a fresh node hits EMFILE under load.
        assert!(unit.contains("LimitNOFILE=65536"));
    }

    /// The generated unit MUST bound the WorkerPanicAbort crash-loop:
    /// `StartLimitIntervalSec` has to exceed `(StartLimitBurst-1)*RestartSec`, else
    /// a deterministic worker panic (which calls `std::process::abort()`) restarts
    /// forever instead of paging — systemd's default interval (10s) is BELOW that
    /// floor, which is exactly why the unit must set it explicitly. Pin the
    /// inequality against the emitted values so a future edit that lowers the
    /// interval or raises the burst/RestartSec is caught here, not in a fresh-node
    /// incident. Contract source: src/network/state_core.rs (WorkerPanicAbort).
    #[test]
    fn generated_unit_bounds_worker_panic_crash_loop() {
        let unit = unit_file_content(
            Path::new("/opt/elara/elara-node"),
            &[],
            &[],
            Path::new("/opt/elara"),
            true,
        );
        let val = |key: &str| -> u64 {
            unit.lines()
                .find_map(|l| {
                    l.trim()
                        .strip_prefix(key)?
                        .strip_prefix('=')?
                        .trim()
                        .parse::<u64>()
                        .ok()
                })
                .unwrap_or_else(|| panic!("unit missing numeric `{key}=`:\n{unit}"))
        };
        let interval = val("StartLimitIntervalSec");
        let burst = val("StartLimitBurst");
        let restart = val("RestartSec");
        let floor = (burst - 1) * restart;
        assert!(
            interval > floor,
            "StartLimitIntervalSec={interval} must exceed (StartLimitBurst-1)*RestartSec \
             = ({burst}-1)*{restart} = {floor}, or a deterministic panic crash-loops forever"
        );
    }

    #[test]
    fn user_mode_unit_targets_default_target() {
        let unit = unit_file_content(
            Path::new("/home/op/elara-node"),
            &[],
            &[],
            Path::new("/home/op"),
            false,
        );
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains("ExecStart=/home/op/elara-node\n"));
    }

    #[test]
    fn env_snapshot_renders_environment_lines_between_exec_and_restart() {
        let env = vec![
            ("ELARA_AUTO_WITNESS".to_string(), "true".to_string()),
            ("ELARA_GENESIS".to_string(), "abc123".to_string()),
        ];
        let unit = unit_file_content(
            Path::new("/opt/elara/elara-node"),
            &[],
            &env,
            Path::new("/opt/elara"),
            true,
        );
        assert!(unit.contains("Environment=\"ELARA_AUTO_WITNESS=true\"\n"));
        assert!(unit.contains("Environment=\"ELARA_GENESIS=abc123\"\n"));
        let exec_pos = unit.find("ExecStart=").unwrap();
        let env_pos = unit.find("Environment=").unwrap();
        let restart_pos = unit.find("Restart=on-failure").unwrap();
        assert!(exec_pos < env_pos && env_pos < restart_pos);
    }

    #[test]
    fn service_flags_are_stripped_from_reemitted_invocation() {
        let raw = [
            "--config",
            "x.toml",
            "--install-service",
            "--service-dry-run",
            "--no-windows-autostart",
            "--listen",
            "0.0.0.0:9473",
        ]
        .iter()
        .map(|s| s.to_string());
        let got = sanitized_args(raw);
        assert_eq!(got, vec!["--config", "x.toml", "--listen", "0.0.0.0:9473"]);
    }

    #[test]
    fn paths_with_spaces_are_quoted() {
        let unit = unit_file_content(
            Path::new("/opt/my apps/elara-node"),
            &["--config".to_string(), "/etc/my conf/n.toml".to_string()],
            &[],
            Path::new("/opt/my apps"),
            true,
        );
        assert!(unit.contains("ExecStart=\"/opt/my apps/elara-node\" --config \"/etc/my conf/n.toml\""));
    }

    #[test]
    fn wsl_wake_bat_names_the_distro() {
        let bat = wsl_wake_bat_content("Ubuntu-22.04");
        assert!(bat.contains("wsl.exe -d Ubuntu-22.04 --exec true"));
        assert!(bat.starts_with("@echo off"));
    }

    #[test]
    fn windows_start_bat_launches_minimized_with_args_and_env() {
        let bat = windows_start_bat_content(
            Path::new("C:\\Elara\\elara-node.exe"),
            &["--config".to_string(), "n.toml".to_string()],
            &[("ELARA_GENESIS".to_string(), "abc".to_string())],
        );
        assert!(bat.contains("set \"ELARA_GENESIS=abc\"\r\n"));
        assert!(bat.contains("start \"elara-node\" /min \"C:\\Elara\\elara-node.exe\" --config n.toml"));
    }

    #[test]
    fn detect_platform_runs_without_panicking() {
        let _ = detect_platform();
    }

    /// SVC-1: uninstall dry-run must complete without touching the real system.
    /// The dry-run path routes every removal + systemctl call through ctx.act's
    /// print-only branch, so this exercises the both-scopes loop end-to-end with
    /// no filesystem or systemd side effects, and asserts it never errors on the
    /// nothing-to-do case (the old code always printed success; the new code
    /// only errors when a real unit resists removal).
    #[test]
    fn uninstall_dry_run_is_side_effect_free_and_ok() {
        let opts = ServiceOpts { dry_run: true, windows_autostart: false };
        // Must return Ok on every platform (dry-run makes no real calls); the
        // key property is it does not panic and does not falsely error.
        assert!(uninstall(&opts).is_ok());
    }

    /// SVC-1: the fix depends on system and user scopes resolving to DISTINCT
    /// paths so uninstall can address both. Pin that invariant.
    #[test]
    fn system_and_user_unit_paths_are_distinct() {
        // user scope needs HOME; set a throwaway one for determinism.
        std::env::set_var("HOME", "/tmp/elara-svc-test-home");
        let sys = unit_path(true).expect("system path");
        let usr = unit_path(false).expect("user path");
        assert_ne!(sys, usr, "system and user unit paths must differ");
        assert!(sys.starts_with("/etc/systemd/system"));
        assert!(usr.to_string_lossy().contains(".config/systemd/user"));
    }
}
