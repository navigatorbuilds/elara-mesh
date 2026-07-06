//! ZSP Phase E Slice 3: durable persistence of the local node's zone
//! subscription set across restarts.
//!
//! The in-memory [`ZoneManager`](super::zone::ZoneManager) holds the set of
//! zones this node has chosen to store records for. Phase E Slice 1 added
//! the admin endpoints (`/admin/zones/subscribe`, `/admin/zones/unsubscribe`)
//! that mutate this set at runtime, but the manager was in-memory only — a
//! restart wiped operator-applied subscriptions, silently flipping the node
//! back to "accept all zones" (per the L523 ingest filter) and undoing the
//! disk-leak fix from Phases B/C/D.
//!
//! This module persists the subscription set to a JSON sidecar file
//! `{data_dir}/zone_subscriptions.json` so:
//!
//! 1. The file is human-readable for debugging / operator scripts.
//! 2. It avoids a RocksDB column-family migration (no schema change to
//!    the 28-CF layout, no ALL_CF_NAMES touch).
//! 3. Writes are atomic via tempfile + rename; a power-cut mid-write
//!    leaves either the previous good state or the new one, never half-
//!    written JSON.
//! 4. Corrupt or missing file falls back to an empty set with a warning,
//!    so a manual fsck on the file can never brick boot.
//!
//! Wire format: `{"version": 1, "zones": ["medical/eu", "trade/us"]}`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::zone::ZoneId;

const SUBSCRIPTIONS_FILE: &str = "zone_subscriptions.json";
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSubscriptions {
    version: u32,
    zones: Vec<String>,
}

/// Resolve the path to the subscriptions sidecar file under `data_dir`.
pub fn subscriptions_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SUBSCRIPTIONS_FILE)
}

/// Atomically write the subscription set to disk.
///
/// Writes to `{data_dir}/zone_subscriptions.json.tmp` then renames over the
/// real file, so a partial write cannot corrupt the previous good copy.
/// Creates `data_dir` if it does not exist (matches the existing identity /
/// vrf-key persistence pattern in this crate).
pub fn save_subscriptions(data_dir: &Path, subs: &HashSet<ZoneId>) -> std::io::Result<()> {
    if let Err(e) = std::fs::create_dir_all(data_dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }

    let mut zones: Vec<String> = subs.iter().map(|z| z.path().to_string()).collect();
    zones.sort();

    let body = PersistedSubscriptions {
        version: FORMAT_VERSION,
        zones,
    };
    let json = serde_json::to_string_pretty(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let final_path = subscriptions_path(data_dir);
    let tmp_path = data_dir.join(format!("{SUBSCRIPTIONS_FILE}.tmp"));
    std::fs::write(&tmp_path, json.as_bytes())?;
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

/// Read the persisted subscription set. Infallible from the caller's POV:
/// missing file, IO failure, or corrupt JSON all fall back to an empty set
/// with a warning logged. An empty set is the documented "accept all zones"
/// default per the L523 ingest filter, so a corrupt file produces the
/// pre-Phase-E-Slice-3 behavior — never bricks boot.
pub fn load_subscriptions(data_dir: &Path) -> HashSet<ZoneId> {
    let path = subscriptions_path(data_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HashSet::new(),
        Err(e) => {
            tracing::warn!(
                "zone_persist: failed to read {} ({e}) — falling back to empty (accept-all)",
                path.display()
            );
            return HashSet::new();
        }
    };

    let parsed: PersistedSubscriptions = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                "zone_persist: corrupt JSON at {} ({e}) — falling back to empty (accept-all)",
                path.display()
            );
            return HashSet::new();
        }
    };

    if parsed.version != FORMAT_VERSION {
        tracing::warn!(
            "zone_persist: unknown version {} at {} (expected {}) — falling back to empty",
            parsed.version,
            path.display(),
            FORMAT_VERSION
        );
        return HashSet::new();
    }

    // ZoneId::new is infallible — trims/normalizes; an empty entry becomes
    // "default" which is the protocol's root zone, also valid. Dedupe via
    // HashSet collect.
    parsed.zones.into_iter().map(|p| ZoneId::new(&p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn zone(p: &str) -> ZoneId {
        ZoneId::new(p)
    }

    #[test]
    fn round_trip_preserves_set() {
        let tmp = TempDir::new().unwrap();
        let mut subs = HashSet::new();
        subs.insert(zone("medical/eu"));
        subs.insert(zone("trade/us"));
        save_subscriptions(tmp.path(), &subs).unwrap();
        let loaded = load_subscriptions(tmp.path());
        assert_eq!(loaded, subs);
    }

    #[test]
    fn missing_file_returns_empty_set() {
        let tmp = TempDir::new().unwrap();
        let loaded = load_subscriptions(tmp.path());
        assert!(loaded.is_empty(), "missing file must yield empty set");
    }

    #[test]
    fn corrupt_json_falls_back_to_empty() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(subscriptions_path(tmp.path()), b"{not valid json").unwrap();
        let loaded = load_subscriptions(tmp.path());
        assert!(loaded.is_empty(), "corrupt file must yield empty set");
    }

    #[test]
    fn unknown_version_falls_back_to_empty() {
        let tmp = TempDir::new().unwrap();
        let body = serde_json::json!({"version": 99, "zones": ["medical/eu"]});
        std::fs::write(
            subscriptions_path(tmp.path()),
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        let loaded = load_subscriptions(tmp.path());
        assert!(loaded.is_empty(), "future-version file must yield empty");
    }

    #[test]
    fn empty_entry_normalizes_to_default_zone() {
        // ZoneId::new("") -> ZoneId("default"), per the existing newtype
        // constructor. Persistence preserves whatever round-trips through
        // that constructor; this guards against an accidental drift where
        // the file contains "" and someone later expects it to be filtered
        // (in which case both new() and load_subscriptions need updating
        // together).
        let tmp = TempDir::new().unwrap();
        let body = serde_json::json!({
            "version": 1,
            "zones": ["", "medical/eu"]
        });
        std::fs::write(
            subscriptions_path(tmp.path()),
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        let loaded = load_subscriptions(tmp.path());
        assert!(loaded.contains(&zone("medical/eu")));
        assert!(loaded.contains(&ZoneId::default_zone()));
    }

    #[test]
    fn empty_set_writes_valid_file() {
        let tmp = TempDir::new().unwrap();
        let subs = HashSet::new();
        save_subscriptions(tmp.path(), &subs).unwrap();
        let loaded = load_subscriptions(tmp.path());
        assert!(loaded.is_empty());
    }

    #[test]
    fn overwrite_replaces_previous_set() {
        let tmp = TempDir::new().unwrap();
        let mut a = HashSet::new();
        a.insert(zone("a"));
        a.insert(zone("b"));
        save_subscriptions(tmp.path(), &a).unwrap();

        let mut b = HashSet::new();
        b.insert(zone("c"));
        save_subscriptions(tmp.path(), &b).unwrap();

        let loaded = load_subscriptions(tmp.path());
        assert_eq!(loaded, b, "save must replace, not merge");
    }

    #[test]
    fn save_creates_data_dir_if_missing() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("does/not/exist/yet");
        let mut subs = HashSet::new();
        subs.insert(zone("x/y/z"));
        save_subscriptions(&nested, &subs).unwrap();
        let loaded = load_subscriptions(&nested);
        assert_eq!(loaded, subs);
    }

    #[test]
    fn output_is_deterministic_sorted() {
        let tmp = TempDir::new().unwrap();
        let mut subs = HashSet::new();
        subs.insert(zone("zzz"));
        subs.insert(zone("aaa"));
        subs.insert(zone("mmm"));
        save_subscriptions(tmp.path(), &subs).unwrap();
        let raw = std::fs::read_to_string(subscriptions_path(tmp.path())).unwrap();
        let pos_a = raw.find("aaa").unwrap();
        let pos_m = raw.find("mmm").unwrap();
        let pos_z = raw.find("zzz").unwrap();
        assert!(pos_a < pos_m && pos_m < pos_z, "zones must be sorted on disk");
    }

    // ─── fixture-free ────────────────────────────────────
    //
    // Five axes covering surface NOT covered by existing semantic tests:
    //   1. Constants strict-pin (SUBSCRIPTIONS_FILE filename, FORMAT_VERSION=1)
    //      + subscriptions_path component decomposition
    //   2. JSON wire-format byte-shape pin — {"version": 1, "zones": [...]}
    //      with pretty-print indentation + sorted entries
    //   3. Tempfile lifecycle: post-save the `.tmp` file MUST be gone
    //      (renamed atomically away)
    //   4. Version mismatch reject sweep at {0, 2, 100, u32::MAX}
    //      — anything != FORMAT_VERSION falls back to empty set
    //   5. Load deduplication: file with duplicate zone entries collapses
    //      to a single HashSet entry

    #[test]
    fn batch_b_constants_strict_pin_and_subscriptions_path_component_decomposition() {
        // Constants pin: drift here breaks operator runbooks + every
        // restart loads the wrong sidecar.
        assert_eq!(SUBSCRIPTIONS_FILE, "zone_subscriptions.json",
            "SUBSCRIPTIONS_FILE drift breaks operator scripts + sidecar discovery");
        assert_eq!(FORMAT_VERSION, 1,
            "FORMAT_VERSION drift breaks load_subscriptions version gate");

        // Type pin: FORMAT_VERSION is u32 (matches JSON wire format).
        let v: u32 = FORMAT_VERSION;
        assert_eq!(v, 1);

        // subscriptions_path returns data_dir + SUBSCRIPTIONS_FILE.
        let data_dir = Path::new("/tmp/elara-batch-b-zone-persist-test");
        let p = subscriptions_path(data_dir);
        let components: Vec<_> = p.components().collect();
        let last = components.last().expect("path must have at least one component");
        assert_eq!(last.as_os_str(), "zone_subscriptions.json",
            "subscriptions_path last component must equal SUBSCRIPTIONS_FILE");

        // Path starts with the data_dir (cross-platform parent check).
        assert!(p.starts_with(data_dir),
            "subscriptions_path must be under data_dir; got: {p:?}");
        assert_eq!(p.parent(), Some(data_dir),
            "parent of subscriptions_path must equal data_dir");
    }

    #[test]
    fn batch_b_json_wire_format_byte_shape_pin_with_pretty_print_and_sorted_entries() {
        // Wire format per module docs: {"version": 1, "zones": [sorted...]}
        // Pretty-printed (serde_json::to_string_pretty) so it's
        // human-readable for debugging / operator scripts (per docs §1).
        let tmp = TempDir::new().unwrap();
        let mut subs = HashSet::new();
        subs.insert(zone("zzz/last"));
        subs.insert(zone("aaa/first"));
        subs.insert(zone("mmm/middle"));
        save_subscriptions(tmp.path(), &subs).unwrap();

        let raw = std::fs::read_to_string(subscriptions_path(tmp.path())).unwrap();

        // Field name pin: snake_case (serde default).
        assert!(raw.contains("\"version\""),
            "JSON must contain `version` field name: {raw}");
        assert!(raw.contains("\"zones\""),
            "JSON must contain `zones` field name: {raw}");

        // Version literal pin: explicit 1 (not "1" string, not just present).
        assert!(raw.contains("\"version\": 1"),
            "JSON must pin version: 1 literal: {raw}");

        // Pretty-print signature: contains newlines + indentation
        // (serde_json::to_string_pretty uses 2-space indent by default).
        assert!(raw.contains("\n"),
            "JSON must be pretty-printed with newlines (operator-readable): {raw}");
        assert!(raw.contains("  \""),
            "JSON must have 2-space indented fields: {raw}");

        // Sorted entries: aaa < mmm < zzz alphabetically.
        let pos_a = raw.find("aaa").expect("aaa must be present");
        let pos_m = raw.find("mmm").expect("mmm must be present");
        let pos_z = raw.find("zzz").expect("zzz must be present");
        assert!(pos_a < pos_m,
            "aaa/first must appear BEFORE mmm/middle in sorted output");
        assert!(pos_m < pos_z,
            "mmm/middle must appear BEFORE zzz/last in sorted output");

        // Empty-set wire format: {"version": 1, "zones": []}
        let tmp2 = TempDir::new().unwrap();
        let empty: HashSet<ZoneId> = HashSet::new();
        save_subscriptions(tmp2.path(), &empty).unwrap();
        let raw2 = std::fs::read_to_string(subscriptions_path(tmp2.path())).unwrap();
        assert!(raw2.contains("\"version\": 1"),
            "empty-set file still pins version: 1");
        assert!(raw2.contains("\"zones\": []"),
            "empty-set file must show empty array: {raw2}");
    }

    #[test]
    fn batch_b_tempfile_lifecycle_post_save_tmp_file_absent_and_final_present() {
        // Atomic write via tempfile + rename. Post-save:
        //   - final file MUST exist
        //   - `.tmp` sibling MUST be gone (renamed away)
        // If either invariant fails, future writes might collide with
        // a stale tmp or operator scripts could read the wrong file.
        let tmp = TempDir::new().unwrap();
        let mut subs = HashSet::new();
        subs.insert(zone("medical/eu"));
        save_subscriptions(tmp.path(), &subs).unwrap();

        let final_path = subscriptions_path(tmp.path());
        let tmp_path = tmp.path().join(format!("{SUBSCRIPTIONS_FILE}.tmp"));

        assert!(final_path.exists(),
            "final file must exist post-save: {final_path:?}");
        assert!(!tmp_path.exists(),
            "tempfile must be renamed away post-save (no stale .tmp): {tmp_path:?}");

        // Repeated save: tempfile must STILL be absent after the second
        // write (no accumulation of stale .tmp).
        let mut subs2 = HashSet::new();
        subs2.insert(zone("trade/us"));
        save_subscriptions(tmp.path(), &subs2).unwrap();
        assert!(final_path.exists(),
            "final file still exists after second save");
        assert!(!tmp_path.exists(),
            "tempfile must STILL be absent after second save (no accumulation)");
    }

    #[test]
    fn batch_b_version_mismatch_reject_sweep_across_zero_two_hundred_and_u32_max() {
        // Anything != FORMAT_VERSION (=1) must fall back to an empty set.
        // Sweep covers: 0 (pre-format), 2 (next version), 100 (future drift),
        // u32::MAX (boundary). All must reject WITHOUT panicking.
        for version in [0u32, 2, 100, u32::MAX] {
            let tmp = TempDir::new().unwrap();
            let body = serde_json::json!({
                "version": version,
                "zones": ["medical/eu", "trade/us"]
            });
            std::fs::write(
                subscriptions_path(tmp.path()),
                serde_json::to_vec(&body).unwrap(),
            ).unwrap();

            let loaded = load_subscriptions(tmp.path());
            assert!(loaded.is_empty(),
                "version={version} (!= FORMAT_VERSION) must fall back to empty set; \
                 got {} entries", loaded.len());
        }

        // Sanity: version=1 (=FORMAT_VERSION) DOES load the zones.
        let tmp = TempDir::new().unwrap();
        let body = serde_json::json!({
            "version": FORMAT_VERSION,
            "zones": ["medical/eu"]
        });
        std::fs::write(
            subscriptions_path(tmp.path()),
            serde_json::to_vec(&body).unwrap(),
        ).unwrap();
        let loaded = load_subscriptions(tmp.path());
        assert_eq!(loaded.len(), 1,
            "version=FORMAT_VERSION must load the zones list");
        assert!(loaded.contains(&zone("medical/eu")));
    }

    #[test]
    fn batch_b_load_deduplication_collapses_duplicate_zone_entries_via_hashset() {
        // The on-disk file may contain duplicate zone entries (operator
        // hand-edit, merged sidecars, etc). load_subscriptions collects
        // into HashSet → duplicates collapse to a single entry.
        let tmp = TempDir::new().unwrap();
        let body = serde_json::json!({
            "version": FORMAT_VERSION,
            "zones": [
                "medical/eu",
                "medical/eu",     // duplicate
                "trade/us",
                "medical/eu",     // 2nd duplicate
                "trade/us",       // dupe of trade/us
            ]
        });
        std::fs::write(
            subscriptions_path(tmp.path()),
            serde_json::to_vec(&body).unwrap(),
        ).unwrap();

        let loaded = load_subscriptions(tmp.path());
        assert_eq!(loaded.len(), 2,
            "5 entries with 2 unique zones must collapse via HashSet to 2");
        assert!(loaded.contains(&zone("medical/eu")));
        assert!(loaded.contains(&zone("trade/us")));

        // Round-trip preserves the DEDUPED set (writing it back yields
        // 2 entries, not 5).
        save_subscriptions(tmp.path(), &loaded).unwrap();
        let raw = std::fs::read_to_string(subscriptions_path(tmp.path())).unwrap();
        // Count occurrences of "medical/eu" — must appear exactly once
        // (twice if you count the inner separator, but as a substring it's once).
        let med_count = raw.matches("medical/eu").count();
        assert_eq!(med_count, 1,
            "after save → load → save, medical/eu must appear exactly once: {raw}");
        let trade_count = raw.matches("trade/us").count();
        assert_eq!(trade_count, 1,
            "after save → load → save, trade/us must appear exactly once: {raw}");
    }
}
