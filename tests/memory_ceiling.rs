//! Memory ceiling tests — proves DAG hot tier stays bounded as record count grows.
//!
//! GC eviction keeps the hot tier to ~3 epoch windows even as total
//! record count grows. This is the primary memory bound for the node.
//!
//! Tests at three scales:
//! - 100K records: baseline (seconds)
//! - 500K records: medium scale (tens of seconds)
//! - 1M records: stress test (minutes, #[ignore] by default)

fn dag_memory_ceiling(total_records: usize, records_per_epoch: usize, label: &str) {
    use elara_runtime::dag::{DagIndex, HOT_EPOCH_WINDOW};

    let mut dag = DagIndex::new();
    let total_epochs = total_records / records_per_epoch;
    let mut prev_id = String::new();
    let mut total_inserted = 0usize;
    let report_interval = total_epochs / 4;

    let rss_before = get_rss_mb();
    let t0 = std::time::Instant::now();

    for epoch in 0..total_epochs {
        for i in 0..records_per_epoch {
            let id = format!("e{epoch:05}_r{i:04}");
            let parents = if prev_id.is_empty() {
                vec![]
            } else {
                vec![prev_id.clone()]
            };
            dag.insert(id.clone(), parents, (epoch * 1000 + i) as f64).unwrap();
            prev_id = id;
            total_inserted += 1;
        }

        for i in 0..records_per_epoch {
            let id = format!("e{epoch:05}_r{i:04}");
            dag.mark_finalized(&id, epoch as u64);
        }

        dag.set_current_epoch(epoch as u64);
        let evicted = dag.evict_old_epochs();

        if report_interval > 0 && epoch % report_interval == report_interval - 1 {
            let rss = get_rss_mb();
            let elapsed = t0.elapsed().as_secs();
            eprintln!(
                "[{label}] epoch {:5}: inserted={:7}, hot_tier={:5}, evicted={:5}, RSS={}MB, {elapsed}s",
                epoch, total_inserted, dag.len(), evicted, rss,
            );
        }
    }

    let rss_after = get_rss_mb();
    let hot_final = dag.len();
    let rss_delta = rss_after.saturating_sub(rss_before);
    let elapsed = t0.elapsed();

    eprintln!("\n=== MEMORY CEILING: {label} ===");
    eprintln!("Total records inserted: {total_inserted}");
    eprintln!("DAG hot tier final:     {hot_final}");
    eprintln!("Epoch window:           {HOT_EPOCH_WINDOW}");
    eprintln!("Expected hot max:       ~{}", (HOT_EPOCH_WINDOW + 1) as usize * records_per_epoch);
    eprintln!("RSS before: {rss_before}MB, after: {rss_after}MB, delta: {rss_delta}MB");
    eprintln!("Time: {:.1}s", elapsed.as_secs_f64());

    // Hot tier bounded: epoch window × records_per_epoch + current epoch
    let max_hot = (HOT_EPOCH_WINDOW as usize + 2) * records_per_epoch;
    assert!(
        hot_final <= max_hot,
        "FAIL: hot tier has {hot_final} records, expected <= {max_hot}"
    );

    // RSS should not blow up — ceiling scales linearly with hot tier size, not total records
    let rss_ceiling = 200; // MB
    assert!(
        rss_delta < rss_ceiling,
        "FAIL: RSS grew by {rss_delta}MB — exceeds {rss_ceiling}MB ceiling for {label}"
    );

    eprintln!("PASS: hot tier bounded at {hot_final}/{max_hot}, RSS +{rss_delta}MB\n");
}

#[test]
fn test_dag_memory_ceiling_100k_records() {
    dag_memory_ceiling(100_000, 1_000, "100K");
}

#[test]
fn test_dag_memory_ceiling_500k_records() {
    dag_memory_ceiling(500_000, 5_000, "500K");
}

#[test]
#[ignore] // ~2-3 min, run with `cargo test --test memory_ceiling -- --ignored`
fn test_dag_memory_ceiling_1m_records() {
    dag_memory_ceiling(1_000_000, 10_000, "1M");
}

fn get_rss_mb() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let kb_str = rest.trim().trim_end_matches(" kB").trim();
                    if let Ok(kb) = kb_str.parse::<usize>() {
                        return kb / 1024;
                    }
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    { 0 }
}
