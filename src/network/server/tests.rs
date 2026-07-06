//! Tests for the HTTP server / routing layer (lifted verbatim from the
//! former inline `mod tests` in server.rs; logic unchanged).

use super::*;

// ── parse_sockstat (proc-free unit test) ──────────────────────

#[test]
fn test_parse_sockstat_real_kernel_sample() {
    let raw = "\
sockets: used 1449
TCP: inuse 56 orphan 3 tw 36 alloc 67 mem 713
UDP: inuse 10 mem 658
UDPLITE: inuse 0
RAW: inuse 0
FRAG: inuse 0 memory 0
";
    let (used, t_inuse, t_orphan, t_tw, t_alloc, t_mem, u_inuse, u_mem) = parse_sockstat(raw);
    assert_eq!(used, 1449);
    assert_eq!(t_inuse, 56);
    assert_eq!(t_orphan, 3);
    assert_eq!(t_tw, 36);
    assert_eq!(t_alloc, 67);
    assert_eq!(t_mem, 713);
    assert_eq!(u_inuse, 10);
    assert_eq!(u_mem, 658);
}

#[test]
fn test_parse_sockstat_empty_returns_zeros() {
    let (used, t_inuse, t_orphan, t_tw, t_alloc, t_mem, u_inuse, u_mem) = parse_sockstat("");
    assert_eq!(
        (used, t_inuse, t_orphan, t_tw, t_alloc, t_mem, u_inuse, u_mem),
        (0, 0, 0, 0, 0, 0, 0, 0)
    );
}

#[test]
fn test_parse_sockstat_partial_lines_keep_zero_fields() {
    // Older kernels or lockdown setups may emit a subset; missing keys
    // must default to 0, not poison the whole tuple.
    let raw = "TCP: inuse 12\n";
    let (used, t_inuse, t_orphan, t_tw, t_alloc, t_mem, u_inuse, u_mem) = parse_sockstat(raw);
    assert_eq!(used, 0);
    assert_eq!(t_inuse, 12);
    assert_eq!(t_orphan, 0);
    assert_eq!(t_tw, 0);
    assert_eq!(t_alloc, 0);
    assert_eq!(t_mem, 0);
    assert_eq!(u_inuse, 0);
    assert_eq!(u_mem, 0);
}

// ── parse_tcp_netstat_extras (proc-free unit test) ────────────

#[test]
fn test_parse_tcp_netstat_extras_real_kernel_sample() {
    // Trimmed real /proc/net/netstat sample. The five interesting
    // columns are spread across the line; verify the header→value
    // alignment finds them by name not by position.
    let raw = "\
TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPHPHits TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery TCPSACKReneging TCPSACKReorder TCPRenoReorder TCPTSReorder TCPFullUndo TCPPartialUndo TCPDSACKUndo TCPLossUndo TCPLostRetransmit TCPRenoFailures TCPSackFailures TCPLossFailures TCPFastRetrans TCPSlowStartRetrans TCPTimeouts TCPLossProbes TCPLossProbeRecovery TCPRenoRecoveryFail TCPSackRecoveryFail TCPRcvCollapsed TCPDSACKOldSent TCPDSACKOfoSent TCPDSACKRecv TCPDSACKOfoRecv TCPAbortOnData TCPAbortOnClose TCPAbortOnMemory TCPAbortOnTimeout TCPAbortOnLinger TCPAbortFailed TCPMemoryPressures TCPMemoryPressuresChrono TCPSACKDiscard TCPDSACKIgnoredOld TCPDSACKIgnoredNoUndo TCPSpuriousRTOs TCPMD5NotFound TCPMD5Unexpected TCPMD5Failure TCPSackShifted TCPSackMerged TCPSackShiftFallback TCPBacklogDrop PFMemallocDrop TCPMinTTLDrop TCPDeferAcceptDrop IPReversePathFilter TCPTimeWaitOverflow TCPReqQFullDoCookies TCPReqQFullDrop TCPRetransFail TCPRcvCoalesce TCPOFOQueue TCPOFODrop TCPOFOMerge TCPChallengeACK TCPSYNChallenge TCPFastOpenActive TCPFastOpenActiveFail TCPFastOpenPassive TCPFastOpenPassiveFail TCPFastOpenListenOverflow TCPFastOpenCookieReqd TCPFastOpenBlackhole TCPSpuriousRtxHostQueues BusyPollRxPackets TCPAutoCorking TCPFromZeroWindowAdv TCPToZeroWindowAdv TCPWantZeroWindowAdv TCPSynRetrans TCPOrigDataSent TCPHystartTrainDetect TCPHystartTrainCwnd TCPHystartDelayDetect TCPHystartDelayCwnd TCPACKSkippedSynRecv TCPACKSkippedPAWS TCPACKSkippedSeq TCPACKSkippedFinWait2 TCPACKSkippedTimeWait TCPACKSkippedChallenge TCPWinProbe TCPKeepAlive TCPMTUPFail TCPMTUPSuccess TCPDelivered TCPDeliveredCE TCPAckCompressed TCPZeroWindowDrop TCPRcvQDrop TCPWqueueTooBig TCPFastOpenPassiveAltKey TcpTimeoutRehash TcpDuplicateDataRehash TCPDSACKRecvSegs TCPDSACKIgnoredDubious TCPMigrateReqSuccess TCPMigrateReqFailure
TcpExt: 0 0 0 0 0 0 0 0 0 0 1234 0 0 0 0 100 0 50 7 11 1000 200 300 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 9876 0 0 0 0 0 0 0 0 0 0 0 33 0 0 0 5 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
";
    let (overflow, drops, timeouts, mem_pressure, abort_on_mem) = parse_tcp_netstat_extras(raw);
    assert_eq!(overflow, 7, "ListenOverflows column 19 (0-indexed 18)");
    assert_eq!(drops, 11, "ListenDrops column 20");
    assert_eq!(timeouts, 9876, "TCPTimeouts");
    assert_eq!(mem_pressure, 5, "TCPMemoryPressures");
    assert_eq!(abort_on_mem, 33, "TCPAbortOnMemory");
}

#[test]
fn test_parse_tcp_netstat_extras_empty_returns_zeros() {
    let (overflow, drops, timeouts, mem_pressure, abort_on_mem) = parse_tcp_netstat_extras("");
    assert_eq!(
        (overflow, drops, timeouts, mem_pressure, abort_on_mem),
        (0, 0, 0, 0, 0)
    );
}

#[test]
fn test_parse_tcp_netstat_extras_missing_keys_keep_zero() {
    // A kernel that omits one of the named columns (rare; LSM
    // hardening or container netns visibility) must zero-fill that
    // single key without breaking the others.
    let raw = "\
TcpExt: ListenOverflows ListenDrops TCPTimeouts
TcpExt: 4 5 6
";
    let (overflow, drops, timeouts, mem_pressure, abort_on_mem) = parse_tcp_netstat_extras(raw);
    assert_eq!(overflow, 4);
    assert_eq!(drops, 5);
    assert_eq!(timeouts, 6);
    assert_eq!(mem_pressure, 0, "missing column → 0, not garbage");
    assert_eq!(abort_on_mem, 0, "missing column → 0, not garbage");
}

#[test]
fn test_parse_tcp_netstat_extras_ignores_ipext_lines() {
    // /proc/net/netstat also has an IpExt: section. Make sure we
    // strictly match on the TcpExt: prefix.
    let raw = "\
IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts
IpExt: 7 7 7 7
TcpExt: ListenOverflows
TcpExt: 99
";
    let (overflow, _, _, _, _) = parse_tcp_netstat_extras(raw);
    assert_eq!(overflow, 99, "must not pick up IpExt values by accident");
}

// ── parse_tcp_drops (proc-free unit test) ────────────────────

#[test]
fn test_parse_tcp_drops_real_kernel_sample() {
    // Header→value alignment must find the 6 drop-class columns by
    // name, not position. Same kernel format as the deeper-counters parser (TcpExt:
    // header line followed by data line).
    let raw = "\
TcpExt: TCPSynRetrans TCPRcvQDrop TCPBacklogDrop PFMemallocDrop TCPSpuriousRTOs TCPLostRetransmit
TcpExt: 142 9876 7 0 33 5
";
    let v = parse_tcp_drops(raw);
    assert_eq!(v.syn_retrans, 142);
    assert_eq!(v.rcv_q_drop, 9876);
    assert_eq!(v.backlog_drop, 7);
    assert_eq!(v.pf_memalloc_drop, 0);
    assert_eq!(v.spurious_rtos, 33);
    assert_eq!(v.lost_retransmit, 5);
}

#[test]
fn test_parse_tcp_drops_empty_returns_zeros() {
    let v = parse_tcp_drops("");
    assert_eq!(v, TcpDropCounters::default());
}

#[test]
fn test_parse_tcp_drops_missing_keys_keep_zero() {
    // Older kernels (< 4.10) may not have TCPRcvQDrop; LSM-hardened
    // netns may strip arbitrary keys. Missing → 0, not garbage.
    let raw = "\
TcpExt: TCPSynRetrans TCPSpuriousRTOs
TcpExt: 17 4
";
    let v = parse_tcp_drops(raw);
    assert_eq!(v.syn_retrans, 17);
    assert_eq!(v.spurious_rtos, 4);
    assert_eq!(v.rcv_q_drop, 0, "missing TCPRcvQDrop → 0");
    assert_eq!(v.backlog_drop, 0);
    assert_eq!(v.pf_memalloc_drop, 0);
    assert_eq!(v.lost_retransmit, 0);
}

#[test]
fn test_parse_tcp_drops_ignores_ipext_lines() {
    // Don't pick up IpExt: values by accident — strict prefix match.
    let raw = "\
IpExt: TCPSynRetrans
IpExt: 99999
TcpExt: TCPSynRetrans
TcpExt: 7
";
    let v = parse_tcp_drops(raw);
    assert_eq!(v.syn_retrans, 7, "must not read from IpExt");
}

#[test]
fn test_classify_metric_p1_tcp_drops() {
    // These counters are P1 (default tier — not P0_EXACT, not
    // DEBUG_PREFIXES). Operators wanting alerts on these subscribe
    // at the P1 tier.
    for name in [
        "elara_tcp_syn_retrans_total",
        "elara_tcp_rcv_queue_drop_total",
        "elara_tcp_backlog_drop_total",
        "elara_tcp_pfmemalloc_drop_total",
        "elara_tcp_spurious_rtos_total",
        "elara_tcp_lost_retransmit_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — same tier as OPS-87 host_listen_overflows etc)"
        );
    }
}

// ── parse_tcp_recovery (proc-free unit test) ─────────────────

#[test]
fn test_parse_tcp_recovery_real_kernel_sample() {
    // Header→value alignment must find the 5 recovery/ECN columns by
    // name. Same TcpExt: format as the deeper-counters + drop-class parsers.
    let raw = "\
TcpExt: TCPDelivered TCPDeliveredCE TCPLossProbes TCPLossProbeRecovery TCPSACKReorder
TcpExt: 1234567890 4567 89 71 12
";
    let v = parse_tcp_recovery(raw);
    assert_eq!(v.delivered, 1234567890);
    assert_eq!(v.delivered_ce, 4567);
    assert_eq!(v.loss_probes, 89);
    assert_eq!(v.loss_probe_recovery, 71);
    assert_eq!(v.sack_reorder, 12);
}

#[test]
fn test_parse_tcp_recovery_empty_returns_zeros() {
    assert_eq!(parse_tcp_recovery(""), TcpRecoveryStats::default());
}

#[test]
fn test_parse_tcp_recovery_missing_keys_keep_zero() {
    // Older kernels < 4.11 lack TCPDeliveredCE; netns hardening can
    // strip arbitrary keys. Missing → 0, not garbage.
    let raw = "\
TcpExt: TCPDelivered TCPLossProbes
TcpExt: 100 5
";
    let v = parse_tcp_recovery(raw);
    assert_eq!(v.delivered, 100);
    assert_eq!(v.loss_probes, 5);
    assert_eq!(v.delivered_ce, 0, "missing TCPDeliveredCE → 0");
    assert_eq!(v.loss_probe_recovery, 0);
    assert_eq!(v.sack_reorder, 0);
}

#[test]
fn test_parse_tcp_recovery_ignores_ipext_lines() {
    // Strict TcpExt: prefix — IpExt: lines must not contaminate.
    let raw = "\
IpExt: TCPDelivered
IpExt: 99999999
TcpExt: TCPDelivered
TcpExt: 42
";
    let v = parse_tcp_recovery(raw);
    assert_eq!(v.delivered, 42, "must not read from IpExt");
}

#[test]
fn test_classify_metric_p1_tcp_recovery() {
    // These counters are P1 (default tier — same tier as the other TcpExt counters).
    for name in [
        "elara_host_tcp_delivered_total",
        "elara_host_tcp_delivered_ce_total",
        "elara_host_tcp_loss_probes_total",
        "elara_host_tcp_loss_probe_recovery_total",
        "elara_host_tcp_sack_reorder_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — TCP recovery/ECN counters)"
        );
    }
}

// ── parse_softnet_stat (proc-free unit test) ─────────────────

#[test]
fn test_parse_softnet_stat_real_kernel_sample() {
    // Two-CPU sample. Column 0 = processed (hex), col 1 = dropped,
    // col 2 = time_squeeze, col 8 = flow_limit. Verify aggregation
    // and that dropped_max_per_cpu picks the larger of the two.
    let raw = "\
00221cb4 00000007 00000003 00000000 00000000 00000000 00000000 00000000 00000004 00000000\n\
00100000 00000002 00000005 00000000 00000000 00000000 00000000 00000000 00000001 00000000\n";
    let v = parse_softnet_stat(raw);
    // 0x00221cb4 = 2235572, 0x00100000 = 1048576
    assert_eq!(v.processed_total, 2235572 + 1048576);
    // dropped: 7 + 2 = 9
    assert_eq!(v.dropped_total, 9);
    // squeeze: 3 + 5 = 8
    assert_eq!(v.time_squeeze_total, 8);
    // flow_limit: 4 + 1 = 5
    assert_eq!(v.flow_limit_total, 5);
    // max-per-cpu picks the larger of {7, 2}
    assert_eq!(v.dropped_max_per_cpu, 7);
}

#[test]
fn test_parse_softnet_stat_empty_returns_zeros() {
    assert_eq!(parse_softnet_stat(""), SoftnetStats::default());
}

#[test]
fn test_parse_softnet_stat_short_lines_ignored() {
    // A row with < 9 columns must not cause out-of-bounds reads or
    // partial accumulation — the parser returns the same value as
    // if the row weren't there at all.
    let raw = "\
00000010 00000001 00000001\n\
00000020 00000002 00000003 00000000 00000000 00000000 00000000 00000000 00000005 00000000\n";
    let v = parse_softnet_stat(raw);
    // First row has only 3 cols: skipped. Second row alone:
    assert_eq!(v.processed_total, 0x20);
    assert_eq!(v.dropped_total, 2);
    assert_eq!(v.time_squeeze_total, 3);
    assert_eq!(v.flow_limit_total, 5);
    assert_eq!(v.dropped_max_per_cpu, 2);
}

#[test]
fn test_parse_softnet_stat_invalid_hex_treated_as_zero() {
    // Some kernels (very old) emit a bizarre number of columns or
    // include non-hex content if the file is being read while NAPI
    // is mid-update. Garbage cells default to 0; the rest of the
    // line still parses.
    let raw = "ZZZZZZZZ 00000005 00000003 00000000 00000000 00000000 00000000 00000000 00000007 00000000\n";
    let v = parse_softnet_stat(raw);
    assert_eq!(v.processed_total, 0, "invalid hex → 0, not a parse error");
    assert_eq!(v.dropped_total, 5);
    assert_eq!(v.time_squeeze_total, 3);
    assert_eq!(v.flow_limit_total, 7);
}

#[test]
fn test_classify_metric_p1_softnet() {
    // These counters are P1 (default tier).
    for name in [
        "elara_host_softnet_processed_total",
        "elara_host_softnet_dropped_total",
        "elara_host_softnet_time_squeeze_total",
        "elara_host_softnet_flow_limit_total",
        "elara_host_softnet_dropped_max_per_cpu",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — softnet pipeline metrics)"
        );
    }
}

#[test]
fn test_classify_metric_p1_cgroup_memory_events() {
    // These counters are P1 (default tier — leading-indicator
    // memory-pressure events, not pager-grade until rate is non-zero).
    for name in [
        "elara_cgroup_memory_low_events_total",
        "elara_cgroup_memory_max_events_total",
        "elara_cgroup_memory_oom_events_total",
        "elara_cgroup_memory_oom_group_kill_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — cgroup memory.events leading indicators)"
        );
    }
}

#[test]
fn test_classify_metric_p1_mandate_observability() {
    // Agent-mandate (C4/C16) observability counters are P1 (default tier):
    // operator-facing, observational, never consensus-weighted. They must NOT
    // regress to P0 (would bloat the phone-tier body with a non-pager signal)
    // nor to Debug (would hide them from standard scrapes). snapshot_rejected
    // in particular is the virgin-join tamper signal — non-zero means a
    // snapshot producer shipped a mandate that failed the content-address/
    // well-formed guard — and must survive a default P1 scrape.
    for name in [
        "elara_mandate_flag_total",
        "elara_mandate_records_total",
        "elara_mandate_revocations_total",
        "elara_mandate_acts_total",
        "elara_mandate_malformed_ref_total",
        "elara_mandate_snapshot_rejected_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (mandate observability — operator-facing, not consensus)"
        );
    }
}

#[test]
fn test_classify_metric_build_info_is_p0() {
    // Pinned to P0 alongside elara_metric_tier — phone-tier operators
    // still need to confirm what binary their node is running. If this
    // flipped to P1/Debug, a phone-tier `/metrics` body at tier=P0
    // would silently lose binary-identity information that the
    // fleet-uniformity probe depends on.
    assert_eq!(classify_metric("elara_build_info"), MetricTier::P0);
}

#[test]
fn public_metric_tier_clamp_blocks_anonymous_debug_escalation() {
    // Loopback operator keeps the full debug spot-check override.
    assert_eq!(
        clamp_public_metric_tier(true, Some(MetricTier::Debug), MetricTier::P1),
        Some(MetricTier::Debug)
    );
    // THE finding: a non-loopback (public-internet) caller cannot escalate a
    // P1-default node to Debug — `?tier=debug` is downgraded to the ceiling.
    assert_eq!(
        clamp_public_metric_tier(false, Some(MetricTier::Debug), MetricTier::P1),
        Some(MetricTier::P1)
    );
    // A public caller MAY downgrade to a smaller surface (harmless).
    assert_eq!(
        clamp_public_metric_tier(false, Some(MetricTier::P0), MetricTier::P1),
        Some(MetricTier::P0)
    );
    // No param (or garbage → None) yields the node default, never more.
    assert_eq!(
        clamp_public_metric_tier(false, None, MetricTier::P1),
        Some(MetricTier::P1)
    );
    // A P0-default node never leaks P1/Debug to the public plane.
    assert_eq!(
        clamp_public_metric_tier(false, Some(MetricTier::Debug), MetricTier::P0),
        Some(MetricTier::P0)
    );
    // Equal tier passes through unchanged.
    assert_eq!(
        clamp_public_metric_tier(false, Some(MetricTier::P1), MetricTier::P1),
        Some(MetricTier::P1)
    );
}

#[test]
fn public_metric_tier_clamp_caps_archive_debug_ceiling_at_p1() {
    // Archive nodes default their ceiling to Debug (NodeProfile::Archive =>
    // MetricTier::Debug, see current_metric_tier). Debug is host fingerprint —
    // per-core CPU freq, hwmon/thermal, per-disk IO, NIC counters, process
    // rlimits — and must NEVER reach a non-loopback caller, even on a node whose
    // configured ceiling IS Debug. Parallels the /status host-fingerprint gate.
    // Before the P1 cap these returned Debug: a machine fingerprint served to
    // anonymous internet callers on every public-facing Archive node.

    // Public caller explicitly requesting debug on an Archive node → capped P1.
    assert_eq!(
        clamp_public_metric_tier(false, Some(MetricTier::Debug), MetricTier::Debug),
        Some(MetricTier::P1)
    );
    // Public caller with no param on an Archive node → P1, NOT the Debug ceiling.
    assert_eq!(
        clamp_public_metric_tier(false, None, MetricTier::Debug),
        Some(MetricTier::P1)
    );
    // A public caller may still downgrade to P0 on an Archive node.
    assert_eq!(
        clamp_public_metric_tier(false, Some(MetricTier::P0), MetricTier::Debug),
        Some(MetricTier::P0)
    );
    // The loopback operator on the SAME Archive node still gets full Debug — the
    // host fingerprint stays available locally; only the public plane is capped.
    assert_eq!(
        clamp_public_metric_tier(true, Some(MetricTier::Debug), MetricTier::Debug),
        Some(MetricTier::Debug)
    );
}

#[test]
fn test_build_info_metric_render_shape() {
    // Pin the BUILD_INFO_METRIC string shape so a future edit can't
    // accidentally break the labels or the `1` value. Parsing here
    // mirrors what Prometheus scrapers do.
    let s = BUILD_INFO_METRIC;
    assert!(s.starts_with("# HELP elara_build_info"));
    assert!(s.contains("# TYPE elara_build_info gauge\n"));
    assert!(s.contains("elara_build_info{git_sha=\""));
    assert!(s.contains("\",git_ref=\""));
    assert!(s.contains("\",git_dirty=\""));
    assert!(s.contains("\",build_ts=\""));
    assert!(s.ends_with("\"} 1\n"));
}

#[test]
fn test_classify_metric_p1_cgroup_memory_stat() {
    // These metrics are P1 (default tier — observability for
    // memory composition; alerts come from cross-tabbing with the cgroup
    // memory accounting + memory.events, not from these gauges/counters in isolation).
    for name in [
        "elara_cgroup_memory_anon_bytes",
        "elara_cgroup_memory_file_bytes",
        "elara_cgroup_memory_kernel_bytes",
        "elara_cgroup_memory_pgfault_total",
        "elara_cgroup_memory_pgmajfault_total",
        "elara_cgroup_memory_workingset_refault_file_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — cgroup memory.stat detailed breakdown)"
        );
    }
}

#[test]
fn test_classify_metric_p1_host_ip_stats() {
    // These metrics are P1 (default tier — IP-pipeline observability
    // for layer-3 drops/discards/fragmentation; alerts derive from
    // cross-tabbing the rates against TCP-layer counters, not from
    // these counters in isolation).
    for name in [
        "elara_host_ip_in_receives_total",
        "elara_host_ip_in_hdr_errors_total",
        "elara_host_ip_in_addr_errors_total",
        "elara_host_ip_in_discards_total",
        "elara_host_ip_in_delivers_total",
        "elara_host_ip_out_requests_total",
        "elara_host_ip_out_discards_total",
        "elara_host_ip_out_no_routes_total",
        "elara_host_ip_reasm_fails_total",
        "elara_host_ip_frag_fails_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — host IP-layer pipeline counters)"
        );
    }
}

#[test]
fn test_classify_metric_p1_host_udp_stats() {
    // These metrics are P1 (default tier — UDP datagram-pipeline
    // observability; rates and ratios feed gossip-fanout dashboards
    // and pair with the IP-layer + snmp RcvbufErrors).
    for name in [
        "elara_host_udp_in_datagrams_total",
        "elara_host_udp_no_ports_total",
        "elara_host_udp_in_errors_total",
        "elara_host_udp_out_datagrams_total",
        "elara_host_udp_sndbuf_errors_total",
        "elara_host_udp_mem_errors_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — host UDP datagram counters)"
        );
    }
}

#[test]
fn test_classify_metric_p1_host_icmp_stats() {
    // These metrics are P1 (default tier — ICMP-layer path-error
    // observability; pairs 1:1 with UDP NoPorts and surfaces
    // out-of-band signals invisible to TCP/UDP layers alone).
    for name in [
        "elara_host_icmp_in_msgs_total",
        "elara_host_icmp_in_errors_total",
        "elara_host_icmp_in_csum_errors_total",
        "elara_host_icmp_in_dest_unreachs_total",
        "elara_host_icmp_in_time_excds_total",
        "elara_host_icmp_in_redirects_total",
        "elara_host_icmp_out_msgs_total",
        "elara_host_icmp_out_dest_unreachs_total",
        "elara_host_icmp_out_time_excds_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — host ICMP path-error counters)"
        );
    }
}

#[test]
fn test_classify_metric_p1_gossip_select_path() {
    // These metrics are P1 (default tier — pull-side peer-selection path
    // visibility, complements existing push-side content-routing counters).
    // Operationally interesting for "is the DHT contributing" diagnosis,
    // not a consensus-core SLO signal.
    for name in [
        "elara_gossip_select_dht_total",
        "elara_gossip_select_fallback_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — gossip select-path visibility)"
        );
    }
}

#[test]
fn test_classify_metric_p1_delta_sync() {
    // delta_sync attempt + failure counters.
    // P1 tier: the path was previously only logged via journalctl; a
    // Prometheus-visible failure rate is operator-grade observability,
    // not a pager-grade SLO. (A pager-grade equivalent would be the rate
    // pinned at 100%, which the existing fork-monitor + sync log already
    // catches via a different code path.)
    for name in [
        "elara_delta_sync_attempts_total",
        "elara_delta_sync_failures_timeout_total",
        "elara_delta_sync_failures_other_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — delta_sync visibility)"
        );
    }
}

#[test]
fn test_classify_metric_p1_delta_sync_latency() {
    // pq_delta_sync per-call latency buckets-as-
    // counters. Same P1 tier rationale as the attempt counters: tail-latency visibility
    // is operator-grade observability for diagnosing peer-handshake
    // saturation before timeouts start firing. The buckets sum to total
    // successes; pair with attempts/failures for full surface.
    for name in [
        "elara_delta_sync_latency_lt_2s_total",
        "elara_delta_sync_latency_lt_10s_total",
        "elara_delta_sync_latency_lt_30s_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — delta_sync latency visibility)"
        );
    }
}

#[test]
fn test_classify_metric_p1_delta_sync_timeout_split() {
    // pq_delta_sync timeout attribution counters
    // (handshake vs RPC). Same P1 tier as the attempt/latency counters: this is operator-
    // grade observability for distinguishing peer-PQ-port-saturation from
    // verb-handler-stall when the fleet shows 100% timeout. Both subsets
    // partition _failures_timeout_total by error-string pattern.
    for name in [
        "elara_delta_sync_failures_timeout_handshake_total",
        "elara_delta_sync_failures_timeout_rpc_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} should be P1 (default — delta_sync timeout split)"
        );
    }
}

/// scan_hit_cap counter classifies P1. This is the
/// pair to the timeout-attribution counters — operators check "did rpc-timeouts drop AND
/// scan_hit_cap stay low" to verify the bound is working. Same P1 tier as
/// the rest of the delta_sync diagnostic family.
#[test]
fn test_classify_metric_p1_delta_sync_scan_hit_cap() {
    assert_eq!(
        classify_metric("elara_delta_sync_scan_hit_cap_total"),
        MetricTier::P1,
        "delta_sync_scan_hit_cap should be P1 (default — server-side OPS-123 cap counter)"
    );
}

/// Tier-gating contract: every metric family produced by a /proc reader that
/// `metrics_body_tiered` gates at `collect_debug` MUST classify as Debug,
/// and every family produced by one gated at `collect_p1` MUST classify
/// as P1 (or P0 — the gate fires when target_tier ≥ P1, so P0 metrics
/// would never reach the gate). If this test trips, someone changed
/// classify_metric for one of these names without updating the gate.
/// That breaks the tier-gating invariant: at tier=P0 the gate would skip a
/// reader whose output the filter wouldn't have stripped — silently
/// dropping a metric we promised to surface.
#[test]
fn test_ops119_gate_tier_contract() {
    // Sample one representative metric per Debug-gated reader. Full list
    // is exhaustive: extending the gate list also extends this test.
    let debug_gated_metrics = &[
        // host_thermal_zones (line ~6913)
        "elara_host_thermal_celsius",
        // host_hwmon_temps
        "elara_host_hwmon_temp_celsius",
        // host_cpu_frequencies
        "elara_host_cpu_frequency_hz",
        // process_rlimits
        "elara_process_rlimit_soft",
        "elara_process_rlimit_hard",
        // host_disk_stats — sample family
        "elara_host_disk_reads_total",
        "elara_host_disk_writes_total",
        // host_netdev_stats — sample family
        "elara_host_netdev_rx_errs_total",
    ];
    for name in debug_gated_metrics {
        assert_eq!(
            classify_metric(name),
            MetricTier::Debug,
            "{name} is gated at collect_debug; classify_metric must agree \
                 (otherwise tier=P0 silently drops a metric the filter would have kept)"
        );
    }

    // Sample one representative metric per P1-gated scalar reader.
    let p1_gated_metrics = &[
        // process_status_extended / page_faults / scheduler / rss
        "elara_process_vmpeak_kb",
        "elara_process_minor_faults_total",
        "elara_process_vmhwm_kb",
        "elara_process_rss_anon_kb",
        // host_meminfo_extras (one of nine)
        "elara_meminfo_total_kb",
        // process_blkio_wait_seconds
        "elara_process_blkio_wait_seconds_total",
        // host_proc_stat_extras
        "elara_host_procs_running",
        // host_file_nr
        "elara_host_fd_allocated",
        // host_sockstat
        "elara_host_sockets_used",
        // process_cpu_seconds
        "elara_process_cpu_user_seconds_total",
        // process_io_bytes
        "elara_process_io_rchar_bytes_total",
        // process_net_bytes
        "elara_process_net_rx_bytes_total",
        // process_tcp_states
        "elara_tcp_established",
        // process_pressure_stats — psi_*
        "elara_psi_cpu_some_avg10",
        // process_oom_state
        "elara_process_oom_score",
        // host_cpu_jiffies
        "elara_host_cpu_user_seconds_total",
        // host_loadavg_extra
        "elara_system_load_5m",
        // process_fd_state
        "elara_process_open_fds",
        // host_tcp_udp_state
        "elara_host_tcp_retrans_segs_total",
        // host_tcp_netstat_extras
        "elara_host_listen_overflows_total",
        // host_tcp_drops
        "elara_tcp_syn_retrans_total",
        // host_softnet_stats
        "elara_host_softnet_processed_total",
        // host_tcp_recovery
        "elara_host_tcp_delivered_total",
        // host_ip_stats
        "elara_host_ip_in_receives_total",
        // host_udp_stats
        "elara_host_udp_in_datagrams_total",
        // host_icmp_stats
        "elara_host_icmp_in_msgs_total",
        // host_vmstat_pressure
        "elara_host_pgmajfault_total",
        // process_schedstat
        "elara_process_sched_run_delay_seconds_total",
        // process_pressure_totals_us
        "elara_host_pressure_some_total_us",
        // cgroup_memory_state
        "elara_cgroup_memory_current_bytes",
        // cgroup_memory_stat_breakdown
        "elara_cgroup_memory_anon_bytes",
        // cgroup_cpu_state
        "elara_cgroup_cpu_usage_us_total",
        // host_softirq_totals
        "elara_softirq_net_rx_total",
        // host_buddy_free_pages
        "elara_buddy_free_pages_order0",
        // host_jemalloc_stats
        "elara_jemalloc_allocated_bytes",
    ];
    for name in p1_gated_metrics {
        let tier = classify_metric(name);
        assert!(
            tier >= MetricTier::P1,
            "{name} is gated at collect_p1; classify_metric returned {:?} \
                 — a P0 metric coming from a P1-gated reader silently disappears \
                 at target_tier=P0 (gate skips reader, filter would have kept the \
                 metric). Either move the metric out of P0 or relax the gate.",
            tier,
        );
    }
}

// ── parse_cgroup_memory_stat (proc-free unit tests) ──────────

#[test]
fn test_parse_cgroup_memory_stat_real_kernel_sample() {
    // Real sample from a live elara-node /metrics, trimmed. Verifies the
    // parser pulls anon/file/kernel + the three fault counters out of
    // the dozens of intervening fields the kernel emits.
    let raw = "\
anon 663838720
file 660893696
kernel 30187520
kernel_stack 409600
pagetables 6496256
sec_pagetables 0
percpu 160
sock 32768
vmalloc 0
shmem 0
slab_reclaimable 21272024
slab_unreclaimable 1998536
slab 23270560
workingset_refault_anon 0
workingset_refault_file 128
workingset_activate_anon 0
workingset_activate_file 0
pgfault 1159925
pgmajfault 0
pgrefill 0
pgscan 0
pgsteal 0
pgactivate 0
pgdeactivate 0
pglazyfree 0
pglazyfreed 0
";
    let s = parse_cgroup_memory_stat(raw);
    assert_eq!(s.anon, 663838720);
    assert_eq!(s.file, 660893696);
    assert_eq!(s.kernel, 30187520);
    assert_eq!(s.pgfault, 1159925);
    assert_eq!(s.pgmajfault, 0);
    assert_eq!(s.workingset_refault_file, 128);
}

#[test]
fn test_parse_cgroup_memory_stat_empty_returns_default() {
    // cgroup v1 hybrid (no v2 unified hierarchy) → file unreadable →
    // empty string → all fields zero, no panic.
    assert_eq!(parse_cgroup_memory_stat(""), CgroupMemoryStat::default());
}

#[test]
fn test_parse_cgroup_memory_stat_unknown_keys_ignored() {
    // Future kernel adds extra fields (e.g. zswap variants in 6.10+);
    // parser must extract documented ones and ignore the rest.
    let raw = "\
anon 100
totally_new_kernel_field 99999
file 200
some_unrelated_thing nonsense
kernel 50
zswap_writeback 7
pgfault 1000
pgmajfault 5
workingset_refault_file 3
";
    let s = parse_cgroup_memory_stat(raw);
    assert_eq!(s.anon, 100);
    assert_eq!(s.file, 200);
    assert_eq!(s.kernel, 50);
    assert_eq!(s.pgfault, 1000);
    assert_eq!(s.pgmajfault, 5);
    assert_eq!(s.workingset_refault_file, 3);
}

#[test]
fn test_parse_cgroup_memory_stat_malformed_lines_dont_poison() {
    // Truncated reads / partial writes during cgroup migration:
    // unparseable values must not corrupt subsequent valid lines.
    let raw = "\
anon notanumber
file 12345
kernel
pgfault 999
pgmajfault abc
workingset_refault_file 7
";
    let s = parse_cgroup_memory_stat(raw);
    assert_eq!(s.anon, 0, "non-numeric value → 0, parser keeps going");
    assert_eq!(
        s.file, 12345,
        "valid line after malformed line still parses"
    );
    assert_eq!(s.kernel, 0, "missing value → 0");
    assert_eq!(s.pgfault, 999);
    assert_eq!(s.pgmajfault, 0, "non-numeric counter → 0");
    assert_eq!(s.workingset_refault_file, 7);
}

#[test]
fn test_parse_cgroup_memory_stat_healthy_node_zero_faults() {
    // Healthy phone-tier baseline: anon/file populated, kernel small,
    // and crucially pgmajfault + refault counters at exactly 0 — that
    // is what an operator wants the dashboard to show on a quiet box.
    let raw = "\
anon 600000000
file 200000000
kernel 25000000
pgfault 500000
pgmajfault 0
workingset_refault_file 0
";
    let s = parse_cgroup_memory_stat(raw);
    assert_eq!(s.pgmajfault, 0, "healthy node has zero major faults");
    assert_eq!(
        s.workingset_refault_file, 0,
        "healthy node has zero refaults — early-warning silent"
    );
    assert!(s.anon > 0 && s.file > 0);
}

// ── parse_host_ip_stats (proc-free unit tests) ───────────────

#[test]
fn test_parse_host_ip_stats_real_kernel_sample() {
    // Real /proc/net/snmp Ip: pair from kernel 6.8 — header line
    // "Ip: Forwarding DefaultTTL InReceives ..." followed immediately
    // by the value line. Parser must zip the header against the values
    // and pull out the documented fields.
    let raw = "\
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits
Ip: 2 64 118866385 0 14 0 0 0 118393681 110666420 511 8 0 0 0 0 0 0 0 110666420
";
    let s = parse_host_ip_stats(raw);
    assert_eq!(s.in_receives, 118866385);
    assert_eq!(s.in_hdr_errors, 0);
    assert_eq!(s.in_addr_errors, 14);
    assert_eq!(s.in_discards, 0);
    assert_eq!(s.in_delivers, 118393681);
    assert_eq!(s.out_requests, 110666420);
    assert_eq!(s.out_discards, 511);
    assert_eq!(s.out_no_routes, 8);
    assert_eq!(s.reasm_fails, 0);
    assert_eq!(s.frag_fails, 0);
}

#[test]
fn test_parse_host_ip_stats_empty_returns_default() {
    // /proc/net/snmp unreadable (cgroup userns restriction, missing
    // file on minimal kernel) → empty string → all fields zero.
    assert_eq!(parse_host_ip_stats(""), HostIpStats::default());
}

#[test]
fn test_parse_host_ip_stats_only_tcp_section_no_ip() {
    // If the file exists but only has Tcp:/Udp: prefixes (e.g. parser
    // ran during a partial write between Ip: lines), we must return
    // the default rather than crashing or pulling random columns.
    let raw = "\
Tcp: RtoAlgorithm RtoMin OutSegs RetransSegs CurrEstab
Tcp: 1 200 1000 5 50
Udp: InDatagrams NoPorts InErrors RcvbufErrors
Udp: 100 0 0 0
";
    assert_eq!(parse_host_ip_stats(raw), HostIpStats::default());
}

#[test]
fn test_parse_host_ip_stats_field_order_independent() {
    // The kernel HAS reordered Ip: columns across versions (e.g.
    // OutTransmits was added at the end in 5.10+). Parser uses
    // header-key matching not positional, so swapping any two columns
    // must still yield the right values.
    let raw = "\
Ip: InReceives OutRequests InDiscards OutDiscards InHdrErrors InAddrErrors InDelivers OutNoRoutes ReasmFails FragFails
Ip: 999 888 7 6 5 4 777 3 2 1
";
    let s = parse_host_ip_stats(raw);
    assert_eq!(s.in_receives, 999);
    assert_eq!(s.out_requests, 888);
    assert_eq!(s.in_discards, 7);
    assert_eq!(s.out_discards, 6);
    assert_eq!(s.in_hdr_errors, 5);
    assert_eq!(s.in_addr_errors, 4);
    assert_eq!(s.in_delivers, 777);
    assert_eq!(s.out_no_routes, 3);
    assert_eq!(s.reasm_fails, 2);
    assert_eq!(s.frag_fails, 1);
}

#[test]
fn test_parse_host_ip_stats_truncated_value_line_doesnt_panic() {
    // Truncated read during /proc/net/snmp poll: header has 10 columns,
    // value line has only 5. Parser must populate what it has and
    // silently zero the rest — not panic on the missing indices.
    let raw = "\
Ip: InReceives InHdrErrors InAddrErrors InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmFails FragFails
Ip: 100 0 0
";
    let s = parse_host_ip_stats(raw);
    assert_eq!(s.in_receives, 100);
    assert_eq!(s.in_hdr_errors, 0);
    assert_eq!(s.in_addr_errors, 0);
    // Tail fields silently zero — no panic, no garbage.
    assert_eq!(s.in_discards, 0);
    assert_eq!(s.out_requests, 0);
}

#[test]
fn test_parse_host_ip_stats_healthy_node_arithmetic_identity() {
    // On a non-router host (Forwarding=2 = "host-only"),
    // InReceives = InDelivers + InDiscards + InHdrErrors + InAddrErrors
    // must hold. Sanity-check that our parser returns numbers an
    // operator dashboard can use to assert this identity.
    let raw = "\
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
Ip: 2 64 1000 5 3 0 0 2 990 800 0 0 0 0 0 0 0 0 0
";
    let s = parse_host_ip_stats(raw);
    let identity = s.in_delivers + s.in_discards + s.in_hdr_errors + s.in_addr_errors;
    assert_eq!(
        identity, s.in_receives,
        "host-only InReceives identity must hold: {} != {}",
        identity, s.in_receives
    );
}

// ── parse_host_udp_stats (proc-free unit tests) ──────────────

#[test]
fn test_parse_host_udp_stats_real_kernel_sample() {
    // Real /proc/net/snmp Udp: section from kernel 6.8.
    let raw = "\
Tcp: RtoAlgorithm RtoMin Retrans
Tcp: 1 200 12345
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 18234 47 3 18901 0 2 0 0 0
UdpLite: InDatagrams NoPorts
UdpLite: 0 0
";
    let s = parse_host_udp_stats(raw);
    assert_eq!(s.in_datagrams, 18234);
    assert_eq!(s.no_ports, 47);
    assert_eq!(s.in_errors, 3);
    assert_eq!(s.out_datagrams, 18901);
    assert_eq!(s.sndbuf_errors, 2);
    assert_eq!(s.mem_errors, 0);
}

#[test]
fn test_parse_host_udp_stats_empty_returns_default() {
    // Empty input → all fields zero. No panic.
    assert_eq!(parse_host_udp_stats(""), HostUdpStats::default());
}

#[test]
fn test_parse_host_udp_stats_only_tcp_section_no_udp() {
    // /proc/net/snmp scoped to Tcp lines only (theoretical — kernel
    // always emits Udp:, but the parser must not panic if absent).
    let raw = "\
Tcp: RtoAlgorithm RtoMin
Tcp: 1 200
";
    assert_eq!(parse_host_udp_stats(raw), HostUdpStats::default());
}

#[test]
fn test_parse_host_udp_stats_field_order_independent() {
    // Some distros / kernel patches reorder snmp fields. Parser keys on
    // header NAME, not column index — verify a synthetic reordering
    // (NoPorts before InDatagrams) still produces correct values.
    let raw = "\
Udp: NoPorts InDatagrams MemErrors OutDatagrams SndbufErrors InErrors
Udp: 9 12345 7 6789 4 1
";
    let s = parse_host_udp_stats(raw);
    assert_eq!(s.in_datagrams, 12345);
    assert_eq!(s.no_ports, 9);
    assert_eq!(s.in_errors, 1);
    assert_eq!(s.out_datagrams, 6789);
    assert_eq!(s.sndbuf_errors, 4);
    assert_eq!(s.mem_errors, 7);
}

#[test]
fn test_parse_host_udp_stats_truncated_value_line_doesnt_panic() {
    // Truncated read (kernel race / fs error) — header full, values
    // half-missing. Parser must take what it can and leave the rest 0.
    let raw = "\
Udp: InDatagrams NoPorts InErrors OutDatagrams SndbufErrors MemErrors
Udp: 100 5 2
";
    let s = parse_host_udp_stats(raw);
    assert_eq!(s.in_datagrams, 100);
    assert_eq!(s.no_ports, 5);
    assert_eq!(s.in_errors, 2);
    assert_eq!(s.out_datagrams, 0);
    assert_eq!(s.sndbuf_errors, 0);
    assert_eq!(s.mem_errors, 0);
}

#[test]
fn test_parse_host_udp_stats_healthy_node_baseline() {
    // Healthy non-overloaded node: NoPorts, InErrors, SndbufErrors,
    // MemErrors all zero; only InDatagrams and OutDatagrams nonzero.
    // Operator dashboards must see a clean zero-row in steady state.
    let raw = "\
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 50000 0 0 49995 0 0 0 0 0
";
    let s = parse_host_udp_stats(raw);
    assert!(s.in_datagrams > 0);
    assert!(s.out_datagrams > 0);
    assert_eq!(s.no_ports, 0);
    assert_eq!(s.in_errors, 0);
    assert_eq!(s.sndbuf_errors, 0);
    assert_eq!(s.mem_errors, 0);
}

// ── parse_host_icmp_stats (proc-free unit tests) ────────────

#[test]
fn test_parse_host_icmp_stats_real_kernel_sample() {
    // Real /proc/net/snmp Icmp: section from kernel 6.8.
    let raw = "\
Tcp: RtoAlgorithm RtoMin
Tcp: 1 200
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal OutRateLimitHost OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps
Icmp: 6121 0 0 324 0 0 0 0 0 5797 0 0 0 0 7669 0 0 206 1141 0 0 0 0 6528 0 0 0 0 0
IcmpMsg: InType0 InType3 OutType3 OutType8
IcmpMsg: 5797 324 1141 6528
";
    let s = parse_host_icmp_stats(raw);
    assert_eq!(s.in_msgs, 6121);
    assert_eq!(s.in_errors, 0);
    assert_eq!(s.in_csum_errors, 0);
    assert_eq!(s.in_dest_unreachs, 324);
    assert_eq!(s.in_time_excds, 0);
    assert_eq!(s.in_redirects, 0);
    assert_eq!(s.out_msgs, 7669);
    assert_eq!(s.out_dest_unreachs, 1141);
    assert_eq!(s.out_time_excds, 0);
}

#[test]
fn test_parse_host_icmp_stats_empty_returns_default() {
    // Empty input → all fields zero. No panic.
    assert_eq!(parse_host_icmp_stats(""), HostIcmpStats::default());
}

#[test]
fn test_parse_host_icmp_stats_must_not_match_icmpmsg_section() {
    // Critical: parser uses prefix "Icmp: " (with trailing space). The
    // adjacent "IcmpMsg: " section has a different schema (per-type
    // counters: InType0/InType3/OutType3/OutType8) — if the parser
    // mistakenly accepts that prefix the field names won't match and
    // we'd silently return zeros, but we'd also discard the legitimate
    // header that was read just before. Guard against the regression.
    let raw = "\
IcmpMsg: InType0 InType3 OutType3 OutType8
IcmpMsg: 5797 324 1141 6528
";
    // No Icmp: section at all → all zeros, NOT a panic and NOT picking
    // up the IcmpMsg row by mistake.
    assert_eq!(parse_host_icmp_stats(raw), HostIcmpStats::default());
}

#[test]
fn test_parse_host_icmp_stats_field_order_independent() {
    // Some hardened kernels reorder snmp columns. Parser keys on header
    // NAME, not column index — verify a reordered header still produces
    // correct field values.
    let raw = "\
Icmp: OutMsgs InMsgs OutTimeExcds InRedirects InTimeExcds OutDestUnreachs InCsumErrors InErrors InDestUnreachs
Icmp: 7669 6121 0 0 0 1141 0 0 324
";
    let s = parse_host_icmp_stats(raw);
    assert_eq!(s.in_msgs, 6121);
    assert_eq!(s.in_errors, 0);
    assert_eq!(s.in_csum_errors, 0);
    assert_eq!(s.in_dest_unreachs, 324);
    assert_eq!(s.in_time_excds, 0);
    assert_eq!(s.in_redirects, 0);
    assert_eq!(s.out_msgs, 7669);
    assert_eq!(s.out_dest_unreachs, 1141);
    assert_eq!(s.out_time_excds, 0);
}

#[test]
fn test_parse_host_icmp_stats_truncated_value_line_doesnt_panic() {
    // Truncated read (kernel race / fs error) — header full, values
    // half-missing. Parser must take what it can and leave the rest 0.
    let raw = "\
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InRedirects OutMsgs OutDestUnreachs OutTimeExcds
Icmp: 100 0 0 5
";
    let s = parse_host_icmp_stats(raw);
    assert_eq!(s.in_msgs, 100);
    assert_eq!(s.in_errors, 0);
    assert_eq!(s.in_csum_errors, 0);
    assert_eq!(s.in_dest_unreachs, 5);
    // Remaining fields not present — must default-zero, not panic.
    assert_eq!(s.in_time_excds, 0);
    assert_eq!(s.in_redirects, 0);
    assert_eq!(s.out_msgs, 0);
    assert_eq!(s.out_dest_unreachs, 0);
    assert_eq!(s.out_time_excds, 0);
}

// ── parse_host_disk_stats (proc-free unit tests) ────────────

#[test]
fn test_parse_host_disk_stats_real_kernel_sample() {
    // Real kernel 6.8 /proc/diskstats: 20 fields per row (kernel ≥5.5).
    // sda is OS root with no discard activity (TRIM bound to a virtual
    // device); nvme0n1 is an active data-disk with all 20 fields
    // populated. Verify both rows parse and the discard fields land
    // on the right columns.
    let raw = "\
   8       0 sda 144 0 11506 28 0 0 0 0 0 32 28 0 0 0 0 0 0
 259       0 nvme0n1 213821 28 13045213 39537 1010103 33121 28100416 230451 0 73044 235732 4214 0 17269464 1041 1156 1010
";
    let s = parse_host_disk_stats(raw);
    assert_eq!(s.len(), 2, "both sda and nvme0n1 should be retained");
    let nvme = s
        .iter()
        .find(|d| d.device == "nvme0n1")
        .expect("nvme0n1 present");
    assert_eq!(nvme.reads, 213821);
    assert_eq!(nvme.read_sectors, 13045213);
    assert_eq!(nvme.read_ms, 39537);
    assert_eq!(nvme.writes, 1010103);
    assert_eq!(nvme.write_sectors, 28100416);
    assert_eq!(nvme.write_ms, 230451);
    assert_eq!(nvme.in_flight, 0);
    assert_eq!(nvme.io_ms, 73044);
    assert_eq!(nvme.weighted_io_ms, 235732);
    // discard fields:
    assert_eq!(nvme.discards, 4214);
    assert_eq!(nvme.discards_merged, 0);
    assert_eq!(nvme.sectors_discarded, 17269464);
    assert_eq!(nvme.discard_ms, 1041);
    assert_eq!(nvme.flushes, 1156);
    assert_eq!(nvme.flush_ms, 1010);
}

#[test]
fn test_parse_host_disk_stats_kernel_4x_no_discards() {
    // Pre-4.18 kernel emits only 14 fields (no discards, no flushes).
    // Parser must not panic and must surface 0 for the missing fields
    // — operators on a 4.x box still see read/write counters work.
    let raw = "\
 259       0 nvme0n1 213821 28 13045213 39537 1010103 33121 28100416 230451 0 73044 235732
";
    let s = parse_host_disk_stats(raw);
    assert_eq!(s.len(), 1);
    let d = &s[0];
    assert_eq!(d.reads, 213821);
    assert_eq!(d.weighted_io_ms, 235732);
    assert_eq!(d.discards, 0, "no discard column → 0 fallback");
    assert_eq!(d.discards_merged, 0);
    assert_eq!(d.sectors_discarded, 0);
    assert_eq!(d.discard_ms, 0);
    assert_eq!(d.flushes, 0);
    assert_eq!(d.flush_ms, 0);
}

#[test]
fn test_parse_host_disk_stats_skips_virtual_devices() {
    // loop/ram/dm-/zd/md devices must be filtered — they are virtual
    // / composite and would double-count when summed against the real
    // backing devices.
    let raw = "\
   7       0 loop0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
   1       0 ram0  0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 253       0 dm-0  0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 230       0 zd0   0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
   9       0 md0   0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
";
    let s = parse_host_disk_stats(raw);
    assert!(s.is_empty(), "all 5 virtual/composite devices filtered");
}

#[test]
fn test_parse_host_disk_stats_skips_partitions() {
    // sda is whole-disk → kept; sda1 is a partition → skipped.
    // nvme0n1 is whole-disk → kept; nvme0n1p1 is a partition → skipped.
    // mmcblk0 is whole-disk → kept; mmcblk0p1 is a partition → skipped.
    let raw = "\
   8       0 sda       100 0 1000 10 0 0 0 0 0 0 10 0 0 0 0 0 0
   8       1 sda1      50  0  500 5  0 0 0 0 0 0 5  0 0 0 0 0 0
 259       0 nvme0n1   200 0 2000 20 0 0 0 0 0 0 20 0 0 0 0 0 0
 259       1 nvme0n1p1 100 0 1000 10 0 0 0 0 0 0 10 0 0 0 0 0 0
 179       0 mmcblk0   300 0 3000 30 0 0 0 0 0 0 30 0 0 0 0 0 0
 179       1 mmcblk0p1 150 0 1500 15 0 0 0 0 0 0 15 0 0 0 0 0 0
";
    let s = parse_host_disk_stats(raw);
    let names: Vec<&str> = s.iter().map(|d| d.device.as_str()).collect();
    assert_eq!(names.len(), 3, "only whole-disks retained, got {names:?}");
    assert!(names.contains(&"sda"));
    assert!(names.contains(&"nvme0n1"));
    assert!(names.contains(&"mmcblk0"));
}

#[test]
fn test_parse_host_disk_stats_empty_returns_empty() {
    assert!(parse_host_disk_stats("").is_empty());
}

#[test]
fn test_parse_host_disk_stats_short_row_doesnt_panic() {
    // <14 fields → row skipped (insufficient data even for the aggregate
    // baseline). Must not panic on truncation.
    let raw = "8 0 sda 1 2 3 4\n";
    assert!(parse_host_disk_stats(raw).is_empty());
}

#[test]
fn test_parse_host_disk_stats_two_disks_independent() {
    // Two whole-disks with distinct stats: confirms per-device
    // labelling is preserved (no aggregation, no overwrite). Row
    // shape is the kernel ≥5.5 form: 17 values after the device
    // name = 20 fields total. sda has no TRIM activity (discards=0)
    // — typical for an OS root that the filesystem doesn't pass
    // discards through. nvme0n1 has TRIM activity on every column.
    let raw = "\
   8       0 sda     100 0 1000 10 0 0 0 0 0 10 11 0 0 0 0 0 0
 259       0 nvme0n1 200 0 2000 20 0 0 0 0 0 20 21 222 0 333 444 555 666
";
    let s = parse_host_disk_stats(raw);
    assert_eq!(s.len(), 2);
    let sda = s.iter().find(|d| d.device == "sda").unwrap();
    let nvme = s.iter().find(|d| d.device == "nvme0n1").unwrap();
    assert_eq!(sda.reads, 100);
    assert_eq!(sda.io_ms, 10);
    assert_eq!(sda.weighted_io_ms, 11);
    assert_eq!(sda.discards, 0);
    assert_eq!(sda.sectors_discarded, 0);
    assert_eq!(nvme.reads, 200);
    assert_eq!(nvme.io_ms, 20);
    assert_eq!(nvme.weighted_io_ms, 21);
    assert_eq!(nvme.discards, 222);
    assert_eq!(nvme.discards_merged, 0);
    assert_eq!(nvme.sectors_discarded, 333);
    assert_eq!(nvme.discard_ms, 444);
    assert_eq!(nvme.flushes, 555);
    assert_eq!(nvme.flush_ms, 666);
}

// ── parse_vmstat_pressure (proc-free unit test) ───────────────

#[test]
fn test_parse_vmstat_pressure_real_kernel_sample() {
    // Trimmed real /proc/vmstat sample (kernel 6.8). The five
    // interesting fields are scattered among ~150 entries; verify
    // the parser finds them by name.
    let raw = "\
nr_free_pages 100000
nr_zone_inactive_anon 0
pgfault 24924533700
pgmajfault 2262699
pgsteal_kswapd 414730691
pgsteal_direct 0
pgscan_kswapd 500000000
pgscan_direct 0
oom_kill 0
pswpin 1969200
pswpout 3843671
some_other_counter 12345
";
    let (maj, kswapd, oom, swpin, swpout) = parse_vmstat_pressure(raw);
    assert_eq!(maj, 2262699);
    assert_eq!(kswapd, 414730691);
    assert_eq!(oom, 0);
    assert_eq!(swpin, 1969200);
    assert_eq!(swpout, 3843671);
}

#[test]
fn test_parse_vmstat_pressure_empty_returns_zeros() {
    let (maj, kswapd, oom, swpin, swpout) = parse_vmstat_pressure("");
    assert_eq!((maj, kswapd, oom, swpin, swpout), (0, 0, 0, 0, 0));
}

#[test]
fn test_parse_vmstat_pressure_old_kernel_per_zone_kswapd_sums() {
    // Older kernels (<5.0) split pgsteal_kswapd into per-zone
    // counters: pgsteal_kswapd_dma / pgsteal_kswapd_dma32 /
    // pgsteal_kswapd_normal. Parser must sum them so the metric
    // is comparable across kernel versions in the same fleet.
    let raw = "\
pgmajfault 100
pgsteal_kswapd_dma 10
pgsteal_kswapd_dma32 200
pgsteal_kswapd_normal 30000
oom_kill 0
pswpin 0
pswpout 0
";
    let (_, kswapd, _, _, _) = parse_vmstat_pressure(raw);
    assert_eq!(kswapd, 10 + 200 + 30000, "per-zone fields must sum");
}

#[test]
fn test_parse_vmstat_pressure_oom_kill_increment_visible() {
    // oom_kill must be 0 in healthy state and surface immediately
    // when ANY victim was killed.
    let raw_healthy = "oom_kill 0\n";
    let raw_one_victim = "oom_kill 1\n";
    assert_eq!(parse_vmstat_pressure(raw_healthy).2, 0);
    assert_eq!(parse_vmstat_pressure(raw_one_victim).2, 1);
}

#[test]
fn test_parse_vmstat_pressure_malformed_lines_dont_poison() {
    // A line with no value, or with garbage in the value position,
    // must skip the line silently — not corrupt other counters.
    let raw = "\
pgmajfault
pgmajfault notanumber
pgmajfault 42
oom_kill garbage
oom_kill 7
";
    let (maj, _, oom, _, _) = parse_vmstat_pressure(raw);
    assert_eq!(maj, 42);
    assert_eq!(oom, 7);
}

// ── parse_schedstat (proc-free unit test) ─────────────────────

#[test]
fn test_parse_schedstat_real_kernel_sample() {
    // Format documented in Documentation/scheduler/sched-stats.rst
    // (kernel ≥ 2.6): three whitespace-separated u64s on a single
    // line, in the order exec_runtime / run_delay / pcount.
    let raw = "1234567890 9876543210 12345\n";
    let (exec, delay, pcount) = parse_schedstat(raw);
    assert_eq!(exec, 1234567890);
    assert_eq!(delay, 9876543210);
    assert_eq!(pcount, 12345);
}

#[test]
fn test_parse_schedstat_empty_returns_zeros() {
    let (exec, delay, pcount) = parse_schedstat("");
    assert_eq!((exec, delay, pcount), (0, 0, 0));
}

#[test]
fn test_parse_schedstat_malformed_zeros_only_bad_field() {
    // If the kernel ever emits garbage in one slot (it shouldn't,
    // but containers and LSM hardening can do strange things), we
    // zero-fill THAT field but keep parsing the rest — losing all
    // three counters because of one bad token would be worse.
    let raw = "9999 garbage 7\n";
    let (exec, delay, pcount) = parse_schedstat(raw);
    assert_eq!(exec, 9999);
    assert_eq!(delay, 0, "garbage delay → 0");
    assert_eq!(pcount, 7, "but the third field still parses cleanly");
}

#[test]
fn test_parse_schedstat_zero_run_delay_is_healthy_state() {
    // The healthy idle case: process has run a tiny bit, never
    // waited on the runqueue. Every value 0 except exec.
    let raw = "1137196 0 1\n";
    let (exec, delay, pcount) = parse_schedstat(raw);
    assert_eq!(exec, 1137196);
    assert_eq!(delay, 0);
    assert_eq!(pcount, 1);
}

// ── parse_psi_total (proc-free unit test) ─────────────────────

#[test]
fn test_parse_psi_total_cpu_real_kernel_sample() {
    // Real /proc/pressure/cpu sample. Verifies we extract `total=` from
    // the `some` line and ignore CPU `full` (which kernel docs flag as
    // ill-defined; cpu_full is hardcoded 0 on ≥5.13).
    let raw = "\
some avg10=0.06 avg60=0.39 avg300=5.55 total=32244492821
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
";
    let (some, full) = parse_psi_total(raw);
    assert_eq!(some, 32_244_492_821);
    assert_eq!(full, 0);
}

#[test]
fn test_parse_psi_total_memory_real_kernel_sample() {
    let raw = "\
some avg10=0.00 avg60=0.00 avg300=0.00 total=184964232
full avg10=0.00 avg60=0.00 avg300=0.00 total=167426198
";
    let (some, full) = parse_psi_total(raw);
    assert_eq!(some, 184_964_232);
    assert_eq!(full, 167_426_198);
}

#[test]
fn test_parse_psi_total_io_real_kernel_sample() {
    // Sample where mem_full < mem_some (typical: not every reclaim
    // wedges every task) and IO has both `some` and `full` accumulated.
    let raw = "\
some avg10=0.00 avg60=0.36 avg300=0.42 total=3718904007
full avg10=0.00 avg60=0.36 avg300=0.29 total=2994126254
";
    let (some, full) = parse_psi_total(raw);
    assert_eq!(some, 3_718_904_007);
    assert_eq!(full, 2_994_126_254);
    // PSI invariant: full ≤ some (you cannot have more time when ALL
    // tasks were stalled than when AT LEAST ONE was stalled).
    assert!(full <= some, "PSI total invariant violated");
}

#[test]
fn test_parse_psi_total_empty_returns_zeros() {
    // Containers without /proc/pressure exposure see read_to_string
    // succeed with empty string OR fail; both paths must give zeros
    // (not panic, not unwrap_or_default cascade into NaN-shaped
    // counters that get rejected by Prometheus parsers).
    let (some, full) = parse_psi_total("");
    assert_eq!(some, 0);
    assert_eq!(full, 0);
}

#[test]
fn test_parse_psi_total_malformed_total_field_keeps_zero() {
    // Garbage in `total=` field must not propagate to a poisoned
    // counter — we drop the bad value and keep zero. Critical because
    // a Prometheus counter that goes from N to garbage to back-to-N
    // computes a giant negative rate that a dashboard then divides by
    // zero somewhere downstream.
    let raw = "\
some avg10=0.00 avg60=0.00 avg300=0.00 total=NOTANUMBER
full avg10=0.00 avg60=0.00 avg300=0.00 total=42
";
    let (some, full) = parse_psi_total(raw);
    assert_eq!(some, 0, "garbage total= must not pollute counter");
    assert_eq!(full, 42, "next line still parses");
}

#[test]
fn test_parse_psi_total_unknown_label_ignored() {
    // Forward-compat: future kernels could add a third row (`partial`?
    // `worst`?). Our parser must not panic or treat it as `some`/`full`.
    let raw = "\
some avg10=0.00 avg60=0.00 avg300=0.00 total=100
extra avg10=0.00 avg60=0.00 avg300=0.00 total=999
full avg10=0.00 avg60=0.00 avg300=0.00 total=50
";
    let (some, full) = parse_psi_total(raw);
    assert_eq!(some, 100);
    assert_eq!(full, 50);
    // The `extra` line's total=999 must not have leaked into either.
}

// ── cgroup v2 memory accounting (proc-free unit tests) ─────────

#[test]
fn test_parse_self_cgroup_path_systemd_unit() {
    // Real shape on a systemd-managed VPS running elara-node as a unit.
    let raw = "0::/system.slice/elara-node.service\n";
    let p = parse_self_cgroup_path(raw).expect("v2 line present");
    assert_eq!(p, "/system.slice/elara-node.service");
}

#[test]
fn test_parse_self_cgroup_path_root_bare_metal() {
    // Bare-metal box with no nested unit — process at root cgroup.
    let raw = "0::/\n";
    let p = parse_self_cgroup_path(raw).expect("v2 line present");
    assert_eq!(p, "/");
}

#[test]
fn test_parse_self_cgroup_path_v1_hybrid_returns_none() {
    // RHEL 7/8 hybrid mode exposes both v1 and v2 lines but the
    // v2 entry is the literal `0::` with no path. We treat that as
    // unavailable so /sys/fs/cgroup reads short-circuit to zero
    // gauges instead of probing an empty path.
    let raw = "12:cpuset:/\n11:memory:/\n0::\n";
    let p = parse_self_cgroup_path(raw);
    assert!(p.is_none(), "empty 0:: path should be unavailable");
}

#[test]
fn test_parse_self_cgroup_path_v1_only_returns_none() {
    // Pure cgroup v1 — no `0::` line at all. Helper must not pick
    // up controller-prefixed paths like `12:memory:/foo`.
    let raw = "12:cpuset:/\n11:memory:/\n10:cpu:/\n";
    let p = parse_self_cgroup_path(raw);
    assert!(p.is_none(), "v1-only systems return None");
}

#[test]
fn test_parse_cgroup_max_value_unlimited() {
    // Kernel writes the literal string `max` when no limit is set.
    // Coerce to 0 so a single u64 metric carries both states.
    assert_eq!(parse_cgroup_max_value("max\n"), 0);
    assert_eq!(parse_cgroup_max_value("max"), 0);
}

#[test]
fn test_parse_cgroup_max_value_byte_limit() {
    // 2 GiB limit, real shape with trailing newline as kernel writes.
    assert_eq!(parse_cgroup_max_value("2147483648\n"), 2_147_483_648);
    assert_eq!(parse_cgroup_max_value("485158912"), 485_158_912);
}

#[test]
fn test_parse_cgroup_max_value_empty_or_garbage_is_zero() {
    // Empty file (read failure recovered to default empty) and
    // garbage input both must yield 0 — safe posture for a counter
    // that an operator alerts on as a ratio (current/max). 0 means
    // no ceiling, ratio undefined, alert correctly silent.
    assert_eq!(parse_cgroup_max_value(""), 0);
    assert_eq!(parse_cgroup_max_value("notanumber"), 0);
    assert_eq!(parse_cgroup_max_value("   "), 0);
}

#[test]
fn test_parse_memory_events_real_kernel_sample() {
    // Real /sys/fs/cgroup/<>/memory.events shape from a 5.15 box.
    let raw = "low 0
high 12
max 0
oom 0
oom_kill 3
oom_group_kill 0
";
    let ev = parse_memory_events(raw);
    assert_eq!(ev.high, 12);
    assert_eq!(ev.oom_kill, 3);
    assert_eq!(ev.low, 0);
    assert_eq!(ev.max, 0);
    assert_eq!(ev.oom, 0);
    assert_eq!(ev.oom_group_kill, 0);
}

#[test]
fn test_parse_memory_events_healthy_node_all_zeros() {
    // The shape we see on every healthy phone-tier node — never
    // throttled, never OOM-killed.
    let raw = "low 0
high 0
max 0
oom 0
oom_kill 0
oom_group_kill 0
";
    assert_eq!(parse_memory_events(raw), MemoryEvents::default());
}

#[test]
fn test_parse_memory_events_empty_returns_zeros() {
    // Containers / read-failure path — must not panic, must give 0s.
    assert_eq!(parse_memory_events(""), MemoryEvents::default());
}

#[test]
fn test_parse_memory_events_unknown_keys_ignored() {
    // Forward-compat: kernel 5.19 added `oom_group_kill`; future
    // kernels may add more rows. Our parser must ignore unknown
    // keys, NOT panic or sum them into the wrong counter.
    let raw = "low 100
high 5
max 7
oom 2
oom_kill 1
oom_group_kill 999
new_kernel_field_TBD 12345
";
    let ev = parse_memory_events(raw);
    assert_eq!(ev.low, 100);
    assert_eq!(ev.high, 5);
    assert_eq!(ev.max, 7);
    assert_eq!(ev.oom, 2);
    assert_eq!(ev.oom_kill, 1);
    assert_eq!(ev.oom_group_kill, 999);
    // The 12345 from the unknown field must NOT have leaked
    // into any counter.
}

#[test]
fn test_parse_memory_events_malformed_lines_dont_poison() {
    // A line missing its value, OR with non-numeric value, must
    // be skipped — not propagate to whichever counter happens to
    // be parsing at that moment.
    let raw = "high
oom_kill notanumber
max
oom_group_kill bogus
high 7
oom_kill 2
max 9
oom_group_kill 4
";
    let ev = parse_memory_events(raw);
    assert_eq!(ev.high, 7, "second valid `high` line wins");
    assert_eq!(ev.oom_kill, 2, "second valid `oom_kill` line wins");
    assert_eq!(ev.max, 9, "second valid `max` line wins");
    assert_eq!(ev.oom_group_kill, 4, "second valid `oom_group_kill` wins");
}

#[test]
fn test_parse_memory_events_ops110_full_coverage() {
    // Confirms all 6 keys of the kernel memory.events file
    // are surfaced. Distinct non-zero values per row catch any
    // cross-wiring (e.g. `low` value leaking into `max` field).
    let raw = "low 11
high 22
max 33
oom 44
oom_kill 55
oom_group_kill 66
";
    let ev = parse_memory_events(raw);
    assert_eq!(ev.low, 11);
    assert_eq!(ev.high, 22);
    assert_eq!(ev.max, 33);
    assert_eq!(ev.oom, 44);
    assert_eq!(ev.oom_kill, 55);
    assert_eq!(ev.oom_group_kill, 66);
}

// ── cgroup v2 cpu.stat / cpu.max parsers ──────────────────────

#[test]
fn test_parse_cpu_stat_real_kernel_sample_with_quota() {
    // Real sample from a managed cluster cgroup that DOES have
    // a quota — every documented field present.
    let raw = "usage_usec 12345678
user_usec 9876543
system_usec 2469135
nr_periods 1000
nr_throttled 17
throttled_usec 234567
core_sched.force_idle_usec 0
burst_usec 0
nr_bursts 0
";
    let (usage, user, system, throttled_us, nr_throttled) = parse_cpu_stat(raw);
    assert_eq!(usage, 12345678);
    assert_eq!(user, 9876543);
    assert_eq!(system, 2469135);
    assert_eq!(throttled_us, 234567);
    assert_eq!(nr_throttled, 17);
}

#[test]
fn test_parse_cpu_stat_real_kernel_sample_no_quota() {
    // Real sample from a live elara-node /metrics — no quota set,
    // kernel still emits the throttle fields but they stay 0.
    let raw = "usage_usec 718565846
user_usec 598599316
system_usec 119966530
nr_periods 0
nr_throttled 0
throttled_usec 0
";
    let (usage, user, system, throttled_us, nr_throttled) = parse_cpu_stat(raw);
    assert_eq!(usage, 718565846);
    assert_eq!(user, 598599316);
    assert_eq!(system, 119966530);
    assert_eq!(throttled_us, 0);
    assert_eq!(nr_throttled, 0);
}

#[test]
fn test_parse_cpu_stat_empty_returns_all_zeros() {
    // Empty file (cgroup v1 hybrid where v2 unified-hierarchy
    // file does not exist) must return all zeros, never panic.
    let (usage, user, system, throttled_us, nr_throttled) = parse_cpu_stat("");
    assert_eq!(usage, 0);
    assert_eq!(user, 0);
    assert_eq!(system, 0);
    assert_eq!(throttled_us, 0);
    assert_eq!(nr_throttled, 0);
}

#[test]
fn test_parse_cpu_stat_unknown_keys_ignored() {
    // Future kernel adds extra fields — parser must not crash
    // and must extract the documented ones intact.
    let raw = "usage_usec 100
totally_new_kernel_field 42
user_usec 70
some_unrelated_thing nonsense
system_usec 30
";
    let (usage, user, system, _, _) = parse_cpu_stat(raw);
    assert_eq!(usage, 100);
    assert_eq!(user, 70);
    assert_eq!(system, 30);
}

#[test]
fn test_parse_cpu_stat_malformed_value_skipped() {
    // Garbage value on one line must not poison sibling fields.
    let raw = "usage_usec garbage
user_usec 50
system_usec 20
";
    let (usage, user, system, _, _) = parse_cpu_stat(raw);
    assert_eq!(usage, 0, "garbage value parses to 0, not propagated");
    assert_eq!(user, 50);
    assert_eq!(system, 20);
}

#[test]
fn test_parse_cpu_max_unlimited_with_period() {
    // 'max <period>' = no quota; quota gauge MUST be 0 so
    // operators can distinguish 'unconfigured' from 'tight quota'.
    let (quota, period) = parse_cpu_max("max 100000\n");
    assert_eq!(quota, 0, "literal 'max' → 0 quota in our coercion");
    assert_eq!(period, 100000, "period preserved even when quota unlimited");
}

#[test]
fn test_parse_cpu_max_quota_with_period() {
    // 200ms quota per 100ms period = 2 vCPU equivalent.
    let (quota, period) = parse_cpu_max("200000 100000\n");
    assert_eq!(quota, 200000);
    assert_eq!(period, 100000);
}

#[test]
fn test_parse_cpu_max_empty_returns_zeros() {
    // Empty file (cgroup v1 hybrid OR cpu.max missing on the
    // kernel's hierarchy) — parser MUST return (0, 0), never
    // panic. Operator reads both as unobservable.
    let (quota, period) = parse_cpu_max("");
    assert_eq!(quota, 0);
    assert_eq!(period, 0);
}

#[test]
fn test_parse_cpu_max_one_token_returns_zeros() {
    // A single-token file is malformed — kernel always emits two
    // tokens. Treat as unobservable, never half-fill the gauges.
    let (quota, period) = parse_cpu_max("max\n");
    assert_eq!(quota, 0);
    assert_eq!(period, 0);
}

#[test]
fn test_parse_cpu_max_garbage_returns_zeros() {
    // Numeric parse failures on either field → 0; the gauge then
    // pairs with a healthy throttle_us=0 to look like a no-quota
    // baseline, which is operator-correct (we have no signal).
    let (quota, period) = parse_cpu_max("garbage trash\n");
    assert_eq!(quota, 0);
    assert_eq!(period, 0);
}

// ── /proc/net/dev parser ──────────────────────────────────────

#[test]
fn test_parse_proc_net_dev_real_kernel_sample() {
    // Real local sample with multiple devices: lo (skipped),
    // wired eth0 (kept, has rx_drop=2), wifi (kept, large
    // rx_drop), tailscale0 (kept, all zeros).
    let raw = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 68731596842 14324272    0    0    0     0          0         0 68731596842 14324272    0    0    0     0       0          0
eth0: 3557798   32428    0    2    0     0          0        19 21295639  105324    0    0    0     0       0          0
wlan0: 141051711610 131905366    0 341773    0     0          0         0 102559349497 116961799    0    0    0     0       0          0
tailscale0: 2003300940 2485422    0    0    0     0          0         0 11940062362 4270725    0    0    0     0       0          0
";
    let stats = parse_proc_net_dev(raw);
    // lo filtered out, three real devices remain.
    assert_eq!(
        stats.len(),
        3,
        "lo must be skipped, three real devices remain"
    );
    let names: Vec<&str> = stats.iter().map(|s| s.device.as_str()).collect();
    assert_eq!(names, vec!["eth0", "wlan0", "tailscale0"]);
    // eth0 has rx_drop=2 — real low-level packet loss.
    assert_eq!(stats[0].rx_drop, 2);
    assert_eq!(stats[0].rx_errs, 0);
    assert_eq!(stats[0].tx_drop, 0);
    // wifi has large rx_drop=341773.
    assert_eq!(stats[1].rx_drop, 341773);
    // tailscale baseline.
    assert_eq!(stats[2].tx_carrier, 0);
}

#[test]
fn test_parse_proc_net_dev_empty_returns_empty_vec() {
    // Empty file (extreme edge — /proc/net/dev unavailable in
    // a stripped namespace) must return empty vec, never panic.
    let stats = parse_proc_net_dev("");
    assert_eq!(stats.len(), 0);
}

#[test]
fn test_parse_proc_net_dev_skips_docker_bridges() {
    // Docker / k8s bridges add cardinality without surfacing
    // real NIC pain — kernel attributes namespace-internal
    // drops to them, which would inflate operator alerts.
    let raw = "    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
docker0: 100 5 0 0 0 0 0 0 200 5 0 0 0 0 0 0
br-abc123: 50 2 0 7 0 0 0 0 100 3 0 0 0 0 0 0
veth1234: 30 1 0 0 0 0 0 0 60 2 0 0 0 0 0 0
virbr0: 10 1 0 0 0 0 0 0 20 1 0 0 0 0 0 0
flannel.1: 5 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0
kube-bridge: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0
eth0: 1000 50 0 1 0 0 0 0 2000 100 0 0 0 0 0 0
";
    let stats = parse_proc_net_dev(raw);
    assert_eq!(stats.len(), 1, "only eth0 survives the bridge filter");
    assert_eq!(stats[0].device, "eth0");
    assert_eq!(stats[0].rx_drop, 1);
}

#[test]
fn test_parse_proc_net_dev_short_line_skipped() {
    // A device row with fewer than 16 fields (kernel format
    // truncation, OR the header rows themselves) must be
    // dropped, not crash on index out-of-bounds.
    let raw = "    lo: 0 0
eth0: 1 2 3
goodnic: 1000 50 0 4 0 0 0 0 2000 100 0 0 0 0 0 0
";
    let stats = parse_proc_net_dev(raw);
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].device, "goodnic");
    assert_eq!(stats[0].rx_drop, 4);
}

#[test]
fn test_parse_proc_net_dev_garbage_value_yields_zero() {
    // Non-numeric field must parse to 0 (matches disk
    // pattern), not propagate Err and lose the whole device.
    let raw = "eth0: 100 50 garbage 7 0 0 0 0 200 100 0 0 0 0 0 0\n";
    let stats = parse_proc_net_dev(raw);
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].rx_errs, 0, "garbage field → 0, not propagated");
    assert_eq!(stats[0].rx_drop, 7, "neighbour fields parse correctly");
}

#[test]
fn test_parse_proc_net_dev_keeps_tailscale() {
    // Tailscale is the deploy backbone for the laptop node — must NOT be
    // filtered. Verify explicitly so a future bridge-filter
    // change doesn't accidentally drop it.
    let raw = "tailscale0: 100 5 0 1 0 0 0 0 200 10 0 2 0 0 0 0\n";
    let stats = parse_proc_net_dev(raw);
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].device, "tailscale0");
    assert_eq!(stats[0].rx_drop, 1);
    assert_eq!(stats[0].tx_drop, 2);
}

// ── /proc/softirqs aggregate parser ───────────────────────────

#[test]
fn test_parse_softirqs_real_multi_cpu_sample() {
    // Real /proc/softirqs sample showing the local-box CPU6 imbalance
    // (NET_RX 58M on CPU6 vs ~1.3M elsewhere) — exactly the asymmetry
    // the aggregate is meant to surface. Aggregate must equal sum across CPUs.
    let raw = concat!(
            "                    CPU0       CPU1       CPU2       CPU3       CPU4       CPU5       CPU6       CPU7\n",
            "          HI:          1          2          4          0          1          0       100          4\n",
            "       TIMER:   16753931   21215895   18149707   14785295   13796905   13300025   35751114   13497897\n",
            "      NET_TX:       3041       2925       2734       3041       2950       2754     118567       3111\n",
            "      NET_RX:    1357327    1328051    1286154    1319183    1321003    1293100   58169166    1846699\n",
            "       BLOCK:       8885     393811       7967       8065       7898       9218       8500       9588\n",
            "    IRQ_POLL:          0          0          0          0          0          0          0          0\n",
            "     TASKLET:       9271       8707       9226       7908       7811       7531  268604215      10260\n",
            "       SCHED:  281093767  144025818  102659170   80135797   76386117   74851884   88132905   68847732\n",
            "     HRTIMER:        350        247        290        195        129        144     322972        392\n",
            "         RCU:  102846264   98438067   96507714   95068994   92122035   93336654   97713484   94064913\n",
        );
    let (net_rx, net_tx, block, sched, timer) = parse_softirqs(raw);
    // NET_RX sum: 1357327+1328051+1286154+1319183+1321003+1293100+58169166+1846699 = 67920683
    assert_eq!(net_rx, 67_920_683);
    // NET_TX: 3041+2925+2734+3041+2950+2754+118567+3111 = 139123
    assert_eq!(net_tx, 139_123);
    // BLOCK: 8885+393811+7967+8065+7898+9218+8500+9588 = 453932
    assert_eq!(block, 453_932);
    // SCHED: 281093767+144025818+102659170+80135797+76386117+74851884+88132905+68847732 = 916133190
    assert_eq!(sched, 916_133_190);
    // TIMER: 16753931+21215895+18149707+14785295+13796905+13300025+35751114+13497897 = 147250769
    assert_eq!(timer, 147_250_769);
}

#[test]
fn test_parse_softirqs_single_cpu() {
    // Single-CPU phone-tier scenario: counts come back unmolested.
    let raw = concat!(
        "                    CPU0\n",
        "      NET_RX:       12345\n",
        "      NET_TX:        2222\n",
        "       BLOCK:         100\n",
        "       SCHED:    99999999\n",
        "       TIMER:      500000\n",
    );
    let (net_rx, net_tx, block, sched, timer) = parse_softirqs(raw);
    assert_eq!(net_rx, 12345);
    assert_eq!(net_tx, 2222);
    assert_eq!(block, 100);
    assert_eq!(sched, 99_999_999);
    assert_eq!(timer, 500_000);
}

#[test]
fn test_parse_softirqs_missing_timer_row_yields_zero() {
    // Some virtualized kernels (older Xen) suppress TIMER row.
    // The other counts must still be correct; missing row = 0.
    let raw = concat!(
        "                    CPU0       CPU1\n",
        "      NET_RX:       1000       2000\n",
        "      NET_TX:        100        200\n",
        "       BLOCK:         50         50\n",
        "       SCHED:    1000000    2000000\n",
    );
    let (net_rx, net_tx, block, sched, timer) = parse_softirqs(raw);
    assert_eq!(net_rx, 3000);
    assert_eq!(net_tx, 300);
    assert_eq!(block, 100);
    assert_eq!(sched, 3_000_000);
    assert_eq!(timer, 0);
}

#[test]
fn test_parse_softirqs_empty_returns_all_zeros() {
    // /proc/softirqs unreadable (cgroup namespace strip, container
    // restriction). Helper coerces to all zeros — operator sees
    // flat-zero counters and reads it as "unobservable".
    let (net_rx, net_tx, block, sched, timer) = parse_softirqs("");
    assert_eq!((net_rx, net_tx, block, sched, timer), (0, 0, 0, 0, 0));
}

#[test]
fn test_parse_softirqs_malformed_values_skipped_not_panic() {
    // A garbage column must not poison the row sum — we sum only
    // the columns that parse cleanly. Aggregate stays well-defined.
    let raw = concat!(
        "                    CPU0       CPU1       CPU2\n",
        "      NET_RX:       1000     ABC123       2000\n",
        "       SCHED:    1000000    1500000   garbage\n",
    );
    let (net_rx, _, _, sched, _) = parse_softirqs(raw);
    assert_eq!(net_rx, 3000); // 1000+2000, "ABC123" skipped
    assert_eq!(sched, 2_500_000); // 1000000+1500000, "garbage" skipped
}

#[test]
fn test_parse_softirqs_header_only_returns_zeros() {
    // /proc/softirqs with header line but no rows (kernel boot
    // race window). All five counters must come back zero.
    let raw = "                    CPU0       CPU1\n";
    let (net_rx, net_tx, block, sched, timer) = parse_softirqs(raw);
    assert_eq!((net_rx, net_tx, block, sched, timer), (0, 0, 0, 0, 0));
}

#[test]
fn test_parse_softirqs_unknown_label_ignored() {
    // Newer kernels add labels we don't track (POSIX_TIMER, NET_RX_DROP,
    // etc). Unknown labels must be silently skipped — five tracked
    // counters unchanged.
    let raw = concat!(
        "                    CPU0       CPU1\n",
        "  POSIX_TIMER:        500       1000\n",
        " NET_RX_DROP:        100        200\n",
        "      NET_RX:       1000       2000\n",
    );
    let (net_rx, net_tx, block, sched, timer) = parse_softirqs(raw);
    assert_eq!(net_rx, 3000);
    assert_eq!((net_tx, block, sched, timer), (0, 0, 0, 0));
}

// ── /proc/buddyinfo memory fragmentation parser ───────────────

#[test]
fn test_parse_buddyinfo_real_local_sample() {
    // Real /proc/buddyinfo from local box: 3 zones (DMA tiny, DMA32
    // medium, Normal large). Order 0/4/8 must sum across all three.
    let raw = concat!(
            "Node 0, zone      DMA      0      0      0      0      0      0      0      0      1      1      2 \n",
            "Node 0, zone    DMA32  43688  22046   8323   1529    714    275    165    110     97     35     54 \n",
            "Node 0, zone   Normal  42820  14159  13457   9227   5974   3095   1359    401      3      0      0 \n",
        );
    let (o0, o4, o8) = parse_buddyinfo(raw);
    // Order 0: 0 + 43688 + 42820 = 86508
    assert_eq!(o0, 86508);
    // Order 4: 0 + 714 + 5974 = 6688
    assert_eq!(o4, 6688);
    // Order 8: 1 + 97 + 3 = 101
    assert_eq!(o8, 101);
}

#[test]
fn test_parse_buddyinfo_empty_returns_zeros() {
    // /proc/buddyinfo unreadable → all three orders = 0.
    let (o0, o4, o8) = parse_buddyinfo("");
    assert_eq!((o0, o4, o8), (0, 0, 0));
}

#[test]
fn test_parse_buddyinfo_multi_numa() {
    // 2-NUMA-node server: zones must sum across BOTH nodes
    // not just the first one.
    let raw = concat!(
            "Node 0, zone   Normal   100    200    300    400    500    600    700    800    900   1000   1100\n",
            "Node 1, zone   Normal    10     20     30     40     50     60     70     80     90    100    110\n",
        );
    let (o0, o4, o8) = parse_buddyinfo(raw);
    assert_eq!(o0, 110); // 100 + 10
    assert_eq!(o4, 550); // 500 + 50
    assert_eq!(o8, 990); // 900 + 90
}

#[test]
fn test_parse_buddyinfo_short_freelist_safe() {
    // Older kernel emits only 9 orders (0..=8) — order 8 column
    // present, missing orders are simply absent. Helper must
    // handle without panic.
    let raw = "Node 0, zone   Normal     50     0     0     0   100     0     0     0     7\n";
    let (o0, o4, o8) = parse_buddyinfo(raw);
    assert_eq!(o0, 50);
    assert_eq!(o4, 100);
    assert_eq!(o8, 7);
}

#[test]
fn test_parse_buddyinfo_truncated_below_order8_clamps() {
    // Hypothetical kernel emits only 6 orders (0..=5) — order 8
    // column missing entirely. Helper coerces missing column to 0
    // rather than reading garbage.
    let raw = "Node 0, zone   Normal     50     0     0     0   100     0\n";
    let (o0, o4, o8) = parse_buddyinfo(raw);
    assert_eq!(o0, 50);
    assert_eq!(o4, 100);
    assert_eq!(o8, 0); // missing column → 0, not crash
}

#[test]
fn test_parse_buddyinfo_garbage_column_skipped() {
    // A column with non-numeric content must not poison the row.
    // Kernels never produce this in practice but we should be
    // robust to /proc namespace mounting weirdness.
    let raw =
        "Node 0, zone   Normal    ABC      0      0      0    100      0      0      0      7\n";
    let (o0, o4, o8) = parse_buddyinfo(raw);
    assert_eq!(o0, 0); // "ABC" skipped → 0
    assert_eq!(o4, 100);
    assert_eq!(o8, 7);
}

#[test]
fn test_parse_buddyinfo_non_node_lines_skipped() {
    // Some /proc namespaces or older kernels prefix with banner
    // lines or comments. Anything not starting with "Node" must
    // be silently skipped.
    let raw = concat!(
        "# /proc/buddyinfo header\n",
        "garbage line with no Node prefix\n",
        "Node 0, zone   Normal     50     0     0     0    100      0      0      0     7\n",
    );
    let (o0, o4, o8) = parse_buddyinfo(raw);
    assert_eq!(o0, 50);
    assert_eq!(o4, 100);
    assert_eq!(o8, 7);
}

// ── jemalloc stats helper ─────────────────────────────────────
//
// host_jemalloc_stats() returns (allocated, active, resident, metadata,
// mapped, retained). On the `node` feature we get real values; on other
// builds it returns all zeros. We can only meaningfully assert the
// monotonic relationship `allocated <= active <= resident <= mapped`
// when the node feature is on; otherwise we just confirm zeros.

#[cfg(all(feature = "node", target_family = "unix", not(target_arch = "wasm32")))]
#[test]
fn test_jemalloc_stats_monotonic_relationship() {
    // Allocate something the test can hold so the heap has a non-zero
    // value to read. Vec<u8> of 1 MiB forces a large-class arena pull.
    let _hold: Vec<u8> = vec![0u8; 1024 * 1024];
    let (allocated, active, resident, _metadata, mapped, _retained) = host_jemalloc_stats();
    // jemalloc invariants: each layer is a superset of the prior. We
    // allow equality because tiny test workloads can hit identical
    // bucket boundaries — strict-less would be flaky.
    assert!(allocated > 0, "allocated must be > 0 with active heap");
    assert!(
        active >= allocated,
        "active({}) >= allocated({})",
        active,
        allocated
    );
    assert!(
        resident >= active,
        "resident({}) >= active({})",
        resident,
        active
    );
    assert!(mapped >= active, "mapped({}) >= active({})", mapped, active);
}

#[cfg(all(feature = "node", target_family = "unix", not(target_arch = "wasm32")))]
#[test]
fn test_jemalloc_stats_epoch_advance_refreshes() {
    // Reads bracketing a live allocation should show the new bytes.
    // Without epoch::advance() (which the helper calls on every entry)
    // the second read would return identical cached numbers — the
    // stale-stats trap the jemalloc reader closes. Jemalloc stats are process-global,
    // so sibling parallel tests deallocating during our read window can
    // mask a 4 MB delta — retry with a 16 MB balloon up to 10 times and
    // require at least one iteration to register ≥8 MB. black_box keeps
    // the Vec live across the second read in --release builds.
    let mut detected = false;
    let mut last_before = 0u64;
    let mut last_after = 0u64;
    for _ in 0..10 {
        let (alloc_before, _, _, _, _, _) = host_jemalloc_stats();
        let balloon: Vec<u8> = vec![0u8; 16 * 1024 * 1024];
        std::hint::black_box(&balloon);
        let (alloc_after, _, _, _, _, _) = host_jemalloc_stats();
        std::hint::black_box(&balloon);
        last_before = alloc_before;
        last_after = alloc_after;
        if alloc_after > alloc_before + (8 * 1024 * 1024) {
            detected = true;
            break;
        }
    }
    assert!(
        detected,
        "epoch advance failed across 10 iterations: last before={} after={}",
        last_before, last_after
    );
}

#[cfg(not(all(feature = "node", target_family = "unix", not(target_arch = "wasm32"))))]
#[test]
fn test_jemalloc_stats_returns_zeros_on_non_node_builds() {
    let (allocated, active, resident, metadata, mapped, retained) = host_jemalloc_stats();
    assert_eq!(allocated, 0);
    assert_eq!(active, 0);
    assert_eq!(resident, 0);
    assert_eq!(metadata, 0);
    assert_eq!(mapped, 0);
    assert_eq!(retained, 0);
}

// ── /proc/self/io extended fields ─────────────────────────────
// The base reader exposed rchar/wchar/read_bytes/write_bytes; this widens
// the same parser to also surface syscr/syscw/cancelled_write_bytes
// without paying for a second file read. Tests below pin the parser
// to canonical kernel format and verify the live helper returns
// monotonic counters.

#[test]
fn test_parse_proc_self_io_canonical() {
    // Verbatim shape from a Linux 6.x /proc/self/io.
    let raw = "rchar: 1234567\n\
                   wchar: 89012\n\
                   syscr: 4321\n\
                   syscw: 765\n\
                   read_bytes: 65536\n\
                   write_bytes: 16384\n\
                   cancelled_write_bytes: 4096\n";
    let (rchar, wchar, read_b, write_b, syscr, syscw, cancelled) = parse_proc_self_io(raw);
    assert_eq!(rchar, 1234567);
    assert_eq!(wchar, 89012);
    assert_eq!(syscr, 4321);
    assert_eq!(syscw, 765);
    assert_eq!(read_b, 65536);
    assert_eq!(write_b, 16384);
    assert_eq!(cancelled, 4096);
}

#[test]
fn test_parse_proc_self_io_handles_empty() {
    // /proc not mounted (some containers, non-Linux): empty string.
    let (rchar, wchar, read_b, write_b, syscr, syscw, cancelled) = parse_proc_self_io("");
    assert_eq!(rchar, 0);
    assert_eq!(wchar, 0);
    assert_eq!(syscr, 0);
    assert_eq!(syscw, 0);
    assert_eq!(read_b, 0);
    assert_eq!(write_b, 0);
    assert_eq!(cancelled, 0);
}

#[test]
fn test_parse_proc_self_io_skips_unknown_keys() {
    // Forward-compatibility: kernels may add new keys (e.g. a future
    // 'pgfault_bytes' field). Parser should ignore unknowns, not panic.
    let raw = "rchar: 100\n\
                   future_field: 999\n\
                   wchar: 50\n\
                   syscr: 5\n\
                   another_unknown: garbage\n\
                   syscw: 2\n\
                   read_bytes: 4096\n\
                   write_bytes: 2048\n\
                   cancelled_write_bytes: 0\n";
    let (rchar, wchar, _, _, syscr, syscw, _) = parse_proc_self_io(raw);
    assert_eq!(rchar, 100);
    assert_eq!(wchar, 50);
    assert_eq!(syscr, 5);
    assert_eq!(syscw, 2);
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_io_bytes_live_syscr_positive() {
    // On Linux, this test process has done reads (cargo test loads
    // libraries, the binary itself). syscr must be > 0 by the time
    // the test runs, regardless of test ordering.
    let (_, _, _, _, syscr, _, _) = process_io_bytes();
    assert!(
        syscr > 0,
        "syscr must be > 0 in a Linux process that has booted"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_io_bytes_rchar_grows_after_read() {
    // Bracket a file read: rchar AFTER must exceed rchar BEFORE.
    // Use a large file the test process has access to (own binary).
    let (rchar_before, _, _, _, syscr_before, _, _) = process_io_bytes();
    // Force a read of meaningful size — read this source file. Any
    // file works; we just need >rchar_before bytes of read syscalls.
    let _ = std::fs::read_to_string("/proc/self/cmdline").ok();
    let (rchar_after, _, _, _, syscr_after, _, _) = process_io_bytes();
    assert!(
        rchar_after >= rchar_before,
        "rchar must be monotonic: before={} after={}",
        rchar_before,
        rchar_after
    );
    assert!(
        syscr_after >= syscr_before,
        "syscr must be monotonic: before={} after={}",
        syscr_before,
        syscr_after
    );
}

// ── /proc/self/status RSS composition (Anon/File/Shmem) ─────────

#[test]
fn test_parse_rss_composition_canonical() {
    // Verbatim shape from a Linux 6.x /proc/self/status excerpt — the
    // three RssAnon/RssFile/RssShmem lines surrounded by other fields
    // that must be ignored.
    let raw = "Name:\telara-node\n\
                   Pid:\t12345\n\
                   VmPeak:\t  2097152 kB\n\
                   VmHWM:\t  1638400 kB\n\
                   RssAnon:\t  524288 kB\n\
                   RssFile:\t  819200 kB\n\
                   RssShmem:\t       0 kB\n\
                   VmSwap:\t       0 kB\n\
                   Threads:\t  16\n";
    let (anon, file, shmem) = parse_rss_composition(raw);
    assert_eq!(anon, 524288);
    assert_eq!(file, 819200);
    assert_eq!(shmem, 0);
}

#[test]
fn test_parse_rss_composition_handles_empty() {
    // /proc unavailable (some containers, non-Linux): empty string.
    let (anon, file, shmem) = parse_rss_composition("");
    assert_eq!(anon, 0);
    assert_eq!(file, 0);
    assert_eq!(shmem, 0);
}

#[test]
fn test_parse_rss_composition_handles_pre_4_5_kernel() {
    // Kernels before 4.5 don't have the RssAnon/RssFile/RssShmem split
    // — only VmRSS as a single field. Parser returns (0, 0, 0) which
    // is the documented "kernel doesn't expose this" sentinel.
    let raw = "Name:\told-kernel\n\
                   VmRSS:\t  500000 kB\n\
                   Threads:\t  4\n";
    let (anon, file, shmem) = parse_rss_composition(raw);
    assert_eq!(anon, 0);
    assert_eq!(file, 0);
    assert_eq!(shmem, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_rss_composition_live_anon_positive() {
    // On a running Linux test process, RssAnon must be > 0 — the test
    // harness has heap allocations (Vec, String, etc.) and stack pages.
    let (anon, _, _) = process_rss_composition();
    assert!(
        anon > 0,
        "RssAnon must be > 0 in a Linux process with allocations"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_rss_composition_sums_consistent_with_total_rss() {
    // RSS = RssAnon + RssFile + RssShmem on every modern kernel. Verify
    // the identity holds on a single /proc/self/status snapshot. Reading
    // the file ONCE and parsing all four fields off the same snapshot
    // avoids the drift that two consecutive open(/proc/self/status)
    // calls would introduce — the kernel updates these counters
    // asynchronously and a busy test process can shift them by several
    // MB between two reads.
    let raw = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let (anon, file, shmem) = parse_rss_composition(&raw);
    let vmrss: u64 = raw
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let sum = anon + file + shmem;
    // Within a single snapshot the kernel may still have written the
    // four fields at slightly different microsecond ticks. 64 kB
    // tolerance (one large page) catches real format drift while
    // absorbing single-update races.
    let diff = sum.abs_diff(vmrss);
    assert!(diff <= 64,
            "RssAnon+RssFile+RssShmem ({}) should equal VmRSS ({}) within 64kB on a single status snapshot; diff={}",
            sum, vmrss, diff);
}

// ── extended meminfo parser ───────────────────────────────────

#[test]
fn test_parse_meminfo_extras_canonical() {
    // Canonical 6.x kernel /proc/meminfo with all 9 extracted fields plus
    // surrounding context; verifies prefix matching is exact (e.g. the
    // parser must distinguish "MemTotal:" from "MemAvailable:").
    let raw = "MemTotal:       65764440 kB\n\
                   MemFree:         3334364 kB\n\
                   MemAvailable:   55603984 kB\n\
                   Buffers:          711020 kB\n\
                   Cached:         49699636 kB\n\
                   SwapCached:       428388 kB\n\
                   SwapTotal:       8388604 kB\n\
                   SwapFree:        4223228 kB\n\
                   Slab:            2703932 kB\n\
                   SReclaimable:    2185976 kB\n\
                   SUnreclaim:       517956 kB\n\
                   PageTables:       157780 kB\n";
    let (total, available, free, buffers, slab, sreclaim, sw_total, sw_free, ptables) =
        parse_meminfo_extras(raw);
    assert_eq!(total, 65764440);
    assert_eq!(available, 55603984);
    assert_eq!(free, 3334364);
    assert_eq!(buffers, 711020);
    assert_eq!(slab, 2703932);
    assert_eq!(sreclaim, 2185976);
    assert_eq!(sw_total, 8388604);
    assert_eq!(sw_free, 4223228);
    assert_eq!(ptables, 157780);
}

#[test]
fn test_parse_meminfo_extras_handles_empty() {
    let (total, available, free, buffers, slab, sreclaim, sw_total, sw_free, ptables) =
        parse_meminfo_extras("");
    assert_eq!(
        (total, available, free, buffers, slab, sreclaim, sw_total, sw_free, ptables),
        (0, 0, 0, 0, 0, 0, 0, 0, 0)
    );
}

#[test]
fn test_parse_meminfo_extras_handles_partial_kernel() {
    // Pre-3.14 kernels (RHEL 6 era) lack MemAvailable; some embedded
    // kernels lack PageTables. Missing fields default to 0; present
    // fields parse correctly.
    let raw = "MemTotal:       2097152 kB\n\
                   MemFree:         500000 kB\n\
                   Buffers:          10000 kB\n";
    let (total, available, free, buffers, slab, sreclaim, sw_total, sw_free, ptables) =
        parse_meminfo_extras(raw);
    assert_eq!(total, 2097152);
    assert_eq!(available, 0);
    assert_eq!(free, 500000);
    assert_eq!(buffers, 10000);
    assert_eq!(
        (slab, sreclaim, sw_total, sw_free, ptables),
        (0, 0, 0, 0, 0)
    );
}

#[test]
fn test_parse_meminfo_extras_prefix_match_exact() {
    // The parser must NOT pick up "MemTotalSwap" or similar future
    // prefix-collision additions. Use a synthetic line that prefix-
    // collides to confirm exactness.
    let raw = "MemTotal:       1000 kB\n\
                   MemTotalShim:   9999 kB\n\
                   SwapFree:        500 kB\n\
                   SwapFreeXXX:    9999 kB\n";
    let (total, _, _, _, _, _, _, sw_free, _) = parse_meminfo_extras(raw);
    // Lines using split_whitespace + key match on full token — collision
    // candidates (MemTotalShim:, SwapFreeXXX:) are different tokens.
    assert_eq!(total, 1000);
    assert_eq!(sw_free, 500);
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_meminfo_extras_live_total_positive() {
    // On any Linux host /proc/meminfo MemTotal must be > 0.
    let (total, _available, _free, _buffers, _slab, _sreclaim, _sw_total, _sw_free, _ptables) =
        host_meminfo_extras();
    assert!(
        total > 0,
        "MemTotal must be > 0 on a running Linux host; got {}",
        total
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_meminfo_extras_invariants() {
    // Sanity-check kernel-enforced invariants on a live system:
    //  - MemFree ≤ MemAvailable (MemAvailable includes free + reclaimable)
    //  - MemAvailable ≤ MemTotal (can't be more available than exists)
    //  - SwapFree ≤ SwapTotal
    //  - SReclaimable ≤ Slab (reclaimable is a subset of slab)
    let (total, available, free, _buffers, slab, sreclaim, sw_total, sw_free, _ptables) =
        host_meminfo_extras();
    assert!(
        free <= available,
        "MemFree ({}) must be ≤ MemAvailable ({})",
        free,
        available
    );
    assert!(
        available <= total,
        "MemAvailable ({}) must be ≤ MemTotal ({})",
        available,
        total
    );
    assert!(
        sw_free <= sw_total,
        "SwapFree ({}) must be ≤ SwapTotal ({})",
        sw_free,
        sw_total
    );
    assert!(
        sreclaim <= slab,
        "SReclaimable ({}) must be ≤ Slab ({})",
        sreclaim,
        slab
    );
}

// ── process_blkio_wait_seconds parser ─────────────────────────

/// Minimal stat-line parser sanity check: verify the helper extracts
/// field 42 (delayacct_blkio_ticks) by reading a synthetic line that
/// places a known value at exactly that field and zeros elsewhere. Done
/// via an inline helper so we don't have to refactor the production
/// reader to take a string. The real `process_blkio_wait_seconds()`
/// uses identical token-indexing logic (after rsplit(`)`).next() and
/// split_whitespace, take parts[39]).
fn parse_blkio_ticks_for_test(stat: &str) -> u64 {
    let tail = stat.rsplit(')').next().unwrap_or("");
    let parts: Vec<&str> = tail.split_whitespace().collect();
    parts.get(39).and_then(|s| s.parse().ok()).unwrap_or(0)
}

#[test]
fn test_parse_blkio_ticks_canonical_zero() {
    // Synthetic /proc/self/stat with all post-comm fields zero except
    // delayacct_blkio_ticks (index 39 in post-paren tokens).
    // Layout after the `)`: state(0) ppid(1) … policy(38) **delayacct(39)**.
    let post_paren: String = std::iter::once("S".to_string())
        .chain(std::iter::repeat_n("0".to_string(), 38))
        .chain(std::iter::once("1234".to_string()))
        .collect::<Vec<_>>()
        .join(" ");
    let s = format!("1234 (test) {}", post_paren);
    assert_eq!(parse_blkio_ticks_for_test(&s), 1234);
}

#[test]
fn test_parse_blkio_ticks_with_paren_in_comm() {
    // Process names can contain parens: e.g. "(my )proc)". The parser
    // splits on the LAST ")" so the kernel disambiguates. Verify our
    // post-paren indexing is unaffected by an embedded ")".
    let post_paren: String = std::iter::once("S".to_string())
        .chain(std::iter::repeat_n("0".to_string(), 38))
        .chain(std::iter::once("9876".to_string()))
        .collect::<Vec<_>>()
        .join(" ");
    let s = format!("4242 (weird ) name) {}", post_paren);
    assert_eq!(parse_blkio_ticks_for_test(&s), 9876);
}

#[test]
fn test_parse_blkio_ticks_handles_empty() {
    // Empty input (containers without /proc/self/stat) returns 0.
    assert_eq!(parse_blkio_ticks_for_test(""), 0);
    assert_eq!(parse_blkio_ticks_for_test("garbage no parens"), 0);
}

#[test]
fn test_parse_blkio_ticks_handles_truncated() {
    // Pre-2008 kernels (or extremely old containers) may emit fewer
    // than 42 fields. Returning 0 (rather than panicking) is the
    // documented fallback.
    let s = "1234 (test) S 0 0 0 0 0 0 0 0 0 0 0 0 0";
    assert_eq!(parse_blkio_ticks_for_test(s), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_blkio_wait_seconds_live_non_negative() {
    // Live system call: must return a finite non-negative f64. On a
    // CONFIG_TASK_DELAY_ACCT=n kernel this is 0; on every modern distro
    // it grows monotonically. Either way, finite and >= 0.
    let secs = process_blkio_wait_seconds();
    assert!(secs.is_finite(), "blkio wait must be finite (got {})", secs);
    assert!(secs >= 0.0, "blkio wait must be >= 0 (got {})", secs);
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_blkio_wait_seconds_monotonic_across_reads() {
    // Two reads in immediate succession: second must be >= first
    // (counter, never decreases). Yields a strong sanity check that
    // we are reading the right field — a wrong index would scatter
    // across utime/stime/etc. and could regress between reads.
    let a = process_blkio_wait_seconds();
    let b = process_blkio_wait_seconds();
    assert!(b >= a, "blkio wait must be monotonic (a={}, b={})", a, b);
}

// ── thermal zone helpers ──────────────────────────────────────

#[test]
fn test_escape_prom_label_passthrough() {
    // Plain ASCII content (the common case for thermal zone type strings
    // like "x86_pkg_temp", "coretemp", "cpu-thermal") flows through
    // unchanged.
    assert_eq!(escape_prom_label("x86_pkg_temp"), "x86_pkg_temp");
    assert_eq!(escape_prom_label("cpu-thermal"), "cpu-thermal");
    assert_eq!(escape_prom_label(""), "");
}

#[test]
fn test_escape_prom_label_escapes_quotes_and_backslashes() {
    // Per Prometheus text format spec, label values quote with " and
    // escape \\ and \" inside the value. A type string containing one
    // of these chars (some BIOS/ACPI tables produce odd names) must be
    // sanitized so the emitted line round-trips through a parser.
    assert_eq!(escape_prom_label(r#"weird"name"#), r#"weird\"name"#);
    assert_eq!(escape_prom_label(r"a\b"), r"a\\b");
    assert_eq!(escape_prom_label(r#"\"both\""#), r#"\\\"both\\\""#);
}

#[test]
fn test_escape_prom_label_drops_newlines() {
    // Newlines in label values would corrupt the line-oriented exposition
    // format (a parser would treat the rest as a fresh metric line).
    // We drop them entirely rather than escape, since real thermal-zone
    // type strings should never legitimately contain a newline.
    assert_eq!(escape_prom_label("a\nb\nc"), "abc");
    assert_eq!(escape_prom_label("\n\n"), "");
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_thermal_zones_finite_temps() {
    // On any Linux host the helper either returns an empty Vec (no
    // /sys/class/thermal — virtualised VPS) or a Vec of (zone, type, °C)
    // tuples where every temperature is finite. We do not assert any
    // specific value because thermal readings are wildly variable; we
    // only assert the contract that we never produce NaN or infinity.
    let zones = host_thermal_zones();
    for (zone, type_label, celsius) in &zones {
        assert!(
            zone.starts_with("thermal_zone"),
            "zone name must start with thermal_zone, got {}",
            zone
        );
        assert!(!type_label.is_empty(), "type label must not be empty");
        assert!(
            celsius.is_finite(),
            "celsius must be finite (zone={} got {})",
            zone,
            celsius
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_thermal_zones_sorted() {
    // Stable Prometheus output requires deterministic ordering: zones
    // sorted by name. Two reads of /sys/class/thermal in unspecified
    // order would otherwise produce gauge rows that flip between scrapes.
    let zones = host_thermal_zones();
    for w in zones.windows(2) {
        assert!(
            w[0].0 <= w[1].0,
            "zones must be sorted: {} > {}",
            w[0].0,
            w[1].0
        );
    }
}

// ── hwmon thermal helpers ────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn test_host_hwmon_temps_finite_and_well_formed() {
    // Every tuple from hwmon must have a non-empty chip name, a sensor
    // name starting with 'temp', and a finite Celsius reading. Empty Vec
    // (host has no hwmon) is also valid — we don't fake values.
    let rows = host_hwmon_temps();
    for (chip, sensor, _label, celsius) in &rows {
        assert!(
            !chip.is_empty(),
            "chip name must not be empty (sensor={})",
            sensor
        );
        assert!(
            sensor.starts_with("temp"),
            "sensor must start with 'temp', got {}",
            sensor
        );
        assert!(
            celsius.is_finite(),
            "celsius must be finite (chip={} sensor={} got {})",
            chip,
            sensor,
            celsius
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_hwmon_temps_sorted() {
    // Stable scrape order requires deterministic sorting by (chip,
    // sensor). Without it, two reads of /sys/class/hwmon could produce
    // gauge rows in different orders between scrapes — Prometheus then
    // reports the metric family as having an unstable label set.
    let rows = host_hwmon_temps();
    for w in rows.windows(2) {
        let a = (&w[0].0, &w[0].1);
        let b = (&w[1].0, &w[1].1);
        assert!(
            a <= b,
            "hwmon rows must be sorted: ({:?},{:?}) > ({:?},{:?})",
            a.0,
            a.1,
            b.0,
            b.1
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_hwmon_temps_label_field_optional() {
    // Many hwmon chips ship without temp{N}_label files (just the bare
    // _input). We must surface those rows with an EMPTY label string,
    // not a fabricated one. This is the contract that lets operators
    // see 'the kernel did not name this sensor' rather than misread an
    // invented label as authoritative.
    let rows = host_hwmon_temps();
    // Just assert we don't panic and labels are well-typed strings —
    // can't assert a specific value because hwmon shape is hardware
    // specific. Empty-string labels are legal; non-empty must be
    // printable-ASCII-ish (let escape_prom_label sanitize at emit).
    for (_chip, _sensor, label, _celsius) in &rows {
        // No panic on .clone() = correctly-typed String.
        let _ = label.clone();
    }
}

// ── cpufreq helpers ──────────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn test_host_cpu_frequencies_sane_range() {
    // Modern x86 cpufreq governors report between ~400 MHz (deep idle)
    // and ~6 GHz (turbo boost). Anything outside [10 MHz, 10 GHz] is
    // either a sysfs read error or a unit conversion bug — assert the
    // sanity bounds rather than a specific value because freq depends
    // on hardware + current load. Empty Vec (cloud VPS without
    // scaling_cur_freq) is also valid.
    let freqs = host_cpu_frequencies();
    for (cpu, hz) in &freqs {
        assert!(
            *hz >= 10_000_000,
            "cpu{} freq {} Hz < 10 MHz lower bound — sysfs read or conversion bug?",
            cpu,
            hz
        );
        assert!(
            *hz <= 10_000_000_000,
            "cpu{} freq {} Hz > 10 GHz upper bound — sysfs read or conversion bug?",
            cpu,
            hz
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_cpu_frequencies_sorted_unique() {
    // Stable scrape order requires deterministic sorting by cpu_id.
    // Each cpu_id should appear exactly once — duplicates would mean
    // we matched a non-cpu directory (e.g. cpufreq, cpuidle subdirs).
    let freqs = host_cpu_frequencies();
    let ids: Vec<u32> = freqs.iter().map(|t| t.0).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        ids, sorted,
        "cpu ids must be sorted and unique: got {:?}",
        ids
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_cpu_frequencies_khz_to_hz_scaling() {
    // The kernel reports kHz; we emit Hz. Verify the scaling didn't
    // off-by-1000: every frequency in the resulting Hz value must be
    // strictly greater than 1_000_000 (1 MHz) — even a deeply-idle
    // core won't drop below ~100 MHz on modern hardware. If the values
    // came back un-scaled (still kHz), they'd be ~1_000_000 to
    // 4_000_000, which fails this assertion.
    let freqs = host_cpu_frequencies();
    for (cpu, hz) in &freqs {
        assert!(
            *hz >= 100_000_000,
            "cpu{} freq {} Hz too low — likely emitted in kHz not Hz",
            cpu,
            hz
        );
    }
}

// ── process rlimits ──────────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn test_process_rlimits_returns_rows() {
    // /proc/self/limits is a kernel ABI that has shipped in every Linux
    // for >15 years; every row should parse. The minimum we should see
    // on any sane Linux is ~16 rlimit entries.
    let rl = process_rlimits();
    assert!(
        rl.len() >= 10,
        "expected >=10 rlimit rows, got {} — /proc/self/limits parser broken",
        rl.len()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_rlimits_has_max_open_files() {
    // The single most actionable rlimit at mainnet scale: if this
    // helper drops max_open_files, the EMFILE alert can never fire.
    let rl = process_rlimits();
    let nofile = rl.iter().find(|(name, _, _)| name == "max_open_files");
    assert!(
        nofile.is_some(),
        "max_open_files (RLIMIT_NOFILE) missing from rlimit output: {:?}",
        rl.iter().map(|(n, _, _)| n.clone()).collect::<Vec<_>>()
    );
    if let Some((_, soft, hard)) = nofile {
        assert!(
            *soft >= 64,
            "max_open_files soft {} too low — even Linux default is 1024",
            soft
        );
        assert!(
            *hard >= *soft,
            "max_open_files hard ({}) must be >= soft ({})",
            hard,
            soft
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_rlimits_unlimited_encoding() {
    // 'unlimited' must encode as u64::MAX so single-gauge type works.
    // Most Linux kernels report at least one 'unlimited' resource
    // (typically Max cpu time, Max file size, Max data size, Max
    // resident set, Max address space, Max file locks). Tag at least
    // one of them as expected to be unlimited and verify encoding.
    let rl = process_rlimits();
    let any_unlimited = rl
        .iter()
        .any(|(_, soft, hard)| *soft == u64::MAX || *hard == u64::MAX);
    assert!(
        any_unlimited,
        "expected at least one 'unlimited' (u64::MAX) rlimit on Linux; got: {:?}",
        rl
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_rlimits_labels_snake_case() {
    // Labels should be snake_case for Prometheus convention.
    // No spaces, no capitals, must start with 'max_' for /proc/self/limits.
    let rl = process_rlimits();
    for (name, _, _) in &rl {
        assert!(
            !name.contains(' '),
            "rlimit label '{}' contains spaces",
            name
        );
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "rlimit label '{}' has non-snake-case chars",
            name
        );
        assert!(
            name.starts_with("max_"),
            "rlimit label '{}' should start with 'max_'",
            name
        );
    }
}

// ── Metric tier ──────────────────────────────

#[test]
fn test_metric_tier_parse_round_trip() {
    for s in ["P0", "p0"] {
        assert_eq!(MetricTier::parse(s), Some(MetricTier::P0), "input={s}");
    }
    for s in ["P1", "p1"] {
        assert_eq!(MetricTier::parse(s), Some(MetricTier::P1), "input={s}");
    }
    for s in ["debug", "Debug", "DEBUG"] {
        assert_eq!(MetricTier::parse(s), Some(MetricTier::Debug), "input={s}");
    }
    assert_eq!(MetricTier::parse("p2"), None);
    assert_eq!(MetricTier::parse(""), None);
}

#[test]
fn test_metric_tier_ordering_p0_lt_p1_lt_debug() {
    // The filter relies on `<=` to mean "drop higher tiers." If this
    // ordering ever flips, /metrics for P0 operators would silently
    // start emitting Debug-only families.
    assert!(MetricTier::P0 < MetricTier::P1);
    assert!(MetricTier::P1 < MetricTier::Debug);
    assert!(MetricTier::P0 < MetricTier::Debug);
}

#[test]
fn test_metric_tier_label_stable() {
    // Label is part of the public /metrics surface — operator dashboards
    // filter on these strings, so they must not change silently.
    assert_eq!(MetricTier::P0.label(), "P0");
    assert_eq!(MetricTier::P1.label(), "P1");
    assert_eq!(MetricTier::Debug.label(), "debug");
}

#[test]
fn test_classify_metric_self_gauge_is_p0() {
    // The self-reporting gauge must always be P0 so it survives every
    // filter level — without it operators can't tell what tier each
    // node is publishing.
    assert_eq!(classify_metric("elara_metric_tier"), MetricTier::P0);
}

#[test]
fn test_classify_metric_p0_consensus_essentials() {
    // Names verified against live `/metrics` on a running node — every
    // entry below must exist in the production surface.
    for name in [
        "elara_consensus_settled",
        "elara_finalized_count",
        "elara_records_processed",
        "elara_attestations_processed_total",
        "elara_epoch_seals_total",
        "elara_phase6d_ready",
        "elara_peers_connected",
        "elara_disk_pressure",
        "elara_disk_avail_pressure",
        "elara_disk_cap_pressure",
        "elara_uptime_seconds",
        "elara_circuit_breaker_level",
        "elara_pending_ledger_depth",
        "elara_pending_ledger_oldest_age_seconds",
        "elara_adaptive_interval_floor_seconds",
        "elara_node_open_fds",
        "elara_host_pressure_some_avg10",
        "elara_host_pressure_full_avg10",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P0,
            "{name} must be P0 — pager-grade essential",
        );
    }
    // Longer PSI windows are P1 (capacity-planning, not pager-grade).
    for name in [
        "elara_host_pressure_some_avg60",
        "elara_host_pressure_some_avg300",
        "elara_host_pressure_some_total_us",
        "elara_host_pressure_full_avg60",
        "elara_host_pressure_full_avg300",
        "elara_host_pressure_full_total_us",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} must be P1 — capacity-planning, not pager-grade",
        );
    }
}

#[test]
fn test_classify_metric_phase6d_attestation_globals_p0_over_debug_prefix() {
    // Regression guard. The DEBUG_PREFIXES list contains
    // `"elara_committee_attestations_"` to drop the high-cardinality
    // per-zone breakdown (`...total{zone="..."}`). The two scalar globals
    // `_member_total` and `_nonmember_total` share that prefix but feed
    // the `member_observations` predicate in `phase6d_readiness()` — they
    // are what tells an operator WHY `elara_phase6d_ready=0`. They MUST
    // resolve to P0 via the EXACT-match list before the DEBUG_PREFIXES
    // sweep catches them. If someone ever reorders classify_metric() or
    // drops these from P0_EXACT, this test fails before the regression
    // ships.
    for name in [
        "elara_committee_attestations_member_total",
        "elara_committee_attestations_nonmember_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P0,
            "{name} must be P0 — Phase 6D readiness diagnosis depends on it",
        );
    }
    // Sanity: per-zone breakdown stays Debug. The labelled metric line
    // reaches classify_metric() as the family name (no labels), so what
    // we test here is the unlabelled per-zone family — `_total` without
    // `_member_total` / `_nonmember_total` suffix.
    assert_eq!(
        classify_metric("elara_committee_attestations_total"),
        MetricTier::Debug,
        "per-zone committee_attestations_total must stay Debug — high-cardinality",
    );
}

#[test]
fn test_classify_metric_token_velocity_gauges_are_p1() {
    // Earlier work shipped elara_token_volume_24h + elara_token_velocity_24h.
    // Monetary-health indicators — not pager-grade essentials. Pin P1 so
    // a future P0_EXACT edit doesn't silently inflate phone-tier scrape cost.
    for name in ["elara_token_volume_24h", "elara_token_velocity_24h"] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} must be P1 — monetary health indicator, not pager-grade",
        );
    }
}

#[test]
fn test_host_pressure_stall_parser_handles_kernel_format() {
    // Verify the parser handles the canonical /proc/pressure/cpu format.
    // Kernel >=5.13 emits both 'some' and 'full' for cpu; older kernels
    // emit only 'some'. Both shapes must produce a PsiResource entry.
    // We do this by reading the live /proc/pressure/cpu — if the test
    // host doesn't expose PSI (kernel <4.20, container), we get an
    // empty vec and the test passes vacuously. On a PSI-capable host
    // we assert the structure of the returned data.
    let psi = host_pressure_stall();
    for entry in &psi {
        assert!(
            ["cpu", "memory", "io"].contains(&entry.resource.as_str()),
            "unexpected resource label '{}'",
            entry.resource,
        );
        // At least one of some/full must be present — otherwise the
        // entry should not have been pushed.
        assert!(
            entry.some.is_some() || entry.full.is_some(),
            "PsiResource for {} has no scope — should not be in vec",
            entry.resource,
        );
        // Per-scope sanity: averages are %, so 0..100 (kernel never emits
        // negative; pathologically saturated could exceed slightly under
        // kernel rounding, but >>100 means we parsed wrong).
        for s in [&entry.some, &entry.full].iter().filter_map(|x| x.as_ref()) {
            assert!(
                (0.0..150.0).contains(&s.avg10),
                "{} avg10 out of range: {}",
                entry.resource,
                s.avg10,
            );
            assert!(s.total_us < u64::MAX / 2, "total_us suspiciously large");
        }
    }
}

#[test]
fn test_process_cgroup_pressure_stall_returns_valid_or_empty() {
    // Same shape contract as host_pressure_stall: empty vec on cgroupv1
    // / kernels <4.20, otherwise valid PsiResource entries with at least
    // one of some/full present and reasonable bounds. Auto-discovers the
    // cgroup via /proc/self/cgroup so this works whether the test host
    // runs in a systemd unit, a container, or unconstrained.
    let psi = process_cgroup_pressure_stall();
    for entry in &psi {
        assert!(
            ["cpu", "memory", "io"].contains(&entry.resource.as_str()),
            "unexpected cgroup resource label '{}'",
            entry.resource,
        );
        assert!(
            entry.some.is_some() || entry.full.is_some(),
            "cgroup PsiResource for {} has no scope",
            entry.resource,
        );
        for s in [&entry.some, &entry.full].iter().filter_map(|x| x.as_ref()) {
            assert!(
                (0.0..150.0).contains(&s.avg10),
                "{} cgroup avg10 out of range: {}",
                entry.resource,
                s.avg10,
            );
            assert!(
                s.total_us < u64::MAX / 2,
                "cgroup total_us suspiciously large"
            );
        }
    }
}

#[test]
fn test_classify_metric_p0_cgroup_pressure_avg10() {
    // Cgroup PSI avg10 (some + full) must be P0 — pairs with
    // host PSI to disambiguate noisy-neighbour vs cgroup-bound, and both
    // diagnostic states are pager-grade in containerized phone-tier.
    for name in [
        "elara_cgroup_pressure_some_avg10",
        "elara_cgroup_pressure_full_avg10",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P0,
            "{name} must be P0 — pager-grade cgroup-vs-host PSI cross-check",
        );
    }
}

#[test]
fn test_classify_metric_p1_cgroup_pressure_capacity_windows() {
    // Cgroup PSI avg60/avg300/total go P1, same shape as the
    // host PSI tier split — pager-grade signal lives at avg10, the
    // longer windows are capacity-planning.
    for name in [
        "elara_cgroup_pressure_some_avg60",
        "elara_cgroup_pressure_some_avg300",
        "elara_cgroup_pressure_some_total_us",
        "elara_cgroup_pressure_full_avg60",
        "elara_cgroup_pressure_full_avg300",
        "elara_cgroup_pressure_full_total_us",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::P1,
            "{name} must be P1 — capacity-planning, not pager-grade",
        );
    }
}

#[test]
fn test_classify_metric_p0_seal_latency_histogram_suffixes() {
    // Histogram families emit base + _bucket + _sum + _count — all
    // three suffixes must classify the same as the base name. The seal
    // latency families are the closest physical-floor signal we expose
    // (in-zone finality is a counter, not a histogram).
    for base in [
        "elara_seal_attestation_latency_seconds",
        "elara_seal_propagation_latency_seconds",
        "elara_seal_quorum_latency_seconds",
    ] {
        for suffix in ["", "_bucket", "_sum", "_count"] {
            let name = format!("{base}{suffix}");
            assert_eq!(
                classify_metric(&name),
                MetricTier::P0,
                "{name} histogram suffix must inherit base tier",
            );
        }
    }
}

#[test]
fn test_classify_metric_debug_high_cardinality() {
    // The high-cardinality breakdowns are Debug-tier so phone-tier
    // nodes don't pay for per-CPU/zone/resource label explosions.
    // NOTE: `elara_committee_attestations_member_total` and `_nonmember_total`
    // are NOT in this list — they are scalar globals (no labels) that
    // drive Phase 6D readiness diagnosis and are EXACT-matched to P0
    // before the DEBUG_PREFIXES sweep. The labelled per-zone family
    // `elara_committee_attestations_total` stays Debug.
    for name in [
        "elara_host_cpu_frequency_hz",
        "elara_host_cpu_temperature_celsius",
        "elara_thermal_zone_celsius",
        "elara_process_rlimit_soft",
        "elara_process_rlimit_hard",
        "elara_jiffies_user",
        "elara_committee_attestations_total",
    ] {
        assert_eq!(
            classify_metric(name),
            MetricTier::Debug,
            "{name} must be Debug — high-cardinality breakdown",
        );
    }
}

#[test]
fn test_classify_metric_unclassified_falls_through_to_p1() {
    // Unknown / future metrics must NOT silently land at P0 (would
    // pollute pager-grade output) or Debug (would hide them from
    // operators on default tier). P1 is the safe middle.
    assert_eq!(
        classify_metric("elara_some_future_unknown_gauge"),
        MetricTier::P1
    );
    assert_eq!(
        classify_metric("elara_block_processing_latency_secs"),
        MetricTier::P1
    );
}

#[test]
fn test_metric_name_from_line_help_type_data() {
    assert_eq!(
        metric_name_from_line("# HELP elara_foo something"),
        Some("elara_foo")
    );
    assert_eq!(
        metric_name_from_line("# TYPE elara_foo gauge"),
        Some("elara_foo")
    );
    assert_eq!(metric_name_from_line("elara_foo 42"), Some("elara_foo"));
    assert_eq!(
        metric_name_from_line("elara_foo{a=\"b\"} 42"),
        Some("elara_foo")
    );
    assert_eq!(metric_name_from_line(""), None);
    // Free-form comments without HELP/TYPE prefix are preserved (returns None
    // so filter keeps them).
    assert_eq!(metric_name_from_line("# operator note"), None);
}

#[test]
fn test_filter_metrics_by_tier_debug_is_passthrough() {
    let body = "# HELP elara_foo bar\n# TYPE elara_foo gauge\nelara_foo 42\n";
    let out = filter_metrics_by_tier(body, MetricTier::Debug);
    assert_eq!(out, body);
}

#[test]
fn test_filter_metrics_by_tier_p0_drops_p1_and_debug() {
    // Build a synthetic body with one of each tier; P0 filter must
    // emit only P0 lines.
    let body = "\
# HELP elara_consensus_settled P0
# TYPE elara_consensus_settled counter
elara_consensus_settled 100
# HELP elara_some_future_unknown_gauge P1 by default
# TYPE elara_some_future_unknown_gauge gauge
elara_some_future_unknown_gauge 7
# HELP elara_host_cpu_frequency_hz Debug per-CPU
# TYPE elara_host_cpu_frequency_hz gauge
elara_host_cpu_frequency_hz{cpu=\"0\"} 3000000000
";
    let out = filter_metrics_by_tier(body, MetricTier::P0);
    assert!(
        out.contains("elara_consensus_settled 100"),
        "P0 metric must survive"
    );
    assert!(
        !out.contains("elara_some_future_unknown_gauge"),
        "P1 metric must be dropped at P0"
    );
    assert!(
        !out.contains("elara_host_cpu_frequency_hz"),
        "Debug metric must be dropped at P0"
    );
}

#[test]
fn test_filter_metrics_by_tier_p1_keeps_p0_and_p1_drops_debug() {
    let body = "\
# HELP elara_consensus_settled P0
# TYPE elara_consensus_settled counter
elara_consensus_settled 100
# HELP elara_some_future_unknown_gauge P1 by default
# TYPE elara_some_future_unknown_gauge gauge
elara_some_future_unknown_gauge 7
# HELP elara_host_cpu_frequency_hz Debug
# TYPE elara_host_cpu_frequency_hz gauge
elara_host_cpu_frequency_hz{cpu=\"0\"} 3000000000
";
    let out = filter_metrics_by_tier(body, MetricTier::P1);
    assert!(out.contains("elara_consensus_settled 100"));
    assert!(out.contains("elara_some_future_unknown_gauge 7"));
    assert!(!out.contains("elara_host_cpu_frequency_hz"));
}

#[test]
fn test_filter_metrics_by_tier_preserves_self_gauge_at_every_tier() {
    // The self-reporting tier gauge MUST always survive — without it
    // operators on P0 dashboards can't see what tier each node is on.
    let body = "\
# HELP elara_metric_tier self-reporting
# TYPE elara_metric_tier gauge
elara_metric_tier{tier=\"P0\"} 0
# HELP elara_some_future_unknown_gauge P1 by default
# TYPE elara_some_future_unknown_gauge gauge
elara_some_future_unknown_gauge 7
";
    for t in [MetricTier::P0, MetricTier::P1, MetricTier::Debug] {
        let out = filter_metrics_by_tier(body, t);
        assert!(
            out.contains("elara_metric_tier{tier=\"P0\"} 0"),
            "self-gauge dropped at tier={:?}",
            t,
        );
    }
}

#[test]
fn test_filter_metrics_by_tier_drops_help_and_type_for_filtered_family() {
    // When a metric is filtered out, its HELP and TYPE lines MUST also
    // go — otherwise Prometheus emits a parse warning for orphaned
    // metadata and the body fails strict scrapers.
    let body = "\
# HELP elara_host_cpu_frequency_hz Debug per-CPU
# TYPE elara_host_cpu_frequency_hz gauge
elara_host_cpu_frequency_hz{cpu=\"0\"} 3000000000
";
    let out = filter_metrics_by_tier(body, MetricTier::P0);
    assert!(!out.contains("# HELP elara_host_cpu_frequency_hz"));
    assert!(!out.contains("# TYPE elara_host_cpu_frequency_hz"));
    assert!(!out.contains("elara_host_cpu_frequency_hz{cpu="));
}

// ── per-request tier override widen/narrow contract ──────────

#[test]
fn test_metric_tier_parse_rejects_trailing_whitespace() {
    // `?tier=` URL params arrive already URL-decoded but a buggy operator
    // wrapper might leave a trailing space. The parser must reject it so
    // the route falls back to the node default rather than silently
    // matching anything close.
    assert_eq!(MetricTier::parse("p0 "), None);
    assert_eq!(MetricTier::parse(" p0"), None);
    assert_eq!(MetricTier::parse("verbose"), None);
}

#[test]
fn test_filter_metrics_by_tier_p0_widening_to_debug_is_passthrough() {
    // Override guarantee: `?tier=debug` on a P1-defaulted node returns the
    // full debug body. Verified at the filter level — the filter is what
    // metrics_body_tiered calls last with `tier_override.unwrap_or(...)`.
    let body = "\
elara_consensus_settled 100
elara_some_future_unknown_gauge 7
elara_host_cpu_frequency_hz{cpu=\"0\"} 3000000000
";
    let out = filter_metrics_by_tier(body, MetricTier::Debug);
    assert!(out.contains("elara_consensus_settled 100"));
    assert!(out.contains("elara_some_future_unknown_gauge 7"));
    assert!(out.contains("elara_host_cpu_frequency_hz{cpu=\"0\"} 3000000000"));
}

#[test]
fn test_filter_metrics_by_tier_debug_to_p0_narrowing_drops_debug_metrics() {
    // Override guarantee: `?tier=p0` on a Debug-defaulted node narrows the
    // body. This is the inverse of the previous test — same body, P0
    // tier, only consensus survives.
    let body = "\
elara_consensus_settled 100
elara_some_future_unknown_gauge 7
elara_host_cpu_frequency_hz{cpu=\"0\"} 3000000000
";
    let out = filter_metrics_by_tier(body, MetricTier::P0);
    assert!(out.contains("elara_consensus_settled 100"));
    assert!(!out.contains("elara_some_future_unknown_gauge"));
    assert!(!out.contains("elara_host_cpu_frequency_hz"));
}

// ── Public-route gate (L1995 Phase 1) ─────────────────────────────────

#[test]
fn test_public_route_allows_pq_ws() {
    assert!(is_public_route("/pq-ws"));
}

#[test]
fn test_public_route_rejects_legacy_ws() {
    // /ws Slice 3c: legacy /ws route deleted; the gate must 404 it now.
    assert!(!is_public_route("/ws"));
}

#[test]
fn test_public_route_allows_metrics() {
    assert!(is_public_route("/metrics"));
}

#[test]
fn test_public_route_allows_health_status_ping_version() {
    assert!(is_public_route("/health"));
    assert!(is_public_route("/status"));
    assert!(is_public_route("/ping"));
    assert!(is_public_route("/version"));
}

#[test]
fn test_public_route_allows_alive() {
    // /alive is the lightweight liveness probe — must be reachable
    // without auth (k8s livenessProbe, haproxy, systemd watchdog).
    assert!(is_public_route("/alive"));
}

#[tokio::test]
async fn test_alive_handler_returns_alive_true_no_state_required() {
    // /alive must remain state-free: no NodeState arg, no async I/O,
    // no lock acquisition. Body shape pinned at `{"alive": true}`.
    let body = super::super::routes::core::alive().await;
    let v: serde_json::Value = body.0;
    assert_eq!(
        v.as_object().map(|o| o.len()),
        Some(1),
        "/alive body must have exactly 1 key — extra fields belong in /health"
    );
    assert_eq!(
        v["alive"],
        serde_json::Value::Bool(true),
        "/alive body must be {{\"alive\": true}} verbatim"
    );
    assert!(
        v["alive"].is_boolean(),
        "alive must be JSON Bool, not String — load-balancer parsers expect bool"
    );
}

#[test]
fn test_public_route_allows_light_client_proofs_and_headers() {
    // Gap 1 light-client SDK pulls these from external accounts; they
    // are signed, read-only, idempotent. (/account/{identity} joined the public
    // explorer surface in the 2026-06-23 audit — see the explorer-surface test.)
    assert!(is_public_route("/proof/account"));
    assert!(is_public_route("/proof/account/abcdef"));
    assert!(is_public_route("/headers"));
    assert!(is_public_route("/headers/from/42"));
}

#[test]
fn test_public_route_allows_state_delta_only() {
    // Audit-3: /snapshot/state-delta is publicly callable for light
    // clients. The heavier archive paths (/snapshot, /snapshot/fast,
    // /snapshot/epoch/{N}) stay loopback-only — only this single
    // delta route is whitelisted. Note: `is_public_route` is fed
    // `req.uri().path()`, which excludes the query string; so the
    // ?since_epoch=… form is irrelevant here.
    assert!(is_public_route("/snapshot/state-delta"));
    assert!(!is_public_route("/snapshot"));
    assert!(!is_public_route("/snapshot/fast"));
    assert!(!is_public_route("/snapshot/latest"));
    assert!(!is_public_route("/snapshot/epoch/42"));
    assert!(!is_public_route("/snapshot/epochs"));
}

#[test]
fn test_agent_acts_is_loopback_only_not_public() {
    // C4 agent-acts: the by-signer forensic enumeration `/agent/{hash}/acts` is
    // LOOPBACK-ONLY. A public by-signer index makes per-identity behavioral
    // aggregation cheap — the same deanon surface the protocol already gates for
    // /records/search?creator= (fusion-audited 2026-06-26). It must NOT be
    // reachable by non-loopback peers, so `is_public_route` must return false.
    let agent = "a".repeat(64);
    assert!(
        !is_public_route(&format!("/agent/{agent}/acts")),
        "/agent/{{hash}}/acts must be loopback-only (by-signer deanon surface)"
    );
    assert!(!is_public_route("/agent"));
    assert!(!is_public_route(&format!("/agent/{agent}")));
    // The per-MANDATE acts list stays PUBLIC (scoped to one authority, not to an
    // identity) — this asymmetry between agent-scoped and mandate-scoped is the
    // whole point of the access-model decision.
    assert!(is_public_route(&format!("/mandate/{agent}/acts")));
    // Guard the auto-public trap: the path is OUTSIDE the public `/mandate`
    // prefix, so it can never be swept public by the `/mandate` prefix match.
    assert!(!format!("/agent/{agent}/acts").starts_with("/mandate/"));
}

#[test]
fn test_public_route_allows_subpaths_under_whitelisted_prefix() {
    // /status/peers, /version/build etc. would still be allowed if such
    // routes exist — we whitelist the prefix, not the literal path.
    assert!(is_public_route("/status/peers"));
    assert!(is_public_route("/health/live"));
}

#[test]
fn test_public_route_blocks_data_plane() {
    // Bulk-dump / mutation / data-plane routes stay loopback-only.
    assert!(!is_public_route("/balances"));        // bulk all-account+balance dump (audit 2026-06-23)
    assert!(!is_public_route("/balances/abc123"));
    assert!(!is_public_route("/records"));
    assert!(!is_public_route("/history"));
    // /explorer, /account/{id}, /dag/tips, /epochs, /consensus/status,
    // /dag/stats, /transactions/recent, /record/{id} were promoted to the
    // public block-explorer surface — see test_public_route_explorer_surface_audited.
}

#[test]
fn test_public_route_explorer_surface_audited() {
    // Public block-explorer data surface — fusion-audited 2026-06-23 (3 Sonnet
    // + 1 Opus panel + Opus verify against source). Read-only, idempotent,
    // bounded; same disclosure profile as a public ledger.
    assert!(is_public_route("/explorer")); // exact (PUBLIC_EXACT_ROUTES)
    assert!(is_public_route("/epochs"));
    assert!(is_public_route("/consensus/status"));
    assert!(is_public_route("/dag/stats"));
    assert!(is_public_route("/dag/tips"));
    assert!(is_public_route("/transactions/recent"));
    assert!(is_public_route("/record/abc123"));
    assert!(is_public_route("/record/abc123/causal-proof"));
    assert!(is_public_route("/record/abc123/wire")); // offline-verify read (receipts.html «3»)
    assert!(is_public_route("/account/abc123"));

    // /explorer is EXACT-match — no implicit children exposed.
    assert!(!is_public_route("/explorer/admin"));
    assert!(!is_public_route("/explorerx"));

    // SECURITY INVARIANT — these leak node IPs / bulk enumeration and MUST stay
    // gated. A future edit that exposes any of them fails here by design.
    assert!(!is_public_route("/peers")); // node IP:port topology + per-peer diagnostics
    assert!(!is_public_route("/balances")); // bulk all-account+balance dump
    assert!(!is_public_route("/witness/profiles")); // witness IP /24 via `subnet` (config.rs:471)

    // Sibling-safety: SPECIFIC prefixes must not catch dangerous neighbours
    // under the same parent (/dag, /consensus, /records).
    assert!(!is_public_route("/dag/search"));
    assert!(!is_public_route("/dag/lifecycle"));
    assert!(!is_public_route("/dag/record/abc/graph"));
    assert!(!is_public_route("/consensus/record/abc"));
    assert!(!is_public_route("/records")); // /record prefix must not match /records*
    assert!(!is_public_route("/records/search"));
}

#[test]
fn test_public_route_allows_seal_progress() {
    // Gap 8 follow-up: /seal/progress/{id} surfaces Sealed-vs-Finalized
    // state for phone-tier accounts. Read-only, idempotent — same posture
    // as /proof/account, /headers, /snapshot/state-delta.
    assert!(is_public_route("/seal/progress"));
    assert!(is_public_route("/seal/progress/abc"));
    assert!(is_public_route("/seal/progress/0x1234"));
    // Sibling /seal/* paths (if any) are not auto-allowed unless they
    // start with the exact prefix.
    assert!(!is_public_route("/sealdebug"));
}

#[test]
fn test_public_route_blocks_admin_and_rpc() {
    assert!(!is_public_route("/admin/snapshot"));
    assert!(!is_public_route("/admin/witness/registry"));
    assert!(!is_public_route("/rpc/transfer"));
    assert!(!is_public_route("/rpc/stamp"));
    assert!(!is_public_route("/bootstrap/claim"));
}

#[test]
fn test_exchange_page_not_publicly_served() {
    // Not-a-coin pivot (2026-06-09): the `/exchange` HTML dashboard AND the
    // DEX backend (order book + HTLC atomic swaps) were removed from the
    // binary + public mirror. Regression guard — no /exchange surface may
    // re-enter the public listener.
    assert!(!is_public_route("/exchange"));
    assert!(!is_public_route("/exchange/orderbook"));
    assert!(!is_public_route("/exchange/orders"));
    assert!(!is_public_route("/exchange/htlcs"));
    assert!(!is_public_route("/exchanges"));
    assert!(!is_public_route("/exchangeui"));
}

#[test]
fn test_public_route_does_not_match_partial_prefix() {
    // /statusboard would NOT pass the gate — the helper requires either
    // exact match or a `/` separator after the prefix.
    assert!(!is_public_route("/statusboard"));
    assert!(!is_public_route("/wsadmin"));
    assert!(!is_public_route("/metricsx"));
}

#[test]
fn test_public_route_governance_upgrade_outcomes_surface_exposed() {
    // Protocol §11.18 Slice 4 — the upgrade-outcome
    // read surface MUST clear the gate for non-loopback callers so
    // browser-resident accounts/explorers can render the post-vote
    // Adopted/Vetoed breakdown without reverse-proxy plumbing. The
    // `9717f585` ship added the route to `public_routes()` but forgot
    // to list it in PUBLIC_ROUTE_PREFIXES; the deployed binary 404'd
    // at the gate. This test pins the gate-clearing fix.
    assert!(is_public_route("/governance/upgrade_outcomes"));
    assert!(is_public_route(
        "/governance/upgrade_outcomes/proposal-abc-123"
    ));
    // Mutation surface (proposals / votes / finalizations) flows
    // through POST /submit_record and stays loopback-only. /governance
    // alone is NOT a public prefix — only the upgrade-outcomes leaf is.
    assert!(!is_public_route("/governance"));
    assert!(!is_public_route("/governance/proposals"));
    assert!(!is_public_route("/governance/votes"));
    // Partial-prefix attacks against the leaf are blocked by the
    // `starts_with("{prefix}/")` rule (must have a `/` separator after).
    assert!(!is_public_route("/governance/upgrade_outcomesx"));
    assert!(!is_public_route("/governance/upgrade_outcomes_debug"));
}

#[test]
fn test_public_route_records_by_hash_surface_exposed() {
    // §11.23 Layer A slice 0 — /records/by-hash/{content_hash} lets external
    // explorers resolve a content hash to the full record without first knowing
    // the record id. Read-only, idempotent, O(1) RocksDB point lookup — it MUST
    // clear the gate for non-loopback callers (same posture as /proof/account
    // and /headers). Same drift-bug class as the §11.18 governance 404: the
    // route is in public_routes() but its PUBLIC_ROUTE_PREFIXES entry can be
    // dropped silently, 404ing every off-host explorer. This pins both ends.
    assert!(is_public_route("/records/by-hash"));
    assert!(is_public_route("/records/by-hash/abc123def456"));
    // The sibling record routes stay loopback-only — POST /records (submit) and
    // the /records/search and /records/stream query surfaces are data plane and
    // must NOT be shadowed by the by-hash read prefix.
    assert!(!is_public_route("/records"));
    assert!(!is_public_route("/records/search"));
    assert!(!is_public_route("/records/stream"));
    // Partial-prefix attack blocked by the `starts_with("{prefix}/")` rule.
    assert!(!is_public_route("/records/by-hashx"));
}

#[test]
fn test_public_route_epochs_headers_surface_exposed() {
    // Block-explorer surface (fusion-audited 2026-06-23). `/epochs/headers`
    // serves epoch headers via the SAME `explorer::epoch_headers` handler the
    // already-public `/headers/from/{epoch}` light-client route forwards to, so
    // it carries zero extra disclosure. It is documented public via the
    // PUBLIC_ROUTE_PREFIXES `/epochs` entry. Same drift-bug class as the §11.18
    // governance + §11.23 records/by-hash 404s — but the OPPOSITE direction: the
    // gate cleared `/epochs/headers` (the `/epochs` prefix matches) while
    // public_routes() lacked the registration, so the off-host binary 404'd at
    // the router, not the gate. This pins the GATE side; the router-registration
    // side is verified by the live deploy curl (no NodeState test harness exists
    // to exercise the real public_routes() router here).
    assert!(is_public_route("/epochs"));
    assert!(is_public_route("/epochs/headers"));
    // Partial-prefix attacks against the prefix are blocked by the
    // `starts_with("{prefix}/")` rule (must have a `/` separator after).
    assert!(!is_public_route("/epochsx"));
    assert!(!is_public_route("/epochs_debug"));
}

// ── AppError status code mapping ─────────────────────────────────────

#[test]
fn test_app_error_duplicate_record_is_conflict() {
    let err = AppError(ElaraError::DuplicateRecord("test".into()));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[test]
fn test_app_error_not_found() {
    let err = AppError(ElaraError::RecordNotFound("test".into()));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn test_app_error_rate_limited() {
    let err = AppError(ElaraError::RateLimited);
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn test_app_error_invalid_signature() {
    let err = AppError(ElaraError::InvalidSignature);
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_app_error_token_is_unprocessable() {
    let err = AppError(ElaraError::Ledger("bad amount".into()));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn test_app_error_storage_token_is_unprocessable() {
    let err = AppError(ElaraError::Storage("Ledger error: insufficient".into()));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn test_app_error_storage_not_found() {
    let err = AppError(ElaraError::Storage("record not found".into()));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn test_app_error_storage_generic_is_500() {
    let err = AppError(ElaraError::Storage("disk full".into()));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_app_error_500_body_is_generic_not_internal_detail() {
    // A 5xx body must NOT echo the internal error Display on the public surface —
    // RocksDB CF names, filesystem paths, and tokio internals would aid recon.
    let err = AppError(ElaraError::Storage(
        "rocksdb: CF cf_idx_timestamp at /var/lib/elara/db corrupt block".into(),
    ));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert_eq!(body, "internal server error");
    assert!(!body.contains("rocksdb"), "500 body leaked engine internals: {body}");
    assert!(!body.contains("cf_idx_timestamp"), "500 body leaked CF name: {body}");
    assert!(!body.contains("/var/lib/elara"), "500 body leaked filesystem path: {body}");
}

#[tokio::test]
async fn test_app_error_io_500_body_is_generic_not_path() {
    // The withhold rule must cover the WHOLE catch-all 5xx class, not just
    // Storage — an Io error's OS message can embed a filesystem path. (This also
    // transitively pins the Json variant, which lands on the same catch-all.)
    let err = AppError(ElaraError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "/var/lib/elara/db/LOCK: permission denied",
    )));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert_eq!(body, "internal server error");
    assert!(!body.contains("/var/lib/elara"), "500 body leaked filesystem path: {body}");
}

#[tokio::test]
async fn test_app_error_4xx_body_still_echoes_client_detail() {
    // 4xx client errors must still surface actionable detail — the caller needs
    // to know *what* about their request was rejected.
    let err = AppError(ElaraError::Wire("identity must be 64 hex chars".into()));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        body.contains("identity must be 64 hex chars"),
        "4xx body dropped client-actionable detail: {body}"
    );
}

// ── AdminAuthTracker ─────────────────────────────────────────────────

#[test]
fn test_admin_tracker_not_locked_initially() {
    let tracker = AdminAuthTracker::new();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    assert!(!tracker.is_locked_out(ip));
}

#[test]
fn test_admin_tracker_locks_after_max_failures() {
    let tracker = AdminAuthTracker::new();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    for _ in 0..MAX_ADMIN_FAILURES - 1 {
        assert!(!tracker.record_failure(ip));
    }
    // The Nth failure should trigger lockout
    assert!(tracker.record_failure(ip));
    assert!(tracker.is_locked_out(ip));
}

#[test]
fn test_admin_tracker_different_ips_independent() {
    let tracker = AdminAuthTracker::new();
    let ip1: IpAddr = "1.2.3.4".parse().unwrap();
    let ip2: IpAddr = "5.6.7.8".parse().unwrap();
    for _ in 0..MAX_ADMIN_FAILURES {
        tracker.record_failure(ip1);
    }
    assert!(tracker.is_locked_out(ip1));
    assert!(!tracker.is_locked_out(ip2));
}

#[test]
fn test_admin_tracker_clear() {
    let tracker = AdminAuthTracker::new();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    for _ in 0..MAX_ADMIN_FAILURES {
        tracker.record_failure(ip);
    }
    assert!(tracker.is_locked_out(ip));
    tracker.clear(ip);
    assert!(!tracker.is_locked_out(ip));
}

#[test]
fn test_admin_tracker_clear_resets_partial_failure_window() {
    // Operator makes N-1 failed attempts (one short of lockout), then
    // authenticates successfully (clear). The next single failure must NOT
    // lock them out — the window must be fresh after clear.
    let tracker = AdminAuthTracker::new();
    let ip: IpAddr = "9.8.7.6".parse().unwrap();
    for _ in 0..MAX_ADMIN_FAILURES - 1 {
        assert!(!tracker.record_failure(ip));
    }
    assert!(!tracker.is_locked_out(ip));
    tracker.clear(ip); // simulate successful auth
                       // One more failure after clear — should start a fresh window, not lock.
    assert!(!tracker.record_failure(ip));
    assert!(!tracker.is_locked_out(ip));
}

// ── Histogram ────────────────────────────────────────────────────────

#[test]
fn test_histogram_empty() {
    let h = Histogram::new(&[0.1, 0.5, 1.0]);
    let out = h.to_prometheus("test_latency", "Test latency");
    assert!(out.contains("test_latency_count 0"));
    assert!(out.contains("test_latency_sum 0.000000"));
}

#[test]
fn test_histogram_observe_single() {
    let h = Histogram::new(&[0.1, 0.5, 1.0]);
    h.observe(0.05); // falls in 0.1 bucket
    let out = h.to_prometheus("req", "Requests");
    assert!(out.contains("req_count 1"));
    // 0.05s = in 0.1 bucket
    assert!(out.contains("req_bucket{le=\"0.1\"} 1"));
    // Also in 0.5 and 1.0 (cumulative)
    assert!(out.contains("req_bucket{le=\"0.5\"} 1"));
    assert!(out.contains("req_bucket{le=\"1\"} 1"));
}

#[test]
fn test_histogram_observe_multiple_buckets() {
    let h = Histogram::new(&[0.1, 0.5, 1.0]);
    h.observe(0.05); // in 0.1, 0.5, 1.0
    h.observe(0.3); // in 0.5, 1.0 (not 0.1)
    h.observe(0.8); // in 1.0 only

    let out = h.to_prometheus("t", "T");
    assert!(out.contains("t_count 3"));
    // 0.1 bucket: only the 0.05 observation
    assert!(out.contains("t_bucket{le=\"0.1\"} 1"));
    // 0.5 bucket: 0.05 + 0.3
    assert!(out.contains("t_bucket{le=\"0.5\"} 2"));
    // 1.0 bucket: all 3
    assert!(out.contains("t_bucket{le=\"1\"} 3"));
}

#[test]
fn test_histogram_sum() {
    let h = Histogram::new(&[1.0]);
    h.observe(0.25);
    h.observe(0.75);
    let out = h.to_prometheus("s", "S");
    assert!(out.contains("s_sum 1.000000"));
}

#[test]
fn test_histogram_to_prometheus_with_labels() {
    let h = Histogram::new(&[0.1, 1.0]);
    h.observe(0.05);
    let out = h.to_prometheus_with_labels("req", "route=\"/x\"");
    // Label set is preserved on every line, no HELP/TYPE preamble.
    assert!(out.contains("req_bucket{route=\"/x\",le=\"0.1\"} 1"));
    assert!(out.contains("req_bucket{route=\"/x\",le=\"1\"} 1"));
    assert!(out.contains("req_bucket{route=\"/x\",le=\"+Inf\"} 1"));
    assert!(out.contains("req_sum{route=\"/x\"} 0.050000"));
    assert!(out.contains("req_count{route=\"/x\"} 1"));
    assert!(!out.contains("# HELP"));
    assert!(!out.contains("# TYPE"));
}

// ── LabeledHistogram (per-route) ─────────────────────────────────────

#[test]
fn test_labeled_histogram_observes_per_label() {
    let lh = LabeledHistogram::new(&[0.1, 1.0], 8);
    lh.observe("/headers", 0.05);
    lh.observe("/proof", 0.5);
    lh.observe("/headers", 0.07);
    let out = lh.to_prometheus("elara_test_lat", "Test");
    assert!(out.contains("# HELP elara_test_lat Test"));
    assert!(out.contains("# TYPE elara_test_lat histogram"));
    // /headers: 2 observations, both ≤ 0.1
    assert!(out.contains("elara_test_lat_count{route=\"/headers\"} 2"));
    assert!(out.contains("elara_test_lat_bucket{route=\"/headers\",le=\"0.1\"} 2"));
    // /proof: 1 observation, in 1.0 bucket only (not 0.1)
    assert!(out.contains("elara_test_lat_count{route=\"/proof\"} 1"));
    assert!(out.contains("elara_test_lat_bucket{route=\"/proof\",le=\"0.1\"} 0"));
    assert!(out.contains("elara_test_lat_bucket{route=\"/proof\",le=\"1\"} 1"));
}

#[test]
fn test_labeled_histogram_cap_overflows_into_bucket() {
    // Cap = 2: two distinct labels fill the table; the third overflows.
    let lh = LabeledHistogram::new(&[1.0], 2);
    lh.observe("/a", 0.1);
    lh.observe("/b", 0.2);
    // /a, /b registered. label_count == 2. Next label must overflow.
    assert_eq!(lh.label_count(), 2);
    lh.observe("/c", 0.3);
    // /c was not registered — overflow bucket is created instead, so the
    // total label count rises to 3 (the cap-counter and the overflow live
    // in the same map). Subsequent unseen labels keep folding into the
    // same overflow bucket without further growth.
    let count_after_first_overflow = lh.label_count();
    lh.observe("/d", 0.4);
    lh.observe("/e", 0.5);
    assert_eq!(lh.label_count(), count_after_first_overflow);
    let out = lh.to_prometheus("ovf", "Overflow test");
    // Three originals merged: /c, /d, /e all go to <overflow>, so the
    // overflow bucket has 3 observations. Existing labels keep their counts.
    assert!(out.contains("ovf_count{route=\"/a\"} 1"));
    assert!(out.contains("ovf_count{route=\"/b\"} 1"));
    assert!(out.contains("ovf_count{route=\"<overflow>\"} 3"));
}

#[test]
fn test_labeled_histogram_escapes_quotes_in_label() {
    let lh = LabeledHistogram::new(&[1.0], 8);
    lh.observe("weird\"path", 0.1);
    let out = lh.to_prometheus("esc", "Escape test");
    // The literal `"` inside the label must be backslash-escaped so the
    // Prometheus exposition stays parseable.
    assert!(out.contains("route=\"weird\\\"path\""));
}

#[test]
fn test_labeled_histogram_unmatched_label_used_when_no_route() {
    // Simulates the middleware fallback when MatchedPath is absent (404
    // path or unrouted request).
    let lh = LabeledHistogram::new(&[1.0], 8);
    lh.observe("<unmatched>", 0.1);
    let out = lh.to_prometheus("um", "Unmatched test");
    assert!(out.contains("um_count{route=\"<unmatched>\"} 1"));
}

// ── status_class_for ────────────────────────────────────────────────

#[test]
fn test_status_class_for_buckets() {
    assert_eq!(status_class_for(200), "2xx");
    assert_eq!(status_class_for(204), "2xx");
    assert_eq!(status_class_for(301), "3xx");
    assert_eq!(status_class_for(404), "4xx");
    assert_eq!(status_class_for(429), "4xx");
    assert_eq!(status_class_for(500), "5xx");
    assert_eq!(status_class_for(503), "5xx");
    // 1xx (informational) — should not crash, lands in "other".
    assert_eq!(status_class_for(100), "other");
    // 6xx (non-standard) — same.
    assert_eq!(status_class_for(699), "other");
}

// ── LabeledCounter (per-route × status_class) ───────────────────────

#[test]
fn test_labeled_counter_counts_per_route_and_status() {
    let lc = LabeledCounter::new(8);
    lc.inc("/headers", "2xx");
    lc.inc("/headers", "2xx");
    lc.inc("/headers", "5xx");
    lc.inc("/proof", "4xx");
    let out = lc.to_prometheus("elara_test_status", "Test");
    assert!(out.contains("# HELP elara_test_status Test"));
    assert!(out.contains("# TYPE elara_test_status counter"));
    assert!(out.contains("elara_test_status{route=\"/headers\",status_class=\"2xx\"} 2"));
    assert!(out.contains("elara_test_status{route=\"/headers\",status_class=\"5xx\"} 1"));
    assert!(out.contains("elara_test_status{route=\"/proof\",status_class=\"4xx\"} 1"));
}

#[test]
fn test_labeled_counter_overflow_when_cap_reached() {
    // Cap=2 means after 2 distinct (route, class) keys, the third folds
    // into <overflow>|<status_class> so cardinality stays bounded.
    let lc = LabeledCounter::new(2);
    lc.inc("/a", "2xx");
    lc.inc("/b", "2xx");
    let pre = lc.label_count();
    assert_eq!(pre, 2);
    lc.inc("/c", "2xx"); // overflow
    let out = lc.to_prometheus("ovf_status", "Test");
    // /a, /b kept; /c rolled into <overflow>|2xx
    assert!(out.contains("ovf_status{route=\"/a\",status_class=\"2xx\"} 1"));
    assert!(out.contains("ovf_status{route=\"/b\",status_class=\"2xx\"} 1"));
    assert!(out.contains("ovf_status{route=\"<overflow>\",status_class=\"2xx\"} 1"));
}

#[test]
fn test_labeled_counter_escapes_quotes_in_route() {
    let lc = LabeledCounter::new(4);
    lc.inc("weird\"route", "2xx");
    let out = lc.to_prometheus("esc_status", "Test");
    // The literal `"` inside the route must be escaped so the exposition
    // stays parseable.
    assert!(out.contains("route=\"weird\\\"route\",status_class=\"2xx\""));
}

// ── RateLimiter ──────────────────────────────────────────────────────

#[test]
fn test_rate_limiter_allows_within_limit() {
    let rl = RateLimiter::new(10, 100);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..10 {
        assert!(rl.check(ip, true)); // write limit = 10
    }
    // 11th should be rejected
    assert!(!rl.check(ip, true));
}

#[test]
fn test_rate_limiter_read_vs_write_limits() {
    let rl = RateLimiter::new(5, 20);
    let ip: IpAddr = "10.0.0.2".parse().unwrap();
    // Use up write limit
    for _ in 0..5 {
        assert!(rl.check(ip, true));
    }
    assert!(!rl.check(ip, true)); // writes exhausted

    // Reads should still work (separate counter? — actually same bucket, but higher limit)
    // Actually RateLimiter uses same bucket for both with different limits checked
    // So after 5 writes, count=5. Read limit=20, so reads still allowed.
    // But the counter is shared, so next check adds to same count.
    assert!(rl.check(ip, false)); // count=6, under read limit 20
}

#[test]
fn test_rate_limiter_zero_limit_allows_all() {
    let rl = RateLimiter::new(0, 0);
    let ip: IpAddr = "10.0.0.3".parse().unwrap();
    for _ in 0..1000 {
        assert!(rl.check(ip, true));
        assert!(rl.check(ip, false));
    }
}

#[test]
fn test_rate_limiter_deny_ip() {
    let rl = RateLimiter::new(100, 100);
    let ip: IpAddr = "10.0.0.4".parse().unwrap();
    assert!(rl.check(ip, false)); // allowed

    rl.deny_ip(ip);
    assert!(!rl.check(ip, false)); // denied
    assert!(!rl.check(ip, true)); // denied for writes too
}

#[test]
fn test_rate_limiter_allow_ip_removes_deny() {
    let rl = RateLimiter::new(100, 100);
    let ip: IpAddr = "10.0.0.5".parse().unwrap();
    rl.deny_ip(ip);
    assert!(!rl.check(ip, false));

    assert!(rl.allow_ip(ip)); // returns true (was in deny list)
    assert!(rl.check(ip, false)); // allowed again
}

#[test]
fn test_rate_limiter_denied_ips_list() {
    let rl = RateLimiter::new(100, 100);
    let ip1: IpAddr = "10.0.0.6".parse().unwrap();
    let ip2: IpAddr = "10.0.0.7".parse().unwrap();
    rl.deny_ip(ip1);
    rl.deny_ip(ip2);
    let denied = rl.denied_ips();
    assert_eq!(denied.len(), 2);
    assert!(denied.contains(&ip1));
    assert!(denied.contains(&ip2));
}

#[test]
fn test_rate_limiter_different_ips_independent() {
    let rl = RateLimiter::new(3, 100);
    let ip1: IpAddr = "10.0.0.8".parse().unwrap();
    let ip2: IpAddr = "10.0.0.9".parse().unwrap();
    for _ in 0..3 {
        assert!(rl.check(ip1, true));
    }
    assert!(!rl.check(ip1, true)); // ip1 exhausted
    assert!(rl.check(ip2, true)); // ip2 still fine
}

// ── parse_ipv4_octets ────────────────────────────────────────────────

#[test]
fn test_parse_ipv4_valid() {
    assert_eq!(parse_ipv4_octets("192.168.1.1"), Some([192, 168, 1, 1]));
    assert_eq!(parse_ipv4_octets("0.0.0.0"), Some([0, 0, 0, 0]));
    assert_eq!(
        parse_ipv4_octets("255.255.255.255"),
        Some([255, 255, 255, 255])
    );
}

#[test]
fn test_parse_ipv4_invalid() {
    assert_eq!(parse_ipv4_octets("not-an-ip"), None);
    assert_eq!(parse_ipv4_octets("1.2.3"), None); // too few octets
    assert_eq!(parse_ipv4_octets("1.2.3.4.5"), None); // too many
    assert_eq!(parse_ipv4_octets("256.0.0.0"), None); // out of range
    assert_eq!(parse_ipv4_octets(""), None);
}

// ── CORS preflight (verify.html cross-origin) ───────────────────────
//
// Builds the same CorsLayer the public router applies and checks that
// an OPTIONS preflight from any origin gets `access-control-allow-origin: *`.
// Locks in the post-2026-04-26 contract: public router is permissive by
// default — no env-var gate. If a regression toggles back to deny-by-default,
// verify.html and any browser account will silently break cross-origin.

#[tokio::test]
async fn cors_preflight_allows_any_origin() {
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::routing::get;
    use tower::ServiceExt;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    let app = Router::new()
        .route("/status", get(|| async { "ok" }))
        .layer(cors);

    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/status")
        .header("origin", "https://elara.cash")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let allow_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .expect("access-control-allow-origin header missing");
    assert_eq!(allow_origin.to_str().unwrap(), "*");
}

#[tokio::test]
async fn cors_get_response_carries_allow_origin() {
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::routing::get;
    use tower::ServiceExt;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    let app = Router::new()
        .route("/epochs/headers", get(|| async { "[]" }))
        .layer(cors);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/epochs/headers")
        .header("origin", "https://elara.cash")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let allow_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .expect("GET response must carry allow-origin so browser exposes body");
    assert_eq!(allow_origin.to_str().unwrap(), "*");
}

// ── Gap 1 SMT-binding observability gauge ─────────────────────────────
//
// `smt_disk_root_vs_seal` is the helper that drives
// `elara_account_smt_disk_root_matches_latest_seal`,
// `elara_account_smt_disk_root_age_seconds`, and
// `elara_account_smt_latest_seal_epoch`. Tests cover the three regimes
// dashboards must distinguish: empty chain (no binding), node bound to
// the latest seal (the rotating creator), and node holding a divergent
// root (the witness-flush majority case in the current regime).

fn smt_test_storage() -> std::sync::Arc<crate::storage::rocks::StorageEngine> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("rocks");
    std::mem::forget(tmp);
    std::sync::Arc::new(crate::storage::rocks::StorageEngine::open(path).expect("open rocks"))
}

#[test]
fn smt_disk_root_vs_seal_no_binding_reports_match() {
    // Genesis / pre-Gap-1 chain: no `latest_sealed_account` populated,
    // CF_EPOCHS empty. The gauge should not flag divergence on a
    // network with nothing to diverge from yet, so `matches=1`. Age and
    // epoch use the -1 sentinel so dashboards can filter the
    // "no-binding" rows out of latency plots.
    let storage = smt_test_storage();
    let (matches, age, epoch) = smt_disk_root_vs_seal(&storage, None, 1_745_322_000.0);
    assert_eq!(matches, 1, "no binding -> no divergence -> match=1");
    assert!(age < 0.0, "no binding -> age sentinel < 0");
    assert_eq!(epoch, -1, "no binding -> epoch sentinel = -1");
}

#[test]
fn smt_disk_root_vs_seal_match_returns_age() {
    // Snapshot the empty-tree root and pretend it was signed by a seal.
    // Because nothing has touched the SMT, the on-disk root equals the
    // claimed sealed root -> the gauge reports match=1 with age =
    // now - sealed_at. This is the rotating-creator signal.
    let storage = smt_test_storage();
    let on_disk = crate::network::account_merkle::AccountStateSMT::new(&storage)
        .root()
        .expect("root");
    let zone = super::super::zone::ZoneId::from_legacy(0);
    let sealed_at = 1_745_322_000.0;
    let now = sealed_at + 12.5;
    let (matches, age, epoch) = smt_disk_root_vs_seal(
        &storage,
        Some((4962, zone, "seal-id".into(), on_disk, sealed_at)),
        now,
    );
    assert_eq!(matches, 1, "matching root -> bound");
    assert!(
        (age - 12.5).abs() < 1e-6,
        "age = now - sealed_at, got {age}"
    );
    assert_eq!(epoch, 4962);
}

#[test]
fn smt_disk_root_vs_seal_diverged_returns_negative_age() {
    // Witness-side regime: seal claims a root that differs from
    // anything this node has on disk. Gauge must read 0 + age=-1 so
    // dashboards can count divergent seeds and operators can see the
    // LightClientPool soft-fail surface area. Epoch number is still
    // returned (the binding exists, this node just isn't anchored to
    // it) so cross-node spread is plottable.
    let storage = smt_test_storage();
    let zone = super::super::zone::ZoneId::from_legacy(0);
    let mismatched_root = [0xAB; 32];
    let (matches, age, epoch) = smt_disk_root_vs_seal(
        &storage,
        Some((
            9552,
            zone,
            "seal-id".into(),
            mismatched_root,
            1_745_322_000.0,
        )),
        1_745_322_120.0,
    );
    assert_eq!(matches, 0, "divergent root -> not bound");
    assert!(age < 0.0, "divergent -> age sentinel");
    assert_eq!(epoch, 9552, "epoch surfaced even when diverged");
}

// ─── sync-helper tests ────
//
// Three pure /proc parsers pinned. Every one of these feeds a Prometheus
// gauge that operators alert on (process I/O, meminfo, host + cgroup PSI). A
// silent regression in any parser mis-reports host health and the host
// looks calm while it dies. Pure-fn `#[test]` (no tokio runtime, no
// fixtures) so each costs ~zero suite time.

#[test]
fn batch_w_parse_rss_composition_extracts_anon_file_shmem_in_kib_and_zero_on_missing_lines() {
    // Real-shape `/proc/self/status` fragment — kernel emits these
    // three fields with a `kB` unit suffix that the parser must drop.
    // The contract: only the integer in column 2 lands in the tuple;
    // unit suffix and surrounding rows are ignored.
    let raw = "Name:\telara-node\n\
                   VmRSS:\t  102400 kB\n\
                   RssAnon:\t   65536 kB\n\
                   RssFile:\t   30720 kB\n\
                   RssShmem:\t    6144 kB\n\
                   VmData:\t   89472 kB\n";
    assert_eq!(parse_rss_composition(raw), (65536, 30720, 6144));

    // Empty input — every field defaults to 0 (graceful on non-Linux
    // hosts or containers without /proc/self/status). Regression to
    // `.unwrap()` would panic the metric-collection thread.
    assert_eq!(parse_rss_composition(""), (0, 0, 0));

    // Missing one field — the present fields parse, the absent one
    // stays at 0. Pin so a refactor that switched to `expect()` on
    // a missing key would surface here.
    let partial = "RssAnon:\t   12345 kB\n";
    assert_eq!(parse_rss_composition(partial), (12345, 0, 0));

    // Malformed value — non-numeric in column 2. `.parse().ok()`
    // yields None, falls through to 0. Pin so a regression to
    // `.parse().unwrap()` would crash on the first bad /proc line.
    let bad = "RssAnon:\tNOT-A-NUMBER kB\nRssFile:\t999 kB\n";
    assert_eq!(parse_rss_composition(bad), (0, 999, 0));
}

#[test]
fn batch_w_parse_meminfo_extras_extracts_nine_fields_in_documented_tuple_order() {
    // Real-shape `/proc/meminfo` fragment. Contract: 9-tuple in
    // exactly the documented order `(mem_total, mem_available,
    // mem_free, buffers, slab, sreclaimable, swap_total, swap_free,
    // page_tables)`. A regression that swapped any pair would silently
    // mis-report ratios (MemAvailable/MemTotal is the canonical
    // alert metric; swapping mem_free with mem_available understates
    // pressure by ~10x because mem_free is always much smaller).
    let raw = "MemTotal:        4035680 kB\n\
                   MemFree:           98304 kB\n\
                   MemAvailable:    2516992 kB\n\
                   Buffers:           45056 kB\n\
                   Cached:          1638400 kB\n\
                   Slab:             184320 kB\n\
                   SReclaimable:     106496 kB\n\
                   SUnreclaim:        77824 kB\n\
                   SwapTotal:        524288 kB\n\
                   SwapFree:         524288 kB\n\
                   PageTables:        12288 kB\n";
    assert_eq!(
        parse_meminfo_extras(raw),
        (4035680, 2516992, 98304, 45056, 184320, 106496, 524288, 524288, 12288)
    );

    // Empty input — full 9-tuple of zeros. Containers without
    // /proc/meminfo fall through to this path on the wrapper
    // (`read_to_string(...).unwrap_or_default()`) so the parser
    // must not blow up.
    assert_eq!(parse_meminfo_extras(""), (0, 0, 0, 0, 0, 0, 0, 0, 0));

    // Unknown keys — the `_ => {}` arm must swallow them silently.
    // A regression that turned the wildcard into `panic!("unknown key: {key}")`
    // would crash on every meminfo line we don't care about (Cached,
    // SUnreclaim, etc.).
    let unknown = "Cached:          1638400 kB\nSUnreclaim:        77824 kB\n";
    assert_eq!(parse_meminfo_extras(unknown), (0, 0, 0, 0, 0, 0, 0, 0, 0));

    // Trailing-whitespace-only lines + lines with no value — the
    // `parts.next()` for the value is `None` so val defaults to 0.
    // Pin so neither shape panics.
    let edge = "MemTotal:\n\nSwapTotal:        \n";
    assert_eq!(parse_meminfo_extras(edge), (0, 0, 0, 0, 0, 0, 0, 0, 0));
}

#[test]
fn batch_w_parse_psi_block_splits_some_and_full_lines_with_keyed_token_extraction() {
    // Real-shape `/proc/pressure/cpu` block per the host pressure-stall doc
    // comment. Two lines, each starting with `some ` or `full `,
    // followed by `key=value` tokens. Contract: each scope returns
    // a `PsiScope` with avg10/avg60/avg300/total_us, and the four
    // fields land in EXACTLY those slots — a swap of any pair would
    // silently mis-attribute decay-window values.
    let raw = "some avg10=0.50 avg60=0.20 avg300=0.10 total=12345\n\
                   full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    let (some, full) = parse_psi_block(raw);
    let s = some.expect("some scope must parse");
    assert!((s.avg10 - 0.50).abs() < f64::EPSILON);
    assert!((s.avg60 - 0.20).abs() < f64::EPSILON);
    assert!((s.avg300 - 0.10).abs() < f64::EPSILON);
    assert_eq!(s.total_us, 12345);
    let f = full.expect("full scope must parse");
    assert_eq!(f.avg10, 0.0);
    assert_eq!(f.avg60, 0.0);
    assert_eq!(f.avg300, 0.0);
    assert_eq!(f.total_us, 0);

    // Empty input — both scopes None (CPU-only pressure files on
    // older kernels omit the `full` line; the caller must tolerate
    // both Some/Some, Some/None, and None/None shapes).
    let (none_some, none_full) = parse_psi_block("");
    assert!(none_some.is_none());
    assert!(none_full.is_none());

    // Only `some` line — `full` returns None. Pin so the caller's
    // `some.is_some() || full.is_some()` filter (server.rs:1822)
    // doesn't break when only one scope appears.
    let some_only = "some avg10=1.50 avg60=1.00 avg300=0.75 total=999000\n";
    let (some, full) = parse_psi_block(some_only);
    assert!(full.is_none(), "only `some` line -> full must stay None");
    let s = some.expect("some scope must parse");
    assert!((s.avg10 - 1.5).abs() < f64::EPSILON);
    assert_eq!(s.total_us, 999000);

    // Malformed values fall through to defaults — `v.parse().unwrap_or(0.0)` /
    // `.unwrap_or(0)`. Lines without `key=value` tokens skip via the
    // `split_once('=')` None branch. Pin so a single bad PSI line
    // can't crash the metrics collection or null out neighboring
    // valid fields.
    let bad = "some avg10=NaN-string avg60=0.42 not-a-pair total=BORK\n";
    let (some, full) = parse_psi_block(bad);
    let s = some.expect("partial parse must still yield Some");
    assert_eq!(s.avg10, 0.0, "unparseable avg10 -> default 0.0");
    assert!(
        (s.avg60 - 0.42).abs() < f64::EPSILON,
        "valid avg60 still lands"
    );
    assert_eq!(s.total_us, 0, "unparseable total -> default 0");
    assert!(full.is_none());

    // Unknown scope prefix (e.g. future kernel adds `none ` line) —
    // the `continue` arm skips it. Pin so a forward-compat /proc
    // change doesn't break collection on running nodes.
    let unknown_scope = "none avg10=5.0 total=1\nsome avg10=0.1 avg60=0.0 avg300=0.0 total=1\n";
    let (some, full) = parse_psi_block(unknown_scope);
    assert!(
        some.is_some(),
        "valid some after unknown scope still parses"
    );
    assert!(full.is_none());
}

// Additional coverage on network/server.rs covering
// wire-shape constants (MAX_REQUEST_BODY_BYTES + LATENCY_BUCKETS + LABELED_HISTOGRAM_CAP)
// and the previously-untested `format_op` ParsedLedgerOp → JSON serializer
// (24 variants, all snake_case literal "op" tags + field pass-through).
// batch_w already pins the proc-text parsers (rss/meminfo/psi_block).

#[allow(clippy::assertions_on_constants)]
#[test]
fn batch_b_max_request_body_bytes_two_mebibytes_literal_pin() {
    // Pins MAX_REQUEST_BODY_BYTES at the documented 2 MiB ceiling. Used by
    // both the Content-Length early-reject middleware at L792 and the axum
    // DefaultBodyLimit layer at L9743/9853/9931. A regression that bumped
    // the constant without updating the axum layer (or vice-versa) would
    // leave one side rejecting and the other accepting — phone-tier nodes
    // would either drop large /submit_record posts inconsistently or pull
    // megabytes of attacker-controlled body before evaluating the
    // rate-limit middleware. The 2 MiB ceiling is sized to accommodate
    // the worst-case Dilithium3-signed record (PK ~1952B + sig ~3293B +
    // metadata) with order-of-magnitude headroom; tightening below 1 MiB
    // would break large multi-zone state-delta posts, and loosening to
    // 10+ MiB would expand the per-connection memory pressure surface on
    // 2 GB Hetzner VMs (3 of 6 testnet nodes).
    assert_eq!(
        MAX_REQUEST_BODY_BYTES,
        2 * 1024 * 1024,
        "MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024 (2 MiB)"
    );
    // Bit-equivalent literal for grep-friendly drift detection.
    assert_eq!(
        MAX_REQUEST_BODY_BYTES, 2_097_152,
        "MAX_REQUEST_BODY_BYTES = 2_097_152 bytes (decimal literal)"
    );
    // Headroom check: 2 MiB must comfortably exceed a single Dilithium3
    // record (PK 1952 + sig 3293 + 1 KB metadata ≈ 6.3 KB). If this
    // failed, the body limit would block well-formed witness records.
    const WORST_CASE_DILITHIUM_RECORD_BYTES: usize = 1952 + 3293 + 1024;
    assert!(
        MAX_REQUEST_BODY_BYTES > 100 * WORST_CASE_DILITHIUM_RECORD_BYTES,
        "MAX_REQUEST_BODY_BYTES must have >100x headroom over a single Dilithium record"
    );
}

#[allow(clippy::assertions_on_constants)]
#[test]
fn batch_b_small_command_body_cap_tightens_unauthenticated_value_post_routes() {
    // The `/rpc/*` account commands and the `/bootstrap/claim` faucet
    // untyped-`serde_json::Value`-decode their body in the axum extractor,
    // which runs BEFORE the in-handler auth/genesis check — so an oversized
    // body is an UNAUTHENTICATED decode-amplifier (~10x: every JSON token →
    // a ~24-byte enum node). `small_command_body_cap` gives exactly those
    // routes a 64 KiB Content-Length ceiling (vs the 2 MiB global), mirroring
    // the pq_transport peer-ingress caps. This test pins the cap value and the
    // EXACT allowlist — a route added/removed here is a deliberate change, not
    // an accident, and a prefix-match regression (catching unintended routes)
    // would surface as a non-allowlisted path returning the tight cap.
    assert_eq!(MAX_RPC_BODY_BYTES, 64 * 1024, "MAX_RPC_BODY_BYTES = 64 KiB");

    // Every enumerated small-Value POST route gets the tight cap.
    for path in [
        "/rpc/transfer",
        "/rpc/xzone_lock",
        "/rpc/xzone_claim",
        "/rpc/xzone_abort",
        "/rpc/stake",
        "/rpc/pool_fund",
        "/rpc/unstake",
        "/rpc/stamp",
        "/rpc/stamp-private",
        "/bootstrap/claim",
    ] {
        assert_eq!(
            small_command_body_cap(path),
            MAX_RPC_BODY_BYTES,
            "{path} must get the tight 64 KiB cap"
        );
    }

    // Large-body / unknown / near-miss paths keep the 2 MiB global cap. The
    // trailing-slash and `/rpc/`-prefix near-misses prove the allowlist is an
    // EXACT match, not a prefix (a future large-body `/rpc/*` route must not
    // inherit the tight cap and start 413-ing legit traffic).
    for path in [
        "/records",
        "/delta-sync",
        "/snapshot/state",
        "/",
        "/metrics",
        "/rpc/transfer/", // trailing slash — not the registered route
        "/rpc/future_bulk_import", // hypothetical future large-body /rpc route
        "/bootstrap/claim/extra",
    ] {
        assert_eq!(
            small_command_body_cap(path),
            MAX_REQUEST_BODY_BYTES,
            "{path} must keep the 2 MiB global cap"
        );
    }

    // The tight cap leaves generous headroom over the largest legit account
    // body (a few hundred bytes of scalar fields) yet stays far below the
    // global cap so it actually denies the amplifier.
    assert!(
        MAX_RPC_BODY_BYTES >= 16 * 1024 && MAX_RPC_BODY_BYTES < MAX_REQUEST_BODY_BYTES,
        "tight cap must be headroomed above legit bodies but below the global cap"
    );
}

/// Minimal `NodeState` for router oneshot tests — opens a throwaway RocksDB in a
/// tempdir. Mirrors the established `build_test_state` pattern used in
/// health.rs/discovery.rs (no NodeState harness existed in this module before).
fn build_test_state() -> (std::sync::Arc<crate::network::state::NodeState>, tempfile::TempDir) {
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let config = NodeConfig {
        data_dir: data_dir.clone(),
        identity_path: data_dir.join("identity.json"),
        db_path: data_dir.join("elara.db"),
        admin_token: "test-admin".into(),
        network_id: "rpc-body-limit-test".into(),
        mdns_enabled: false,
        health_check_interval_secs: 0,
        min_pow_difficulty: 0,
        ..Default::default()
    };
    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
        .expect("generate identity");
    let rocks =
        std::sync::Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("open rocks"));
    let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
    let state = std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr));
    (state, tmp)
}

#[tokio::test]
async fn batch_b_rpc_body_limit_413s_oversized_body_without_content_length() {
    // The tight MAX_RPC_BODY_BYTES cap on the /rpc/* + /bootstrap/claim command
    // surface must be enforced by the body EXTRACTOR (the per-route
    // DefaultBodyLimit in rpc_command_routes()), not only by the Content-Length
    // fast-reject in rate_limit_middleware. A request that omits Content-Length
    // (Transfer-Encoding: chunked, or any streaming body) slips past that header
    // check; without the extractor-level limit it would fall back to the 2 MiB
    // global cap and re-open the UNAUTHENTICATED serde_json::Value
    // decode-amplifier on a pre-auth route. This drives the REAL routes() router
    // and asserts 413 on a >64 KiB no-Content-Length POST to /rpc/transfer,
    // proving the bypass is closed end-to-end.
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Method, Request};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let (state, _tmp) = build_test_state();

    // 100 KiB — over the 64 KiB tight cap, under the 2 MiB global cap.
    let oversized = vec![b'x'; 100 * 1024];
    assert!(oversized.len() > MAX_RPC_BODY_BYTES && oversized.len() < MAX_REQUEST_BODY_BYTES);

    // Loopback ConnectInfo so public_route_gate admits the local-only route.
    // NO Content-Length header → the middleware fast-reject is bypassed, so only
    // the extractor-level limit can catch this (the regression we are pinning).
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/rpc/transfer")
        .header("content-type", "application/json")
        .body(Body::from(oversized))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));

    let resp = routes(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "oversized no-Content-Length /rpc/transfer must 413 at the extractor, not slip to the 2 MiB cap"
    );

    // Control: a small body is NOT blocked by the limit. It passes the extractor
    // and reaches auth/handler (which may 4xx/5xx for other reasons) but must
    // NOT be 413 — proves legit account traffic still flows.
    let small = br#"{"to":"00","amount":1}"#.to_vec();
    let mut req2 = Request::builder()
        .method(Method::POST)
        .uri("/rpc/transfer")
        .header("content-type", "application/json")
        .body(Body::from(small))
        .unwrap();
    req2.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40001))));
    let resp2 = routes(state).oneshot(req2).await.unwrap();
    assert_ne!(
        resp2.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a small account body must pass the body limit"
    );
}

#[tokio::test]
async fn attestations_http_body_cap_matches_pq_413s_oversized() {
    // HTTP/PQ ingress parity. POST /attestations must carry the same tight
    // MAX_RPC_BODY_BYTES (64 KiB) extractor cap as the PQ receive_attestation
    // verb (MAX_ATTESTATION_BODY = 64 KiB). Before rpc_body_cap() was layered on
    // the route, the Json<AttestationSubmit> extractor fell back to the 2 MiB
    // global DefaultBodyLimit — 32x the PQ parse-work ceiling per hostile request
    // on the consensus-attestation ingress path. Pin it: a >64 KiB
    // no-Content-Length POST must 413 at the extractor (the regression we close).
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Method, Request};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let (state, _tmp) = build_test_state();

    // 100 KiB — over the 64 KiB tight cap, under the 2 MiB global cap.
    let oversized = vec![b'x'; 100 * 1024];
    assert!(oversized.len() > MAX_RPC_BODY_BYTES && oversized.len() < MAX_REQUEST_BODY_BYTES);

    // No Content-Length → the rate_limit_middleware header fast-reject is
    // bypassed, so only the extractor-level limit can catch this.
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/attestations")
        .header("content-type", "application/json")
        .body(Body::from(oversized))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40010))));
    let resp = routes(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "oversized no-Content-Length POST /attestations must 413 at the extractor (HTTP/PQ 64 KiB parity)"
    );

    // Control: a small body is NOT blocked by the body limit. It passes the
    // extractor and reaches the handler (which may 4xx for a bad signature) but
    // must NOT be 413 — proves legit attestation traffic still flows.
    let small = br#"{"record_id":"00","witness_hash":"00","signature":"00","timestamp":0.0}"#.to_vec();
    let mut req2 = Request::builder()
        .method(Method::POST)
        .uri("/attestations")
        .header("content-type", "application/json")
        .body(Body::from(small))
        .unwrap();
    req2.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40011))));
    let resp2 = routes(state).oneshot(req2).await.unwrap();
    assert_ne!(
        resp2.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a small attestation body must pass the body limit"
    );
}

#[tokio::test]
async fn record_ingest_http_body_cap_matches_pq_413s_oversized() {
    // HTTP/PQ ingress parity, single-record-ingest class. The four routes that
    // decode ONE binary-wire ValidationRecord (POST /records, /slash, /witness,
    // /validate) must carry the same tight MAX_RECORD_BYTES (64 KiB) extractor
    // cap as the PQ transport's guard_record_body gate. Before record_body_cap()
    // was layered on, the Bytes extractor fell back to the 2 MiB global
    // DefaultBodyLimit, so a handshaked peer could force 2 MiB of buffering (32x
    // the PQ parse-work ceiling) per hostile submission before the in-handler
    // MAX_RECORD_BYTES guard fired. Pin it: a >64 KiB no-Content-Length POST must
    // 413 at the extractor on every one of the four routes.
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Method, Request};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let (state, _tmp) = build_test_state();

    // 100 KiB — over the 64 KiB (MAX_RECORD_BYTES) cap, under the 2 MiB global.
    let oversized = vec![b'x'; 100 * 1024];
    assert!(
        oversized.len() > crate::network::ingest::MAX_RECORD_BYTES
            && oversized.len() < MAX_REQUEST_BODY_BYTES
    );

    for (i, path) in ["/records", "/slash", "/witness", "/validate"]
        .iter()
        .enumerate()
    {
        // No Content-Length → the rate_limit_middleware header fast-reject is
        // bypassed (these routes are intentionally NOT in small_command_body_cap),
        // so only the extractor-level record_body_cap can catch this. Loopback
        // ConnectInfo so public_route_gate admits each route.
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(*path)
            .body(Body::from(oversized.clone()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            41000 + i as u16,
        ))));
        let resp = routes(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "oversized no-Content-Length POST {path} must 413 at the extractor, not slip to the 2 MiB cap"
        );

        // Control: a tiny (invalid) record body passes the extractor and reaches
        // the handler (which 4xx/200s on the parse) but must NOT be 413 — proves
        // legit single-record traffic still flows.
        let mut req2 = Request::builder()
            .method(Method::POST)
            .uri(*path)
            .body(Body::from(vec![b'x'; 32]))
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            42000 + i as u16,
        ))));
        let resp2 = routes(state.clone()).oneshot(req2).await.unwrap();
        assert_ne!(
            resp2.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "a small {path} body must pass the body limit"
        );
    }
}

#[tokio::test]
async fn json_command_routes_http_body_cap_413s_oversized() {
    // HTTP/PQ ingress parity, Json-extractor class — same shape as
    // attestations_http_body_cap_matches_pq_413s_oversized. These POST routes
    // decode a small Json<T> with no in-handler size guard, so before
    // rpc_body_cap() was layered they fell back to the 2 MiB global
    // DefaultBodyLimit — an unauthenticated parse/buffer amplifier on each. Every
    // legit body is far under 64 KiB (probe = 2 hashes, offline_notification =
    // node_id+ts+sig, witness_profile = 4 short strings). Pin: a >64 KiB
    // no-Content-Length POST must 413 at the extractor; a small body must not.
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Method, Request};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let (state, _tmp) = build_test_state();

    // 100 KiB — over the 64 KiB tight cap, under the 2 MiB global cap.
    let oversized = vec![b'x'; 100 * 1024];
    assert!(oversized.len() > MAX_RPC_BODY_BYTES && oversized.len() < MAX_REQUEST_BODY_BYTES);

    let mut port = 40020u16;
    for path in ["/probe", "/peers/offline_notification", "/witness/profile"] {
        // No Content-Length → the rate_limit_middleware header fast-reject is
        // bypassed, so only the extractor-level limit can catch this.
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(oversized.clone()))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], port))));
        port += 1;
        let resp = routes(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "oversized no-Content-Length POST {path} must 413 at the extractor (64 KiB rpc_body_cap)"
        );

        // Control: a small body is NOT blocked by the body limit. It passes the
        // extractor and reaches the handler (which may 4xx for a schema mismatch)
        // but must NOT be 413 — proves legit traffic on this route still flows.
        let mut req2 = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(b"{}".to_vec()))
            .unwrap();
        req2.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], port))));
        port += 1;
        let resp2 = routes(state.clone()).oneshot(req2).await.unwrap();
        assert_ne!(
            resp2.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "a small body to {path} must pass the body limit"
        );
    }
}

#[tokio::test]
async fn transition_command_routes_http_body_cap_413s_oversized() {
    // HTTP/PQ ingress parity for the zone-transition POST surface — same
    // Json-extractor-no-guard class as json_command_routes_*. /sig and /veto
    // carry a single Dilithium3 sig so they ride the 64 KiB rpc_body_cap();
    // /propose bundles up to MAX_PROPOSER_SIGS sigs so it rides the wider
    // 512 KiB transition_propose_body_cap(). Pin BOTH tiers: a 100 KiB body
    // (over the tight cap, under the wide one) must 413 on /sig + /veto but
    // PASS on /propose — proving propose got the distinct, wider cap and the
    // single-sig routes did not.
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Method, Request};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let (state, _tmp) = build_test_state();
    // 64-hex (32-byte) id so the {id} path segment is well-formed for the
    // small-body control; the body-limit layer fires before the handler either
    // way, so the exact id is immaterial to the 413 assertions.
    let id = "0011223344556677889900112233445566778899001122334455667788990011";

    // --- Tight-cap routes: /sig + /veto. 100 KiB > 64 KiB tight cap. ---
    let oversized = vec![b'x'; 100 * 1024];
    assert!(oversized.len() > MAX_RPC_BODY_BYTES && oversized.len() < MAX_TRANSITION_PROPOSE_BODY_BYTES);

    let mut port = 40060u16;
    for path in [format!("/transitions/{id}/sig"), format!("/transitions/{id}/veto")] {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(&path)
            .header("content-type", "application/json")
            .body(Body::from(oversized.clone()))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], port))));
        port += 1;
        let resp = routes(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "oversized POST {path} must 413 at the extractor (64 KiB rpc_body_cap)"
        );

        let mut req2 = Request::builder()
            .method(Method::POST)
            .uri(&path)
            .header("content-type", "application/json")
            .body(Body::from(b"{}".to_vec()))
            .unwrap();
        req2.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], port))));
        port += 1;
        let resp2 = routes(state.clone()).oneshot(req2).await.unwrap();
        assert_ne!(
            resp2.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "a small body to {path} must pass the body limit"
        );
    }

    // --- Wide-cap route: /propose. The SAME 100 KiB body must NOT 413 (proves
    //     propose is on the 512 KiB cap, not the 64 KiB tight cap); a body over
    //     512 KiB MUST 413. ---
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/transitions/propose")
        .header("content-type", "application/json")
        .body(Body::from(oversized.clone()))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], port))));
    port += 1;
    let resp = routes(state.clone()).oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a 100 KiB POST /transitions/propose must NOT 413 — it rides the wider 512 KiB cap"
    );

    let way_oversized = vec![b'x'; MAX_TRANSITION_PROPOSE_BODY_BYTES + 4096];
    let mut req2 = Request::builder()
        .method(Method::POST)
        .uri("/transitions/propose")
        .header("content-type", "application/json")
        .body(Body::from(way_oversized))
        .unwrap();
    req2.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], port))));
    let resp2 = routes(state).oneshot(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a >512 KiB POST /transitions/propose must 413 at the extractor"
    );
}

#[test]
fn transition_propose_body_cap_holds_max_proposer_sigs() {
    // Drift guard: the propose cap MUST hold a full-committee proposal, or valid
    // proposals start 413-ing. A single AnchorSig is a 32-byte id + a 3309-byte
    // ML-DSA-65 Dilithium3 sig, both serde_json number-arrays (no hex/base64
    // attr); a byte in 100..=255 costs "NNN," = 4 chars → ~13.4 KiB per sig
    // worst-case. If MAX_PROPOSER_SIGS grows, this forces a re-think of the cap.
    use crate::network::zone_transition_seal::MAX_PROPOSER_SIGS;
    const WORST_CASE_ANCHORSIG_JSON: usize = 13_500;
    const SEAL_ENVELOPE_JSON: usize = 8 * 1024; // kind/epochs/≤3 ZoneSnapshots/split_key
    let legit_max = MAX_PROPOSER_SIGS * WORST_CASE_ANCHORSIG_JSON + SEAL_ENVELOPE_JSON;
    assert!(
        MAX_TRANSITION_PROPOSE_BODY_BYTES >= legit_max,
        "propose cap {MAX_TRANSITION_PROPOSE_BODY_BYTES} must hold a full {MAX_PROPOSER_SIGS}-sig proposal (~{legit_max} B) or valid proposals 413",
    );
    // ...but still strictly tighter than the 2 MiB global, and strictly wider
    // than the 64 KiB single-sig tight cap — the point of a distinct tier.
    // Compile-time invariant: a break in the cap tiering fails the BUILD, not
    // just this test (and is clippy-clean — assertions_on_constants skips const
    // context). All three operands are module consts, so the ordering is const-
    // evaluable; if a future cap edit inverts the tiers, cargo build stops it.
    const _: () = assert!(MAX_TRANSITION_PROPOSE_BODY_BYTES < MAX_REQUEST_BODY_BYTES);
    const _: () = assert!(MAX_TRANSITION_PROPOSE_BODY_BYTES > MAX_RPC_BODY_BYTES);
}

#[tokio::test]
async fn slot_conflicts_route_http_body_cap_413s_oversized() {
    // HTTP/PQ ingress parity for the slot-conflict POST surface — same
    // Json-extractor-no-guard class as the /attestations + /peers/offline_notification
    // routes capped earlier in this sweep. /slot-conflicts decodes
    // Json<ConflictProof> (two full ValidationRecords) pre-verify, so it rides the
    // wider MAX_CONFLICT_PROOF_BODY_BYTES (1 MiB) cap, NOT the 64 KiB tight cap.
    // Pin both edges: a 100 KiB body (over the tight cap, under the wide one) must
    // NOT 413 — proving the wider cap is wired — and a >1 MiB body MUST 413.
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Method, Request};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let (state, _tmp) = build_test_state();

    // 100 KiB > 64 KiB tight cap but < 1 MiB wide cap → must pass the extractor.
    let mid = vec![b'x'; 100 * 1024];
    assert!(mid.len() > MAX_RPC_BODY_BYTES && mid.len() < MAX_CONFLICT_PROOF_BODY_BYTES);
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/slot-conflicts")
        .header("content-type", "application/json")
        .body(Body::from(mid))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40080u16))));
    let resp = routes(state.clone()).oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a 100 KiB POST /slot-conflicts must NOT 413 — it rides the wider 1 MiB cap, not the 64 KiB tight cap"
    );

    // >1 MiB → must 413 at the extractor before the handler runs.
    let way_oversized = vec![b'x'; MAX_CONFLICT_PROOF_BODY_BYTES + 4096];
    let mut req2 = Request::builder()
        .method(Method::POST)
        .uri("/slot-conflicts")
        .header("content-type", "application/json")
        .body(Body::from(way_oversized))
        .unwrap();
    req2.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40081u16))));
    let resp2 = routes(state).oneshot(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a >1 MiB POST /slot-conflicts must 413 at the extractor (conflict_proof_body_cap)"
    );
}

#[test]
fn conflict_proof_body_cap_holds_two_max_records() {
    // Drift guard: the conflict-proof cap MUST hold a proof bundling two
    // max-size records, or legitimate slot-conflict reports start 413-ing.
    // A ValidationRecord is bounded at MAX_RECORD_BYTES (64 KiB) binary; its bulk
    // fields (signature/sphincs_signature/creator_public_key/content_hash/zk_proof)
    // are Vec<u8> with no hex/base64 serde attr → JSON number-arrays at up to
    // "255," = 4 chars/byte worst-case, so a byte-array-dominated record is ~4×
    // its binary size as JSON. Two of them + the {record_a,record_b} envelope is
    // the legit ceiling. If MAX_RECORD_BYTES grows, this forces a cap re-think.
    const WORST_CASE_RECORD_JSON: usize = 4 * crate::network::ingest::MAX_RECORD_BYTES;
    const PROOF_ENVELOPE_JSON: usize = 4 * 1024; // {"record_a":…,"record_b":…} scaffolding
    let legit_max = 2 * WORST_CASE_RECORD_JSON + PROOF_ENVELOPE_JSON;
    assert!(
        MAX_CONFLICT_PROOF_BODY_BYTES >= legit_max,
        "conflict-proof cap {MAX_CONFLICT_PROOF_BODY_BYTES} must hold two {}-byte records (~{legit_max} B JSON) or valid proofs 413",
        crate::network::ingest::MAX_RECORD_BYTES,
    );
    // Strictly tighter than the 2 MiB global, strictly wider than the 64 KiB
    // single-sig tight cap — the point of a distinct tier. Compile-time invariant:
    // a break in the cap tiering fails the BUILD, not just this test.
    const _: () = assert!(MAX_CONFLICT_PROOF_BODY_BYTES < MAX_REQUEST_BODY_BYTES);
    const _: () = assert!(MAX_CONFLICT_PROOF_BODY_BYTES > MAX_RPC_BODY_BYTES);
}

#[tokio::test]
async fn batch_b_rpc_body_limit_enforced_on_admin_router_too() {
    // admin_routes() exposes the same command surface; it must carry the same
    // extractor-level cap. Same no-Content-Length oversized POST → 413.
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Method, Request};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let (state, _tmp) = build_test_state();
    let oversized = vec![b'x'; 100 * 1024];
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/bootstrap/claim")
        .header("content-type", "application/json")
        .body(Body::from(oversized))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40002))));
    let resp = admin_routes(state).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "admin_routes() /bootstrap/claim must also enforce the tight cap at the extractor"
    );
}

#[test]
fn batch_b_latency_buckets_prometheus_default_array_pin_12_buckets_monotonic_one_ms_to_ten_s() {
    // Pins LATENCY_BUCKETS as the Prometheus client_golang default — 12
    // buckets spanning 1 ms to 10 s on roughly log-2 spacing. This array
    // is referenced by every Histogram::new() call in the codebase for
    // request-latency tracking, AND its order maps directly to bucket
    // index in the Prometheus exposition (`{le="0.001"}` etc.). A
    // regression that re-ordered, dropped, or inserted entries would
    // (a) misalign existing dashboard queries that hardcode `le="0.5"`
    // etc., and (b) silently degrade alerting on the SLO bands. Keep the
    // array stable; pick a separate constant if a different bucket
    // layout is needed for a new histogram family.
    let expected: &[f64] = &[
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];
    assert_eq!(
        LATENCY_BUCKETS.len(),
        12,
        "LATENCY_BUCKETS must remain 12-element Prometheus default"
    );
    assert_eq!(
        LATENCY_BUCKETS, expected,
        "LATENCY_BUCKETS must match Prometheus client_golang default exactly"
    );

    // Strict monotonic-ascending invariant — Prometheus histogram math
    // depends on it (cumulative buckets {le=X} require X increasing).
    for w in LATENCY_BUCKETS.windows(2) {
        assert!(
            w[0] < w[1],
            "LATENCY_BUCKETS must be strictly ascending — {} < {} violated",
            w[0],
            w[1]
        );
    }

    // Span pin: first bucket is 1 ms (10^-3 s), last is 10 s.
    assert!(
        (LATENCY_BUCKETS[0] - 0.001).abs() < 1e-12,
        "first bucket must be 1ms (10^-3 s)"
    );
    assert!(
        (LATENCY_BUCKETS[LATENCY_BUCKETS.len() - 1] - 10.0).abs() < 1e-12,
        "last bucket must be 10s"
    );
}

#[allow(clippy::assertions_on_constants)]
#[test]
fn batch_b_labeled_histogram_cap_route_cardinality_ceiling_pin_with_router_headroom() {
    // Pins LABELED_HISTOGRAM_CAP = 256. This is the per-metric label
    // cardinality ceiling for `LabeledHistogram` (per-route HTTP latency)
    // and `LabeledCounter` (per-route per-status HTTP request counters).
    // Today the axum router registers ~50 routes — the cap is sized to
    // ~5x headroom so adding a few dozen routes per release stays under
    // the cap without surfacing the `<overflow>` label. The doc comment
    // at L412-420 names the load-bearing properties; a regression
    // bumping the cap into the thousands would expose the metrics
    // surface to label-cardinality attacks (hostile clients minting
    // distinct routes), and dropping below ~64 would force healthy
    // routes into <overflow> bucket on the next router expansion.
    assert_eq!(
        LABELED_HISTOGRAM_CAP, 256,
        "LABELED_HISTOGRAM_CAP pinned at 256 (SCALE-bounded route cardinality)"
    );
    // Power-of-two pin — picked to make the bound visually obvious in
    // alerts (`label_count{name=...} == 256` reads as "hit the cap").
    assert_eq!(
        LABELED_HISTOGRAM_CAP,
        1usize << 8,
        "LABELED_HISTOGRAM_CAP is 2^8 (256) by design"
    );
    // Sanity: must be at least 64 (room for ~50 current routes + 14 add'l).
    assert!(
        LABELED_HISTOGRAM_CAP >= 64,
        "cap must comfortably exceed the ~50-route axum router surface"
    );
}

#[test]
fn batch_b_format_op_emits_documented_op_field_literal_for_every_parsed_ledger_op_variant() {
    // Pins the snake_case "op" tag emitted by `format_op` (L971-1106) for
    // each ParsedLedgerOp variant. These literals are the canonical wire
    // shape consumed by `/record/{id}`, `/account/{id}/history`, and
    // downstream block explorers / accounts — a regression renaming any
    // tag would silently break every external indexer that pattern-matches
    // on the "op" string. Pin all 19 variants so an additive enum extension
    // forces test maintenance (rustc exhaustiveness covers code; this test
    // covers wire shape).
    use crate::accounting::types::{ParsedLedgerOp, PredictionClaim, StakePurpose};

    let cases: Vec<(&str, ParsedLedgerOp)> = vec![
        (
            "mint",
            ParsedLedgerOp::Mint {
                amount: 0,
                to: String::new(),
                reason: String::new(),
            },
        ),
        (
            "transfer",
            ParsedLedgerOp::Transfer {
                amount: 0,
                to: String::new(),
                memo: None,
            },
        ),
        (
            "stake",
            ParsedLedgerOp::Stake {
                amount: 0,
                purpose: StakePurpose::Witness,
            },
        ),
        (
            "unstake",
            ParsedLedgerOp::Unstake {
                stake_record_id: String::new(),
            },
        ),
        (
            "witness_reward",
            ParsedLedgerOp::WitnessReward {
                amount: 0,
                from: String::new(),
                to: String::new(),
                record_id: String::new(),
            },
        ),
        (
            "slash",
            ParsedLedgerOp::Slash {
                amount: 0,
                offender: String::new(),
                challenger: String::new(),
                jury: Vec::new(),
                stake_record_id: String::new(),
                reason: String::new(),
            },
        ),
        (
            "dormancy_reclaim",
            ParsedLedgerOp::DormancyReclaim {
                amount: 0,
                dormant_identity: String::new(),
                last_activity: 0.0,
            },
        ),
        (
            "burn",
            ParsedLedgerOp::Burn {
                amount: 0,
                memo: None,
            },
        ),
        ("pool_fund", ParsedLedgerOp::PoolFund { amount: 0 }),
        (
            "predict",
            ParsedLedgerOp::Predict {
                amount: 0,
                zone: String::new(),
                target_epoch: 0,
                claim: PredictionClaim::Active,
                predicted_value: 0,
            },
        ),
        (
            "xzone_lock",
            ParsedLedgerOp::XZoneLock {
                amount: 0,
                recipient: String::new(),
                source_zone: String::new(),
                dest_zone: String::new(),
            },
        ),
        (
            "xzone_claim",
            ParsedLedgerOp::XZoneClaim {
                transfer_id: String::new(),
                amount: 0,
                recipient: String::new(),
            },
        ),
        (
            "xzone_cancel",
            ParsedLedgerOp::XZoneCancel {
                transfer_id: String::new(),
            },
        ),
        (
            "xzone_reject",
            ParsedLedgerOp::XZoneReject {
                transfer_id: String::new(),
            },
        ),
        (
            "xzone_abort",
            ParsedLedgerOp::XZoneAbort {
                transfer_id: String::new(),
                dest_committee_hash: [0u8; 32],
                dest_committee_size: 0,
                signers: Vec::new(),
            },
        ),
        (
            "dormancy_declare",
            ParsedLedgerOp::DormancyDeclare {
                target_identity: String::new(),
                last_known_active: 0.0,
            },
        ),
        ("dormancy_heartbeat", ParsedLedgerOp::DormancyHeartbeat),
        (
            "dormancy_proof_of_life",
            ParsedLedgerOp::DormancyProofOfLife {
                target_identity: String::new(),
                signature: String::new(),
            },
        ),
        (
            "witness_register",
            ParsedLedgerOp::WitnessRegister {
                zone_path: String::new(),
                bond: 0,
            },
        ),
    ];

    // 19 variants must be covered. If a new variant is added, this test
    // FAILS the assertion below and the developer must extend the cases
    // vec — surfacing the wire-shape contract for the new variant.
    assert_eq!(cases.len(), 19,
            "format_op must enumerate exactly 19 ParsedLedgerOp variants — new variant requires updating this test");

    for (expected_op, op) in cases {
        let json = format_op(&op);
        assert_eq!(
            json.get("op").and_then(|v| v.as_str()),
            Some(expected_op),
            "format_op {:?} must emit \"op\": \"{}\"",
            op,
            expected_op,
        );
    }
}

#[test]
fn batch_b_format_op_carries_amount_destination_and_enum_string_fields_through_intact() {
    // Pins field-pass-through for the representative variants. Wallets
    // and indexers rely on these JSON shapes: a regression that swapped
    // `amount` ↔ `bond` for WitnessRegister, or that dropped the `purpose`
    // → as_str() conversion for Stake, would silently corrupt downstream
    // accounting. Cover Mint (amount+to+reason), Transfer (memo Some/None),
    // Stake (enum as_str), XZoneAbort (signer_count = signers.len()), and
    // Slash (Vec<String> jury preserved as JSON array).
    use crate::accounting::types::{ParsedLedgerOp, PredictionClaim, StakePurpose};

    // Mint — amount/to/reason pass through verbatim as integers/strings.
    let mint_j = format_op(&ParsedLedgerOp::Mint {
        amount: 1_000_000,
        to: "alice-hash".to_string(),
        reason: "genesis-allocation".to_string(),
    });
    assert_eq!(mint_j["op"], "mint");
    assert_eq!(mint_j["amount"], 1_000_000u64);
    assert_eq!(mint_j["to"], "alice-hash");
    assert_eq!(mint_j["reason"], "genesis-allocation");

    // Transfer with memo=None → JSON null, not missing.
    let xfer_none = format_op(&ParsedLedgerOp::Transfer {
        amount: 42,
        to: "bob-hash".to_string(),
        memo: None,
    });
    assert_eq!(xfer_none["op"], "transfer");
    assert_eq!(xfer_none["amount"], 42u64);
    assert_eq!(xfer_none["to"], "bob-hash");
    assert!(
        xfer_none["memo"].is_null(),
        "Option<String>::None must serialize to JSON null, not be absent"
    );
    // Transfer with memo=Some("…") → string carried verbatim.
    let xfer_some = format_op(&ParsedLedgerOp::Transfer {
        amount: 1,
        to: "c".to_string(),
        memo: Some("for-coffee".to_string()),
    });
    assert_eq!(xfer_some["memo"], "for-coffee");

    // Stake — purpose enum lowered through as_str() to "witness".
    let stake_j = format_op(&ParsedLedgerOp::Stake {
        amount: 5_000,
        purpose: StakePurpose::Witness,
    });
    assert_eq!(
        stake_j["purpose"], "witness",
        "StakePurpose enum must serialize via as_str(), not via Debug"
    );
    // All three StakePurpose variants flow through correctly.
    let stake_g = format_op(&ParsedLedgerOp::Stake {
        amount: 0,
        purpose: StakePurpose::Governance,
    });
    assert_eq!(stake_g["purpose"], "governance");
    let stake_s = format_op(&ParsedLedgerOp::Stake {
        amount: 0,
        purpose: StakePurpose::Storage,
    });
    assert_eq!(stake_s["purpose"], "storage");

    // XZoneAbort — signers Vec collapsed to signer_count integer;
    // dest_committee_hash dropped (32-byte hash not in the JSON).
    let abort_j = format_op(&ParsedLedgerOp::XZoneAbort {
        transfer_id: "xfer-42".to_string(),
        dest_committee_hash: [0xAA; 32],
        dest_committee_size: 11,
        signers: Vec::new(),
    });
    assert_eq!(abort_j["op"], "xzone_abort");
    assert_eq!(abort_j["transfer_id"], "xfer-42");
    assert_eq!(abort_j["dest_committee_size"], 11u32);
    assert_eq!(
        abort_j["signer_count"], 0u64,
        "XZoneAbort.signers Vec must collapse to integer signer_count"
    );
    assert!(
        abort_j.get("dest_committee_hash").is_none(),
        "dest_committee_hash MUST be omitted from JSON (raw 32-byte hash is not wire shape)"
    );

    // Slash — jury Vec<String> preserved as JSON array (not collapsed).
    let slash_j = format_op(&ParsedLedgerOp::Slash {
        amount: 7_000,
        offender: "off".to_string(),
        challenger: "ch".to_string(),
        jury: vec!["j1".to_string(), "j2".to_string(), "j3".to_string()],
        stake_record_id: "stk".to_string(),
        reason: "double-sign".to_string(),
    });
    assert_eq!(slash_j["amount"], 7_000u64);
    assert_eq!(slash_j["offender"], "off");
    let jury = slash_j["jury"].as_array().expect("jury must be JSON array");
    assert_eq!(
        jury.len(),
        3,
        "Slash.jury Vec<String> must be preserved as 3-element array"
    );
    assert_eq!(jury[0], "j1");
    assert_eq!(jury[2], "j3");

    // Predict — claim enum via as_str().
    let predict_j = format_op(&ParsedLedgerOp::Predict {
        amount: 1,
        zone: "root/eu".to_string(),
        target_epoch: 999,
        claim: PredictionClaim::IdentityCount,
        predicted_value: 42,
    });
    assert_eq!(predict_j["claim"], "identity_count",
            "PredictionClaim::IdentityCount must serialize as \"identity_count\" (not \"IdentityCount\")");
    assert_eq!(predict_j["target_epoch"], 999u64);
    assert_eq!(predict_j["predicted_value"], 42u64);
    assert_eq!(predict_j["zone"], "root/eu");
}
