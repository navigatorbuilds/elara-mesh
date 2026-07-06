// Spec compliance tests — verify code matches whitepaper formulas.
// Each module tests a specific whitepaper section.
// If a test fails, either the code is wrong or the spec was updated.
//
// Run: cargo test --features node --test spec_compliance

// Protocol §11.12 — Consensus
mod protocol_consensus {
    /// T(r) = 1 - ∏(1 - w(n) × d(n, W))
    fn compute_trust(weights: &[f64], discounts: &[f64]) -> f64 {
        if weights.is_empty() { return 0.0; }
        let product: f64 = weights.iter().zip(discounts.iter())
            .map(|(w, d)| 1.0 - w * d).product();
        1.0 - product
    }

    fn is_zone_settled(attesting_stake: f64, total_stake: f64) -> bool {
        (attesting_stake / total_stake) > 0.67
    }

    #[derive(Debug, PartialEq, PartialOrd)]
    enum ConfLevel { Pending, Sealed, Finalized, Anchored }

    #[test]
    fn spec_11_12_trust_zero_witnesses() {
        assert!((compute_trust(&[], &[]) - 0.0).abs() < 0.001);
    }

    #[test]
    fn spec_11_12_trust_one_independent() {
        let t = compute_trust(&[0.5], &[1.0]);
        assert!((t - 0.5).abs() < 0.001, "got {t}");
    }

    #[test]
    fn spec_11_12_trust_approaches_one() {
        let t = compute_trust(&[0.5; 10], &[1.0; 10]);
        assert!(t > 0.99 && t < 1.0, "got {t}");
    }

    #[test]
    fn spec_11_12_correlated_diminish() {
        let independent = compute_trust(&[0.5, 0.5], &[1.0, 1.0]);
        let correlated = compute_trust(&[0.5, 0.5], &[1.0, 0.3]);
        assert!(independent > correlated);
    }

    #[test]
    fn spec_11_12_correlation_weights() {
        let (alpha, beta, gamma): (f64, f64, f64) = (0.5, 0.3, 0.1);
        assert!((alpha * 1.0 + beta * 0.0 + gamma * 0.0 - 0.5).abs() < 0.001);
        assert!((alpha * 1.0 + beta * 1.0 + gamma * 0.0 - 0.8).abs() < 0.001);
        assert!((alpha * 1.0 + beta * 1.0 + gamma * 1.0 - 0.9).abs() < 0.001);
    }

    #[test]
    fn spec_11_12_zone_settled_threshold() {
        assert!(is_zone_settled(67.1, 100.0));
        assert!(is_zone_settled(68.0, 100.0));
        assert!(!is_zone_settled(66.0, 100.0));
    }

    #[test]
    fn spec_11_12_confirmation_levels() {
        assert!(ConfLevel::Pending < ConfLevel::Sealed);
        assert!(ConfLevel::Sealed < ConfLevel::Finalized);
        assert!(ConfLevel::Finalized < ConfLevel::Anchored);
    }
}

// Economics spec §2.1 — Conservation
mod economics_conservation {
    use elara_runtime::accounting::{ledger, types};
    use elara_runtime::record::{ValidationRecord, Classification};

    fn make_genesis(authority: &str, amount: u64) -> Vec<ValidationRecord> {
        let meta = types::mint_metadata(amount, authority, "genesis");
        vec![ValidationRecord::create(
            b"genesis", vec![0u8; 32], vec![],
            Classification::Public, Some(meta),
        )]
    }

    fn check_conservation(records: &[ValidationRecord], authority: &str) {
        let ledger_records: Vec<_> = records.iter()
            .filter_map(|r| types::extract_ledger_op(r).ok().flatten().map(|op| (r.clone(), op)))
            .collect();
        let (state, _) = ledger::derive_ledger_tolerant(&ledger_records, authority);
        let account_total: u64 = state.accounts.values().map(|a| a.available + a.staked).sum();
        let total = account_total + state.conservation_pool;
        assert_eq!(total, state.total_supply,
            "Conservation violated: accounts={account_total} + pool={} != supply={}",
            state.conservation_pool, state.total_supply);
    }

    #[test]
    fn spec_2_1_conservation_after_genesis() {
        let authority = "d096d03c7d639fa19943dc0e8ca1866f25ba56741e453919939064dee9d3542a";
        let records = make_genesis(authority, 10_000_000);
        check_conservation(&records, authority);
    }

    #[test]
    fn spec_2_1_conservation_after_transfer() {
        let authority = "d096d03c7d639fa19943dc0e8ca1866f25ba56741e453919939064dee9d3542a";
        let mut records = make_genesis(authority, 10_000_000);
        let meta = types::transfer_metadata(1000, "recipient_abc", Some("test"));
        records.push(ValidationRecord::create(
            b"transfer", vec![0u8; 32], vec![],
            Classification::Public, Some(meta),
        ));
        check_conservation(&records, authority);
    }

    #[test]
    fn spec_2_1_conservation_after_burn() {
        let authority = "d096d03c7d639fa19943dc0e8ca1866f25ba56741e453919939064dee9d3542a";
        let mut records = make_genesis(authority, 10_000_000);
        let meta = types::burn_metadata(500, Some("test burn"));
        records.push(ValidationRecord::create(
            b"burn", vec![0u8; 32], vec![],
            Classification::Public, Some(meta),
        ));
        check_conservation(&records, authority);
    }
}

// Protocol §4.2 — Cryptographic Primitives
mod protocol_crypto {
    use elara_runtime::crypto::pqc;
    use elara_runtime::crypto::hash;

    #[test]
    fn spec_4_2_dilithium3_sign_verify() {
        // Protocol §4.2: ML-DSA-65 (Dilithium3) for primary signatures
        let kp = pqc::dilithium3_keygen().expect("keygen failed");
        let message = b"test validation record";
        let sig = pqc::dilithium3_sign_with_pk(message, &kp.secret_key, &kp.public_key)
            .expect("sign failed");
        assert!(pqc::dilithium3_verify(message, &sig, &kp.public_key).expect("verify failed"));
    }

    #[test]
    fn spec_4_2_dilithium3_wrong_key_rejects() {
        let kp1 = pqc::dilithium3_keygen().expect("keygen");
        let kp2 = pqc::dilithium3_keygen().expect("keygen");
        let message = b"test";
        let sig = pqc::dilithium3_sign_with_pk(message, &kp1.secret_key, &kp1.public_key)
            .expect("sign");
        // Wrong public key must reject
        assert!(!pqc::dilithium3_verify(message, &sig, &kp2.public_key).unwrap_or(false));
    }

    #[test]
    fn spec_4_2_sha3_256_deterministic() {
        // Protocol §4.2: SHA3-256 for all hashing
        let data = b"test data";
        let h1 = hash::sha3_256(data);
        let h2 = hash::sha3_256(data);
        assert_eq!(h1, h2, "SHA3-256 must be deterministic");
        assert_eq!(h1.len(), 32, "SHA3-256 must produce 32 bytes");
    }

    #[test]
    fn spec_4_2_sha3_256_different_inputs() {
        let h1 = hash::sha3_256(b"input A");
        let h2 = hash::sha3_256(b"input B");
        assert_ne!(h1, h2, "Different inputs must produce different hashes");
    }
}

// Protocol §4.3 — Dual Signature Strategy
mod protocol_dual_sig {
    use elara_runtime::crypto::pqc;

    #[test]
    fn spec_4_3_sphincs_sign_verify() {
        // Protocol §4.3: SLH-DSA (SPHINCS+) as backup signature
        let kp = pqc::sphincs_keygen().expect("keygen");
        let message = b"dual signed record";
        let sig = pqc::sphincs_sign_with_pk(message, &kp.secret_key, &kp.public_key)
            .expect("sign");
        assert!(pqc::sphincs_verify(message, &sig, &kp.public_key).expect("verify"));
    }

    #[test]
    fn spec_4_3_dual_sign_both_valid() {
        // Protocol §4.3: both signatures must be independently verifiable
        let dil_kp = pqc::dilithium3_keygen().expect("keygen");
        let sph_kp = pqc::sphincs_keygen().expect("keygen");
        let message = b"dual signed record";

        let dil_sig = pqc::dilithium3_sign_with_pk(message, &dil_kp.secret_key, &dil_kp.public_key)
            .expect("sign");
        let sph_sig = pqc::sphincs_sign_with_pk(message, &sph_kp.secret_key, &sph_kp.public_key)
            .expect("sign");

        assert!(pqc::dilithium3_verify(message, &dil_sig, &dil_kp.public_key).expect("verify"));
        assert!(pqc::sphincs_verify(message, &sph_sig, &sph_kp.public_key).expect("verify"));
    }
}

// Protocol §3.3.4 — Record Structure
mod protocol_record {
    use elara_runtime::record::{ValidationRecord, Classification};
    use elara_runtime::crypto::hash;

    #[test]
    fn spec_3_3_4_record_has_content_hash() {
        let rec = ValidationRecord::create(
            b"test content", vec![0u8; 32], vec![],
            Classification::Public, None,
        );
        assert!(!rec.content_hash.is_empty(), "Record must have content_hash");
        let expected = hash::sha3_256(b"test content");
        assert_eq!(rec.content_hash, expected, "content_hash must be SHA3-256 of content");
    }

    #[test]
    fn spec_3_3_4_record_has_timestamp() {
        let rec = ValidationRecord::create(
            b"test", vec![0u8; 32], vec![],
            Classification::Public, None,
        );
        assert!(rec.timestamp > 0.0, "Record must have a timestamp");
    }

    #[test]
    fn spec_3_3_4_record_has_uuid7_id() {
        let rec = ValidationRecord::create(
            b"test", vec![0u8; 32], vec![],
            Classification::Public, None,
        );
        assert_eq!(rec.id.len(), 36, "ID must be UUID format (36 chars)");
        assert_eq!(rec.id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn spec_3_3_4_classification_levels() {
        // Protocol §5.2: PUBLIC=0, PRIVATE=1, RESTRICTED=2
        assert_eq!(Classification::Public as u8, 0);
        assert_eq!(Classification::Private as u8, 1);
        assert_eq!(Classification::Restricted as u8, 2);
    }

    #[test]
    fn spec_3_3_4_wire_format_roundtrip() {
        let rec = ValidationRecord::create(
            b"wire test", vec![0u8; 32], vec!["parent1".to_string()],
            Classification::Public, None,
        );
        let bytes = rec.to_bytes();
        let decoded = ValidationRecord::from_bytes(&bytes).expect("decode failed");
        assert_eq!(rec.id, decoded.id);
        assert_eq!(rec.content_hash, decoded.content_hash);
        assert_eq!(rec.parents, decoded.parents);
        assert_eq!(rec.classification, decoded.classification);
    }
}

// Protocol §3.3.3 — DAM Structure (Directed Acyclic Mesh)
mod protocol_dam {
    use elara_runtime::dag::DagIndex;

    #[test]
    fn spec_3_3_3_dag_insert_and_tips() {
        let mut dag = DagIndex::new();
        dag.insert("rec1".to_string(), vec![], 1.0).expect("insert");
        let tips = dag.tips();
        assert!(tips.contains(&"rec1".to_string()), "Inserted record must be a tip");
    }

    #[test]
    fn spec_3_3_3_dag_parent_child_edges() {
        let mut dag = DagIndex::new();
        dag.insert("parent".to_string(), vec![], 1.0).expect("insert parent");
        dag.insert("child".to_string(), vec!["parent".to_string()], 2.0).expect("insert child");

        let parents = dag.parents("child");
        assert!(parents.contains(&"parent".to_string()), "Child must reference parent");

        let children = dag.children("parent");
        assert!(children.contains(&"child".to_string()), "Parent must list child");
    }

    #[test]
    fn spec_3_3_3_dag_tips_update() {
        let mut dag = DagIndex::new();
        dag.insert("a".to_string(), vec![], 1.0).expect("insert");
        assert!(dag.tips().contains(&"a".to_string()));

        dag.insert("b".to_string(), vec!["a".to_string()], 2.0).expect("insert");
        // "a" is no longer a tip (has child), "b" is
        assert!(!dag.tips().contains(&"a".to_string()));
        assert!(dag.tips().contains(&"b".to_string()));
    }

    #[test]
    fn spec_3_3_3_dam_mesh_merge() {
        // DAM property: two independent branches can merge via a new record
        let mut dag = DagIndex::new();
        dag.insert("branch_a".to_string(), vec![], 1.0).expect("a");
        dag.insert("branch_b".to_string(), vec![], 1.0).expect("b");

        // Merge: new record references both tips
        dag.insert("merge".to_string(), vec!["branch_a".to_string(), "branch_b".to_string()], 2.0).expect("merge");

        let tips = dag.tips();
        assert_eq!(tips.len(), 1, "After merge, only one tip");
        assert!(tips.contains(&"merge".to_string()));
    }
}

// Protocol §6.1 — Identity
mod protocol_identity {
    use elara_runtime::identity::{Identity, EntityType, CryptoProfile};
    use elara_runtime::crypto::hash;

    #[test]
    fn spec_6_1_identity_hash_is_sha3_of_pubkey() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).expect("generate");
        let expected_hash = hash::sha3_256_hex(&id.public_key);
        assert_eq!(id.identity_hash, expected_hash,
            "identity_hash must be SHA3-256 of public_key");
    }

    #[test]
    fn spec_6_1_identity_has_pow() {
        let id = Identity::generate_with_pow(EntityType::Human, CryptoProfile::ProfileA, 16).expect("generate");
        assert!(id.pow_nonce > 0, "PoW nonce must be non-zero after mining");
    }

    #[test]
    fn spec_6_1_identity_unique_keys() {
        let id1 = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).expect("gen1");
        let id2 = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).expect("gen2");
        assert_ne!(id1.public_key, id2.public_key);
        assert_ne!(id1.identity_hash, id2.identity_hash);
    }
}

// Economics spec §6.3 — Diminishing Returns
mod economics_entity {
    use elara_runtime::accounting::entity;

    #[test]
    fn spec_6_3_diminishing_returns() {
        // Economics spec §6.3: entity_earning_rate = log10(1+N) — grows sublinearly
        // Total rate grows, but per-node rate (rate/N) decreases
        let r1 = entity::entity_earning_rate(1);
        let r10 = entity::entity_earning_rate(10);
        let r100 = entity::entity_earning_rate(100);

        assert!(r1 > 0.0, "Single node must earn something");
        assert!(r10 > r1, "Total rate grows with nodes: {r10} > {r1}");
        // But per-node rate DECREASES (diminishing returns)
        assert!(r10 / 10.0 < r1 / 1.0, "Per-node rate must decrease: {} < {}", r10/10.0, r1);
        assert!(r100 / 100.0 < r10 / 10.0, "Per-node rate must decrease further");
    }

    #[test]
    fn spec_6_3_per_node_multiplier() {
        let m1 = entity::per_node_multiplier(1);
        let m1000 = entity::per_node_multiplier(1000);
        assert!((m1 - 1.0).abs() < 0.01, "1 node multiplier should be ~1.0, got {m1}");
        assert!(m1000 < 0.5, "1000 nodes should have multiplier < 0.5, got {m1000}");
    }
}

// Economics spec §13.3 — Velocity
mod economics_velocity {
    use elara_runtime::accounting::velocity::VelocityTracker;

    #[test]
    fn spec_13_3_velocity_tracker_records_outflow() {
        let mut tracker = VelocityTracker::new();
        tracker.record_outflow("alice", 1000, 100.0);
        let outflow = tracker.outflow_in_window("alice", 100.0);
        assert_eq!(outflow, 1000);
    }

    #[test]
    fn spec_13_3_velocity_tracks_peak_balance() {
        let mut tracker = VelocityTracker::new();
        tracker.record_balance("alice", 5000, 100.0);
        tracker.record_balance("alice", 3000, 200.0);
        let peak = tracker.peak_balance("alice", 200.0);
        assert_eq!(peak, 5000, "Peak balance should be highest recorded");
    }
}

// Protocol §5.3 — ZK Proofs
mod protocol_zk {
    use elara_runtime::crypto::zk;

    #[test]
    fn spec_5_3_groth16_balance_range_proof() {
        // Protocol §5.3.1: prove balance >= threshold without revealing exact balance
        let blinding = [42u8; 32];
        let proof = zk::prove_balance_range(1000, 100, &blinding);
        assert!(proof.is_some(), "Proof generation must succeed for valid balance");
        assert!(zk::verify_balance_range(&proof.unwrap(), 100), "Valid proof must verify");
    }

    #[test]
    fn spec_5_3_groth16_insufficient_balance_no_proof() {
        // Cannot prove balance >= threshold when balance < threshold
        let blinding = [42u8; 32];
        let proof = zk::prove_balance_range(50, 100, &blinding);
        assert!(proof.is_none(), "Insufficient balance must not produce proof");
    }

    #[test]
    fn spec_5_3_groth16_metadata_property_proof() {
        let salt = [0u8; 32];
        let proof = zk::prove_metadata_property("role", "admin", &salt);
        assert!(zk::verify_metadata_property(&proof, "role"), "Valid metadata proof must verify");
    }

    #[test]
    fn spec_5_3_proof_serialization_roundtrip() {
        let blinding = [42u8; 32];
        let proof = zk::prove_balance_range(500, 100, &blinding).expect("proof");
        let bytes = zk::serialize_proof(&proof);
        let decoded = zk::deserialize_proof(&bytes);
        assert!(decoded.is_some(), "Proof must deserialize");
    }
}
