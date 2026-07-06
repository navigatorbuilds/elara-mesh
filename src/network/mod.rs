//! Network daemon — P2P node for the Elara Protocol.
//!
//! All code in this module is feature-gated behind `node`.
//! The PyO3 cdylib never compiles any of this.

/// Extension trait: recover from mutex poisoning instead of panicking.
///
/// In a multi-threaded node, if any background task panics while holding
/// a lock, the poisoned lock must NOT cascade-crash the entire node.
/// `into_inner()` recovers the guarded data — the data is still valid,
/// only the thread that panicked is gone.
pub trait LockRecover<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockRecover<T> for std::sync::Mutex<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Extension trait: recover from RwLock poisoning instead of panicking.
pub trait RwLockRecover<T> {
    fn read_recover(&self) -> std::sync::RwLockReadGuard<'_, T>;
    fn write_recover(&self) -> std::sync::RwLockWriteGuard<'_, T>;
}

impl<T> RwLockRecover<T> for std::sync::RwLock<T> {
    fn read_recover(&self) -> std::sync::RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|e| e.into_inner())
    }
    fn write_recover(&self) -> std::sync::RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|e| e.into_inner())
    }
}

pub mod admin_pq_auth;
pub mod aggregator;
pub mod zone_rtt;
pub mod peer_rtt;
pub mod asn_lookup;
pub mod geo_fraud;
pub mod auto_scale;
pub mod auto_witness;
pub mod config;
pub mod consensus;
pub mod cross_zone_trust;
pub mod realm;
pub mod conflict_proof;
pub mod liveness_proof;
pub mod finalized;
pub mod dispute;
pub mod drand_fetch;
pub mod emergency_node;
pub mod epoch;
pub mod fisherman;
pub mod fork;
pub mod gc;
pub mod identity_fetcher;
pub mod record_hash_fetcher;
pub mod ingest;
pub mod low_stake_replay;
pub mod pending_drain;
pub mod key_rotation;
pub mod vrf_registry;
pub mod liveness;
pub mod health;
pub mod light;
pub mod light_sdk;
pub mod mandate_node;
pub mod merkle;
pub mod account_merkle;
pub mod node_profile;
pub mod powas;
pub mod protocol_upgrade;
pub mod publish;
pub mod reputation;
pub mod reward;
pub mod routes;
pub mod server;
pub mod slashing;
pub mod state;
pub mod state_core;
pub mod sunset;
pub mod system_load;
pub mod tip_merge;
pub mod timestamp_defense;
pub mod time_bracket;
pub mod snapshot;
pub mod witness;
// /ws Slice 3c: `pub mod ws;` removed — the legacy JSON-over-WebSocket
// route is gone. All browser traffic rides /pq-ws via ELPQ now.
pub mod zone;
pub mod zone_persist;
pub mod zone_purge;
pub mod zone_subscription;
pub mod zone_transition_seal;
pub mod zone_registry;
pub mod zone_committee;
pub mod transition_store;

// `dht` was extracted to the standalone `elara-dht` crate (MIT/Apache).
// Re-exported here so existing `crate::network::dht::*` paths keep resolving.
pub use elara_dht as dht;
pub mod discovery;
pub mod gossip;
pub mod seal_replication_reconciler;
pub mod mdns;
// `nat` was extracted to the standalone `elara-nat` crate (MIT/Apache).
// Re-exported so existing `crate::network::nat::*` paths keep resolving.
pub use elara_nat as nat;
pub mod peer;
pub mod peer_bandwidth;
pub mod pq_client;
pub mod pq_server;
pub mod pq_transport;
pub mod probe;
pub mod sync;
pub mod xzone_demotion_probe;

#[cfg(test)]
mod tests {
    use super::{LockRecover, RwLockRecover};
    use std::sync::{Arc, Mutex, RwLock};
    use std::thread;

    // ── LockRecover (std::sync::Mutex) ──────────────────────────────

    /// Happy path: `lock_recover()` on a clean Mutex returns the data
    /// the same way `lock().unwrap()` would. Pins the no-poison branch
    /// of the `unwrap_or_else` so a future refactor can't silently
    /// switch to a default-value-on-clean path.
    #[test]
    fn lock_recover_clean_mutex_returns_inner_data() {
        let m = Mutex::new(42u64);
        assert_eq!(*m.lock_recover(), 42);
        *m.lock_recover() = 99;
        assert_eq!(*m.lock_recover(), 99);
    }

    /// Poison-recovery path: a background thread panics while holding
    /// the Mutex, which poisons it. The docstring at mod.rs:6-11 says
    /// the data is still valid and the node must not cascade-crash.
    /// This test pins that exact contract — `lock_recover()` MUST
    /// return the guarded data after poisoning (not panic, not lose
    /// the value the panicking thread wrote before exiting).
    #[test]
    fn lock_recover_poisoned_mutex_returns_inner_data() {
        let m = Arc::new(Mutex::new(7u64));
        let m_clone = Arc::clone(&m);
        // Background thread acquires the lock, writes a new value,
        // then panics — poisoning the Mutex with `8` as the inner value.
        let _ = thread::spawn(move || {
            let mut guard = m_clone.lock().unwrap();
            *guard = 8;
            panic!("intentional poison for test");
        })
        .join();
        // Sanity: confirm the Mutex really is poisoned (otherwise the
        // test would silently pass via the clean path and we'd never
        // actually exercise `unwrap_or_else`).
        assert!(m.is_poisoned(), "test setup: Mutex should be poisoned");
        // The contract: lock_recover() returns the guarded data even
        // when the std API `lock()` would error.
        assert_eq!(*m.lock_recover(), 8);
    }

    // ── RwLockRecover (std::sync::RwLock) ───────────────────────────

    /// Poison-recovery on the read path. Same setup as the Mutex test:
    /// poison the RwLock via a panicking writer, then verify
    /// `read_recover()` returns the data instead of panicking.
    #[test]
    fn read_recover_poisoned_rwlock_returns_inner_data() {
        let r = Arc::new(RwLock::new(11u64));
        let r_clone = Arc::clone(&r);
        let _ = thread::spawn(move || {
            let mut guard = r_clone.write().unwrap();
            *guard = 12;
            panic!("intentional poison for test");
        })
        .join();
        assert!(r.is_poisoned(), "test setup: RwLock should be poisoned");
        assert_eq!(*r.read_recover(), 12);
    }

    /// Poison-recovery on the write path. Pinning the write side
    /// separately matters because `RwLock::write()` and `read()`
    /// return distinct guard types and the `unwrap_or_else` lives on
    /// each method independently — a regression could silently break
    /// only one.
    #[test]
    fn write_recover_poisoned_rwlock_returns_inner_data_and_allows_mutation() {
        let r = Arc::new(RwLock::new(20u64));
        let r_clone = Arc::clone(&r);
        let _ = thread::spawn(move || {
            let mut guard = r_clone.write().unwrap();
            *guard = 21;
            panic!("intentional poison for test");
        })
        .join();
        assert!(r.is_poisoned(), "test setup: RwLock should be poisoned");
        // Recover, then mutate — pinning that the recovered guard is
        // a fully-functional WriteGuard, not a read-only fallback.
        {
            let mut g = r.write_recover();
            assert_eq!(*g, 21);
            *g = 22;
        }
        assert_eq!(*r.read_recover(), 22);
    }

    // ─── symmetric & cross-type recovery ───────────

    /// Clean (non-poisoned) read_recover happy-path. Existing tests only pin
    /// the poisoned branch of RwLock read; the unwrap_or_else fall-through
    /// to `.read()` must still return the data on a clean lock.
    #[test]
    fn batch_b_read_recover_clean_rwlock_returns_inner_data() {
        let r = RwLock::new(50u64);
        assert_eq!(*r.read_recover(), 50);
        // Two concurrent read guards on a clean RwLock — clean read path must
        // not block when no writer holds it.
        let g1 = r.read_recover();
        let g2 = r.read_recover();
        assert_eq!(*g1, 50);
        assert_eq!(*g2, 50);
    }

    /// Clean (non-poisoned) write_recover happy-path with mutation.
    /// Symmetric to `lock_recover_clean_mutex_returns_inner_data` but pins
    /// the RwLock write side, which has its own unwrap_or_else branch.
    #[test]
    fn batch_b_write_recover_clean_rwlock_returns_inner_data_and_allows_mutation() {
        let r = RwLock::new(60u64);
        {
            let mut g = r.write_recover();
            assert_eq!(*g, 60);
            *g = 70;
        }
        assert_eq!(*r.read_recover(), 70);
        // Multiple sequential writes must each round-trip via read_recover
        *r.write_recover() = 80;
        assert_eq!(*r.read_recover(), 80);
    }

    /// Poison is a sticky property of the lock — once poisoned, every
    /// subsequent acquire goes through the `unwrap_or_else` recovery branch.
    /// Pin that repeated lock_recover() calls after poison continue to
    /// return the latest value, AND that mutations through the recovered
    /// guard persist across subsequent recoveries.
    #[test]
    fn batch_b_lock_recover_idempotent_across_repeated_calls_after_poison() {
        let m = Arc::new(Mutex::new(100u64));
        let m_clone = Arc::clone(&m);
        let _ = thread::spawn(move || {
            let mut guard = m_clone.lock().unwrap();
            *guard = 200;
            panic!("intentional poison for test");
        })
        .join();
        assert!(m.is_poisoned());

        // First recovery
        assert_eq!(*m.lock_recover(), 200);
        // Second recovery — same value, lock still poisoned
        assert_eq!(*m.lock_recover(), 200);
        assert!(m.is_poisoned(), "poison must remain sticky across recovers");

        // Mutate via recovered guard
        *m.lock_recover() = 300;
        // Third recovery sees the new value
        assert_eq!(*m.lock_recover(), 300);
        assert!(m.is_poisoned(), "poison still sticky after mutation");
    }

    /// Recovery must preserve non-Copy heap-allocated payloads (String).
    /// A regression where unwrap_or_else accidentally invokes Default could
    /// silently zero a String to "" — pin that the mutation written by the
    /// panicking thread survives intact.
    #[test]
    fn batch_b_lock_recover_preserves_non_copy_string_payload_across_poison() {
        let m = Arc::new(Mutex::new(String::from("initial")));
        let m_clone = Arc::clone(&m);
        let _ = thread::spawn(move || {
            let mut guard = m_clone.lock().unwrap();
            guard.push_str(" then panic");
            panic!("intentional poison for test");
        })
        .join();
        assert!(m.is_poisoned());
        let recovered = m.lock_recover();
        assert_eq!(*recovered, "initial then panic", "non-Copy payload must survive");
    }

    /// Recovery must work for complex payloads beyond plain primitives —
    /// Vec<u8> (heap, growable) and a user struct. Pin both via RwLock to
    /// stress the read+write paths together.
    #[test]
    fn batch_b_rwlock_recover_handles_complex_vec_and_struct_payloads() {
        // Vec<u8> payload
        let r_vec = Arc::new(RwLock::new(vec![1u8, 2, 3]));
        let r_vec_clone = Arc::clone(&r_vec);
        let _ = thread::spawn(move || {
            let mut g = r_vec_clone.write().unwrap();
            g.push(4);
            g.push(5);
            panic!("intentional poison for test");
        })
        .join();
        assert!(r_vec.is_poisoned());
        assert_eq!(*r_vec.read_recover(), vec![1u8, 2, 3, 4, 5]);

        // Custom struct payload
        #[derive(Debug, PartialEq)]
        struct Payload {
            counter: u32,
            label: String,
        }
        let m = Arc::new(Mutex::new(Payload { counter: 0, label: "start".into() }));
        let m_clone = Arc::clone(&m);
        let _ = thread::spawn(move || {
            let mut g = m_clone.lock().unwrap();
            g.counter = 42;
            g.label = "panic-time".into();
            panic!("intentional poison for test");
        })
        .join();
        assert!(m.is_poisoned());
        let g = m.lock_recover();
        assert_eq!(g.counter, 42);
        assert_eq!(g.label, "panic-time");
    }
}
