//! Cryptographic identity management — Dilithium3 + SPHINCS+ keypairs.

//!
//! Spec references:
//!   @spec Protocol §4.6
//!   @spec Protocol §6.1
//!   @spec Protocol §6.2 (EntityType: HUMAN/AI/DEVICE/ORGANIZATION/COMPOSITE)

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

use crate::crypto::hash::{sha3_256, sha3_256_hex};
use crate::crypto::pqc::{
    dilithium3_keygen, dilithium3_sign_with_pk, dilithium3_verify, sphincs_keygen, sphincs_sign_with_pk,
    sphincs_verify,
};
use crate::errors::{ElaraError, Result};

/// Default PoW difficulty — number of leading zero bits required.
/// SHA3-256(public_key || nonce_le_bytes) must have this many leading zeros.
/// 20 bits ≈ 1M average attempts ≈ ~2-5 min on phone, ~30s on desktop.
/// Increased from 16 bits (16-bit = 86K sybil identities/day on GPU).
pub const DEFAULT_POW_DIFFICULTY: u8 = 20;

/// Maximum allowed difficulty (prevents absurd mining times).
pub const MAX_POW_DIFFICULTY: u8 = 32;

/// Adaptive PoW: rate window in seconds (1 hour).
pub const RATE_WINDOW_SECS: f64 = 3600.0;

/// Adaptive PoW: identity creation threshold per subnet per hour.
/// If a subnet exceeds this, difficulty doubles.
pub const SUBNET_RATE_THRESHOLD: usize = 100;

/// Adaptive PoW: global identity creation threshold per hour.
/// If the entire network exceeds this rate, difficulty increases by +4 bits.
/// At 20 bits base, +4 → 24 bits ≈ 16M attempts ≈ ~30-60 min on phone.
/// Prevents distributed Sybil attacks across many subnets.
pub const GLOBAL_RATE_THRESHOLD: usize = 500;

// ─── Adaptive PoW Difficulty Tracker ─────────────────────────────────────

/// Tracks identity creation rate per subnet AND globally, returns adaptive
/// PoW difficulty.
///
/// - Per-subnet: >100 identities/hour → difficulty doubles
/// - Global: >500 identities/hour → difficulty +4 bits
/// - Both penalties stack (capped at `MAX_POW_DIFFICULTY`)
pub struct SubnetRateTracker {
    /// Subnet prefix → timestamps of identity creations within the window.
    creation_times: HashMap<String, VecDeque<f64>>,
    /// Global identity creation timestamps within the window.
    global_times: VecDeque<f64>,
    /// Base difficulty (usually `DEFAULT_POW_DIFFICULTY`).
    base_difficulty: u8,
}

impl SubnetRateTracker {
    /// Create a new tracker with the given base difficulty.
    pub fn new(base_difficulty: u8) -> Self {
        Self {
            creation_times: HashMap::new(),
            global_times: VecDeque::new(),
            base_difficulty,
        }
    }

    /// Prune timestamps older than `RATE_WINDOW_SECS` from the front of the deque.
    fn prune(&mut self, subnet: &str, now: f64) {
        if let Some(times) = self.creation_times.get_mut(subnet) {
            let cutoff = now - RATE_WINDOW_SECS;
            while times.front().is_some_and(|&t| t < cutoff) {
                times.pop_front();
            }
        }
    }

    /// Prune global timestamps older than the rate window.
    fn prune_global(&mut self, now: f64) {
        let cutoff = now - RATE_WINDOW_SECS;
        while self.global_times.front().is_some_and(|&t| t < cutoff) {
            self.global_times.pop_front();
        }
    }

    /// Record an identity creation from `subnet` at time `now`.
    /// Returns the adaptive difficulty that should be required for the *next*
    /// identity from this subnet.
    pub fn record_creation(&mut self, subnet: &str, now: f64) -> u8 {
        self.prune(subnet, now);
        let times = self.creation_times.entry(subnet.to_owned()).or_default();
        times.push_back(now);

        self.prune_global(now);
        self.global_times.push_back(now);

        self.difficulty_for_subnet(subnet, now)
    }

    /// Current adaptive difficulty for a subnet (does NOT record a creation).
    pub fn difficulty_for_subnet(&mut self, subnet: &str, now: f64) -> u8 {
        self.prune(subnet, now);
        self.prune_global(now);

        let subnet_count = self
            .creation_times
            .get(subnet)
            .map_or(0, |t| t.len());
        let global_count = self.global_times.len();

        let mut difficulty = self.base_difficulty;

        // Per-subnet penalty: double difficulty
        if subnet_count > SUBNET_RATE_THRESHOLD {
            difficulty = difficulty.saturating_mul(2);
        }

        // Global penalty: +4 bits (16× harder)
        if global_count > GLOBAL_RATE_THRESHOLD {
            difficulty = difficulty.saturating_add(4);
        }

        difficulty.min(MAX_POW_DIFFICULTY)
    }

    /// Number of identity creations for `subnet` within the current window.
    pub fn subnet_count(&mut self, subnet: &str, now: f64) -> usize {
        self.prune(subnet, now);
        self.creation_times.get(subnet).map_or(0, |t| t.len())
    }

    /// Total identity creations across all subnets within the current window.
    pub fn global_count(&mut self, now: f64) -> usize {
        self.prune_global(now);
        self.global_times.len()
    }
}

/// Entity types from Protocol Whitepaper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    #[serde(rename = "HUMAN")]
    Human,
    #[serde(rename = "AI")]
    Ai,
    #[serde(rename = "DEVICE")]
    Device,
    #[serde(rename = "ORGANIZATION")]
    Organization,
    #[serde(rename = "COMPOSITE")]
    Composite,
}

/// Cryptographic profiles from Protocol Whitepaper, Section 4.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoProfile {
    /// Full PQC: Dilithium3 + SPHINCS+
    #[serde(rename = "A")]
    ProfileA,
    /// Compact PQC: Dilithium3 only, no dual sig
    #[serde(rename = "B")]
    ProfileB,
    /// Gateway-delegated (not implemented in Layer 1)
    #[serde(rename = "C")]
    ProfileC,
}

/// Device attestation levels (Protocol §8, §11.33).
///
/// Indicates the hardware security backing an identity's key storage.
/// Higher levels provide stronger trust guarantees. Affects trust score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub enum AttestationLevel {
    /// Software-only key storage. No hardware protection.
    #[serde(rename = "NONE")]
    #[default]
    None,
    /// OS-level attestation (Android Keystore, iOS Secure Enclave).
    #[serde(rename = "SOFTWARE")]
    Software,
    /// Verified boot chain attestation.
    #[serde(rename = "SECURE_BOOT")]
    SecureBoot,
    /// TPM/HSM-bound key storage.
    #[serde(rename = "HARDWARE_KEY")]
    HardwareKey,
    /// Physically unclonable function — strongest hardware guarantee.
    #[serde(rename = "PUF")]
    Puf,
}

impl AttestationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Software => "SOFTWARE",
            Self::SecureBoot => "SECURE_BOOT",
            Self::HardwareKey => "HARDWARE_KEY",
            Self::Puf => "PUF",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "NONE" | "none" => Some(Self::None),
            "SOFTWARE" | "software" => Some(Self::Software),
            "SECURE_BOOT" | "secure_boot" => Some(Self::SecureBoot),
            "HARDWARE_KEY" | "hardware_key" => Some(Self::HardwareKey),
            "PUF" | "puf" => Some(Self::Puf),
            _ => Option::None,
        }
    }

    /// Trust multiplier for this attestation level.
    /// Higher levels give a trust boost.
    pub fn trust_multiplier(&self) -> f64 {
        match self {
            Self::None => 1.0,
            Self::Software => 1.1,
            Self::SecureBoot => 1.2,
            Self::HardwareKey => 1.4,
            Self::Puf => 1.5,
        }
    }

    /// Numeric rank (0-4) for comparisons and scoring.
    pub fn rank(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Software => 1,
            Self::SecureBoot => 2,
            Self::HardwareKey => 3,
            Self::Puf => 4,
        }
    }
}

/// An Elara Protocol identity — a self-sovereign cryptographic keypair.
///
/// Secret keys are zeroed from memory when the Identity is dropped,
/// preventing key material from persisting in memory or being swapped to disk.
#[derive(Debug, Clone)]
pub struct Identity {
    pub public_key: Vec<u8>,
    pub identity_hash: String,
    pub entity_type: EntityType,
    pub created: f64,
    pub algorithm: String,
    pub profile: CryptoProfile,
    /// PoW nonce — the value that makes the hash meet difficulty target.
    pub pow_nonce: u64,
    /// PoW difficulty — number of leading zero bits in SHA3-256(pk || nonce).
    pub pow_difficulty: u8,
    secret_key: Option<Vec<u8>>,
    sphincs_public_key: Option<Vec<u8>>,
    sphincs_secret_key: Option<Vec<u8>>,
}

impl Drop for Identity {
    fn drop(&mut self) {
        if let Some(ref mut sk) = self.secret_key {
            sk.zeroize();
        }
        if let Some(ref mut sk) = self.sphincs_secret_key {
            sk.zeroize();
        }
    }
}

/// Count leading zero bits in a byte slice (big-endian: MSB first).
/// Hash bytes are treated in network byte order — byte[0] is most significant.
/// This matches SHA3-256 output ordering and is the standard for PoW difficulty.
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Build the PoW preimage: public_key || nonce_le_bytes.
fn pow_preimage(public_key: &[u8], nonce: u64) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(public_key.len() + 8);
    preimage.extend_from_slice(public_key);
    preimage.extend_from_slice(&nonce.to_le_bytes());
    preimage
}

/// Mine a PoW nonce for a given public key and difficulty.
/// Returns (nonce, attempts) on success.
fn mine_pow(public_key: &[u8], difficulty: u8) -> (u64, u64) {
    let mut nonce: u64 = 0;
    loop {
        let preimage = pow_preimage(public_key, nonce);
        let hash = sha3_256(&preimage);
        if leading_zero_bits(&hash) >= difficulty as u32 {
            return (nonce, nonce + 1);
        }
        nonce += 1;
    }
}

impl Identity {
    /// Generate a new identity with fresh keypairs (no PoW — difficulty=0).
    /// Profile A generates both Dilithium3 and SPHINCS+ keypairs.
    pub fn generate(entity_type: EntityType, profile: CryptoProfile) -> Result<Self> {
        let dil_kp = dilithium3_keygen()?;

        let (sphincs_pk, sphincs_sk) = if profile == CryptoProfile::ProfileA {
            let sp_kp = sphincs_keygen()?;
            let (pk, sk) = sp_kp.into_parts();
            (Some(pk), Some(sk))
        } else {
            (None, None)
        };

        let (dil_pk, dil_sk) = dil_kp.into_parts();
        let identity_hash = sha3_256_hex(&dil_pk);
        let created = crate::record::now_timestamp();

        Ok(Self {
            public_key: dil_pk,
            identity_hash,
            entity_type,
            created,
            algorithm: "dilithium3".to_string(),
            profile,
            pow_nonce: 0,
            pow_difficulty: 0,
            secret_key: Some(dil_sk),
            sphincs_public_key: sphincs_pk,
            sphincs_secret_key: sphincs_sk,
        })
    }

    /// Generate a new identity with PoW anti-spam protection.
    /// Mines SHA3-256(public_key || nonce) until `difficulty` leading zero bits found.
    pub fn generate_with_pow(
        entity_type: EntityType,
        profile: CryptoProfile,
        difficulty: u8,
    ) -> Result<Self> {
        if difficulty > MAX_POW_DIFFICULTY {
            return Err(ElaraError::Crypto(format!(
                "PoW difficulty {difficulty} exceeds max {MAX_POW_DIFFICULTY}"
            )));
        }

        let dil_kp = dilithium3_keygen()?;

        let (sphincs_pk, sphincs_sk) = if profile == CryptoProfile::ProfileA {
            let sp_kp = sphincs_keygen()?;
            let (pk, sk) = sp_kp.into_parts();
            (Some(pk), Some(sk))
        } else {
            (None, None)
        };

        let (dil_pk, dil_sk) = dil_kp.into_parts();
        let (pow_nonce, _attempts) = mine_pow(&dil_pk, difficulty);

        let identity_hash = sha3_256_hex(&dil_pk);
        let created = crate::record::now_timestamp();

        Ok(Self {
            public_key: dil_pk,
            identity_hash,
            entity_type,
            created,
            algorithm: "dilithium3".to_string(),
            profile,
            pow_nonce,
            pow_difficulty: difficulty,
            secret_key: Some(dil_sk),
            sphincs_public_key: sphincs_pk,
            sphincs_secret_key: sphincs_sk,
        })
    }

    /// Verify the PoW on this identity. Returns true if difficulty=0 (no PoW)
    /// or if SHA3-256(public_key || nonce) has enough leading zero bits.
    pub fn verify_pow(&self) -> bool {
        if self.pow_difficulty == 0 {
            return true;
        }
        let preimage = pow_preimage(&self.public_key, self.pow_nonce);
        let hash = sha3_256(&preimage);
        leading_zero_bits(&hash) >= self.pow_difficulty as u32
    }

    /// Verify PoW for arbitrary key/nonce/difficulty (static, for peer validation).
    pub fn verify_pow_static(public_key: &[u8], nonce: u64, difficulty: u8) -> bool {
        if difficulty == 0 {
            return true;
        }
        let preimage = pow_preimage(public_key, nonce);
        let hash = sha3_256(&preimage);
        leading_zero_bits(&hash) >= difficulty as u32
    }

    /// Sign a message with Dilithium3.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = self
            .secret_key
            .as_ref()
            .ok_or_else(|| ElaraError::Crypto("no secret key (public identity)".into()))?;
        dilithium3_sign_with_pk(message, sk, &self.public_key)
    }

    /// Sign a message with SPHINCS+ (Profile A only).
    pub fn sign_sphincs(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = self
            .sphincs_secret_key
            .as_ref()
            .ok_or_else(|| ElaraError::Crypto("no SPHINCS+ key (Profile A only)".into()))?;
        let pk = self
            .sphincs_public_key
            .as_ref()
            .ok_or_else(|| ElaraError::Crypto("no SPHINCS+ public key".into()))?;
        sphincs_sign_with_pk(message, sk, pk)
    }

    /// Verify a Dilithium3 signature against a public key.
    pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        dilithium3_verify(message, signature, public_key).map_err(Into::into)
    }

    /// Verify a SPHINCS+ signature.
    pub fn verify_sphincs(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        sphincs_verify(message, signature, public_key).map_err(Into::into)
    }

    /// Dual-sign a message: Dilithium3 always, plus SPHINCS+ if Profile A.
    /// Returns (dilithium_sig, Option<sphincs_sig>).
    pub fn dual_sign(&self, message: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        let dil_sig = self.sign(message)?;
        let sphincs_sig = if self.profile == CryptoProfile::ProfileA {
            Some(self.sign_sphincs(message)?)
        } else {
            None
        };
        Ok((dil_sig, sphincs_sig))
    }

    /// Sign a ValidationRecord with appropriate signatures for this identity's profile.
    /// Profile A: Dilithium3 + SPHINCS+ (dual-sig) + sets sphincs public key.
    /// Profile B/C: Dilithium3 only.
    pub fn sign_record(&self, record: &mut crate::record::ValidationRecord) -> Result<()> {
        let signable = record.signable_bytes();
        let (dil_sig, sphincs_sig) = self.dual_sign(&signable)?;
        record.signature = Some(dil_sig);
        record.sig_algorithm = crate::crypto::ALG_DILITHIUM3;
        record.sphincs_signature = sphincs_sig;
        if self.profile == CryptoProfile::ProfileA {
            record.creator_sphincs_pk = self.sphincs_public_key.clone();
            record.sphincs_algorithm = Some(crate::crypto::ALG_SPHINCS_SHA2_192F);
        }
        Ok(())
    }

    /// Sign a record in light mode: Dilithium3 only, stripping SPHINCS+ data.
    /// Produces a valid Profile B record regardless of this identity's profile.
    /// Wire size: ~5KB instead of ~41KB. Use for non-critical records on
    /// resource-constrained nodes.
    pub fn sign_record_light(&self, record: &mut crate::record::ValidationRecord) -> Result<()> {
        let signable = record.signable_bytes();
        record.signature = Some(self.sign(&signable)?);
        record.sig_algorithm = crate::crypto::ALG_DILITHIUM3;
        record.strip_sphincs();
        Ok(())
    }

    pub fn has_secret_key(&self) -> bool {
        self.secret_key.is_some()
    }

    /// Get the Dilithium3 secret key bytes (for PQ transport handshake).
    /// Returns empty vec if this is a public-only identity.
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.clone().unwrap_or_default()
    }

    pub fn sphincs_public_key(&self) -> Option<&[u8]> {
        self.sphincs_public_key.as_deref()
    }

    /// Return a copy without secret keys (safe to share).
    pub fn public_identity(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            identity_hash: self.identity_hash.clone(),
            entity_type: self.entity_type.clone(),
            created: self.created,
            algorithm: self.algorithm.clone(),
            profile: self.profile.clone(),
            pow_nonce: self.pow_nonce,
            pow_difficulty: self.pow_difficulty,
            secret_key: None,
            sphincs_public_key: self.sphincs_public_key.clone(),
            sphincs_secret_key: None,
        }
    }

    /// Save identity to JSON (compatible with Python's Identity.save()).
    pub fn to_json(&self) -> BTreeMap<String, serde_json::Value> {
        let mut data = BTreeMap::new();
        data.insert(
            "public_key".into(),
            serde_json::Value::String(hex::encode(&self.public_key)),
        );
        data.insert(
            "identity_hash".into(),
            serde_json::Value::String(self.identity_hash.clone()),
        );
        data.insert(
            "entity_type".into(),
            serde_json::json!(match &self.entity_type {
                EntityType::Human => "HUMAN",
                EntityType::Ai => "AI",
                EntityType::Device => "DEVICE",
                EntityType::Organization => "ORGANIZATION",
                EntityType::Composite => "COMPOSITE",
            }),
        );
        data.insert("created".into(), serde_json::json!(self.created));
        data.insert(
            "algorithm".into(),
            serde_json::Value::String(self.algorithm.clone()),
        );
        data.insert(
            "profile".into(),
            serde_json::json!(match &self.profile {
                CryptoProfile::ProfileA => "A",
                CryptoProfile::ProfileB => "B",
                CryptoProfile::ProfileC => "C",
            }),
        );
        data.insert("pow_nonce".into(), serde_json::json!(self.pow_nonce));
        data.insert(
            "pow_difficulty".into(),
            serde_json::json!(self.pow_difficulty),
        );
        if let Some(sk) = &self.secret_key {
            data.insert(
                "secret_key".into(),
                serde_json::Value::String(hex::encode(sk)),
            );
        }
        if let Some(spk) = &self.sphincs_public_key {
            data.insert(
                "sphincs_public_key".into(),
                serde_json::Value::String(hex::encode(spk)),
            );
        }
        if let Some(ssk) = &self.sphincs_secret_key {
            data.insert(
                "sphincs_secret_key".into(),
                serde_json::Value::String(hex::encode(ssk)),
            );
        }
        data
    }

    /// Load identity from JSON (compatible with Python's Identity.load()).
    pub fn from_json(data: &BTreeMap<String, serde_json::Value>) -> Result<Self> {
        let get_str = |key: &str| -> Result<String> {
            data.get(key)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| ElaraError::Crypto(format!("missing field: {key}")))
        };

        let public_key =
            hex::decode(get_str("public_key")?).map_err(|e| ElaraError::Crypto(e.to_string()))?;
        let identity_hash = get_str("identity_hash")?;
        let entity_type = match get_str("entity_type")?.as_str() {
            "HUMAN" => EntityType::Human,
            "AI" => EntityType::Ai,
            "DEVICE" => EntityType::Device,
            "ORGANIZATION" => EntityType::Organization,
            "COMPOSITE" => EntityType::Composite,
            other => {
                return Err(ElaraError::Crypto(format!(
                    "unknown entity type: {other}"
                )))
            }
        };
        let created = data
            .get("created")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| ElaraError::Crypto("missing created".into()))?;
        let algorithm = get_str("algorithm")?;
        let profile = match get_str("profile")?.as_str() {
            "A" => CryptoProfile::ProfileA,
            "B" => CryptoProfile::ProfileB,
            "C" => CryptoProfile::ProfileC,
            other => {
                return Err(ElaraError::Crypto(format!(
                    "unknown profile: {other}"
                )))
            }
        };

        // PoW fields — backwards-compatible, default to 0 for pre-PoW identities.
        let pow_nonce = data
            .get("pow_nonce")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let pow_difficulty = data
            .get("pow_difficulty")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        let secret_key = data
            .get("secret_key")
            .and_then(|v| v.as_str())
            .map(hex::decode)
            .transpose()
            .map_err(|e| ElaraError::Crypto(e.to_string()))?;

        let sphincs_public_key = data
            .get("sphincs_public_key")
            .and_then(|v| v.as_str())
            .map(hex::decode)
            .transpose()
            .map_err(|e| ElaraError::Crypto(e.to_string()))?;

        let sphincs_secret_key = data
            .get("sphincs_secret_key")
            .and_then(|v| v.as_str())
            .map(hex::decode)
            .transpose()
            .map_err(|e| ElaraError::Crypto(e.to_string()))?;

        Ok(Self {
            public_key,
            identity_hash,
            entity_type,
            created,
            algorithm,
            profile,
            pow_nonce,
            pow_difficulty,
            secret_key,
            sphincs_public_key,
            sphincs_secret_key,
        })
    }
}

// ─── Encrypted identity storage (AES-256-GCM + Argon2id) ─────────────────

/// Encrypted identity file format version.
pub const ENCRYPTED_FORMAT_V1: &str = "aes-256-gcm-argon2id-v1";

/// Argon2id parameters — 64 MiB memory, 3 iterations, 1 lane.
/// Balances security against startup latency (~0.5s on modern hardware).
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Derive a 256-bit encryption key from a passphrase using Argon2id.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| ElaraError::Crypto(format!("Argon2 params error: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| ElaraError::Crypto(format!("Argon2id key derivation failed: {e}")))?;
    Ok(key)
}

/// Encrypt a byte slice with AES-256-GCM. Returns nonce || ciphertext || tag.
fn encrypt_field(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ElaraError::Crypto(format!("AES-256-GCM init failed: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| ElaraError::Crypto(format!("nonce generation failed: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ElaraError::Crypto(format!("AES-256-GCM encryption failed: {e}")))?;

    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

/// Decrypt nonce || ciphertext || tag with AES-256-GCM.
fn decrypt_field(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    if data.len() < NONCE_LEN + 16 {
        return Err(ElaraError::Crypto("encrypted data too short".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ElaraError::Crypto(format!("AES-256-GCM init failed: {e}")))?;
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let plaintext = cipher
        .decrypt(nonce, &data[NONCE_LEN..])
        .map_err(|_| {
            ElaraError::Crypto(
                "decryption failed — wrong passphrase or corrupted data".into(),
            )
        })?;
    Ok(plaintext)
}

/// Check if an identity JSON uses the encrypted format.
pub fn is_encrypted_identity(data: &BTreeMap<String, serde_json::Value>) -> bool {
    data.contains_key("encryption") && data.contains_key("encrypted_secret_key")
}

impl Identity {
    /// Serialize to JSON with secret keys encrypted via AES-256-GCM + Argon2id.
    ///
    /// Public fields (public_key, identity_hash, profile, etc.) stay in cleartext
    /// so the node can identify itself without decryption. Only secret keys are
    /// encrypted.
    pub fn to_encrypted_json(
        &self,
        passphrase: &[u8],
    ) -> Result<BTreeMap<String, serde_json::Value>> {
        if passphrase.is_empty() {
            return Err(ElaraError::Crypto("passphrase must not be empty".into()));
        }

        // Start with public fields from to_json(), then replace secret keys
        let mut data = self.to_json();

        // Remove plaintext secret keys
        data.remove("secret_key");
        data.remove("sphincs_secret_key");

        // Generate salt and derive encryption key
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt)
            .map_err(|e| ElaraError::Crypto(format!("salt generation failed: {e}")))?;
        let key = derive_key(passphrase, &salt)?;

        // Encryption metadata
        let enc_meta = serde_json::json!({
            "format": ENCRYPTED_FORMAT_V1,
            "argon2_salt": hex::encode(salt),
            "argon2_m_cost": ARGON2_M_COST,
            "argon2_t_cost": ARGON2_T_COST,
            "argon2_p_cost": ARGON2_P_COST,
        });
        data.insert("encryption".into(), enc_meta);

        // Encrypt secret keys
        if let Some(sk) = &self.secret_key {
            let encrypted = encrypt_field(&key, sk)?;
            data.insert(
                "encrypted_secret_key".into(),
                serde_json::Value::String(hex::encode(&encrypted)),
            );
        }
        if let Some(ssk) = &self.sphincs_secret_key {
            let encrypted = encrypt_field(&key, ssk)?;
            data.insert(
                "encrypted_sphincs_secret_key".into(),
                serde_json::Value::String(hex::encode(&encrypted)),
            );
        }

        Ok(data)
    }

    /// Load identity from encrypted JSON format.
    ///
    /// Parses public fields from cleartext, then decrypts secret keys using
    /// the provided passphrase.
    pub fn from_encrypted_json(
        data: &BTreeMap<String, serde_json::Value>,
        passphrase: &[u8],
    ) -> Result<Self> {
        if passphrase.is_empty() {
            return Err(ElaraError::Crypto("passphrase must not be empty".into()));
        }

        // Parse encryption metadata
        let enc = data
            .get("encryption")
            .ok_or_else(|| ElaraError::Crypto("missing encryption metadata".into()))?;
        let format = enc
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if format != ENCRYPTED_FORMAT_V1 {
            return Err(ElaraError::Crypto(format!(
                "unsupported encryption format: {format}"
            )));
        }
        let salt_hex = enc
            .get("argon2_salt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ElaraError::Crypto("missing argon2_salt".into()))?;
        let salt =
            hex::decode(salt_hex).map_err(|e| ElaraError::Crypto(format!("bad salt hex: {e}")))?;

        // Derive key
        let key = derive_key(passphrase, &salt)?;

        // Build a temporary data map with decrypted secret keys for from_json()
        let mut decrypted_data = data.clone();
        decrypted_data.remove("encryption");

        // Decrypt secret key
        if let Some(v) = data
            .get("encrypted_secret_key")
            .and_then(|v| v.as_str())
        {
            let encrypted = hex::decode(v)
                .map_err(|e| ElaraError::Crypto(format!("bad encrypted_secret_key hex: {e}")))?;
            let plaintext = decrypt_field(&key, &encrypted)?;
            decrypted_data.remove("encrypted_secret_key");
            decrypted_data.insert(
                "secret_key".into(),
                serde_json::Value::String(hex::encode(&plaintext)),
            );
        }

        // Decrypt SPHINCS+ secret key
        if let Some(v) = data
            .get("encrypted_sphincs_secret_key")
            .and_then(|v| v.as_str())
        {
            let encrypted = hex::decode(v)
                .map_err(|e| ElaraError::Crypto(format!("bad encrypted_sphincs_secret_key hex: {e}")))?;
            let plaintext = decrypt_field(&key, &encrypted)?;
            decrypted_data.remove("encrypted_sphincs_secret_key");
            decrypted_data.insert(
                "sphincs_secret_key".into(),
                serde_json::Value::String(hex::encode(&plaintext)),
            );
        }

        // Reuse from_json() for the rest
        Self::from_json(&decrypted_data)
    }
}

/// Write an identity file with proper Unix permissions (0o600).
pub fn write_identity_file(
    path: &std::path::Path,
    data: &BTreeMap<String, serde_json::Value>,
) -> Result<()> {
    let json_str = serde_json::to_string_pretty(data)
        .map_err(|e| ElaraError::Crypto(format!("JSON serialization failed: {e}")))?;

    // Create parent directories
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ElaraError::Crypto(format!("failed to create directory: {e}")))?;
    }

    std::fs::write(path, &json_str)
        .map_err(|e| ElaraError::Crypto(format!("failed to write identity file: {e}")))?;

    // Set restrictive permissions on Unix (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| ElaraError::Crypto(format!("failed to set file permissions: {e}")))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_profile_a() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        assert_eq!(id.public_key.len(), 1952);
        assert!(id.has_secret_key());
        assert!(id.sphincs_public_key().is_some());
        assert_eq!(id.sphincs_public_key().unwrap().len(), 48);
    }

    #[test]
    fn test_generate_profile_b() {
        let id = Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).unwrap();
        assert_eq!(id.public_key.len(), 1952);
        assert!(id.has_secret_key());
        assert!(id.sphincs_public_key().is_none());
    }

    #[test]
    fn test_sign_verify() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let msg = b"test message";
        let sig = id.sign(msg).unwrap();
        assert!(Identity::verify(msg, &sig, &id.public_key).unwrap());
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let msg = b"test message";
        let sig = id.sign_sphincs(msg).unwrap();
        let pk = id.sphincs_public_key().unwrap();
        assert!(Identity::verify_sphincs(msg, &sig, pk).unwrap());
    }

    #[test]
    fn test_public_identity_cannot_sign() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let pub_id = id.public_identity();
        assert!(!pub_id.has_secret_key());
        assert!(pub_id.sign(b"test").is_err());
    }

    #[test]
    fn test_json_roundtrip() {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileA).unwrap();
        let json = id.to_json();
        let restored = Identity::from_json(&json).unwrap();
        assert_eq!(restored.public_key, id.public_key);
        assert_eq!(restored.identity_hash, id.identity_hash);
        assert!(restored.has_secret_key());
    }

    #[test]
    fn test_identity_uniqueness() {
        let id1 = Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap();
        let id2 = Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap();
        assert_ne!(id1.public_key, id2.public_key);
        assert_ne!(id1.identity_hash, id2.identity_hash);
    }

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(leading_zero_bits(&[0x00, 0x0F, 0xFF]), 12);
        assert_eq!(leading_zero_bits(&[0x80, 0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x40, 0xFF]), 1);
        assert_eq!(leading_zero_bits(&[0x01, 0xFF]), 7);
        assert_eq!(leading_zero_bits(&[0x00]), 8);
        assert_eq!(leading_zero_bits(&[]), 0);
    }

    #[test]
    fn test_generate_no_pow() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap();
        assert_eq!(id.pow_nonce, 0);
        assert_eq!(id.pow_difficulty, 0);
        assert!(id.verify_pow()); // difficulty=0 always passes
    }

    #[test]
    fn test_generate_with_pow() {
        // Use low difficulty (8 bits) for fast test — ~256 average attempts
        let id =
            Identity::generate_with_pow(EntityType::Human, CryptoProfile::ProfileB, 8).unwrap();
        assert_eq!(id.pow_difficulty, 8);
        // pow_nonce is u64 so any value (including 0 if lucky) is valid;
        // verify_pow() below is the actual semantic check.
        assert!(id.verify_pow());
        // Static verification matches
        assert!(Identity::verify_pow_static(
            &id.public_key,
            id.pow_nonce,
            id.pow_difficulty
        ));
    }

    #[test]
    fn test_pow_verification_fails_wrong_nonce() {
        let id =
            Identity::generate_with_pow(EntityType::Human, CryptoProfile::ProfileB, 8).unwrap();
        // Search a small window around the real nonce for one that is
        // provably NOT a valid solution. With difficulty=8 each nonce
        // has ~1/256 chance of being valid, so a wrong nonce is found
        // quickly and the test is no longer probabilistic. Previously
        // this test asserted on `nonce + 1` directly, which had a
        // ~1/256 chance of itself satisfying the PoW and producing a
        // spurious failure under full-suite parallel runs.
        let mut bad_nonce = None;
        for delta in 1u64..1024 {
            let cand = id.pow_nonce.wrapping_add(delta);
            if !Identity::verify_pow_static(&id.public_key, cand, id.pow_difficulty) {
                bad_nonce = Some(cand);
                break;
            }
        }
        let bad = bad_nonce.expect(
            "out of 1023 candidate nonces around the solution at least one must fail \
             verification at difficulty=8 (P(all valid) = 256^-1023, astronomically small)",
        );
        assert!(!Identity::verify_pow_static(
            &id.public_key,
            bad,
            id.pow_difficulty
        ));
    }

    #[test]
    fn test_pow_exceeds_max_difficulty() {
        let result = Identity::generate_with_pow(
            EntityType::Human,
            CryptoProfile::ProfileB,
            MAX_POW_DIFFICULTY + 1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_pow_json_roundtrip() {
        let id =
            Identity::generate_with_pow(EntityType::Device, CryptoProfile::ProfileA, 8).unwrap();
        let json = id.to_json();
        let restored = Identity::from_json(&json).unwrap();
        assert_eq!(restored.pow_nonce, id.pow_nonce);
        assert_eq!(restored.pow_difficulty, id.pow_difficulty);
        assert!(restored.verify_pow());
    }

    #[test]
    fn test_pow_backwards_compat() {
        // Simulate loading a pre-PoW identity (no pow fields in JSON)
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap();
        let mut json = id.to_json();
        json.remove("pow_nonce");
        json.remove("pow_difficulty");
        let restored = Identity::from_json(&json).unwrap();
        assert_eq!(restored.pow_nonce, 0);
        assert_eq!(restored.pow_difficulty, 0);
        assert!(restored.verify_pow());
    }

    #[test]
    fn test_pow_public_identity_preserves_pow() {
        let id =
            Identity::generate_with_pow(EntityType::Human, CryptoProfile::ProfileB, 8).unwrap();
        let pub_id = id.public_identity();
        assert_eq!(pub_id.pow_nonce, id.pow_nonce);
        assert_eq!(pub_id.pow_difficulty, id.pow_difficulty);
        assert!(pub_id.verify_pow());
    }

    #[test]
    fn test_pow_profile_a_with_sphincs() {
        let id =
            Identity::generate_with_pow(EntityType::Human, CryptoProfile::ProfileA, 8).unwrap();
        assert!(id.verify_pow());
        assert!(id.sphincs_public_key().is_some());
        // Can still sign with both algorithms
        let msg = b"pow identity test";
        let sig = id.sign(msg).unwrap();
        assert!(Identity::verify(msg, &sig, &id.public_key).unwrap());
        let sphincs_sig = id.sign_sphincs(msg).unwrap();
        assert!(Identity::verify_sphincs(msg, &sphincs_sig, id.sphincs_public_key().unwrap()).unwrap());
    }

    // ─── Attestation Level Tests ─────────────────────────────────────────

    #[test]
    fn test_attestation_level_ordering() {
        assert!(AttestationLevel::None < AttestationLevel::Software);
        assert!(AttestationLevel::Software < AttestationLevel::SecureBoot);
        assert!(AttestationLevel::SecureBoot < AttestationLevel::HardwareKey);
        assert!(AttestationLevel::HardwareKey < AttestationLevel::Puf);
    }

    #[test]
    fn test_attestation_level_ranks() {
        assert_eq!(AttestationLevel::None.rank(), 0);
        assert_eq!(AttestationLevel::Software.rank(), 1);
        assert_eq!(AttestationLevel::SecureBoot.rank(), 2);
        assert_eq!(AttestationLevel::HardwareKey.rank(), 3);
        assert_eq!(AttestationLevel::Puf.rank(), 4);
    }

    #[test]
    fn test_attestation_trust_multipliers() {
        assert_eq!(AttestationLevel::None.trust_multiplier(), 1.0);
        assert!(AttestationLevel::Software.trust_multiplier() > 1.0);
        assert!(AttestationLevel::Puf.trust_multiplier() > AttestationLevel::HardwareKey.trust_multiplier());
    }

    #[test]
    fn test_attestation_parse_roundtrip() {
        for level in &[
            AttestationLevel::None,
            AttestationLevel::Software,
            AttestationLevel::SecureBoot,
            AttestationLevel::HardwareKey,
            AttestationLevel::Puf,
        ] {
            let s = level.as_str();
            let parsed = AttestationLevel::parse(s).unwrap();
            assert_eq!(&parsed, level);
        }
    }

    #[test]
    fn test_attestation_parse_lowercase() {
        assert_eq!(AttestationLevel::parse("none"), Some(AttestationLevel::None));
        assert_eq!(AttestationLevel::parse("puf"), Some(AttestationLevel::Puf));
        assert_eq!(AttestationLevel::parse("hardware_key"), Some(AttestationLevel::HardwareKey));
    }

    #[test]
    fn test_attestation_default() {
        let level: AttestationLevel = Default::default();
        assert_eq!(level, AttestationLevel::None);
    }

    // ─── Dual-Signature Tests ────────────────────────────────────────────

    #[test]
    fn test_dual_sign_profile_a() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let msg = b"dual sign test";
        let (dil_sig, sphincs_sig) = id.dual_sign(msg).unwrap();

        // Both signatures should be present
        assert!(!dil_sig.is_empty());
        assert!(sphincs_sig.is_some());
        let sphincs_sig = sphincs_sig.unwrap();
        assert_eq!(sphincs_sig.len(), 35664); // SPHINCS+-SHA2-192f

        // Both should verify
        assert!(Identity::verify(msg, &dil_sig, &id.public_key).unwrap());
        assert!(Identity::verify_sphincs(msg, &sphincs_sig, id.sphincs_public_key().unwrap()).unwrap());
    }

    #[test]
    fn test_dual_sign_profile_b() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap();
        let msg = b"single sign test";
        let (dil_sig, sphincs_sig) = id.dual_sign(msg).unwrap();

        // Only Dilithium3 signature
        assert!(!dil_sig.is_empty());
        assert!(sphincs_sig.is_none());

        assert!(Identity::verify(msg, &dil_sig, &id.public_key).unwrap());
    }

    #[test]
    fn test_sign_record_profile_a() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let mut record = crate::record::ValidationRecord::create(
            b"test content",
            id.public_key.clone(),
            vec![],
            crate::record::Classification::Public,
            None,
        );

        id.sign_record(&mut record).unwrap();

        // Both signatures present
        assert!(record.signature.is_some());
        assert!(record.sphincs_signature.is_some());
        assert!(record.creator_sphincs_pk.is_some());
        assert_eq!(record.creator_sphincs_pk.as_ref().unwrap().len(), 48);

        // Both verify
        let signable = record.signable_bytes();
        assert!(Identity::verify(&signable, record.signature.as_ref().unwrap(), &id.public_key).unwrap());
        assert!(Identity::verify_sphincs(
            &signable,
            record.sphincs_signature.as_ref().unwrap(),
            record.creator_sphincs_pk.as_ref().unwrap(),
        ).unwrap());
    }

    #[test]
    fn test_sign_record_profile_b() {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let mut record = crate::record::ValidationRecord::create(
            b"test content",
            id.public_key.clone(),
            vec![],
            crate::record::Classification::Public,
            None,
        );

        id.sign_record(&mut record).unwrap();

        // Only Dilithium3
        assert!(record.signature.is_some());
        assert!(record.sphincs_signature.is_none());
        assert!(record.creator_sphincs_pk.is_none());
    }

    #[test]
    fn test_dual_signed_record_wire_roundtrip() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let mut record = crate::record::ValidationRecord::create(
            b"wire roundtrip test",
            id.public_key.clone(),
            vec![],
            crate::record::Classification::Public,
            None,
        );

        id.sign_record(&mut record).unwrap();

        // Serialize and deserialize
        let wire = record.to_bytes();
        let decoded = crate::record::ValidationRecord::from_bytes(&wire).unwrap();

        // All fields preserved
        assert_eq!(decoded.signature, record.signature);
        assert_eq!(decoded.sphincs_signature, record.sphincs_signature);
        assert_eq!(decoded.creator_sphincs_pk, record.creator_sphincs_pk);

        // Both signatures still verify after roundtrip
        let signable = decoded.signable_bytes();
        assert!(Identity::verify(&signable, decoded.signature.as_ref().unwrap(), &decoded.creator_public_key).unwrap());
        assert!(Identity::verify_sphincs(
            &signable,
            decoded.sphincs_signature.as_ref().unwrap(),
            decoded.creator_sphincs_pk.as_ref().unwrap(),
        ).unwrap());
    }

    // ─── Adaptive PoW Difficulty Tests ───────────────────────────────────

    #[test]
    fn test_subnet_tracker_below_threshold_returns_base() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let now = 1_000_000.0;
        // Record 50 creations — well below the 100 threshold.
        for i in 0..50 {
            tracker.record_creation("10.0.1", now + i as f64);
        }
        let diff = tracker.difficulty_for_subnet("10.0.1", now + 50.0);
        assert_eq!(diff, DEFAULT_POW_DIFFICULTY);
    }

    #[test]
    fn test_subnet_tracker_above_threshold_doubles_difficulty() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let now = 1_000_000.0;
        // Record 101 creations within the window — exceeds threshold.
        for i in 0..101 {
            tracker.record_creation("10.0.1", now + i as f64);
        }
        let diff = tracker.difficulty_for_subnet("10.0.1", now + 101.0);
        assert_eq!(diff, DEFAULT_POW_DIFFICULTY.saturating_mul(2).min(MAX_POW_DIFFICULTY));
        // With base=20, doubled=40 but capped at 32.
        assert_eq!(diff, MAX_POW_DIFFICULTY);
    }

    #[test]
    fn test_subnet_tracker_exactly_at_threshold() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let now = 1_000_000.0;
        // Exactly 100 — should NOT trigger doubling (threshold is >100).
        for i in 0..100 {
            tracker.record_creation("10.0.1", now + i as f64);
        }
        let diff = tracker.difficulty_for_subnet("10.0.1", now + 100.0);
        assert_eq!(diff, DEFAULT_POW_DIFFICULTY);
    }

    #[test]
    fn test_subnet_tracker_prunes_old_entries() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let now = 1_000_000.0;
        // Create 101 identities at t=0..100
        for i in 0..101 {
            tracker.record_creation("10.0.1", now + i as f64);
        }
        // At t=now+101, count is 101 — difficulty should be doubled.
        assert!(tracker.subnet_count("10.0.1", now + 101.0) > SUBNET_RATE_THRESHOLD);

        // Jump forward so all entries (t=now..now+100) fall outside the window.
        // Cutoff = future - 3600, need cutoff > now+100, so future > now+3700.
        let future = now + RATE_WINDOW_SECS + 101.0;
        let diff = tracker.difficulty_for_subnet("10.0.1", future);
        assert_eq!(diff, DEFAULT_POW_DIFFICULTY);
        assert_eq!(tracker.subnet_count("10.0.1", future), 0);
    }

    #[test]
    fn test_subnet_tracker_isolates_subnets() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let now = 1_000_000.0;
        // Flood subnet A, leave subnet B quiet.
        for i in 0..101 {
            tracker.record_creation("10.0.1", now + i as f64);
        }
        tracker.record_creation("192.168.0", now);

        // A should be elevated, B should be base.
        let diff_a = tracker.difficulty_for_subnet("10.0.1", now + 101.0);
        let diff_b = tracker.difficulty_for_subnet("192.168.0", now + 101.0);
        assert_eq!(diff_a, MAX_POW_DIFFICULTY); // doubled & capped
        assert_eq!(diff_b, DEFAULT_POW_DIFFICULTY);
    }

    #[test]
    fn test_subnet_tracker_cap_at_max() {
        // Even with a high base, difficulty cannot exceed MAX_POW_DIFFICULTY.
        let mut tracker = SubnetRateTracker::new(24);
        let now = 1_000_000.0;
        for i in 0..101 {
            tracker.record_creation("10.0.1", now + i as f64);
        }
        let diff = tracker.difficulty_for_subnet("10.0.1", now + 101.0);
        // 24 * 2 = 48, capped at 32.
        assert_eq!(diff, MAX_POW_DIFFICULTY);
    }

    #[test]
    fn test_subnet_tracker_record_returns_difficulty() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let now = 1_000_000.0;
        // The 101st record_creation should return the doubled difficulty.
        let mut last_diff = 0;
        for i in 0..=101 {
            last_diff = tracker.record_creation("10.0.1", now + i as f64);
        }
        assert_eq!(last_diff, MAX_POW_DIFFICULTY);
    }

    // ─── Zeroization of secret keys ─────────────────────

    #[test]
    fn test_identity_keys_zeroed_on_drop() {
        // Profile A generates both Dilithium3 + SPHINCS+ keys
        let mut id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();

        // Keys exist and are non-zero before zeroization
        assert!(id.secret_key.as_ref().unwrap().iter().any(|&b| b != 0),
            "dilithium3 secret key should be non-zero");
        assert!(id.sphincs_secret_key.as_ref().unwrap().iter().any(|&b| b != 0),
            "sphincs+ secret key should be non-zero");

        // Manually invoke the same logic as our custom Drop impl
        if let Some(ref mut sk) = id.secret_key { sk.zeroize(); }
        if let Some(ref mut sk) = id.sphincs_secret_key { sk.zeroize(); }

        // Vec::zeroize() fills with zeros and sets length to 0
        assert!(id.secret_key.as_ref().unwrap().is_empty(),
            "dilithium3 key should be zeroed");
        assert!(id.sphincs_secret_key.as_ref().unwrap().is_empty(),
            "sphincs+ key should be zeroed");

        // Clear to prevent double-zeroize in actual Drop
        id.secret_key = None;
        id.sphincs_secret_key = None;
    }

    // ─── Encrypted identity storage ─────────────────────

    #[test]
    fn test_encrypt_decrypt_roundtrip_profile_b() {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let passphrase = b"test-passphrase-2026";

        let encrypted = id.to_encrypted_json(passphrase).unwrap();

        // Encrypted format markers
        assert!(is_encrypted_identity(&encrypted));
        assert!(encrypted.contains_key("encryption"));
        assert!(encrypted.contains_key("encrypted_secret_key"));
        // Plaintext secret key must NOT be present
        assert!(!encrypted.contains_key("secret_key"));

        // Public fields still in cleartext
        assert_eq!(
            encrypted.get("identity_hash").unwrap().as_str().unwrap(),
            id.identity_hash
        );

        // Decrypt and verify roundtrip
        let restored = Identity::from_encrypted_json(&encrypted, passphrase).unwrap();
        assert_eq!(restored.identity_hash, id.identity_hash);
        assert_eq!(restored.secret_key, id.secret_key);
        assert_eq!(restored.public_key, id.public_key);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_profile_a() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let passphrase = b"dual-sig-passphrase";

        let encrypted = id.to_encrypted_json(passphrase).unwrap();

        // Profile A has both Dilithium3 and SPHINCS+ secret keys
        assert!(encrypted.contains_key("encrypted_secret_key"));
        assert!(encrypted.contains_key("encrypted_sphincs_secret_key"));
        assert!(!encrypted.contains_key("secret_key"));
        assert!(!encrypted.contains_key("sphincs_secret_key"));

        let restored = Identity::from_encrypted_json(&encrypted, passphrase).unwrap();
        assert_eq!(restored.secret_key, id.secret_key);
        assert_eq!(restored.sphincs_secret_key, id.sphincs_secret_key);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();

        let encrypted = id.to_encrypted_json(b"correct-passphrase").unwrap();
        let result = Identity::from_encrypted_json(&encrypted, b"wrong-passphrase");

        assert!(result.is_err(), "wrong passphrase must fail decryption");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("wrong passphrase") || err_msg.contains("decryption failed"),
            "error should mention wrong passphrase, got: {err_msg}"
        );
    }

    #[test]
    fn test_empty_passphrase_rejected() {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();

        assert!(id.to_encrypted_json(b"").is_err());
        assert!(Identity::from_encrypted_json(&BTreeMap::new(), b"").is_err());
    }

    #[test]
    fn test_encrypted_identity_can_sign() {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let passphrase = b"signing-test";

        let encrypted = id.to_encrypted_json(passphrase).unwrap();
        let restored = Identity::from_encrypted_json(&encrypted, passphrase).unwrap();

        // The restored identity must be able to sign
        let msg = b"test message";
        let sig = restored.sign(msg).unwrap();
        assert!(Identity::verify(msg, &sig, &restored.public_key).unwrap());
    }

    #[test]
    fn test_is_encrypted_identity_detection() {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();

        // Plaintext format
        let plaintext = id.to_json();
        assert!(!is_encrypted_identity(&plaintext));

        // Encrypted format
        let encrypted = id.to_encrypted_json(b"test").unwrap();
        assert!(is_encrypted_identity(&encrypted));
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphertext() {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let passphrase = b"same-passphrase";

        let enc1 = id.to_encrypted_json(passphrase).unwrap();
        let enc2 = id.to_encrypted_json(passphrase).unwrap();

        // Different salt + nonce means different ciphertext (even same passphrase)
        let ct1 = enc1.get("encrypted_secret_key").unwrap().as_str().unwrap();
        let ct2 = enc2.get("encrypted_secret_key").unwrap().as_str().unwrap();
        assert_ne!(ct1, ct2, "different encryptions must produce different ciphertext");

        // But both decrypt to the same key
        let r1 = Identity::from_encrypted_json(&enc1, passphrase).unwrap();
        let r2 = Identity::from_encrypted_json(&enc2, passphrase).unwrap();
        assert_eq!(r1.secret_key, r2.secret_key);
    }

    // ─── Adaptive PoW Rate Tracker Tests ─────────────────────────────────

    #[test]
    fn test_subnet_rate_tracker_base_difficulty() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let diff = tracker.difficulty_for_subnet("10.0.1", 1000.0);
        assert_eq!(diff, DEFAULT_POW_DIFFICULTY);
    }

    #[test]
    fn test_subnet_rate_doubles_on_threshold() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let subnet = "10.0.1";
        // Record 101 creations (over threshold of 100)
        for i in 0..=SUBNET_RATE_THRESHOLD {
            tracker.record_creation(subnet, 1000.0 + i as f64);
        }
        let diff = tracker.difficulty_for_subnet(subnet, 1100.0);
        // 20 * 2 = 40, but capped at MAX_POW_DIFFICULTY = 32
        assert_eq!(diff, MAX_POW_DIFFICULTY);
        // Verify it's higher than base
        assert!(diff > DEFAULT_POW_DIFFICULTY);
    }

    #[test]
    fn test_global_rate_adds_4_bits() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        // Distribute 501 creations across many different subnets (each under threshold)
        for i in 0..=GLOBAL_RATE_THRESHOLD {
            let subnet = format!("10.{}.{}", i / 256, i % 256);
            tracker.record_creation(&subnet, 1000.0 + i as f64);
        }
        // Any subnet should now have global penalty even if its own count is low
        let diff = tracker.difficulty_for_subnet("192.168.0", 1600.0);
        assert_eq!(diff, DEFAULT_POW_DIFFICULTY + 4);
    }

    #[test]
    fn test_both_penalties_stack() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let hot_subnet = "10.0.1";
        // Exceed both subnet threshold (100) AND contribute to global threshold
        // First fill other subnets to get global > 500
        for i in 0..400 {
            let subnet = format!("10.{}.{}", (i / 256) + 1, i % 256);
            tracker.record_creation(&subnet, 1000.0 + i as f64);
        }
        // Now push the hot subnet past its own threshold
        for i in 0..=SUBNET_RATE_THRESHOLD {
            tracker.record_creation(hot_subnet, 1500.0 + i as f64);
        }
        let diff = tracker.difficulty_for_subnet(hot_subnet, 1700.0);
        // Subnet penalty: 20 * 2 = 40, then global penalty: 40 + 4 = 44
        // But capped at MAX_POW_DIFFICULTY = 32
        assert_eq!(diff, MAX_POW_DIFFICULTY);
    }

    #[test]
    fn test_rate_tracker_prunes_old_entries() {
        let mut tracker = SubnetRateTracker::new(DEFAULT_POW_DIFFICULTY);
        let subnet = "10.0.1";
        // Record 200 creations in a tight burst at t=1000
        for i in 0..200 {
            tracker.record_creation(subnet, 1000.0 + i as f64 * 0.1);
        }
        // At t=1020 they should still be in window (RATE_WINDOW_SECS = 3600)
        assert!(tracker.subnet_count(subnet, 1020.0) > SUBNET_RATE_THRESHOLD);
        // At t=5000 (>3600s after last entry at ~1020) they should all be pruned
        assert_eq!(tracker.subnet_count(subnet, 5000.0), 0);
        assert_eq!(tracker.global_count(5000.0), 0);
        // Difficulty should be back to base
        assert_eq!(tracker.difficulty_for_subnet(subnet, 5000.0), DEFAULT_POW_DIFFICULTY);
    }

    #[test]
    fn batch_b_attestation_level_parse_rejects_mixed_case_and_unknown_inputs() {
        // parse() only accepts the exact UPPER_SNAKE or all-lowercase forms; anything
        // else (mixed case, truncation, whitespace, synonyms) must return None.
        // Guards against an accidental case-insensitive parser being introduced.
        assert!(AttestationLevel::parse("None").is_none());
        assert!(AttestationLevel::parse("Software").is_none());
        assert!(AttestationLevel::parse("Secure_Boot").is_none());
        assert!(AttestationLevel::parse("Hardware_Key").is_none());
        assert!(AttestationLevel::parse("Puf").is_none());
        assert!(AttestationLevel::parse("HARDWARE").is_none());
        assert!(AttestationLevel::parse("SECURE").is_none());
        assert!(AttestationLevel::parse("").is_none());
        assert!(AttestationLevel::parse("FOO").is_none());
        assert!(AttestationLevel::parse(" NONE ").is_none());
        assert!(AttestationLevel::parse("NONEX").is_none());
        assert!(AttestationLevel::parse("NULL").is_none());
    }

    #[test]
    fn batch_b_attestation_level_ord_matches_rank_for_all_pairs() {
        // Cross-product: PartialOrd/Ord derived from declaration order must
        // stay in lockstep with rank(). Reordering variants without updating
        // rank() (or vice versa) trips this test.
        let levels = [
            AttestationLevel::None,
            AttestationLevel::Software,
            AttestationLevel::SecureBoot,
            AttestationLevel::HardwareKey,
            AttestationLevel::Puf,
        ];
        for &a in &levels {
            for &b in &levels {
                assert_eq!(a < b, a.rank() < b.rank(), "ord vs rank for {:?} {:?}", a, b);
                assert_eq!(a == b, a.rank() == b.rank(), "eq vs rank for {:?} {:?}", a, b);
                assert_eq!(a > b, a.rank() > b.rank(), "gt vs rank for {:?} {:?}", a, b);
            }
        }
    }

    #[test]
    fn batch_b_attestation_level_trust_multiplier_strict_monotonic_pin_exact_values() {
        // Exact multiplier pins — these are economic constants in the trust-score
        // path. Silent edits to the literals must trip the test.
        assert_eq!(AttestationLevel::None.trust_multiplier(), 1.0);
        assert_eq!(AttestationLevel::Software.trust_multiplier(), 1.1);
        assert_eq!(AttestationLevel::SecureBoot.trust_multiplier(), 1.2);
        assert_eq!(AttestationLevel::HardwareKey.trust_multiplier(), 1.4);
        assert_eq!(AttestationLevel::Puf.trust_multiplier(), 1.5);
        let levels = [
            AttestationLevel::None,
            AttestationLevel::Software,
            AttestationLevel::SecureBoot,
            AttestationLevel::HardwareKey,
            AttestationLevel::Puf,
        ];
        for w in levels.windows(2) {
            assert!(
                w[0].trust_multiplier() < w[1].trust_multiplier(),
                "trust_multiplier must be strictly increasing: {:?}={} >= {:?}={}",
                w[0], w[0].trust_multiplier(), w[1], w[1].trust_multiplier(),
            );
        }
    }

    #[test]
    fn batch_b_attestation_level_serde_round_trips_all_five_wire_strings() {
        // Pin serde rename strings — part of the on-wire identity record format;
        // silent change would break light-client identity sync. Round-trip + literal pin.
        let cases = [
            (AttestationLevel::None, "\"NONE\""),
            (AttestationLevel::Software, "\"SOFTWARE\""),
            (AttestationLevel::SecureBoot, "\"SECURE_BOOT\""),
            (AttestationLevel::HardwareKey, "\"HARDWARE_KEY\""),
            (AttestationLevel::Puf, "\"PUF\""),
        ];
        for (level, expected_wire) in cases {
            let wire = serde_json::to_string(&level).expect("serialize");
            assert_eq!(wire, expected_wire, "wire string for {:?}", level);
            let back: AttestationLevel = serde_json::from_str(&wire).expect("deserialize");
            assert_eq!(back, level, "round-trip for {:?}", level);
        }
        let bad: std::result::Result<AttestationLevel, _> = serde_json::from_str("\"WORMHOLE\"");
        assert!(bad.is_err(), "unknown wire string must fail to deserialize");
    }

    #[test]
    fn batch_b_entity_type_and_crypto_profile_serde_pin_wire_strings() {
        // EntityType — all five variants pin wire strings + round-trip.
        let entity_cases = [
            (EntityType::Human, "\"HUMAN\""),
            (EntityType::Ai, "\"AI\""),
            (EntityType::Device, "\"DEVICE\""),
            (EntityType::Organization, "\"ORGANIZATION\""),
            (EntityType::Composite, "\"COMPOSITE\""),
        ];
        for (etype, expected) in entity_cases {
            let wire = serde_json::to_string(&etype).expect("serialize entity");
            assert_eq!(wire, expected, "EntityType wire for {:?}", etype);
            let back: EntityType = serde_json::from_str(&wire).expect("deserialize entity");
            assert_eq!(back, etype, "EntityType round-trip for {:?}", etype);
        }
        let bad_entity: std::result::Result<EntityType, _> = serde_json::from_str("\"ROBOT\"");
        assert!(bad_entity.is_err(), "unknown EntityType 'ROBOT' must fail");

        // CryptoProfile — A/B/C pin + reject "D".
        let profile_cases = [
            (CryptoProfile::ProfileA, "\"A\""),
            (CryptoProfile::ProfileB, "\"B\""),
            (CryptoProfile::ProfileC, "\"C\""),
        ];
        for (p, expected) in profile_cases {
            let wire = serde_json::to_string(&p).expect("serialize profile");
            assert_eq!(wire, expected, "CryptoProfile wire for {:?}", p);
            let back: CryptoProfile = serde_json::from_str(&wire).expect("deserialize profile");
            assert_eq!(back, p, "CryptoProfile round-trip for {:?}", p);
        }
        let bad_profile: std::result::Result<CryptoProfile, _> = serde_json::from_str("\"D\"");
        assert!(bad_profile.is_err(), "unknown CryptoProfile 'D' must fail");
    }
}
