//! Mandate accountability SDK — the **query/read-side** client for the
//! "who-or-what-was-authorized-to-do-what" layer (the project's reason-to-exist).
//!
//! This is the typed, footgun-fenced way to consume the mandate layer from
//! another program — the live-node complement of the offline browser verifier.
//! It deliberately ships **read-only**: there is no issue/revoke surface here.
//! Mandates and revocations are created by submitting *signed records* (see
//! `elara-cli mandate-issue` / `mandate-revoke`), which requires a Dilithium3
//! secret key and the PQ transport; an SDK that made signing trivial would
//! invite exactly the genesis/consensus-key-signing mistake the first dogfood
//! avoided by hand. A read client holds no key material — zero custody surface.
//!
//! ## Two paths, two trust models — DO NOT conflate them
//!
//! 1. [`verify_bundle`] — **offline, zero-trust-in-any-server**. Re-exports the
//!    audited [`crate::mandate_bundle::evaluate_mandate_bundle`]. A green
//!    [`BundleVerdict`] means "CONSISTENT *given this bundle*", **not**
//!    "authorized on-chain": an offline bundle structurally cannot detect a
//!    revocation its author withheld, nor that a record is actually on the
//!    ledger. Those non-dismissible caveats travel in
//!    [`BundleVerdict::soundness_caveats`] — never strip them.
//!
//! 2. [`MandateQueryClient`] (feature `node-core`) — **trusts the queried node**.
//!    Its verdict is only as complete as that node's mandate + revocation index.
//!    A snapshot-bootstrapped follower can hold an *incomplete* act index
//!    (`CF_MANDATE_ACT` is live-ingest-only, never snapshot-carried), so a
//!    "not a mandate act" answer there is a possible **false negative** — query
//!    a full-history node. This is surfaced as [`Coverage`], not hidden.
//!
//! ## Why there is no `authorized: bool`
//!
//! The single most likely way an SDK over this layer over-claims is a leaky
//! `authorized` flag that a caller branches on while ignoring the caveats. So
//! the verdict is an enum ([`MandateActVerdict`]) whose only unqualified
//! authorization state — [`MandateActVerdict::Authorized`] — is reachable
//! **only** when the flag is `Valid` AND the node is authoritative AND scope was
//! actually enforced (`!scope_deferred`). Any caveat downgrades it to
//! [`MandateActVerdict::AuthorizedWithCaveats`], where the caveat fields cannot
//! be ignored. v0 is observational: a `Valid` flag means *agent-identity +
//! time-window + revocation* were checked; when `scope_deferred` is true the
//! mandate's op/zone/amount scope was **recorded but not enforced**.
//!
//! An unrecognized flag string from a newer node maps to
//! [`MandateActVerdict::UnknownFlag`] — never silently to "not authorized".

use crate::mandate::MandateFlag;
use serde::Deserialize;

// ─── Offline, zero-trust path (always compiled — wasm/default-feature safe) ───

pub use crate::mandate_bundle::{evaluate_mandate_bundle, BundleCheck, BundleVerdict, LineageHop};

/// Verify a self-contained mandate bundle **entirely offline**.
///
/// Thin, documented passthrough to [`crate::mandate_bundle::evaluate_mandate_bundle`].
/// Returns the [`BundleVerdict`] unchanged — in particular its
/// [`BundleVerdict::soundness_caveats`] always travel with it. A green verdict is
/// "consistent & authorizing GIVEN THIS BUNDLE", not "authorized on-chain":
/// offline you cannot see a withheld revocation, nor confirm the record is on
/// the ledger. For an authoritative live answer, use [`MandateQueryClient`].
pub fn verify_bundle(bundle_json: &str) -> BundleVerdict {
    evaluate_mandate_bundle(bundle_json)
}

// ─── Coverage — node-completeness honesty ─────────────────────────────────────

/// How complete the answering node's view is. A negative ("not a mandate act",
/// "no acts") from an [`Coverage::IncompleteSnapshotFollower`] is **not
/// definitive** — that node bootstrapped from a snapshot and may have indexed no
/// acts sealed before its baseline. Query a full-history (archive) node to be sure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// The node replayed from genesis (or the verdict is judged from
    /// snapshot-carried mandate+revocation state, which is authoritative on any
    /// node) — this answer is complete.
    Authoritative,
    /// The node bootstrapped from a snapshot; a negative may be a false negative.
    IncompleteSnapshotFollower,
}

impl Coverage {
    fn from_authoritative_complete(authoritative_complete: bool) -> Self {
        if authoritative_complete {
            Coverage::Authoritative
        } else {
            Coverage::IncompleteSnapshotFollower
        }
    }

    /// True only for [`Coverage::Authoritative`].
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Coverage::Authoritative)
    }
}

// ─── Typed parse of GET /mandate/status/{record_id} ───────────────────────────

/// One verified leaf→root delegation hop, as surfaced by `/mandate/status`
/// (present only on a `Valid` verdict — anti-libel). Note the field names differ
/// from [`LineageHop`] (the offline-bundle shape): the HTTP endpoint emits
/// `principal_identity_hash` / `agent_identity_hash` / `hop_index`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LineageHopView {
    #[serde(default)]
    pub hop_index: u32,
    pub mandate_id: String,
    pub principal_identity_hash: String,
    pub agent_identity_hash: String,
}

/// Faithful typed parse of `GET /mandate/status/{record_id}`.
///
/// The **not-found** response carries only `record_id`, `is_mandate_act:false`
/// and `authoritative_complete` — every act-specific field is therefore
/// [`Option`]. Do not branch on the raw fields; call [`Self::classify`] for a
/// verdict that cannot be misread. (The node's own `authorized` boolean is
/// intentionally **not** deserialized here — it does not fold in coverage or
/// scope-deferral, so the SDK recomputes an honest verdict from `flag` instead.)
#[derive(Debug, Clone, Deserialize)]
pub struct MandateActStatus {
    pub record_id: String,
    /// `false` either because the record genuinely referenced no mandate, or —
    /// on a snapshot follower — because the act index has no entry for it. Use
    /// `authoritative_complete` (→ [`Coverage`]) to tell those apart.
    pub is_mandate_act: bool,
    /// `true` when this node can vouch for the answer; `false` on a
    /// snapshot-bootstrapped follower's not-found path.
    pub authoritative_complete: bool,
    #[serde(default)]
    pub mandate_ref: Option<String>,
    #[serde(default)]
    pub agent_identity_hash: Option<String>,
    #[serde(default)]
    pub act_timestamp_ms: Option<u64>,
    /// Wire-stable [`MandateFlag`] label (e.g. `"valid"`, `"post_revocation"`),
    /// or `"malformed"` for an unparseable mandate reference.
    #[serde(default)]
    pub flag: Option<String>,
    /// `true` when the mandate has a non-wildcard scope that v0 **recorded but
    /// did not enforce** (op/zone/amount). A `Valid` act may exceed it.
    #[serde(default)]
    pub scope_deferred: Option<bool>,
    /// Present only when the flag genuinely attributes the act to this principal
    /// (`Valid`/`Lapsed`/`NotYetValid`/`PostRevocation`/`OverScope`).
    #[serde(default)]
    pub principal_identity_hash: Option<String>,
    /// Present only for `AgentMismatch` — the principal is **exonerated**.
    #[serde(default)]
    pub principal_note: Option<String>,
    #[serde(default)]
    pub chain_depth: Option<u64>,
    /// Verified leaf→root chain — non-empty only on a `Valid` verdict.
    #[serde(default)]
    pub lineage: Vec<LineageHopView>,
    #[serde(default)]
    pub lineage_note: Option<String>,
}

/// The safe, misread-proof verdict for a single act. There is no bare
/// `authorized: bool`; the caveats live inside the variants so a caller must
/// confront them.
#[derive(Debug, Clone)]
pub enum MandateActVerdict {
    /// This record is not a mandate act on this node. With
    /// [`Coverage::IncompleteSnapshotFollower`] this is **not** definitive.
    NotAMandateAct { coverage: Coverage },
    /// The node returned a flag string this SDK does not recognize (the node is
    /// newer than this client). Never treated as "not authorized".
    UnknownFlag { raw: String, coverage: Coverage },
    /// Fully authorized: `Valid`, on an authoritative node, with scope enforced
    /// (`!scope_deferred`). The only unqualified-authorization state.
    Authorized {
        agent: String,
        /// The authorizing principal (always present for `Valid`).
        principal: Option<String>,
        mandate_ref: String,
        act_timestamp_ms: u64,
        lineage: Vec<LineageHopView>,
    },
    /// `Valid`, **but** one or more caveats apply: a non-authoritative node
    /// and/or `scope_deferred`. Inspect the fields before relying on it.
    AuthorizedWithCaveats {
        agent: String,
        principal: Option<String>,
        mandate_ref: String,
        act_timestamp_ms: u64,
        coverage: Coverage,
        /// `true` = op/zone/amount scope was recorded but NOT enforced in v0.
        scope_deferred: bool,
        lineage: Vec<LineageHopView>,
    },
    /// The flag is not `Valid`. `principal` is present only when the flag
    /// attributes to it (anti-libel — absent for `NoChain`/`AgentMismatch`/etc).
    NotAuthorized {
        flag: MandateFlag,
        agent: Option<String>,
        principal: Option<String>,
        mandate_ref: Option<String>,
        act_timestamp_ms: Option<u64>,
        coverage: Coverage,
        scope_deferred: bool,
    },
}

impl MandateActVerdict {
    /// True ONLY for the unqualified [`Self::Authorized`] state (authoritative
    /// node, scope enforced, `Valid`). Use this for a security-gating decision.
    pub fn is_authorized_strict(&self) -> bool {
        matches!(self, MandateActVerdict::Authorized { .. })
    }

    /// True for `Valid` as judged by this node, *including* the caveated case.
    /// Honest name: this is "this node says Valid", which may be incomplete
    /// (snapshot follower) or scope-unenforced. Prefer [`Self::is_authorized_strict`]
    /// unless you have separately handled the caveats.
    pub fn is_valid_on_this_node(&self) -> bool {
        matches!(
            self,
            MandateActVerdict::Authorized { .. } | MandateActVerdict::AuthorizedWithCaveats { .. }
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_act(
    flag: MandateFlag,
    coverage: Coverage,
    scope_deferred: bool,
    agent: Option<String>,
    principal: Option<String>,
    mandate_ref: Option<String>,
    act_timestamp_ms: Option<u64>,
    lineage: Vec<LineageHopView>,
) -> MandateActVerdict {
    if flag.is_authorized() {
        if coverage.is_authoritative() && !scope_deferred {
            MandateActVerdict::Authorized {
                agent: agent.unwrap_or_default(),
                principal,
                mandate_ref: mandate_ref.unwrap_or_default(),
                act_timestamp_ms: act_timestamp_ms.unwrap_or(0),
                lineage,
            }
        } else {
            MandateActVerdict::AuthorizedWithCaveats {
                agent: agent.unwrap_or_default(),
                principal,
                mandate_ref: mandate_ref.unwrap_or_default(),
                act_timestamp_ms: act_timestamp_ms.unwrap_or(0),
                coverage,
                scope_deferred,
                lineage,
            }
        }
    } else {
        MandateActVerdict::NotAuthorized {
            flag,
            agent,
            principal,
            mandate_ref,
            act_timestamp_ms,
            coverage,
            scope_deferred,
        }
    }
}

impl MandateActStatus {
    /// Distil the raw response into a misread-proof [`MandateActVerdict`].
    pub fn classify(&self) -> MandateActVerdict {
        let coverage = Coverage::from_authoritative_complete(self.authoritative_complete);
        if !self.is_mandate_act {
            return MandateActVerdict::NotAMandateAct { coverage };
        }
        let raw = self.flag.clone().unwrap_or_default();
        let Some(flag) = MandateFlag::from_str(&raw) else {
            return MandateActVerdict::UnknownFlag { raw, coverage };
        };
        classify_act(
            flag,
            coverage,
            self.scope_deferred.unwrap_or(false),
            self.agent_identity_hash.clone(),
            self.principal_identity_hash.clone(),
            self.mandate_ref.clone(),
            self.act_timestamp_ms,
            self.lineage.clone(),
        )
    }
}

// ─── Typed parse of GET /mandate/{mandate_id} ─────────────────────────────────

/// A mandate's declared scope, as recorded on-chain. In v0 a non-wildcard scope
/// is **recorded but not enforced** (`scope_enforced_v0` on [`MandateDetail`]).
#[derive(Debug, Clone, Deserialize)]
pub struct MandateScopeView {
    #[serde(default)]
    pub allowed_ops: Vec<String>,
    #[serde(default)]
    pub allowed_zones: Vec<String>,
    #[serde(default)]
    pub max_amount: Option<u64>,
}

/// Typed parse of a *found* `GET /mandate/{mandate_id}` (the client returns
/// `Ok(None)` for the `{found:false}` case, so every field here is populated).
#[derive(Debug, Clone, Deserialize)]
pub struct MandateDetail {
    pub mandate_id: String,
    pub network_id: String,
    pub principal_identity_hash: String,
    pub agent_identity_hash: String,
    pub scope: MandateScopeView,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    #[serde(default)]
    pub parent_mandate_id: Option<String>,
    #[serde(default)]
    pub sub_delegation_max_depth: u8,
    /// `true` only for a wildcard scope — for a non-wildcard scope, op/zone/amount
    /// are recorded but NOT enforced in v0.
    #[serde(default)]
    pub scope_enforced_v0: bool,
    #[serde(default)]
    pub revoked: bool,
    /// Wall-clock ms of the principal-authorized revocation, if revoked.
    #[serde(default)]
    pub revoked_at_ms: Option<u64>,
}

// ─── Typed parse of GET /mandate/{mandate_id}/acts ────────────────────────────

/// One compact row of `GET /mandate/{id}/acts`. Like [`MandateActStatus`] but
/// without per-row coverage (it is page-level on [`MandateActsPage`]); pass the
/// page's [`MandateActsPage::coverage`] to [`Self::classify`].
#[derive(Debug, Clone, Deserialize)]
pub struct MandateActSummary {
    pub record_id: String,
    #[serde(default)]
    pub mandate_ref: Option<String>,
    #[serde(default)]
    pub agent_identity_hash: Option<String>,
    #[serde(default)]
    pub act_timestamp_ms: Option<u64>,
    #[serde(default)]
    pub amount: Option<u64>,
    #[serde(default)]
    pub flag: Option<String>,
    #[serde(default)]
    pub scope_deferred: Option<bool>,
    #[serde(default)]
    pub principal_identity_hash: Option<String>,
    #[serde(default)]
    pub principal_note: Option<String>,
}

impl MandateActSummary {
    /// Classify this row given the page-level [`Coverage`]. (Acts-list rows are
    /// always mandate acts, so there is no `NotAMandateAct` outcome here.)
    pub fn classify(&self, coverage: Coverage) -> MandateActVerdict {
        let raw = self.flag.clone().unwrap_or_default();
        let Some(flag) = MandateFlag::from_str(&raw) else {
            return MandateActVerdict::UnknownFlag { raw, coverage };
        };
        classify_act(
            flag,
            coverage,
            self.scope_deferred.unwrap_or(false),
            self.agent_identity_hash.clone(),
            self.principal_identity_hash.clone(),
            self.mandate_ref.clone(),
            self.act_timestamp_ms,
            Vec::new(),
        )
    }
}

/// Typed parse of a `GET /mandate/{mandate_id}/acts` page.
#[derive(Debug, Clone, Deserialize)]
pub struct MandateActsPage {
    pub mandate_id: String,
    /// `present-with-zero-acts` vs `unknown-mandate` are different answers.
    #[serde(default)]
    pub mandate_found: bool,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub acts: Vec<MandateActSummary>,
    /// Opaque keyset cursor — pass back as `from` to page forward; `None` ends it.
    #[serde(default)]
    pub next_from: Option<String>,
    /// `false` on a snapshot follower whose enumeration may omit pre-baseline
    /// acts — so `{mandate_found:true, count:0}` there is not "never acted".
    #[serde(default)]
    pub authoritative_complete: bool,
    /// Set (e.g. `"malformed_mandate_id"`) when the request was rejected; the
    /// HTTP client maps this to an error.
    #[serde(default)]
    pub error: Option<String>,
}

impl MandateActsPage {
    /// Page-level coverage to pass to [`MandateActSummary::classify`].
    pub fn coverage(&self) -> Coverage {
        Coverage::from_authoritative_complete(self.authoritative_complete)
    }
}

// ─── HTTP query client (native only — mirrors network::light_sdk) ─────────────

#[cfg(feature = "node-core")]
pub use http_client::{MandateQueryClient, MandateSdkError};

#[cfg(feature = "node-core")]
mod http_client {
    use super::*;
    use std::time::Duration;

    /// Errors from the read-only mandate HTTP client.
    #[derive(Debug, thiserror::Error)]
    pub enum MandateSdkError {
        #[error("HTTP error: {0}")]
        Http(String),
        #[error("response parse error: {0}")]
        Parse(String),
        /// The node accepted the request but returned an in-band error (e.g. a
        /// malformed mandate id on `/mandate/{id}/acts`).
        #[error("node returned an error: {0}")]
        NodeError(String),
        #[error("reqwest client build failed: {0}")]
        ClientBuild(String),
    }

    pub type Result<T> = std::result::Result<T, MandateSdkError>;

    /// Read-only HTTP client for the mandate accountability endpoints. Holds **no
    /// key material** — it can only query. Mirrors
    /// [`crate::network::light_sdk::LightClient`]: a fixed node URL + a reqwest
    /// client with redirects disabled (SSRF guard).
    pub struct MandateQueryClient {
        node_url: String,
        http: reqwest::Client,
    }

    impl MandateQueryClient {
        /// Build a client pointed at a node's public read URL. The URL must
        /// include scheme + host:port — e.g. `http://127.0.0.1:9474`. (The
        /// reverse `/agent/{hash}/acts` index is loopback-only by design and is
        /// deliberately not exposed by this SDK.)
        pub fn new(node_url: impl Into<String>) -> Result<Self> {
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                // SSRF: only ever talk to the fixed node; never follow a redirect
                // a hostile node could point at an internal address.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| MandateSdkError::ClientBuild(e.to_string()))?;
            Ok(Self {
                node_url: node_url.into(),
                http,
            })
        }

        pub fn node_url(&self) -> &str {
            &self.node_url
        }

        async fn get_text(&self, path: &str) -> Result<String> {
            let url = format!("{}{}", self.node_url, path);
            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| MandateSdkError::Http(format!("{url}: {e}")))?;
            if !resp.status().is_success() {
                return Err(MandateSdkError::Http(format!(
                    "{url}: HTTP {}",
                    resp.status().as_u16()
                )));
            }
            resp.text()
                .await
                .map_err(|e| MandateSdkError::Http(format!("{url}: {e}")))
        }

        /// `GET /mandate/status/{record_id}` → the typed status. Call
        /// [`MandateActStatus::classify`] on the result for a misread-proof
        /// verdict — do not branch on the raw fields.
        pub async fn act_status(&self, record_id: &str) -> Result<MandateActStatus> {
            let body = self
                .get_text(&format!("/mandate/status/{record_id}"))
                .await?;
            serde_json::from_str(&body).map_err(|e| MandateSdkError::Parse(e.to_string()))
        }

        /// `GET /mandate/{mandate_id}` → the mandate, or `None` when unknown.
        pub async fn mandate_detail(&self, mandate_id: &str) -> Result<Option<MandateDetail>> {
            let body = self.get_text(&format!("/mandate/{mandate_id}")).await?;
            let v: serde_json::Value =
                serde_json::from_str(&body).map_err(|e| MandateSdkError::Parse(e.to_string()))?;
            if !v.get("found").and_then(|f| f.as_bool()).unwrap_or(false) {
                return Ok(None);
            }
            serde_json::from_value(v)
                .map(Some)
                .map_err(|e| MandateSdkError::Parse(e.to_string()))
        }

        /// `GET /mandate/{mandate_id}/acts?from=&limit=` → one bounded page. Pass
        /// the returned [`MandateActsPage::next_from`] back as `from` to page
        /// forward (`None` ends it). A malformed mandate id maps to
        /// [`MandateSdkError::NodeError`].
        pub async fn mandate_acts(
            &self,
            mandate_id: &str,
            from: Option<&str>,
            limit: usize,
        ) -> Result<MandateActsPage> {
            let mut path = format!("/mandate/{mandate_id}/acts?limit={limit}");
            if let Some(f) = from {
                path.push_str("&from=");
                path.push_str(f);
            }
            let body = self.get_text(&path).await?;
            let page: MandateActsPage =
                serde_json::from_str(&body).map_err(|e| MandateSdkError::Parse(e.to_string()))?;
            if let Some(err) = &page.error {
                return Err(MandateSdkError::NodeError(err.clone()));
            }
            Ok(page)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_from(json: &str) -> MandateActStatus {
        serde_json::from_str(json).expect("valid MandateActStatus json")
    }

    #[test]
    fn not_found_response_parses_and_is_not_a_mandate_act() {
        // The not-found shape carries ONLY these three fields — a flat
        // required-field struct would fail to parse this valid response.
        let s = status_from(
            r#"{"record_id":"abc","is_mandate_act":false,"authoritative_complete":true}"#,
        );
        assert!(matches!(
            s.classify(),
            MandateActVerdict::NotAMandateAct {
                coverage: Coverage::Authoritative
            }
        ));
    }

    #[test]
    fn not_found_on_snapshot_follower_is_non_authoritative() {
        let s = status_from(
            r#"{"record_id":"abc","is_mandate_act":false,"authoritative_complete":false}"#,
        );
        // A follower's "no" is a possible false negative — coverage says so.
        assert!(matches!(
            s.classify(),
            MandateActVerdict::NotAMandateAct {
                coverage: Coverage::IncompleteSnapshotFollower
            }
        ));
    }

    #[test]
    fn clean_valid_is_authorized() {
        let s = status_from(
            r#"{"record_id":"r","is_mandate_act":true,"authoritative_complete":true,
                "mandate_ref":"m","agent_identity_hash":"a","act_timestamp_ms":5,
                "flag":"valid","scope_deferred":false,
                "principal_identity_hash":"p","authorized":true}"#,
        );
        match s.classify() {
            MandateActVerdict::Authorized {
                agent,
                principal,
                mandate_ref,
                act_timestamp_ms,
                ..
            } => {
                assert_eq!(agent, "a");
                assert_eq!(principal.as_deref(), Some("p"));
                assert_eq!(mandate_ref, "m");
                assert_eq!(act_timestamp_ms, 5);
            }
            other => panic!("expected Authorized, got {other:?}"),
        }
        assert!(s.classify().is_authorized_strict());
    }

    #[test]
    fn valid_on_snapshot_follower_does_not_collapse_to_authorized() {
        // The load-bearing caveat-non-collapse test: Valid + non-authoritative
        // must NOT yield the unqualified Authorized state.
        let s = status_from(
            r#"{"record_id":"r","is_mandate_act":true,"authoritative_complete":false,
                "mandate_ref":"m","agent_identity_hash":"a","act_timestamp_ms":5,
                "flag":"valid","scope_deferred":false,"authorized":true}"#,
        );
        let v = s.classify();
        assert!(!v.is_authorized_strict(), "must not be strictly authorized");
        assert!(matches!(
            v,
            MandateActVerdict::AuthorizedWithCaveats {
                coverage: Coverage::IncompleteSnapshotFollower,
                ..
            }
        ));
    }

    #[test]
    fn valid_with_scope_deferred_is_caveated() {
        let s = status_from(
            r#"{"record_id":"r","is_mandate_act":true,"authoritative_complete":true,
                "mandate_ref":"m","agent_identity_hash":"a","act_timestamp_ms":5,
                "flag":"valid","scope_deferred":true,"authorized":true}"#,
        );
        let v = s.classify();
        assert!(!v.is_authorized_strict());
        assert!(matches!(
            v,
            MandateActVerdict::AuthorizedWithCaveats {
                scope_deferred: true,
                coverage: Coverage::Authoritative,
                ..
            }
        ));
    }

    #[test]
    fn post_revocation_is_not_authorized_and_names_principal() {
        let s = status_from(
            r#"{"record_id":"r","is_mandate_act":true,"authoritative_complete":true,
                "mandate_ref":"m","agent_identity_hash":"a","act_timestamp_ms":5,
                "flag":"post_revocation","scope_deferred":false,
                "principal_identity_hash":"p","authorized":false}"#,
        );
        match s.classify() {
            MandateActVerdict::NotAuthorized {
                flag,
                principal,
                ..
            } => {
                assert_eq!(flag, MandateFlag::PostRevocation);
                assert_eq!(principal.as_deref(), Some("p"));
            }
            other => panic!("expected NotAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn agent_mismatch_carries_no_principal() {
        // The node omits principal_identity_hash for AgentMismatch (anti-libel);
        // the SDK must preserve that — no principal in the verdict.
        let s = status_from(
            r#"{"record_id":"r","is_mandate_act":true,"authoritative_complete":true,
                "mandate_ref":"m","agent_identity_hash":"a","act_timestamp_ms":5,
                "flag":"agent_mismatch","scope_deferred":false,
                "principal_note":"the referenced mandate authorized a different agent",
                "authorized":false}"#,
        );
        match s.classify() {
            MandateActVerdict::NotAuthorized {
                flag, principal, ..
            } => {
                assert_eq!(flag, MandateFlag::AgentMismatch);
                assert!(principal.is_none(), "AgentMismatch must not name a principal");
            }
            other => panic!("expected NotAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn unknown_flag_from_newer_node_is_not_collapsed_to_unauthorized() {
        let s = status_from(
            r#"{"record_id":"r","is_mandate_act":true,"authoritative_complete":true,
                "mandate_ref":"m","agent_identity_hash":"a","act_timestamp_ms":5,
                "flag":"some_v2_flag","scope_deferred":false,"authorized":false}"#,
        );
        assert!(matches!(
            s.classify(),
            MandateActVerdict::UnknownFlag { .. }
        ));
    }

    #[test]
    fn malformed_reference_is_not_authorized() {
        let s = status_from(
            r#"{"record_id":"r","is_mandate_act":true,"authoritative_complete":true,
                "mandate_ref":"zz","agent_identity_hash":"a","act_timestamp_ms":5,
                "flag":"malformed","scope_deferred":false,"authorized":false}"#,
        );
        assert!(matches!(
            s.classify(),
            MandateActVerdict::NotAuthorized {
                flag: MandateFlag::Malformed,
                ..
            }
        ));
    }

    #[test]
    fn status_lineage_parses_with_http_field_names() {
        let s = status_from(
            r#"{"record_id":"r","is_mandate_act":true,"authoritative_complete":true,
                "mandate_ref":"m","agent_identity_hash":"a","act_timestamp_ms":5,
                "flag":"valid","scope_deferred":false,"principal_identity_hash":"p",
                "chain_depth":1,
                "lineage":[{"hop_index":0,"mandate_id":"m","principal_identity_hash":"p","agent_identity_hash":"a"}]}"#,
        );
        assert_eq!(s.lineage.len(), 1);
        assert_eq!(s.lineage[0].mandate_id, "m");
        match s.classify() {
            MandateActVerdict::Authorized { lineage, .. } => assert_eq!(lineage.len(), 1),
            other => panic!("expected Authorized, got {other:?}"),
        }
    }

    #[test]
    fn acts_page_and_summary_classify() {
        let page: MandateActsPage = serde_json::from_str(
            r#"{"mandate_id":"m","mandate_found":true,"count":1,
                "acts":[{"record_id":"r","mandate_ref":"m","agent_identity_hash":"a",
                         "act_timestamp_ms":5,"amount":null,"flag":"valid",
                         "scope_deferred":false,"principal_identity_hash":"p","authorized":true}],
                "next_from":null,"authoritative_complete":true}"#,
        )
        .expect("valid page");
        assert_eq!(page.count, 1);
        assert!(page.coverage().is_authoritative());
        assert!(page.acts[0].classify(page.coverage()).is_authorized_strict());
    }

    #[test]
    fn acts_page_malformed_id_shape_parses() {
        let page: MandateActsPage = serde_json::from_str(
            r#"{"mandate_id":"zz","error":"malformed_mandate_id","acts":[],"count":0}"#,
        )
        .expect("malformed-id page must still parse");
        assert_eq!(page.error.as_deref(), Some("malformed_mandate_id"));
        assert!(page.acts.is_empty());
    }

    #[test]
    fn mandate_detail_found_shape_parses() {
        let d: MandateDetail = serde_json::from_str(
            r#"{"mandate_id":"m","found":true,"network_id":"elara-mainnet",
                "principal_identity_hash":"p","agent_identity_hash":"a",
                "scope":{"allowed_ops":["agent_audit"],"allowed_zones":[],"max_amount":null},
                "not_before_ms":1,"not_after_ms":2,"parent_mandate_id":null,
                "sub_delegation_max_depth":0,"scope_enforced_v0":false,
                "revoked":false,"revoked_at_ms":null}"#,
        )
        .expect("valid detail");
        assert_eq!(d.network_id, "elara-mainnet");
        assert_eq!(d.scope.allowed_ops, vec!["agent_audit".to_string()]);
        assert!(!d.scope_enforced_v0);
    }

    #[test]
    fn verify_bundle_delegates_to_core() {
        // The re-export must be a faithful passthrough (same flag as the core),
        // and it must preserve the non-dismissible soundness caveats.
        let garbage = "not even json";
        let via_sdk = verify_bundle(garbage);
        let via_core = evaluate_mandate_bundle(garbage);
        assert_eq!(via_sdk.flag, via_core.flag);
        assert!(!via_sdk.authorized);
        assert!(
            !via_sdk.soundness_caveats.is_empty(),
            "soundness caveats must always be present"
        );
    }
}
