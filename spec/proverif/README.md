# ProVerif model of the Elara PQ transport

Symbolic (Dolev-Yao) security proof of Elara's post-quantum network transport —
the 3-message **handshake** and the post-handshake **record/stream** layer —
machine-checked with [ProVerif](https://proverif.inria.fr/) 2.05. Companion to
the TLA+ consensus model in [`../tla/`](../tla/). CI-gated as `formal-proverif`.

The handshake (`crates/elara-pq-transport/src/handshake.rs`) is a 3-message
Noise-XX-style **hybrid** key exchange: X25519 ECDH **and** ML-KEM-768 KEM for
the session secret, mutually authenticated by Dilithium3 / ML-DSA-65 signatures
over the running SHA3-256 transcript, with ChaCha20-Poly1305 for the channel.

## What is proven

Under an attacker that fully controls the network, ProVerif establishes:

| Scenario (`scenarios/`) | Property | Expected |
|---|---|---|
| `baseline` | session-key secrecy | holds |
| `baseline` | initiator injectively authenticates responder (over the transcript) | holds |
| `baseline` | responder injectively authenticates initiator (over the transcript) | holds |
| `mlkem_broken` | secrecy with **ML-KEM fully broken** (X25519 carries it) | holds |
| `x25519_broken` | secrecy with **X25519 fully broken** (ML-KEM carries it) | holds |
| `both_broken` | secrecy with **both broken** | **fails** (intentional) |
| `forward_secrecy` | **forward secrecy**: both long-term keys leak *after* the sessions | holds |
| `forward_secrecy_broken` | responder key known *during* the session ⇒ MITM | **fails** (intentional) |
| `kci` | **KCI resistance**: initiator's own key `skI` leaked *during* sessions — session-key secrecy holds | holds |
| `kci` | initiator (with `skI` leaked) still injectively authenticates the pinned responder | holds |
| `kci` | attacker holding `skI` impersonates the *compromised party itself* to the accept-any responder | **fails** (expected, not KCI) |
| `kci_broken` | `kci` world but the **pinned peer's** key `skR` also leaked ⇒ MITM | **fails** (intentional) |
| `uks` | **UKS / identity-misbinding freedom**: two honest initiators I, I2 both pin R — R never cross-attributes one initiator's session to the other (per-identity injective agreement) | holds (×2) |
| `uks` | session-key secrecy survives the multi-principal world | holds |
| `uks_broken` | I2's key `skI2` leaked — I's attribution still holds (cross-key signature separation) | holds |
| `uks_broken` | …while I2's attribution becomes forgeable (non-vacuity witness: `RespAcceptInit(skI2,·)` is reachable) | **fails** (intentional) |
| `uks_broken_sym` | mirror (`skI` leaked) — witnesses `RespAcceptInit(skI,·)` reachable; I2's attribution holds | **fails** / holds (intentional) |

Mutual authentication is the headline: the transcript-bound Dilithium3
signature is proven to be the man-in-the-middle defense, not merely asserted.

The hybrid property cannot be one query (a symbolic attacker either can or
cannot derive a value), so it is decomposed into capability-grant sub-models.
`both_broken` is an **intentional violation** — the analogue of
[`../tla/MCTightBreak`](../tla/): the session key is derived by **public** KDF
constructors the attacker can apply to anything it knows, so secrecy holds
exactly when one shared secret is missing. If `both_broken` ever reported
secrecy *holding*, the KDF abstraction would be vacuous and every hybrid pass
above meaningless. Its failure proves the abstraction is sound.

`forward_secrecy` uses ProVerif's `phase` clock: unboundedly many honest
sessions run in phase 0, then **both** long-term Dilithium3 keys are handed to
the attacker in phase 1, and the query is checked against that post-compromise
attacker (`attacker_p1`). It holds because the session secret is derived only
from per-session ephemerals (X25519 + ML-KEM); the long-term keys *sign* the
transcript but never enter the KDF, so leaking them afterwards reveals nothing
about a past session. `forward_secrecy_broken` is the non-vacuity gate (analogue
of `both_broken`): the **same** honest sessions, but the responder key is known
*during* them — the attacker then MITMs the pinned initiator and the probe
leaks. The pair proves the property is timing-dependent (reveal-after is safe,
reveal-during is fatal) — which is exactly what forward secrecy is — and that
the `is true` is not vacuous (probe genuinely is reachable).

**Unknown-key-share (UKS) / identity-misbinding** is the one property that needs
**more than one honest initiator**, so `uks` is the first multi-principal model:
two honest initiators `I`, `I2` both pin the same honest responder `R`. The
question is whether the **accept-any responder** — whose session keys
`kdf_{send,recv}(dh_ss, kem_ss, t2)` contain *no* initiator long-term identity,
and which authenticates the initiator *solely* by the Dilithium3 signature inside
the msg3 AEAD — can be driven to attribute a completed session to the **wrong**
honest identity. It cannot: `RespAcceptInit(spk(skI),·) ⇒ InitCommit(spk(skI),·)`
and the same for `skI2` both hold injectively. The structural reason is that the
initiator's identity rides *inside* the msg3 blob, AEAD-encrypted under a session
key only the genuine endpoints can derive — a relay attacker cannot re-encrypt a
substituted identity (it never holds that key), so `R` always records the true
signer. The queries are deliberately **per-identity (ground), not one
universally-quantified `∀xpk`** query: the ∀-form is *false* here, and correctly
so — the accept-any responder lets the Dolev-Yao attacker generate its *own*
keypair and complete a session recorded under its own key, which is the attacker
being recorded as *itself*, by design, not a UKS. UKS-freedom is therefore a claim
about the *honest* identities, and the ground queries holding **in the presence of
that key-registering attacker** is exactly registered-key-UKS resistance — no
extra corrupt principal is needed. The **initiator** side needs no UKS query at
all: it pins (`idh(rpk)=idh(pkRexp)`, a full-public-key equality in the symbolic
model since `idh` is an injective constructor), so it is UKS-immune by
construction — a second honest *responder* would only re-derive that, and is
omitted (the symbolic `idh` abstracts identity-hash collision, so this immunity is
a modelling assumption, not a proof of SHA3-256 collision resistance).

Non-vacuity follows the same-world-twin convention as `kci`. Because `uks` has
*two* `true` authentication queries, **both** accept events are machine-witnessed
reachable rather than one being argued "by symmetry": `uks_broken` leaks `skI2`
(so the attacker completes a *fresh* session **as** I2 — its own ephemerals, hence
a real session key — and signs with the leaked key, flipping I2's query to
`false`), and `uks_broken_sym` leaks `skI` and flips I's query instead. Each twin
also doubles as a precise **cross-key separation** check: leaking one initiator's
key leaves the *other's* attribution intact (`true`), because forging the other's
msg3 needs *its* signing key — this is signature unforgeability holding per-key
between two distinct identities, stated precisely, not a broad "isolation" claim.
Secrecy stays `true` across both twins (the responder emits no probe; the honest
initiators still complete only with the honest `R`).

## Post-handshake record/stream protocol

Once the handshake yields the two directional session keys, the record layer
(driver `src/network/pq_transport/stream.rs`, AEAD primitives
`crates/elara-pq-transport/src/crypto.rs`) carries application payloads as a
sequence of ChaCha20-Poly1305 frames — one per `send`, each sealed under a
**strictly-monotonic per-direction counter nonce** (4 zero bytes ‖ 8-byte
big-endian counter), with the 1-byte frame **type bound into the AEAD associated
data**. The receiver is **strictly sequential**: it opens frame *i* only under
counter *i*, then advances (`decrypt_frame`), so any replay, reorder, or
injection lands on the wrong nonce and fails the Poly1305 tag. `Rekey` is
unimplemented (`RekeyUnsupported`), so no key-rotation claim is made.

`elara_record_core.pvi` shares the AEAD primitives and the cleartext frame-type
tags; each `scenarios/record_*.pvh` carries its own sender/receiver body so the
non-vacuity twins can vary the protocol. Under a network-controlling attacker:

| Scenario (`scenarios/`) | Property | Expected |
|---|---|---|
| `record_baseline` | record payload secrecy | holds |
| `record_baseline` | injective agreement — every record the receiver accepts was sent, once, in order (no replay / reorder / injection) | holds |
| `record_nonce_reuse` | reuse the counter ⇒ replay reappears | **fails** (intentional) |
| `record_direction` | direction separation — a frame in one direction is never accepted in the other (distinct `k_send`/`k_recv`) | holds (×2) |
| `record_direction_confusion` | collapse `k_send = k_recv` ⇒ a reflected frame is accepted | **fails** (intentional) |
| `record_no_aead` | strip the AEAD ⇒ forgery **and** payload disclosure | **fails** (intentional) |
| `record_type_binding` | the cleartext type byte is bound into the AD ⇒ a relabelled `Data`→`Admission` frame cannot misroute an authenticated payload | holds |
| `record_type_binding_broken` | empty AD (the pre-fix design) ⇒ the relabel misroutes | **fails** (intentional) |
| `record_close_unauth` | the unauthenticated `Close` frame ⇒ a forged teardown (truncation) | **fails** (intentional — documents the gap) |

**Anti-replay rests on per-session keys *and* distinct counters — both are
machine-witnessed load-bearing.** The injective query holds in `record_baseline`
only because the key is fresh per session (a handshake binds it to a distinct
transcript) *and* the receiver is strictly sequential over distinct counters. A
single global key across sessions would readmit cross-session replay, and a
reused counter (`record_nonce_reuse`) readmits in-session replay — the latter is
the explicit non-vacuity twin, the analogue of the handshake's `both_broken`.

**The frame type byte is bound into the AEAD.** The ELPQ wire header carries the
1-byte frame type (`frame.rs`) in the **clear**, outside the ciphertext, so an
on-path attacker can relabel `Data`↔`StreamChunk`↔`Admission` without touching
the Poly1305-protected payload. Binding the observed type into the associated
data (`send_typed` / `decrypt_frame`) means a relabelled frame opens under the
wrong AD and fails the tag, so it cannot be dispatched down the wrong branch
(`handle_inbound_admission`). `record_type_binding` proves the misroute event is
unreachable; its twin `record_type_binding_broken` shows it *is* reachable under
the prior empty-AD design — i.e. the binding is load-bearing, not decorative.
The `/pq-ws` transport (`ws_session.rs`) needs no analogous binding: it has no
cleartext type byte — unary-vs-stream intent lives *inside* the AEAD-sealed
`PqResponse`/`PqStreamChunk` envelope, and dispatch keys off `req.method` inside
the ciphertext.

**Injective agreement is a *safety* property, not *liveness*.** It states "no
spurious accepts" — every accepted record was genuinely sent, in order — and it
is what rules out replay/reorder/injection. It does **not** claim *delivery
completeness*: an attacker that drops the tail of a stream trivially satisfies
it. The record layer has no authenticated stream terminator — `Close` is an
unauthenticated cleartext framing signal (`stream.rs`), so a forged `Close` can
truncate a session early. `record_close_unauth` makes that boundary explicit (a
deliberate `false`, the analogue of `forward_secrecy_broken`) rather than leaving
it silent. Application payloads are discrete self-framed blobs, so truncation is
detectable above this layer; an authenticated terminator is a candidate hardening,
not a claimed property.

## Layout

- `elara_handshake_core.pvi` — the handshake protocol body (single source of truth).
- `elara_record_core.pvi` — shared AEAD primitives + cleartext frame-type tags
  for the record scenarios (whose bodies vary per twin).
- `elara_composed_core.pvi` — handshake ∘ record layer with the record key = the
  genuine handshake output (verbatim handshake mirror; see *Full composition*).
- `elara_admission_core.pvi` — handshake ∘ realm-admission cert exchange (verbatim
  handshake mirror; see *Realm admission*).
- `scenarios/*.pvh` — per-scenario queries + top-level process.
- `run-proverif.sh` — concatenates core + each scenario, runs ProVerif, and
  asserts each scenario's **expected** outcome (including the intentional
  `both_broken`, `forward_secrecy_broken` and `kci_broken` violations, the
  expected non-KCI auth failure inside `kci`, and the intentional per-identity
  failures inside the `uks_broken` / `uks_broken_sym` non-vacuity twins). The
  `uks` twins are matched by **event name** — `RespAcceptInit(spk(skI[]),…)` vs
  `RespAcceptInit(spk(skI2[]),…)` — so the two initiators' results cannot be
  confused. The record scenarios run against `elara_record_core.pvi` and are
  asserted the same way (by query event name, not a bare `is false` grep). Exit
  0 = all twenty-five as expected (incl. the two `composed_*` full-composition
  scenarios — `composed_broken` is asserted by its goal-reachable line — and the
  four `admission_*` realm-admission scenarios).

## Model ↔ code correspondence

| Model (`elara_handshake_core.pvi`) | Code (`crates/elara-pq-transport/src/…`) |
|---|---|
| `msg1 = (ts0, exp(g,xi), kempk(ikem))` | `handshake.rs` timestamp ‖ X25519 eph pk ‖ ML-KEM eph pk |
| `repk_x, ct, aead2` (msg2) | resp X25519 pk ‖ ML-KEM ct ‖ AEAD(pk‖sig) |
| `aead(t3,(pk,sig),ksend)` (msg3) | AEAD(pk‖sig) |
| `exp(_,_)` / `encap`/`decap`/`kemss` | X25519 ECDH (`crypto.rs`) / ML-KEM (`kem.rs`) |
| `t1=h(msg1)`, `t2=h((t1,msg2pub))`, `t3=h((t2,aead2))` | running SHA3-256 transcript (`crypto.rs`) |
| `kdf_send/recv(dh_ss,kem_ss,t2)` | `derive_session_keys`: HKDF, IKM `x25519‖ml_kem`, salt = transcript, two labels, role-flip (`crypto.rs`) |
| `sign(t2,skR)` / `sign(t3,skI)` | Dilithium3 over the transcript snapshot, empty context (`handshake.rs`, `sig.rs`) |
| `aead(ad,pt,k)`, `ad=t2`/`t3` | ChaCha20-Poly1305, transcript snapshot as associated data (`crypto.rs`) |
| `idh(pk)`, init pin check | `identity_hash = SHA3-256(pk)`, `PeerExpectation::Pinned` (`handshake.rs`) |
| responder fires accept with no pin | responder accepts any initiator, `peer_expectation = None` (`handshake.rs`) |

## Modeled / abstracted / omitted

**Abstracted (sound, possibly incomplete):** ML-KEM as a generic IND-CCA KEM
with **no** false ciphertext-binding equation (the ciphertext is folded into the
transcript before key derivation, so malleability is caught by the signed
transcript); HKDF as one public KDF constructor per label (soundness enforced by
`both_broken` failing); ProVerif's basic DH theory (no low-order points);
signatures/hashes as ideal symbolic primitives.

**Deliberately omitted:** the 30-second timestamp-skew check (a pre-crypto DoS
fast-abort with no cryptographic role; Dolev-Yao has no clock — replay
resistance comes from per-session ephemerals + injective agreement). The
post-handshake record/stream protocol is modelled both ways: standalone (see
*Post-handshake record/stream protocol* above) against an **abstract per-session
key**, AND **fully composed** with `elara_handshake_core.pvi` (see *Full
composition* below) so the record key is the genuine handshake output. The
standalone record model proves the layer is sound *given* a good per-session key;
the composition proves that key genuinely IS the secret, transcript-bound
handshake output and the record properties survive an attacker who saw the whole
transcript.

**Forward secrecy — scope of the `forward_secrecy` proof.** It covers compromise
of the **long-term Dilithium3 signing keys only** (skI, skR), the realistic
"identity key stolen later" threat. It does **not** model compromise of
per-session ephemeral state (the X25519 scalars or ML-KEM decapsulation key): in
the symbolic model those are `new`-bound per session and never leave the role
process, mirroring the code (`EphemeralSecret` is consumed; `KemKeypair`
zeroizes on drop), so there is no separate "ephemeral leak" scenario — leaking
them would by construction expose that one session's key. Post-compromise
security (safety of *new* sessions after a key leak) is explicitly **not**
claimed — `forward_secrecy_broken` shows such sessions are MITM-able.

**Key-Compromise-Impersonation (KCI) resistance** is machine-checked by the
`kci` / `kci_broken` pair (previously only *argued* from the model↔code table —
"the long-term key never enters the KDF"). `kci` hands the attacker the
**initiator's own** long-term key `skI` *during* the sessions (the realistic
"my own identity key was stolen" threat) while the responder stays honest, and
proves two properties hold: session-key secrecy, and the initiator's injective
authentication of the pinned responder — i.e. holding `skI` does **not** let the
attacker impersonate the honest responder *to* the initiator. The initiator is
the only meaningful KCI victim because it is the only party that pins; the
responder accepts any initiator, so "impersonate X to the responder" is not a
coherent KCI target there. An attacker holding `skI` can of course impersonate
the *compromised party itself* to the accept-any responder — `kci` asserts that
expected, non-KCI failure (a `false` result) rather than hiding it, which also
proves the model is live. `kci_broken` is the non-vacuity twin: the **same**
skI-public world but with the **pinned peer's** key `skR` *also* leaked, which
flips secrecy to broken — proving the probe genuinely flows in this world (so
`kci`'s pass is not vacuous) and isolating the KCI boundary, since the only
varied parameter is whether the pinned peer's key is also compromised: it is the
*peer's* key, never the *victim's own*, that is load-bearing for the victim's
session secrecy. `kci` cannot borrow `forward_secrecy_broken` for non-vacuity —
that twin lives in a different world (skR leaked, skI private), and a ProVerif
`true` is textually identical for a secure model and one whose probe is simply
unreachable, so the witness must live in the same world `kci` runs in.

**Unknown-Key-Share (UKS) / identity-misbinding resistance** is machine-checked by
the `uks` / `uks_broken` / `uks_broken_sym` trio (the first multi-principal model —
two honest initiators pinning one responder). It proves the accept-any responder
never cross-attributes one honest initiator's session to the other, even though
its session-key derivation carries no initiator identity; the binding is the msg3
identity blob being AEAD-sealed under a session key only the genuine endpoints can
derive. The full reasoning — why the queries are per-identity rather than a
(false-here) universally-quantified one, why no corrupt principal is needed, and
why the two same-world twins witness both accept events reachable — is in the
*"Unknown-key-share"* paragraphs under **What is proven** above.

**Coverage frontier.** The handshake's symbolic security surface (secrecy ·
mutual injective auth · hybrid degradation · forward secrecy · KCI · UKS), the
post-handshake record layer (secrecy · injective agreement / anti-replay ·
direction separation · type-dispatch integrity, with the truncation boundary
documented), their **full composition** (record key = genuine handshake output —
see *Full composition* below), AND the **realm-admission exchange** (`realm.rs`
membership-cert admission — see *Realm admission* below) are all now machine-
checked. What remains is **out of implemented scope, not a pending slice**:
ephemeral-state / weak-randomness compromise is *deliberately* excluded per the
forward-secrecy scope note below; revocation lists and M-of-N threshold roots are
`realm.rs` follow-ups that are **not yet built** (a feature is modelled when it
ships, not before). For every protocol behaviour implemented today, the symbolic
surface is complete.

## Full composition

`elara_composed_core.pvi` + `scenarios/composed_{baseline,broken}.pvh` close the
seam the two standalone cores leave open. The standalone record model
(`record_baseline`) seals its payload under `new k: key` — a fresh name the
Dolev-Yao attacker can never derive, so the record proofs are conditional on an
*idealized* key. The composition makes the record key the genuine handshake
output `kdf_send(dh_ss, kem_ss, t2)`: the honest initiator runs the real 3-message
hybrid handshake, then sends the secret `probe` as a post-handshake record frame
under its derived `ksend`; the responder runs the real handshake and exchanges a
record under its derived keys; one Dolev-Yao attacker observes the entire
transcript AND the record frames.

`composed_baseline` proves **four** properties hold together under the genuine
derived key: (1) record payload secrecy — so record secrecy rests on *handshake*
key secrecy; (2) record injective agreement / anti-replay in the **R→I
attributable direction** (the initiator pins the responder, so a record it
accepts under `krecv` can only come from the honest responder — the accept-any
responder direction is *not* attributable, mirroring the pinned-side-only
handshake probe); (3) and (4) both handshake injective-authentication directions,
unaffected by the record tail.

`composed_broken` is the non-vacuity twin: leaking BOTH ephemeral shared secrets
(X25519 + ML-KEM, exactly as handshake `both_broken`) lets the attacker
reconstruct the record key `kdf_recv(dh_ss,kem_ss,t2)` and **forge a Record B the
pinned initiator accepts** — so the composed record-layer injective agreement
FAILS (`inj-event(RtoI_Recv(...)) ==> inj-event(RtoI_Send(...)) is false`). That
proves record integrity (and, by the same key, secrecy) is genuinely a
consequence of handshake key secrecy — a dependency the fresh-key record model
can never exhibit. If the record key were NOT the breakable handshake output, the
forgery would be impossible and the gate would fail (agreement would stay true).
**Honest scope note:** the gate is the anti-replay forgery, not the companion
`attacker(probe)` secrecy goal. The secrecy goal is also reachable once the
secrets leak, but ProVerif's generic-KEM abstraction (`kemss(pk,coins)`,
deliberately given no ciphertext-binding equation) leaves the encapsulation
randomness undischarged during *trace reconstruction*, so it reports a
non-deterministic `cannot be proved` rather than a stable verdict; the injective-
agreement forgery reconstructs to a clean, deterministic `is false`. The clean
reconstructed secrecy-`is false` for this *exact* key derivation is already
machine-checked by handshake `both_broken` (probe under the transcript-AD
handshake AEAD, which reconstructs). The
counter-nonce boundary (handshake consumes counter 0 each direction; records
start at counter 1, `stream.rs:606`) is verified by code-reading + the symbolic
`record_nonce_reuse` scenario, not re-mechanised here — the composition's
contribution is **key genuineness**, and symbolic AEAD models no keystream/nonce-
reuse harm regardless.

**Not claimed:** this is a *symbolic* proof — it shows that *if* Dilithium3 is
unforgeable, ML-KEM-768 is IND-CCA, SHA3-256 is collision-free and HKDF is a
good KDF, *then* the abstract protocol has the properties above. It does not
prove the computational security of the primitives (FIPS 203/204), and the
model↔code correspondence is human-verified. It complements, not replaces, the
implementation-level fuzz sweeps and known-answer vectors in the crate.

## Realm admission

`elara_admission_core.pvi` + `scenarios/admission_*.pvh` machine-check the
post-handshake **realm admission** exchange (`src/network/realm.rs`,
`pq_transport/stream.rs`): a `Federated` realm admits a peer only when it presents
a membership certificate signed by the federation **root** key *and* the cert's
member field matches the identity the handshake authenticated. The core reuses the
verbatim handshake mirror (so the responder holds a genuinely authenticated peer
identity `idh(ipk)`), then runs the admission tail.

| Scenario (`scenarios/`) | Property | Expected |
| --- | --- | --- |
| `admission_baseline` | **admission integrity** — `Admitted(mid) ⟹ RootIssued(mid)`: every admitted (handshake-authenticated) identity was genuinely issued a cert by the federation root | holds |
| `admission_forge_broken` | realm **root secret key** leaks ⇒ attacker forges a cert for its own identity (unforgeability is load-bearing) | **fails** (non-vacuity) |
| `admission_bind_broken` | identity binding `midc = idh(ipk)` **dropped** ⇒ a stolen valid cert admits the wrong (handshake) identity (the binding is load-bearing) | **fails** (non-vacuity) |
| `admission_cross_realm` | attacker fully **owns a foreign federation root**, yet a realm-B cert never verifies against our root | holds (realm isolation) |

The single correspondence `event(Admitted(mid)) ==> event(RootIssued(mid))`
captures **both** halves of the realm.rs trust claim — "a stolen cert fails the
identity match, and a forged cert fails root-signature verification; each check
covers the other's gap." `admission_forge_broken` falsifies it by breaking the
root-signature leg; `admission_bind_broken` falsifies it by breaking the
identity-match leg; with both checks intact (`admission_baseline`) it holds. Both
broken twins reach `Admitted` with an unissued identity, so the baseline's
`is true` is **non-vacuous**.

**Cleartext-cert model — and why it is the *strongest* form.** The model presents
the cert in cleartext on the public wire, **not** inside the established AEAD
session. realm.rs:10-17 asserts the cert "does NOT need to ride inside the
handshake transcript … the PQ handshake already proves the peer possesses the
secret key behind `peer_identity_hash`; the cert binds that identity to the realm
root." Modelling cleartext certs is the strongest Dolev-Yao attacker for the
*integrity* argument (it reads, replays, and re-presents any cert it sees), so
admission integrity holding here **machine-validates that design claim** rather
than assuming it. Confidentiality of the cert in transit (member-list privacy)
is the *separate, weaker-attacker* property, and it is **already established** by
the composed record-secrecy proof above: the real code carries admission messages
as AEAD-encrypted `FrameType::Admission` frames (`realm.rs:196`) — typed
post-handshake record frames on the exact path whose payload secrecy
`composed_baseline` proves and whose type-dispatch integrity the record
`type_binding` scenarios pin. Member-list privacy is therefore inherited, not a
pending increment; this core deliberately models the cert in *cleartext* because
that is the strongest attacker for the orthogonal *integrity* claim it owns
(`Admitted ⟹ RootIssued`).

**Abstracted:** cert **validity windows** (`issued_at`/`expires_at` + clock skew)
and the `network_id` pre-check are local monotonic-clock / string-equality guards
with their own unit tests in realm.rs; they carry no cryptographic correspondence
and are omitted from the symbolic model. Revocation lists and M-of-N threshold
roots are documented realm.rs follow-ups, not P1, and are out of scope here.

## Running it

```bash
# one-time install (no paid services)
apt-get install -y opam && opam init --bare -y --disable-sandboxing \
  && opam switch create elarapv ocaml-system && opam install -y proverif.2.05

./run-proverif.sh      # exit 0 = all twenty-five scenarios produced their expected outcome
```
