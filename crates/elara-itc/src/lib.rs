//! Interval Tree Clocks — Almeida, Baquero & Fonte (2008).
//!
//! Space-efficient logical clocks for dynamic systems. Provides the same
//! causal ordering guarantees as vector clocks with O(log n) space instead
//! of O(n): the identity space is shared by *forking* and *joining* stamps
//! rather than pre-assigning one slot per participant.
//!
//! # Core operations
//!
//! - [`Stamp::fork`]: split a stamp's identity in two (a node joins → receives half)
//! - [`Stamp::join`]: merge two stamps (combine causality on receive)
//! - [`Stamp::event`]: increment the stamp (a local event happens)
//! - [`Stamp::leq`]: causal ordering (happened-before-or-equal)
//!
//! # Wire format
//!
//! [`Stamp::to_bytes`] / [`Stamp::from_bytes`] are a compact, dependency-free
//! binary codec (1-byte tags + LEB128 varints). The decoder is bounded by
//! [`MAX_ITC_DEPTH`] so untrusted input can't overflow the stack, and returns
//! [`ItcError`] on malformed bytes rather than panicking.
//!
//! The `Serialize`/`Deserialize` derives (provided for config/storage
//! convenience) are depth-bounded too: `Deserialize` rejects input nested past
//! [`MAX_ITC_SERDE_DEPTH`] before it can overflow the stack. For untrusted
//! bytes still prefer [`Stamp::from_bytes`] — it tolerates deeper trees
//! ([`MAX_ITC_DEPTH`]), is the compact canonical wire form, and also rejects
//! trailing-byte / overflowing-varint faults the structured `serde` formats
//! can't express.
//!
//! Extracted from the Elara Protocol node; the algebra and codec here carry no
//! protocol dependencies.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Error returned by the ITC wire decoders ([`Stamp::from_bytes`]).
///
/// The only failure mode is malformed wire bytes: premature EOF, an invalid
/// tag, a varint that overflows 64 bits, or nesting past [`MAX_ITC_DEPTH`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItcError {
    /// Malformed wire bytes; the string describes the specific fault.
    Wire(String),
}

impl std::fmt::Display for ItcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ItcError::Wire(s) => write!(f, "ITC wire format error: {s}"),
        }
    }
}

impl std::error::Error for ItcError {}

/// Result alias for the ITC wire decoders.
pub type Result<T> = std::result::Result<T, ItcError>;

// ─── serde Deserialize depth guard ────────────────────────────────────────────

use std::cell::Cell;

thread_local! {
    /// Per-thread recursion counter for the `serde` `Deserialize` impls. The
    /// derived impls recurse through boxed children, so a deeply-nested blob
    /// from a format without its own recursion limit could overflow the stack.
    /// [`DepthGuard`] caps the descent at [`MAX_ITC_SERDE_DEPTH`] (lower than the
    /// binary codec's bound — `serde` stack frames are much larger).
    static DESER_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// RAII guard: increments [`DESER_DEPTH`] on construction, decrements on drop.
/// Construction past [`MAX_ITC_SERDE_DEPTH`] fails, so `serde` deserialization
/// of a hostile, over-nested `Id`/`Event` returns an error instead of
/// overflowing the stack. The counter unwinds correctly on the `?` error path
/// because the guard is a local whose `Drop` runs as the stack frame is dropped.
struct DepthGuard;

impl DepthGuard {
    fn enter<E: serde::de::Error>() -> std::result::Result<Self, E> {
        DESER_DEPTH.with(|d| {
            if d.get() >= MAX_ITC_SERDE_DEPTH {
                return Err(E::custom(format!(
                    "ITC serde: nesting depth exceeds limit {MAX_ITC_SERDE_DEPTH}"
                )));
            }
            d.set(d.get() + 1);
            Ok(DepthGuard)
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        DESER_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// `deserialize_with` hook for the recursive `Id::Node` children: bumps the
/// thread-local depth guard, then defers to the derived `Id` impl. Shape is
/// unchanged — only the descent is depth-bounded.
fn deser_boxed_id<'de, D>(deserializer: D) -> std::result::Result<Box<Id>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _guard = DepthGuard::enter::<D::Error>()?;
    Ok(Box::new(Id::deserialize(deserializer)?))
}

/// `deserialize_with` hook for the recursive `Event::Node` children.
fn deser_boxed_event<'de, D>(deserializer: D) -> std::result::Result<Box<Event>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _guard = DepthGuard::enter::<D::Error>()?;
    Ok(Box::new(Event::deserialize(deserializer)?))
}

// ─── Identity Tree ──────────────────────────────────────────────────────────

/// Identity component of an ITC stamp.
///
/// Binary tree where leaves are `false` (no ownership) or `true` (full
/// ownership). Internal nodes split ownership between left and right subtrees.
///
/// The leaf carries a `bool`, not an integer: an ITC id leaf is binary by
/// definition, so a `bool` makes invalid ownership values unrepresentable.
/// There is no `Leaf(2)` to silently truncate on the wire, nor to make
/// `is_one()` and `fill()` disagree about whether a leaf is owned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Id {
    /// Leaf: `false` = no identity, `true` = full identity.
    Leaf(bool),
    /// Node: split identity between left and right.
    Node(
        #[serde(deserialize_with = "deser_boxed_id")] Box<Id>,
        #[serde(deserialize_with = "deser_boxed_id")] Box<Id>,
    ),
}

impl Id {
    /// The seed identity — owns everything.
    pub fn seed() -> Self {
        Id::Leaf(true)
    }

    /// Zero identity — owns nothing.
    pub fn zero() -> Self {
        Id::Leaf(false)
    }

    /// Is this identity all-zero (owns nothing)?
    pub fn is_zero(&self) -> bool {
        matches!(self, Id::Leaf(false))
    }

    /// Is this identity all-one (owns everything)?
    pub fn is_one(&self) -> bool {
        matches!(self, Id::Leaf(true))
    }

    /// Normalize the tree (collapse nodes with identical children).
    pub fn normalize(self) -> Self {
        match self {
            Id::Node(l, r) => {
                let l = l.normalize();
                let r = r.normalize();
                match (&l, &r) {
                    (Id::Leaf(a), Id::Leaf(b)) if a == b => Id::Leaf(*a),
                    _ => Id::Node(Box::new(l), Box::new(r)),
                }
            }
            leaf => leaf,
        }
    }

    /// Fork: split this identity into two halves.
    ///
    /// - `Leaf(false)` → `(Leaf(false), Leaf(false))` — can't split nothing
    /// - `Leaf(true)` → `(Node(true,false), Node(false,true))` — split ownership
    /// - `Node(0, r)` → `(Node(0, r1), Node(0, r2))` — split the owned half
    /// - `Node(l, 0)` → `(Node(l1, 0), Node(l2, 0))` — split the owned half
    /// - `Node(l, r)` → `(l, r)` — each child becomes independent
    pub fn fork(self) -> (Self, Self) {
        match self {
            Id::Leaf(false) => (Id::Leaf(false), Id::Leaf(false)),
            Id::Leaf(true) => (
                Id::Node(Box::new(Id::Leaf(true)), Box::new(Id::Leaf(false))),
                Id::Node(Box::new(Id::Leaf(false)), Box::new(Id::Leaf(true))),
            ),
            Id::Node(l, r) => {
                if r.is_zero() {
                    let (l1, l2) = l.fork();
                    (
                        Id::Node(Box::new(l1), Box::new(Id::Leaf(false))),
                        Id::Node(Box::new(l2), Box::new(Id::Leaf(false))),
                    )
                } else if l.is_zero() {
                    let (r1, r2) = r.fork();
                    (
                        Id::Node(Box::new(Id::Leaf(false)), Box::new(r1)),
                        Id::Node(Box::new(Id::Leaf(false)), Box::new(r2)),
                    )
                } else {
                    // Both sides have identity — split at this level
                    (*l, *r)
                }
            }
        }
    }

    /// Join: merge two identities back together.
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Id::Leaf(false), other) => other,
            (this, Id::Leaf(false)) => this,
            (Id::Node(l1, r1), Id::Node(l2, r2)) => {
                Id::Node(Box::new(l1.join(*l2)), Box::new(r1.join(*r2))).normalize()
            }
            // Any other combination with owned leaves = full ownership
            _ => Id::Leaf(true),
        }
    }
}

// ─── Event Tree ─────────────────────────────────────────────────────────────

/// Event component of an ITC stamp.
///
/// Tree of counters. A leaf holds a single counter value. An internal node
/// holds a base counter plus left/right subtrees whose values are relative
/// to the base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    /// Leaf counter.
    Leaf(u64),
    /// Node: base counter + left/right relative subtrees.
    Node(
        u64,
        #[serde(deserialize_with = "deser_boxed_event")] Box<Event>,
        #[serde(deserialize_with = "deser_boxed_event")] Box<Event>,
    ),
}

impl Event {
    /// Zero event.
    pub fn zero() -> Self {
        Event::Leaf(0)
    }

    /// Normalize: collapse trivial nodes.
    pub fn normalize(self) -> Self {
        match self {
            Event::Node(n, l, r) => {
                let l = l.normalize();
                let r = r.normalize();
                match (&l, &r) {
                    (Event::Leaf(a), Event::Leaf(b)) if a == b => Event::Leaf(n.saturating_add(*a)),
                    _ => Event::Node(n, Box::new(l), Box::new(r)),
                }
            }
            leaf => leaf,
        }
    }

    /// Lift: add a base value to all counters in this event.
    pub fn lift(self, m: u64) -> Self {
        if m == 0 {
            return self;
        }
        match self {
            Event::Leaf(n) => Event::Leaf(n.saturating_add(m)),
            Event::Node(n, l, r) => Event::Node(n.saturating_add(m), l, r),
        }
    }

    /// Sink: subtract a base value from the root.
    pub fn sink(self, m: u64) -> Self {
        if m == 0 {
            return self;
        }
        match self {
            Event::Leaf(n) => Event::Leaf(n.saturating_sub(m)),
            Event::Node(n, l, r) => Event::Node(n.saturating_sub(m), l, r),
        }
    }

    /// Get the base (minimum) value of this event tree.
    pub fn base(&self) -> u64 {
        match self {
            Event::Leaf(n) => *n,
            Event::Node(n, _, _) => *n,
        }
    }

    /// Get the maximum value in this event tree.
    pub fn max_val(&self) -> u64 {
        match self {
            Event::Leaf(n) => *n,
            Event::Node(n, l, r) => n.saturating_add(std::cmp::max(l.max_val(), r.max_val())),
        }
    }

    /// Join: take the pointwise maximum of two event trees.
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Event::Leaf(n1), Event::Leaf(n2)) => Event::Leaf(std::cmp::max(n1, n2)),
            (Event::Leaf(n1), Event::Node(n2, l2, r2)) => {
                if n1 >= n2.saturating_add(l2.max_val().max(r2.max_val())) {
                    // n1 dominates the whole subtree
                    Event::Leaf(n1)
                } else {
                    Event::Node(
                        n2,
                        Box::new(Event::Leaf(n1.saturating_sub(n2)).join(*l2)),
                        Box::new(Event::Leaf(n1.saturating_sub(n2)).join(*r2)),
                    )
                    .normalize()
                }
            }
            (Event::Node(n1, l1, r1), Event::Leaf(n2)) => {
                if n2 >= n1.saturating_add(l1.max_val().max(r1.max_val())) {
                    Event::Leaf(n2)
                } else {
                    Event::Node(
                        n1,
                        Box::new(l1.join(Event::Leaf(n2.saturating_sub(n1)))),
                        Box::new(r1.join(Event::Leaf(n2.saturating_sub(n1)))),
                    )
                    .normalize()
                }
            }
            (Event::Node(n1, l1, r1), Event::Node(n2, l2, r2)) => {
                if n1 > n2 {
                    Event::Node(
                        n1,
                        Box::new(l1.join(l2.lift(n2).sink(n1))),
                        Box::new(r1.join(r2.lift(n2).sink(n1))),
                    )
                    .normalize()
                } else if n2 > n1 {
                    Event::Node(
                        n2,
                        Box::new(l1.lift(n1).sink(n2).join(*l2)),
                        Box::new(r1.lift(n1).sink(n2).join(*r2)),
                    )
                    .normalize()
                } else {
                    // n1 == n2
                    Event::Node(n1, Box::new(l1.join(*l2)), Box::new(r1.join(*r2))).normalize()
                }
            }
        }
    }

    /// Is `self <= other` (happened-before-or-equal)?
    pub fn leq(&self, other: &Self) -> bool {
        match (self, other) {
            (Event::Leaf(n1), Event::Leaf(n2)) => n1 <= n2,
            (Event::Leaf(n1), Event::Node(n2, _, _)) => n1 <= n2,
            (Event::Node(n1, l1, r1), Event::Leaf(n2)) => {
                n1.saturating_add(l1.max_val().max(r1.max_val())) <= *n2
            }
            (Event::Node(n1, l1, r1), Event::Node(n2, l2, r2)) => {
                if n1 > n2 {
                    return false;
                }
                let l1_shifted = l1.clone().lift(*n1).sink(*n2);
                let r1_shifted = r1.clone().lift(*n1).sink(*n2);
                l1_shifted.leq(l2) && r1_shifted.leq(r2)
            }
        }
    }
}

// ─── Stamp ──────────────────────────────────────────────────────────────────

/// An ITC Stamp = (Id, Event). The atomic unit of causal time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stamp {
    pub id: Id,
    pub event: Event,
}

impl Stamp {
    /// Create the seed stamp — initial clock for the first node.
    pub fn seed() -> Self {
        Stamp {
            id: Id::seed(),
            event: Event::zero(),
        }
    }

    /// Create a zero stamp (no identity, no events).
    pub fn zero() -> Self {
        Stamp {
            id: Id::zero(),
            event: Event::zero(),
        }
    }

    /// Fork: split this stamp into two stamps with disjoint identities
    /// and the same event history.
    ///
    /// Used when a new node joins — parent gives half its identity to child.
    pub fn fork(self) -> (Self, Self) {
        let (id1, id2) = self.id.fork();
        (
            Stamp {
                id: id1,
                event: self.event.clone(),
            },
            Stamp {
                id: id2,
                event: self.event,
            },
        )
    }

    /// Join: merge two stamps — combines identities and takes max of events.
    ///
    /// Used when receiving a record from another node.
    pub fn join(self, other: Self) -> Self {
        Stamp {
            id: self.id.join(other.id),
            event: self.event.join(other.event),
        }
    }

    /// Event: increment the stamp where we have identity.
    ///
    /// Used when creating a new record. Only fills where our identity is 1.
    pub fn event(self) -> Self {
        let event = fill(&self.id, &self.event);
        Stamp {
            id: self.id,
            event: event.normalize(),
        }
    }

    /// Causal ordering: is `self` happened-before-or-equal to `other`?
    pub fn leq(&self, other: &Stamp) -> bool {
        self.event.leq(&other.event)
    }

    /// Are these stamps concurrent (neither happened before the other)?
    pub fn concurrent(&self, other: &Stamp) -> bool {
        !self.leq(other) && !other.leq(self)
    }

    /// Did `self` happen strictly before `other`?
    pub fn before(&self, other: &Stamp) -> bool {
        self.leq(other) && !other.leq(self)
    }

    // ─── Compact Binary Serialization ───────────────────────────────────

    /// Serialize to compact binary format.
    ///
    /// Encoding:
    /// - Id: tag byte (0=zero-leaf, 1=one-leaf, 2=node) + children
    /// - Event: tag byte (0=leaf, 1=node) + varint counter + children
    ///
    /// Typical size: ~40 bytes for a 100K-node zone.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        encode_id(&self.id, &mut buf);
        encode_event(&self.event, &mut buf);
        buf
    }

    /// Deserialize from compact binary format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let id = decode_id(data, &mut pos, 0)?;
        let event = decode_event(data, &mut pos, 0)?;
        // Reject trailing bytes: the codec must be bijective so that
        // `from_bytes(x).to_bytes() == x` — otherwise stamps are wire-malleable.
        if pos != data.len() {
            return Err(ItcError::Wire(format!(
                "ITC stamp: {} trailing byte(s) after valid stamp",
                data.len() - pos
            )));
        }
        Ok(Stamp { id, event })
    }
}

/// Fill: increment the event tree where the identity tree has ownership.
///
/// This is the core of the `event()` operation — it grows the event counter
/// at positions corresponding to owned identity segments.
fn fill(id: &Id, event: &Event) -> Event {
    match (id, event) {
        (Id::Leaf(false), e) => e.clone(),
        (Id::Leaf(true), Event::Leaf(n)) => Event::Leaf(n.saturating_add(1)),
        (Id::Leaf(true), Event::Node(n, l, r)) => {
            Event::Leaf(n.saturating_add(std::cmp::max(l.max_val(), r.max_val())).saturating_add(1))
        }
        (Id::Node(l_id, r_id), Event::Leaf(n)) => {
            // Expand leaf to node, then fill the owned subtree
            let le = fill(l_id, &Event::Leaf(0));
            let re = fill(r_id, &Event::Leaf(0));
            Event::Node(*n, Box::new(le), Box::new(re)).normalize()
        }
        (Id::Node(l_id, r_id), Event::Node(n, l_e, r_e)) => {
            if l_id.is_zero() {
                // Only right side has identity
                Event::Node(*n, l_e.clone(), Box::new(fill(r_id, r_e))).normalize()
            } else if r_id.is_zero() {
                // Only left side has identity
                Event::Node(*n, Box::new(fill(l_id, l_e)), r_e.clone()).normalize()
            } else {
                // Both sides have identity — fill both
                Event::Node(*n, Box::new(fill(l_id, l_e)), Box::new(fill(r_id, r_e))).normalize()
            }
        }
    }
}

// ─── Binary Serialization ───────────────────────────────────────────────────

/// Maximum ITC tree recursion depth accepted by the wire decoders.
///
/// A stamp's bytes are an opaque, possibly attacker-controlled string decoded
/// by `Stamp::from_bytes`. Without a cap, `decode_id` / `decode_event` recurse
/// once per `Node` tag — a crafted input of repeated `0x02` / `0x01` tags
/// recurses ~1 level per byte, overflowing the thread stack and aborting the
/// process.
///
/// A legitimate ITC tree is shaped by identity-fork topology and is normalized
/// on construction, so its depth is logarithmic in node count; 1024 levels is
/// far beyond any real stamp while bounding worst-case stack use to ~tens of
/// KiB. The decoders count the root as depth 0 and reject at depth
/// `MAX_ITC_DEPTH`, so at most `MAX_ITC_DEPTH` nesting levels are accepted.
pub const MAX_ITC_DEPTH: usize = 1024;

/// Recursion bound for the `serde` `Deserialize` impls — deliberately lower
/// than [`MAX_ITC_DEPTH`].
///
/// The hand-rolled binary decoder uses small stack frames, so 1024 levels cost
/// only tens of KiB. A `serde` deserializer's frames are far larger, and each
/// ITC level nests *two* serde container levels (an object wrapping an array,
/// `{"Node":[..]}`), so an ITC depth of D drives ~2·D levels of recursive
/// descent — empirically, ~1024 ITC levels of `serde_json` descent overflow a
/// default thread stack *before* a 1024 guard could fire, making such a guard
/// useless. 64 ITC levels = 128 serde container levels = `serde_json`'s own
/// default recursion limit, a battle-tested stack-safe value (safe even on the
/// ~1 MiB thread stacks of phone-tier targets). It is still far beyond any
/// normalized ITC tree (depth ≈ log of participant count). For deeper or
/// untrusted input use the binary codec [`Stamp::from_bytes`].
pub const MAX_ITC_SERDE_DEPTH: usize = 64;

// Varint encoding (LEB128-style, unsigned)

fn encode_varint(val: u64, buf: &mut Vec<u8>) {
    let mut v = val;
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

fn decode_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= data.len() {
            return Err(ItcError::Wire("ITC varint: unexpected EOF".into()));
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(ItcError::Wire("ITC varint: overflow".into()));
        }
    }
    Ok(result)
}

// Id encoding: tag(1 byte) + children
// Tag: 0 = Leaf(0), 1 = Leaf(1), 2 = Node(left, right)

fn encode_id(id: &Id, buf: &mut Vec<u8>) {
    match id {
        Id::Leaf(false) => buf.push(0),
        Id::Leaf(true) => buf.push(1),
        Id::Node(l, r) => {
            buf.push(2);
            encode_id(l, buf);
            encode_id(r, buf);
        }
    }
}

fn decode_id(data: &[u8], pos: &mut usize, depth: usize) -> Result<Id> {
    if depth >= MAX_ITC_DEPTH {
        return Err(ItcError::Wire(format!(
            "ITC id: nesting depth exceeds limit {MAX_ITC_DEPTH}"
        )));
    }
    if *pos >= data.len() {
        return Err(ItcError::Wire("ITC id: unexpected EOF".into()));
    }
    let tag = data[*pos];
    *pos += 1;
    match tag {
        0 => Ok(Id::Leaf(false)),
        1 => Ok(Id::Leaf(true)),
        2 => {
            let l = decode_id(data, pos, depth + 1)?;
            let r = decode_id(data, pos, depth + 1)?;
            Ok(Id::Node(Box::new(l), Box::new(r)))
        }
        _ => Err(ItcError::Wire(format!("ITC id: invalid tag {tag}"))),
    }
}

// Event encoding: tag(1 byte) + varint(counter) [+ children for node]
// Tag: 0 = Leaf(n), 1 = Node(n, left, right)

fn encode_event(event: &Event, buf: &mut Vec<u8>) {
    match event {
        Event::Leaf(n) => {
            buf.push(0);
            encode_varint(*n, buf);
        }
        Event::Node(n, l, r) => {
            buf.push(1);
            encode_varint(*n, buf);
            encode_event(l, buf);
            encode_event(r, buf);
        }
    }
}

fn decode_event(data: &[u8], pos: &mut usize, depth: usize) -> Result<Event> {
    if depth >= MAX_ITC_DEPTH {
        return Err(ItcError::Wire(format!(
            "ITC event: nesting depth exceeds limit {MAX_ITC_DEPTH}"
        )));
    }
    if *pos >= data.len() {
        return Err(ItcError::Wire("ITC event: unexpected EOF".into()));
    }
    let tag = data[*pos];
    *pos += 1;
    match tag {
        0 => {
            let n = decode_varint(data, pos)?;
            Ok(Event::Leaf(n))
        }
        1 => {
            let n = decode_varint(data, pos)?;
            let l = decode_event(data, pos, depth + 1)?;
            let r = decode_event(data, pos, depth + 1)?;
            Ok(Event::Node(n, Box::new(l), Box::new(r)))
        }
        _ => Err(ItcError::Wire(format!("ITC event: invalid tag {tag}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Id tests ---

    #[test]
    fn test_id_seed() {
        assert!(Id::seed().is_one());
        assert!(!Id::seed().is_zero());
    }

    #[test]
    fn test_id_zero() {
        assert!(Id::zero().is_zero());
        assert!(!Id::zero().is_one());
    }

    #[test]
    fn test_id_fork_seed() {
        let (a, b) = Id::seed().fork();
        // Seed forks into complementary halves.
        assert_eq!(
            a,
            Id::Node(Box::new(Id::Leaf(true)), Box::new(Id::Leaf(false)))
        );
        assert_eq!(
            b,
            Id::Node(Box::new(Id::Leaf(false)), Box::new(Id::Leaf(true)))
        );
    }

    #[test]
    fn test_id_fork_zero() {
        let (a, b) = Id::zero().fork();
        assert!(a.is_zero());
        assert!(b.is_zero());
    }

    #[test]
    fn test_id_fork_twice() {
        let (a, bc) = Id::seed().fork();
        let (b, c) = bc.fork();
        // Re-joining all three yields the seed again (full ownership).
        let rejoined = a.join(b).join(c).normalize();
        assert!(rejoined.is_one());
    }

    #[test]
    fn test_id_normalize() {
        let n = Id::Node(Box::new(Id::Leaf(true)), Box::new(Id::Leaf(true)));
        assert!(n.normalize().is_one());
    }

    // --- Event tests ---

    #[test]
    fn test_event_zero() {
        assert_eq!(Event::zero(), Event::Leaf(0));
        assert_eq!(Event::zero().base(), 0);
    }

    #[test]
    fn test_event_leaf_leq() {
        assert!(Event::Leaf(3).leq(&Event::Leaf(5)));
        assert!(!Event::Leaf(5).leq(&Event::Leaf(3)));
    }

    #[test]
    fn test_event_join() {
        let a = Event::Leaf(3);
        let b = Event::Leaf(5);
        assert_eq!(a.join(b), Event::Leaf(5));
    }

    #[test]
    fn test_event_node_leq() {
        let leaf = Event::Leaf(10);
        let node = Event::Node(2, Box::new(Event::Leaf(1)), Box::new(Event::Leaf(3)));
        // node max = 2 + 3 = 5 <= 10
        assert!(node.leq(&leaf));
    }

    #[test]
    fn test_event_lift_sink() {
        let e = Event::Leaf(5);
        assert_eq!(e.clone().lift(3), Event::Leaf(8));
        assert_eq!(Event::Leaf(8).sink(3), Event::Leaf(5));
    }

    // --- Stamp tests ---

    #[test]
    fn test_stamp_seed() {
        let s = Stamp::seed();
        assert!(s.id.is_one());
        assert_eq!(s.event, Event::Leaf(0));
    }

    #[test]
    fn test_stamp_event_increments() {
        let s = Stamp::seed();
        let s1 = s.clone().event();
        assert!(s.before(&s1));
    }

    #[test]
    fn test_stamp_fork_and_event() {
        let seed = Stamp::seed();
        let (a, b) = seed.fork();
        let a1 = a.event();
        let b1 = b.event();
        // Independent events on disjoint identities are concurrent.
        assert!(a1.concurrent(&b1));
    }

    #[test]
    fn test_stamp_causal_ordering() {
        let s = Stamp::seed();
        let s1 = s.clone().event();
        let s2 = s1.clone().event();
        assert!(s.before(&s1));
        assert!(s1.before(&s2));
        assert!(s.before(&s2));
    }

    #[test]
    fn test_stamp_join_merges_causality() {
        let seed = Stamp::seed();
        let (a, b) = seed.fork();
        let a1 = a.event();
        let b1 = b.event();
        let merged = a1.clone().join(b1.clone());
        // The merge dominates both inputs.
        assert!(a1.before(&merged));
        assert!(b1.before(&merged));
    }

    #[test]
    fn test_stamp_fork_join_roundtrip() {
        let seed = Stamp::seed().event();
        let (a, b) = seed.clone().fork();
        let rejoined = a.join(b);
        // Forking then joining preserves event history.
        assert_eq!(rejoined.event, seed.event);
    }

    #[test]
    fn test_three_node_scenario() {
        // A forks to B, B forks to C; each does work; merges converge.
        let seed = Stamp::seed();
        let (a, b) = seed.fork();
        let (b, c) = b.fork();

        let a = a.event();
        let b = b.event();
        let c = c.event();

        // All three are mutually concurrent.
        assert!(a.concurrent(&b));
        assert!(b.concurrent(&c));
        assert!(a.concurrent(&c));

        // A receives both → dominates all.
        let merged = a.join(b).join(c);
        let after = merged.clone().event();
        assert!(merged.before(&after));
    }

    // --- Serialization tests ---

    #[test]
    fn test_stamp_serialization_roundtrip() {
        let seed = Stamp::seed();
        let (a, b) = seed.fork();
        let a1 = a.event().event().event();
        let b1 = b.event();

        for stamp in &[a1, b1] {
            let bytes = stamp.to_bytes();
            let decoded = Stamp::from_bytes(&bytes).unwrap();
            assert_eq!(&decoded, stamp);
        }
    }

    #[test]
    fn test_stamp_serialization_seed() {
        let seed = Stamp::seed();
        let bytes = seed.to_bytes();
        // Seed: Id::Leaf(true) = 1 byte, Event::Leaf(0) = 2 bytes → 3 bytes total
        assert_eq!(bytes.len(), 3);
        let decoded = Stamp::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, seed);
    }

    #[test]
    fn test_stamp_serialization_compact() {
        // After several forks and events, size should stay reasonable
        let seed = Stamp::seed();
        let (a, bc) = seed.fork();
        let (b, c) = bc.fork();

        let a = a.event().event().event();
        let b = b.event().event();
        let c = c.event();

        // Spec says ~40 bytes for 100K nodes. With 3 nodes, should be tiny.
        assert!(a.to_bytes().len() < 30);
        assert!(b.to_bytes().len() < 30);
        assert!(c.to_bytes().len() < 30);
    }

    #[test]
    fn test_stamp_serialization_empty_data() {
        assert!(Stamp::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_stamp_serialization_invalid_tag() {
        assert!(Stamp::from_bytes(&[99]).is_err());
    }

    // --- Varint tests ---

    #[test]
    fn test_varint_roundtrip() {
        for val in [0, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX / 2] {
            let mut buf = Vec::new();
            encode_varint(val, &mut buf);
            let mut pos = 0;
            let decoded = decode_varint(&buf, &mut pos).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn test_varint_compact() {
        let mut buf = Vec::new();
        encode_varint(0, &mut buf);
        assert_eq!(buf.len(), 1); // 0 fits in 1 byte
        buf.clear();
        encode_varint(127, &mut buf);
        assert_eq!(buf.len(), 1);
        buf.clear();
        encode_varint(128, &mut buf);
        assert_eq!(buf.len(), 2);
    }

    // --- Wire-format pins (consensus-critical: these bytes are carried on
    // every record; a change here forks the chain). Generated from the
    // pre-extraction node code; the extracted codec must reproduce them
    // byte-identically. ---

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn wire_pin_seed() {
        // Id::Leaf(true)=0x01, Event::Leaf(0)=tag 0x00 + varint 0x00.
        assert_eq!(hex(&Stamp::seed().to_bytes()), "010000");
    }

    #[test]
    fn wire_pin_seed_after_event() {
        // seed.event(): Id::Leaf(true)=0x01, Event::Leaf(1)=0x00 0x01.
        assert_eq!(hex(&Stamp::seed().event().to_bytes()), "010001");
    }

    #[test]
    fn wire_pin_forked_left_after_three_events() {
        // Deterministic deep-ish shape: left child of the seed fork, advanced
        // three times. Pins the Id::Node + Event::Node tag/varint layout.
        let (a, _b) = Stamp::seed().fork();
        let a3 = a.event().event().event();
        let bytes = a3.to_bytes();
        // Round-trips and matches the pinned encoding.
        assert_eq!(Stamp::from_bytes(&bytes).unwrap(), a3);
        // id = Node(Leaf1,Leaf0) → 02 01 00; event = Node(0,Leaf3,Leaf0) →
        // 01 00 | 00 03 | 00 00.
        assert_eq!(hex(&bytes), "020100010000030000");
    }

    #[test]
    fn wire_pin_depth_guard_rejects_deep_input() {
        // A byte string of repeated Id::Node tags (0x02) must be rejected by
        // the depth guard, not overflow the stack.
        let deep = vec![0x02u8; MAX_ITC_SERDE_DEPTH + 50];
        assert!(Stamp::from_bytes(&deep).is_err());
    }

    // --- Complex scenarios ---

    #[test]
    fn test_causality_chain() {
        // A → B → C should form a causal chain
        let seed = Stamp::seed();
        let (a_id, rest) = seed.fork();
        let (b_id, c_id) = rest.fork();

        // A creates record
        let a1 = a_id.event();

        // B receives A's record and creates its own
        let b_with_a = b_id.join(Stamp {
            id: Id::zero(),
            event: a1.event.clone(),
        });
        let b1 = b_with_a.event();

        // C receives B's record and creates its own
        let c_with_b = c_id.join(Stamp {
            id: Id::zero(),
            event: b1.event.clone(),
        });
        let c1 = c_with_b.event();

        // Verify causal chain: a1 < b1 < c1
        assert!(a1.before(&b1));
        assert!(b1.before(&c1));
        assert!(a1.before(&c1)); // transitivity
    }

    #[test]
    fn test_concurrent_detection() {
        let seed = Stamp::seed();
        let (a, b) = seed.fork();

        // Both create events independently
        let a1 = a.event();
        let b1 = b.event();

        // They're concurrent
        assert!(a1.concurrent(&b1));

        // After merge, the merged stamp dominates both
        let merged = a1.clone().join(b1.clone());
        assert!(a1.leq(&merged));
        assert!(b1.leq(&merged));
        assert!(!merged.leq(&a1));
        assert!(!merged.leq(&b1));
    }

    #[test]
    fn test_many_events_serialization_size() {
        // Simulate a single node creating 1000 events
        let mut stamp = Stamp::seed();
        for _ in 0..1000 {
            stamp = stamp.event();
        }
        let bytes = stamp.to_bytes();
        // Should be very compact (just incrementing a leaf counter)
        assert!(bytes.len() < 10, "1000 events on seed: {} bytes", bytes.len());
    }

    #[test]
    fn test_event_join_node_node() {
        // Test the Node-Node join path
        let e1 = Event::Node(1, Box::new(Event::Leaf(2)), Box::new(Event::Leaf(3)));
        let e2 = Event::Node(1, Box::new(Event::Leaf(4)), Box::new(Event::Leaf(1)));
        let joined = e1.join(e2);
        // Should take max at each position: base=1, left=max(2,4)=4, right=max(3,1)=3
        assert_eq!(joined.max_val(), 1 + 4); // 5
    }

    #[test]
    fn batch_b_id_normalize_recurses_into_deeply_nested_equal_children() {
        // normalize() must collapse children recursively — not just the top level.
        // Node(Node(0,0), Node(0,0)) → both subtrees collapse to Leaf(0); top also.
        let zero_subtree = Id::Node(
            Box::new(Id::Node(Box::new(Id::Leaf(false)), Box::new(Id::Leaf(false)))),
            Box::new(Id::Node(Box::new(Id::Leaf(false)), Box::new(Id::Leaf(false)))),
        );
        assert_eq!(zero_subtree.normalize(), Id::Leaf(false));

        // Node(Node(1,1), Leaf(1)) — left collapses to Leaf(1); top then collapses.
        let one_collapse = Id::Node(
            Box::new(Id::Node(Box::new(Id::Leaf(true)), Box::new(Id::Leaf(true)))),
            Box::new(Id::Leaf(true)),
        );
        assert_eq!(one_collapse.normalize(), Id::Leaf(true));

        // Asymmetric: left collapses, right does not — top stays as Node.
        let asymmetric = Id::Node(
            Box::new(Id::Node(Box::new(Id::Leaf(false)), Box::new(Id::Leaf(false)))),
            Box::new(Id::Node(Box::new(Id::Leaf(true)), Box::new(Id::Leaf(false)))),
        );
        let normed = asymmetric.normalize();
        match &normed {
            Id::Node(l, r) => {
                assert!(matches!(**l, Id::Leaf(false)));
                assert!(matches!(**r, Id::Node(_, _)));
            }
            other => panic!("expected Node after asymmetric normalize, got {:?}", other),
        }
    }

    #[test]
    fn batch_b_id_fork_then_join_round_trips_to_seed_invariant() {
        // fork() + join() must round-trip across the three branches of fork()'s
        // match: Leaf(1) seed split, Node(0, r) right-owned recursion, and the
        // both-sides-nonzero direct unwrap.
        let seed = Id::seed();
        let (a, b) = seed.fork();
        assert_eq!(a.join(b).normalize(), Id::Leaf(true), "seed fork+join → Leaf(1)");

        // Both-sides-nonzero Node fork branch: (l, r) → (*l, *r) — unwraps directly.
        let split = Id::Node(Box::new(Id::Leaf(true)), Box::new(Id::Leaf(true)));
        let (a, b) = split.fork();
        assert_eq!(a, Id::Leaf(true));
        assert_eq!(b, Id::Leaf(true));
        assert_eq!(a.join(b).normalize(), Id::Leaf(true));

        // Right-owned branch: Node(0, 1).fork() recurses on the right side.
        let right_owned = Id::Node(Box::new(Id::Leaf(false)), Box::new(Id::Leaf(true)));
        let (a, b) = right_owned.clone().fork();
        // Both halves must still have zero on left (preserved zero-side invariant).
        match &a {
            Id::Node(l, _) => assert!(l.is_zero()),
            other => panic!("expected Node, got {:?}", other),
        }
        match &b {
            Id::Node(l, _) => assert!(l.is_zero()),
            other => panic!("expected Node, got {:?}", other),
        }
        // Join recovers something equivalent to the original (under normalize).
        let rejoined = a.join(b).normalize();
        let original_normed = right_owned.normalize();
        assert_eq!(rejoined, original_normed);

        // Zero is the join-identity for Id (per fn join: Leaf(0) merges absorb).
        assert_eq!(Id::Leaf(true).join(Id::zero()), Id::Leaf(true));
        assert_eq!(Id::zero().join(Id::Leaf(true)), Id::Leaf(true));
        assert_eq!(Id::zero().join(Id::zero()), Id::Leaf(false));
    }

    #[test]
    fn batch_b_event_lift_sink_zero_identity_and_sink_saturates() {
        // lift(0) and sink(0) are documented no-ops via the m==0 early-return.
        // sink(m) where m > counter must saturate to 0, never panic on underflow.
        let leaf = Event::Leaf(7);
        assert_eq!(leaf.clone().lift(0), leaf);
        let node = Event::Node(3, Box::new(Event::Leaf(1)), Box::new(Event::Leaf(2)));
        assert_eq!(node.clone().lift(0), node);

        assert_eq!(Event::Leaf(5).sink(0), Event::Leaf(5));
        assert_eq!(
            Event::Node(4, Box::new(Event::Leaf(0)), Box::new(Event::Leaf(1))).sink(0),
            Event::Node(4, Box::new(Event::Leaf(0)), Box::new(Event::Leaf(1))),
        );

        // sink saturates on underflow.
        assert_eq!(Event::Leaf(3).sink(10), Event::Leaf(0));
        assert_eq!(
            Event::Node(2, Box::new(Event::Leaf(5)), Box::new(Event::Leaf(6))).sink(100),
            Event::Node(0, Box::new(Event::Leaf(5)), Box::new(Event::Leaf(6))),
        );

        // lift adds m exactly to leaf, to the base counter for a node.
        assert_eq!(Event::Leaf(5).lift(10), Event::Leaf(15));
        assert_eq!(
            Event::Node(2, Box::new(Event::Leaf(1)), Box::new(Event::Leaf(3))).lift(7),
            Event::Node(9, Box::new(Event::Leaf(1)), Box::new(Event::Leaf(3))),
        );
    }

    #[test]
    fn batch_b_varint_encodes_decodes_byte_boundaries_and_max_u64() {
        // LEB128 inflection points at 2^7, 2^14, 2^21, ... — a bug at the
        // continuation bit (0x80) shows up as truncation at these boundaries.
        let values: &[u64] = &[
            0, 1, 126, 127, 128, 255, 16383, 16384,
            u32::MAX as u64,
            u64::MAX,
        ];
        for &v in values {
            let mut buf = Vec::new();
            encode_varint(v, &mut buf);
            let mut pos = 0;
            let back = decode_varint(&buf, &mut pos).expect("decode");
            assert_eq!(back, v, "round-trip {}", v);
            assert_eq!(pos, buf.len(), "decoder must consume exactly the encoded bytes for {}", v);
        }
        // u64::MAX requires exactly 10 bytes (ceil(64 / 7) = 10).
        let mut max_buf = Vec::new();
        encode_varint(u64::MAX, &mut max_buf);
        assert_eq!(max_buf.len(), 10);

        // 11 bytes all with continuation bit → shift advances past 63 → overflow error.
        let overflow = vec![0xFFu8; 11];
        let mut pos = 0;
        assert!(decode_varint(&overflow, &mut pos).is_err(), "11-byte continuation chain must overflow-error");

        // Truncated input (continuation bit set but no follow-up byte) → EOF error.
        let truncated = vec![0x80u8];
        let mut pos = 0;
        assert!(decode_varint(&truncated, &mut pos).is_err(), "truncated varint must EOF-error");

        // Compact-byte boundary pinning (1-byte vs 2-byte transition).
        let mut buf = Vec::new();
        encode_varint(127, &mut buf);
        assert_eq!(buf.len(), 1);
        buf.clear();
        encode_varint(128, &mut buf);
        assert_eq!(buf.len(), 2);
        buf.clear();
        encode_varint(16383, &mut buf);
        assert_eq!(buf.len(), 2);
        buf.clear();
        encode_varint(16384, &mut buf);
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn batch_b_decode_id_rejects_invalid_tags() {
        // Id tags 0/1/2 are valid; anything else must error.
        for bad_tag in [3u8, 4, 5, 99, 200, 255] {
            let mut pos = 0;
            assert!(decode_id(&[bad_tag], &mut pos, 0).is_err(), "tag {} must be rejected", bad_tag);
        }
        // Empty input → EOF error.
        let mut pos = 0;
        assert!(decode_id(&[], &mut pos, 0).is_err(), "empty input must EOF");
        // Node tag (2) with no children → EOF on first child decode.
        let mut pos = 0;
        assert!(decode_id(&[2u8], &mut pos, 0).is_err(), "Node tag with no children must EOF");
        // Node tag (2) with only left child → EOF on right child.
        let mut pos = 0;
        assert!(
            decode_id(&[2u8, 1u8], &mut pos, 0).is_err(),
            "Node tag with only left leaf must EOF on right child",
        );
    }

    // Pre-order encoding of a left-spine `Id` of `depth` Node levels:
    // `depth` × Node tag (0x02) followed by (depth + 1) Leaf(0) tags (0x00).
    fn left_spine_id_bytes(depth: usize) -> Vec<u8> {
        let mut v = vec![0u8; 2 * depth + 1];
        v[..depth].fill(2u8);
        v
    }

    /// Adversarial deep `Id` chain (`0x02` = Node tag, no leaves) must be
    /// rejected with a typed error, NOT abort the process via stack overflow.
    /// Without `MAX_ITC_DEPTH`, a 65535-byte `itc_stamp` of repeated `0x02`
    /// recurses ~65535 deep and smashes the ingest worker's 2 MiB stack.
    #[test]
    fn decode_id_deep_node_chain_returns_error_not_stack_overflow() {
        let bomb = vec![2u8; 60_000];
        let mut pos = 0;
        let err = decode_id(&bomb, &mut pos, 0).expect_err("deep Id chain must error");
        assert!(
            format!("{err}").contains("nesting depth"),
            "expected nesting-depth error, got: {err}",
        );
    }

    /// Same bomb routed through the real ingest entry point, [`Stamp::from_bytes`]
    /// — must return `Err`, not abort.
    #[test]
    fn stamp_from_bytes_deep_chain_returns_error_not_panic() {
        let bomb = vec![2u8; 60_000];
        assert!(
            Stamp::from_bytes(&bomb).is_err(),
            "deep Id chain via Stamp::from_bytes must error, not abort",
        );
    }

    /// Adversarial deep `Event` chain (`0x01` Node tag + 1-byte zero varint
    /// counter, repeated) drives left-child recursion and must error, not abort.
    #[test]
    fn decode_event_deep_node_chain_returns_error_not_stack_overflow() {
        let mut bomb = Vec::with_capacity(120_000);
        for _ in 0..60_000 {
            bomb.push(1u8); // Event::Node tag
            bomb.push(0u8); // varint counter = 0
        }
        let mut pos = 0;
        let err = decode_event(&bomb, &mut pos, 0).expect_err("deep Event chain must error");
        assert!(
            format!("{err}").contains("nesting depth"),
            "expected nesting-depth error, got: {err}",
        );
    }

    /// A legitimately deep-but-bounded `Id` (depth 100, far under
    /// `MAX_ITC_DEPTH`) still decodes — the cap rejects only pathological input.
    #[test]
    fn decode_id_accepts_legitimate_depth_under_cap() {
        let bytes = left_spine_id_bytes(100);
        let mut pos = 0;
        decode_id(&bytes, &mut pos, 0).expect("depth-100 Id must decode (well under cap)");
    }

    /// A normal stamp produced by the ITC ops round-trips unchanged — the guard
    /// is transparent to real usage.
    #[test]
    fn decode_normal_stamp_round_trips_after_depth_guard() {
        let stamp = Stamp::seed().event().event().event();
        let decoded = Stamp::from_bytes(&stamp.to_bytes()).expect("normal stamp must decode");
        assert_eq!(decoded, stamp);
    }

    /// A standalone consumer may decode a peer-supplied stamp with counters near
    /// `u64::MAX` and then compare/join it. Before the saturating-add hardening
    /// these `+` sites panicked under overflow-checks (and wrapped silently in a
    /// downstream release build). The ops must now terminate without panic.
    #[test]
    fn near_max_counters_do_not_overflow_on_public_ops() {
        let hostile = Event::Node(
            u64::MAX - 1,
            Box::new(Event::Leaf(5)),
            Box::new(Event::Leaf(7)),
        );
        // max_val folds `*n + max(children)` — the canonical overflow site.
        let _ = hostile.max_val();
        let other = Event::Leaf(u64::MAX);
        // leq / join exercise the remaining `n + max_val()` guard sites.
        let _ = hostile.leq(&other);
        let _ = hostile.clone().join(other);
        // lift saturates at the ceiling rather than wrapping to a tiny value.
        assert_eq!(Event::Leaf(u64::MAX - 1).lift(10), Event::Leaf(u64::MAX));
    }

    /// The wire codec must be bijective: trailing bytes after a valid stamp are
    /// rejected, not silently ignored (closes a byte-level malleability vector).
    #[test]
    fn from_bytes_rejects_trailing_garbage() {
        let stamp = Stamp::seed().event();
        let mut bytes = stamp.to_bytes();
        let clean = Stamp::from_bytes(&bytes).expect("exact bytes decode");
        assert_eq!(clean, stamp);
        bytes.push(0xAB); // one trailing byte
        assert!(
            Stamp::from_bytes(&bytes).is_err(),
            "trailing bytes must be rejected"
        );
    }

    // --- serde Deserialize depth guard ---

    /// The `deserialize_with` hooks change only the descent, not the wire shape:
    /// a stamp with nested id and event round-trips through `serde_json`
    /// byte-for-byte (Serialize stays derived; Deserialize only adds the bound).
    #[test]
    fn serde_round_trip_preserves_shape() {
        let s = Stamp {
            id: Id::Node(Box::new(Id::seed()), Box::new(Id::zero())),
            event: Event::Node(3, Box::new(Event::Leaf(1)), Box::new(Event::Leaf(2))),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Stamp = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
        assert_eq!(json, serde_json::to_string(&back).unwrap(), "no shape drift");
    }

    /// Build a left-spine JSON nesting `Id::Node` `n` levels deep *without*
    /// recursing in the builder, so the test input can't itself overflow.
    fn deep_id_json(n: usize) -> String {
        let mut s = String::with_capacity(n * 24);
        for _ in 0..n {
            s.push_str(r#"{"Node":["#);
        }
        s.push_str(r#"{"Leaf":false}"#);
        for _ in 0..n {
            s.push_str(r#",{"Leaf":false}]}"#);
        }
        s
    }

    fn deep_event_json(n: usize) -> String {
        let mut s = String::with_capacity(n * 24);
        for _ in 0..n {
            s.push_str(r#"{"Node":[0,"#);
        }
        s.push_str(r#"{"Leaf":0}"#);
        for _ in 0..n {
            s.push_str(r#",{"Leaf":0}]}"#);
        }
        s
    }

    /// A blob nested past `MAX_ITC_DEPTH` must error, never overflow the stack —
    /// even with the format's own recursion limit disabled, so OUR guard is the
    /// only thing between the parser and a stack overflow.
    #[test]
    fn serde_rejects_overdeep_id_without_overflow() {
        let json = deep_id_json(MAX_ITC_SERDE_DEPTH + 50);
        let mut de = serde_json::Deserializer::from_str(&json);
        de.disable_recursion_limit();
        assert!(Id::deserialize(&mut de).is_err());
    }

    #[test]
    fn serde_rejects_overdeep_event_without_overflow() {
        let json = deep_event_json(MAX_ITC_SERDE_DEPTH + 50);
        let mut de = serde_json::Deserializer::from_str(&json);
        de.disable_recursion_limit();
        assert!(Event::deserialize(&mut de).is_err());
    }

    /// The depth counter must unwind to zero after an error, or a later
    /// deserialization on the same thread would be falsely rejected. Decode an
    /// over-deep blob (errors), then a shallow valid one on the same thread.
    #[test]
    fn serde_depth_counter_unwinds_after_error() {
        let deep = deep_id_json(MAX_ITC_SERDE_DEPTH + 50);
        let mut de = serde_json::Deserializer::from_str(&deep);
        de.disable_recursion_limit();
        assert!(Id::deserialize(&mut de).is_err());
        let ok: Id = serde_json::from_str(r#"{"Node":[{"Leaf":true},{"Leaf":false}]}"#).unwrap();
        assert_eq!(ok, Id::Node(Box::new(Id::seed()), Box::new(Id::zero())));
    }

    /// Legitimate stamps are shallow (depth ≈ log of participant count); a depth
    /// well under the bound (and under serde_json's own 128-container limit,
    /// which an ITC depth hits at ~64) round-trips back to identical bytes.
    #[test]
    fn serde_accepts_legit_depth() {
        let json = deep_id_json(20);
        let v: Id = serde_json::from_str(&json).unwrap();
        assert_eq!(json, serde_json::to_string(&v).unwrap());
    }

    // ── Empirical fail-closed fuzz sweep over `Stamp::from_bytes` ──────────────
    //
    // The hand-picked cases above pin the KNOWN adversarial classes (invalid
    // tag, deep `0x02` chain, trailing garbage, truncation). This backs them
    // with the same EMPIRICAL guarantee the node tree holds for every untrusted
    // decoder (`src/decoder_fuzz.rs`): `from_bytes` MUST fail closed (return
    // `Err`) on ANY input — never panic/abort. The node sweep only reaches this
    // codec transitively (via its `ZoneCausalReference` wrapper) and only under
    // the node crate's gate; this crate publishes standalone (crates.io, a
    // one-way wire-format freeze) and an external caller decodes untrusted bytes
    // directly, so the sweep must also run under `cargo test -p elara-itc`.
    // Zero-dependency, deterministically seeded (splitmix64) so any failure is
    // replayable — no `proptest`/`rand` dep added to a soon-public crate.
    struct FuzzRng(u64);
    impl FuzzRng {
        fn new(seed: u64) -> Self {
            FuzzRng(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, bound: usize) -> usize {
            if bound == 0 {
                0
            } else {
                (self.next_u64() % bound as u64) as usize
            }
        }
    }

    // Lengths capped at 256 (so the worst-case all-`0x02` run recurses ≤256
    // levels — well under MAX_ITC_DEPTH=1024 and any stack limit; the deep-chain
    // guard itself is pinned separately above), biased toward the small sizes
    // the tag/varint codec branches on.
    const FUZZ_BOUNDARY_LENS: &[usize] =
        &[0, 1, 2, 3, 4, 5, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256];

    fn fuzz_to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn fuzz_gen_input(rng: &mut FuzzRng) -> Vec<u8> {
        let len = if rng.next_u64() % 5 < 3 {
            FUZZ_BOUNDARY_LENS[rng.below(FUZZ_BOUNDARY_LENS.len())]
        } else {
            rng.below(257)
        };
        let mut v = vec![0u8; len];
        for b in v.iter_mut() {
            *b = (rng.next_u64() & 0xff) as u8;
        }
        // Bias leading bytes to {0,1,2}: the decoder branches on Id/Event tag
        // bytes, so small leaders drive inputs down the real recursive decode
        // path, not just the invalid-tag early reject.
        if rng.next_u64() & 1 == 0 {
            for b in v.iter_mut().take(6) {
                *b = (rng.next_u64() % 3) as u8;
            }
        }
        v
    }

    fn fuzz_mutate(rng: &mut FuzzRng, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        match rng.below(4) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1u8 << rng.below(8);
            }
            1 if !v.is_empty() => v.truncate(rng.below(v.len())),
            2 => {
                for _ in 0..rng.below(6) {
                    v.push((rng.next_u64() & 0xff) as u8);
                }
            }
            _ => {
                for b in v.iter_mut().take(2) {
                    *b = (rng.next_u64() & 0xff) as u8;
                }
            }
        }
        v
    }

    #[test]
    fn fuzz_stamp_from_bytes_is_fail_closed() {
        const ITERS: usize = 30_000;

        // (a) structured-random sweep.
        let mut rng = FuzzRng::new(0x01C_0001);
        for i in 0..ITERS {
            let input = fuzz_gen_input(&mut rng);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = Stamp::from_bytes(&input);
            }));
            assert!(
                r.is_ok(),
                "Stamp::from_bytes PANICKED (random) iter={i} len={} input=0x{}",
                input.len(),
                fuzz_to_hex(&input),
            );
        }

        // (b) valid-then-mutated sweep — reach the "almost-valid" deep-parse
        // states pure-random rarely lands on. A varied corpus of real stamps
        // (leaf/node id-trees, leaf/node event-trees) built via the public API,
        // each encoded then one-mutation perturbed.
        let mut corpus: Vec<Vec<u8>> = Vec::new();
        corpus.push(Stamp::seed().to_bytes());
        corpus.push(Stamp::zero().to_bytes());
        let (a, b) = Stamp::seed().fork();
        corpus.push(a.to_bytes());
        corpus.push(b.event().to_bytes());
        let (c, _d) = Stamp::seed().fork();
        corpus.push(c.event().event().to_bytes());
        // Sanity: the corpus is genuinely valid (else the mutate layer is moot).
        for enc in &corpus {
            assert!(Stamp::from_bytes(enc).is_ok(), "corpus entry must be valid");
        }

        let mut rng = FuzzRng::new(0x01C_0002);
        for i in 0..ITERS {
            let base = &corpus[rng.below(corpus.len())];
            let m = fuzz_mutate(&mut rng, base);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = Stamp::from_bytes(&m);
            }));
            assert!(
                r.is_ok(),
                "Stamp::from_bytes PANICKED (mutated) iter={i} input=0x{}",
                fuzz_to_hex(&m),
            );
        }
    }
}
