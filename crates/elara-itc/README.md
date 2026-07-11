# elara-itc

**Interval Tree Clocks** (Almeida, Baquero & Fonte, 2008) in safe Rust —
space-efficient logical clocks for dynamic systems. Same causal-ordering
guarantees as vector clocks, but the identity space is shared by *forking* and
*joining* rather than by pre-assigning one slot per participant, so a `Stamp`
stays small (≈ tens of bytes) even as nodes come and go.

Extracted from the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh)
node, where every record carries an ITC stamp for intra-zone causal order. The
crate is protocol-agnostic: it's just the clock algebra plus a compact,
attacker-hardened binary codec.

## Core operations

| Op | Meaning |
|----|---------|
| `Stamp::seed()` | the initial clock — owns the whole identity space |
| `fork()` | split one stamp into two with disjoint identities (a node joins) |
| `join()` | merge two stamps — union identities, pointwise-max the events |
| `event()` | increment where this stamp holds identity (a local event happens) |
| `leq` / `before` / `concurrent` | causal comparison (happened-before lattice) |

```rust
use elara_itc::Stamp;

let seed = Stamp::seed();
let (a, b) = seed.fork();          // two participants, disjoint identities

let a1 = a.event();                // A does work
let b1 = b.event();                // B does work, concurrently

assert!(a1.concurrent(&b1));       // neither happened-before the other

let merged = a1.clone().join(b1);  // A receives B's state
assert!(a1.before(&merged));       // the merge dominates A's prior stamp
```

## Compact, depth-bounded wire format

`Stamp::to_bytes` / `Stamp::from_bytes` are a hand-rolled binary codec (1-byte
tags + LEB128 varints, no serde on the hot path). The decoder is **bounded**:
recursion is capped at `MAX_ITC_DEPTH` (1024) so a crafted byte string of
repeated `Node` tags can't overflow the stack — relevant anywhere stamps are
decoded from untrusted input. Malformed input returns [`ItcError`], never
panics.

```rust
use elara_itc::Stamp;
let bytes = Stamp::seed().to_bytes();          // [0x01, 0x00, 0x00]
let back = Stamp::from_bytes(&bytes).unwrap();
assert_eq!(back, Stamp::seed());
```

The `Id`, `Event`, and `Stamp` types also derive `serde::{Serialize,
Deserialize}` for use with any serde format.

## License

MIT OR Apache-2.0.
