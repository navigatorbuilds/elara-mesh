#### 3.3.5 Dimensional Extensibility

The DAM's dimensional count is not fixed at five. The architecture supports N structural dimensions and M operational layers, constrained by two requirements:

1. **Immutability.** Each coordinate must be deterministic and immutable at record creation. A property whose value changes over time — witness count, reputation score, confidence level — is an overlay metric, not a structural coordinate. Structural coordinates define where a record lives in the mesh; they cannot drift.

2. **Physical substrate mapping.** Each structural dimension must correspond to a physical property that, when implemented natively, eliminates a serialization tax (see Section 13). A dimension without a hardware counterpart adds logical expressiveness but increases the serialization overhead that native hardware is designed to remove.

The current five dimensions — time, concurrency, zone topology, classification projection, and AI analysis — represent the hardware frontier of 2026. As substrate technology evolves, derived properties may be promoted to structural coordinates when they satisfy both requirements above.

**First candidate: Lineage Depth (D).** The number of causal hops from a zone's genesis record to a given record. Depth is currently derivable via DAG traversal at O(n) cost — walking the parent chain backward to the root. As a structural coordinate, it would reduce lineage queries and trust scoring to O(1) address lookups.

Depth satisfies the extensibility criteria partially:

- **Immutable at creation.** A record's depth is determined by its parents at the moment of creation and cannot change. ✓
- **Physically mappable.** 3D stacked memory (236+ layers in production, 2023) provides a substrate where records at the same depth occupy the same physical layer, making depth-based queries a layer selection rather than a graph traversal. ✓
- **Universally useful.** Forensics, trust scoring, provenance chain analysis, and regulatory audit all benefit from first-class depth addressing. ✓
- **Open problem: multi-parent ambiguity.** In a DAG with multiple parents at different depths, a record's depth requires a resolution rule — maximum parent depth + 1 (longest chain), minimum + 1 (shortest path), or zone-relative computation. This ambiguity does not exist in the current five coordinates, where each value is unambiguously determined at creation. ✗

The protocol reserves Depth as a future structural dimension, pending formal resolution of the multi-parent disambiguation rule and validation against production workloads.

**Expansion axes.** The architecture supports expansion in two distinct ways:

- **New structural dimensions** require hardware justification, immutability, and orthogonality to existing coordinates. They extend the address tuple and the wire format.
- **New operational layers** are cheaper to add — they project over the existing mesh without modifying the address space. Reputation scoring, semantic classification, and economic valuation are natural candidates for future layers that do not require structural promotion.

The 5-tuple addressing scheme is designed to accommodate additional coordinates without breaking the wire format — the metadata field in ValidationRecord provides the extension point for dimensions that are structurally validated but not yet promoted to native coordinates.

