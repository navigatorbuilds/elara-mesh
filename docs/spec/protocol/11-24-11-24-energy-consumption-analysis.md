### 11.24 Energy Consumption Analysis

**The obligation:** The paper discusses the energy costs of existing consensus mechanisms. Credibility requires disclosing the Elara Protocol's own energy footprint.

**Estimation by component:**

**Layer 1 (local validation):** Negligible. Hashing + signing = milliseconds of CPU time. Energy cost: ~183 μJ (~50.8 nWh) per validation on a smartphone. Orders of magnitude less than sending a text message.

**Layer 2 (network propagation + witnessing):**

- **Gossip propagation:** Network traffic comparable to a peer-to-peer file-sharing swarm. Each node sends/receives a compact record announcement (~1 KB header + hash, not the full ~4.5 KB record) to √n peers per hop; full records are fetched on demand by interested nodes. Records propagate within their zone (Section 7), not globally — zone partitioning bounds the effective fanout. For a zone with ~10,000 active nodes, epidemic gossip is projected to converge in ~4 rounds of √n fan-out (modelled from epidemic-gossip theory; untested at this scale). Most records are created by leaf nodes and propagated to their zone's witness set, not broadcast to the entire network. The energy estimate below uses network-wide averages accounting for zone partitioning and leaf-node locality.

- **Witness attestation (PoWaS):** The proof-of-work component is calibrated to be lightweight — ~0.1 seconds of CPU per attestation (vs. ~10 minutes of ASIC-scale computation in proof-of-work blockchains). Energy per attestation: ~0.005 Wh. For 1,000 witnesses per record: ~5 Wh total.

- **Anchor node operation:** Comparable to running a modest server. ~100W continuous. Per anchor node per year: ~876 kWh. For 100 anchor nodes globally: ~87,600 kWh/year.

**Layer 3 (AI-assisted analysis):** Dependent on the model and hardware. Ollama running a 1.5B parameter model: ~50W during inference. Intermittent, not continuous. Per node per year (assuming 4 hours/day active): ~73 kWh.

**Total network estimate at scale (1 million nodes, 100 anchor nodes):**

| Component                  | Annual Energy         |
|----------------------------|-----------------------|
| Layer 1 (local validation) | < 1 MWh (negligible)  |
| Layer 2 (propagation)      | ~2,000 MWh            |
| Layer 2 (witnessing PoWaS) | ~5,000 MWh            |
| Anchor nodes               | ~88 MWh               |
| Layer 3 AI (optional, ~10% of nodes) | ~7,300 MWh            |
| **Total**                  | **~14,400 MWh/year**  |

**Comparison:**

| Network Type                   | Annual Energy              |
|--------------------------------|----------------------------|
| Proof-of-work blockchains      | ~150,000,000 MWh (150 TWh) |
| Proof-of-stake platforms       | ~1,500–2,600 MWh           |
| **Elara Protocol (estimated)** | **~14,400 MWh**            |

The Elara Protocol at full scale would consume roughly **10,000x less energy than proof-of-work blockchains** (a projection at the design-target scale of ~1M nodes — the network does not yet operate at that scale, and both sides of the comparison are estimates). It consumes approximately 6x more than proof-of-stake platforms in absolute terms, but the comparison is not apples-to-apples: proof-of-stake networks process financial transactions (~30 TPS), while the Elara Protocol is designed to validate all forms of digital work at IoT scale (millions of records per day — a design target, not measured throughput) with quantum-safe cryptography. Layer 1 validation energy is negligible (~183 μJ per operation) — the dominant costs are network propagation, witness consensus, and optional AI analysis.

The PoWaS component is the largest contributor. If the Sybil resistance proves achievable without PoW (through reputation and staking alone), the energy footprint drops to ~9,400 MWh. Without optional Layer 3 AI, it drops further to ~2,100 MWh — comparable to proof-of-stake networks.

