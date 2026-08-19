### 11.34 Mega-Publication Attack (Economic Shock from Private Network Transition)

> **Status (2026-06-22): both this attack and its Defenses 1–5 are INERT — they presuppose `NETWORK_PUBLISH`, which is DISABLED in code** (`NETWORK_PUBLISH_ENABLED = false`, compile-time guarded in `src/network/publish.rs`; see §10.6.3). With no live publication path, a mega-publication cannot occur on the public network, and the protocol-level publication rate limits, beat-acquisition vesting, governance cooling period, zone absorption quotas, and economic-shock circuit breaker described below are not active. They are retained for reference pending the inert-import reframe and a proven multi-root merge theorem (`docs/MESH-BFT-MERGE-SEMANTICS.md`).

**The attack:** A dominant private entity — hypothetically representing a significant fraction of global economic output — operates a private Elara network for decades. It accumulates a vast, internally-consistent DAG: hundreds of millions or billions of records, spanning every industry vertical, with deep causal chains verified by thousands of internal witnesses. One day, this entity executes a NETWORK_PUBLISH (Section 10.6.3) in SNAPSHOT mode — publishing its entire historical DAG to the public network simultaneously.

This is not a traditional attack. The entity may have entirely legitimate motivations. But the effect on the public network is indistinguishable from an economic weapon.

**Why this matters — five failure modes:**

**Failure 1: Beat Demand Singularity**

The conservation model fixes supply at 10 billion beats. A mega-publisher needs beats for storage delegation of its entire historical DAG across public storage nodes. If the entity's history represents a substantial fraction of all validated work globally, the beat demand could approach or exceed the circulating supply. Beat demand outstrips circulation. Legitimate participants cannot obtain enough beats for storage delegation. The public network's economic model seizes.

**Failure 2: DAG Size Shock**

The public DAG's storage and indexing infrastructure was designed for organic growth — a steady accumulation of records over years. A mega-publication dumps decades of records in a single event. Storage nodes must absorb, verify, and index this volume. Bandwidth saturates. Nodes with limited storage capacity are forced offline. The network's physical infrastructure cannot absorb the data.

**Failure 3: Trust Landscape Inversion**

The mega-publisher's internal DAG is deeply consistent — decades of verified causal chains. Once published and retroactively witnessed, this history dominates the trust landscape. Every existing public participant looks insignificant by comparison. Trust scores that took years to build on the public network become noise relative to the mega-publisher's history. The practical effect: the entity's records become the de facto reference truth for any domain they operated in.

**Failure 4: Governance Capture**

The square-root dampening and 5% per-identity cap (Section 10.4) limit individual governance weight. But a mega-entity can create thousands of legitimate identities — subsidiaries, divisions, regional offices, each operating independently for decades. Each identity falls under the 5% cap individually. Collectively, they could represent majority governance weight. The anti-Sybil mechanisms (Section 11.1) detect fake identities but cannot prevent an entity from having legitimately distinct organizational units that happen to share strategic alignment.

**Failure 5: Attention Economy Capture**

The entity's Layer 3 AI analysis, trained on decades of private data spanning a significant fraction of global economic activity, produces cognitive output that dwarfs anything trained on the public network's smaller dataset. The attention economy concentrates around this entity's analysis capabilities. Other participants become consumers rather than producers of attention-value.

**Defense 1: Protocol-Level Publication Rate Limits**

The NETWORK_PUBLISH protocol (Section 10.6.3) defines STREAMING and GRADUAL transition modes, but these are voluntary — the publisher chooses the mode. Defense requires **mandatory ingestion caps** at the protocol level:

```
MAX_PUBLICATION_RATE = f(public_network_size, publisher_size)

Proposed formula:
  max_records_per_day = public_dag_size × 0.01 / (1 + publisher_dag_size / public_dag_size)

  The divisor scales with the publisher's size relative to the network.
  Larger publishers are throttled harder — proportionally to their
  potential to destabilize the network.

Examples (public DAG = 10 billion records):

  Small publisher (100M records, 1% of network):
    rate = 10B × 0.01 / (1 + 0.01) ≈ 99M/day → ~1 day (negligible impact)

  Medium publisher (10B records, equal to network):
    rate = 10B × 0.01 / (1 + 1) = 50M/day → ~200 days (~7 months)

  Large publisher (100B records, 10× network):
    rate = 10B × 0.01 / (1 + 10) ≈ 9M/day → ~11,000 days (~30 years)

  Dominant publisher (500B records, 50× network):
    rate = 10B × 0.01 / (1 + 50) ≈ 2M/day → ~250,000 days (centuries)
```

The key insight: a flat rate limit (e.g., 1%/day) is insufficient because 100 days is trivial for an entity that operated privately for decades. The scaled formula ensures that the entities most capable of causing economic shock are precisely the ones most throttled. Small publishers barely notice the limit. Dominant publishers face multi-decade publication timelines — which is appropriate, because the network needs decades to economically absorb an entity of that scale.

Note that the public DAG grows as records are published, which gradually increases the rate limit over time. A 10× publisher does not literally wait 30 years at a fixed rate — as each day's published records enlarge the public DAG, the next day's limit rises slightly. The actual timeline is shorter than the static calculation suggests, but still measured in years or decades for truly dominant entities.

The rate can be adjusted through governance (Section 10.3), but the default is deliberately aggressive.

**Defense 2: Beat Acquisition Velocity Limits**

To prevent beat demand shocks, the protocol enforces a **maximum beat acquisition rate** for entities engaged in mega-publication:

```
PUBLICATION_TOKEN_VESTING:
  Any entity publishing > 1% of the public DAG's current size
  must acquire beats over a period proportional to publication duration:

  vesting_period = publication_duration × 0.5
  (beats must be acquired over at least half the publication timeline)

  A medium publisher with a 200-day publication timeline:
    vesting = 100 days minimum beat acquisition period

  A large publisher with a 30-year publication timeline:
    vesting = 15 years minimum beat acquisition period
```

The vesting period is tied to the publication rate limit — the longer the publication takes, the longer the beat acquisition is spread. This prevents an entity from acquiring all beats upfront and sitting on them. Beat markets can absorb gradual demand over years. They cannot absorb a dominant entity purchasing 40% of the circulating supply in a week.

**Defense 3: Governance Cooling Period**

New entrants that exceed a publication size threshold trigger a **governance cooling period:**

```
GOVERNANCE_COOLING:
  Threshold: entity publishes > 5% of public DAG size

  Cooling period: 365 days from first publication
  During cooling:
    - Entity identities can participate in witnessing (earning trust)
    - Entity identities CANNOT vote on governance proposals
    - Entity identities CANNOT submit governance proposals

  After cooling:
    - Governance weight ramps linearly over the following 365 days
    - Full governance weight reached 2 years after first publication
```

This prevents a mega-publisher from immediately influencing protocol rules. The 2-year ramp gives the existing community time to understand the entity's behavior and intentions before granting governance power.

**Defense 4: Zone-Level Absorption Quotas**

Each zone sets its own maximum ingestion rate for published records:

```
ZONE_ABSORPTION_QUOTA:
  Each zone independently sets: max_external_ingestion_per_day
  A mega-publisher must negotiate with each zone independently
  Zones can refuse publication entirely (zone autonomy, Section 10.1)

  Effect: Even if a mega-entity bypasses global rate limits through
  multiple publication streams, each zone absorbs only what it
  can handle. The publication fragments across zones and time.
```

**Defense 5: Economic Shock Circuit Breaker**

The protocol defines an emergency economic mechanism:

```
ECONOMIC_CIRCUIT_BREAKER:
  Trigger: Beat velocity exceeds 3× the 90-day moving average
           AND a mega-publication event is in progress

  Action:
    - Publication ingestion paused for 72 hours
    - Governance vote initiated: "Resume publication at current rate?"
    - If vote passes (>50% conviction): publication resumes
    - If vote fails: publication rate reduced by 50%, new vote after 30 days

  Purpose: Allows the network to catch its breath during economic shocks
```

**The Economic Warfare Variant**

The most dangerous version of this scenario is *intentional* — a dominant entity publishes not to participate in the public network, but to disrupt it. The economic shock is the goal, not a side effect. This is analogous to a financial market manipulation attack executed through legitimate-seeming market activity.

Defenses against the intentional variant:

1. **Publication cannot be anonymous.** The NETWORK_PUBLISH record requires a source identity (Section 10.6.3). The mega-publisher is publicly identified. Reputational consequences apply.
2. **Publication is irreversible.** Once records are published, they cannot be retracted. The entity's internal history is now permanently public. This is a significant deterrent — an entity using publication as a weapon exposes its own historical data in the process.
3. **The attacker pays.** Beat acquisition for storage delegation means the attacker must spend significant capital to execute the attack. The rate limits ensure this spending is spread over months or years, giving the network time to respond. The capital is not recoverable — beats spent on storage delegation compensate storage nodes for real work.
4. **The network can survive partial absorption.** Even if the publication is paused by the circuit breaker, the records already published are valid and useful. The network gains value from partial publication. Only the *rate* is dangerous, not the content.

**What the protocol cannot fully prevent — honest acknowledgment:**

If an entity representing a majority of global economic output genuinely transitions to the public network over a multi-year period using all the rate-limited mechanisms described above, the entity will eventually hold significant governance weight, economic influence, and trust dominance. The defenses slow this transition and prevent shock, but they cannot prevent an entity that is genuinely large from being genuinely influential.

This is not a protocol failure. It is a reflection of reality: in any governance system — political, economic, or cryptographic — entities that represent real economic value eventually accumulate proportional influence. The protocol's contribution is ensuring this happens gradually, transparently, and with structural limits on concentration. The square-root dampening, identity caps, and zone autonomy prevent any single entity from achieving absolute control — but they cannot prevent an entity from becoming the most influential participant.

The ultimate defense is the same as in traditional markets: a healthy public network with many large participants prevents any single mega-publisher from dominating. If the public network grows diverse enough before any mega-publication occurs, the relative impact of any single publication diminishes. This is why the network bootstrap period (Section 11.4) is critical — the first decade of the public network's growth determines its resilience to future mega-publication events.

