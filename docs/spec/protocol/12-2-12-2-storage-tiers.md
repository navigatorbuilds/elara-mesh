### 12.2 Storage Tiers

```
Tier 1: Active Nodes (operational today)
├── Laptops, phones, servers, IoT devices
├── Ephemeral — may go offline at any time
├── Collectively massive storage
└── The working layer of the network

Tier 2: Anchor Nodes (operational today)
├── Hardened infrastructure
├── Geographic diversity (multiple regions)
├── High uptime target
└── The reliability layer

Tier 3: Archive Nodes (future extension)
├── Deep storage with air-gapped or offline sync
├── Full DAG history (not just recent records)
├── Periodic hardware refresh
└── Not yet implemented — requires operational maturity
```

**Note:** Earlier versions of this specification described Tier 3 "salt mine bunkers" and Tier 4 "off-world nodes." These were aspirational and have been removed. The protocol's proof longevity property does not require exotic storage — it requires that proofs are self-contained and medium-independent. If archive nodes or off-world nodes become practical, the protocol supports them naturally. But claiming them as design tiers when they do not exist is dishonest.

