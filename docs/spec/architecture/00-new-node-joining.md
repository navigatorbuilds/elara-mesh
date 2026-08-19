### New node joining
1. Has genesis_authority hash (hardcoded in binary)
2. Connects to ANY node (signed bootstrap list, hardcoded IPs, or DAM peer records)
3. Receives epoch seals → verifies genesis authority chain
4. Learns zone registry FROM epoch seals (zone_registry_root + deltas)
5. Subscribes to desired zones → downloads zone state from zone peers
6. Starts processing

**No centralized registry. The epoch seals ARE the zone registry.**

