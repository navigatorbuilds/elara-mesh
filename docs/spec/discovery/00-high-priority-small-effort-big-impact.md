### HIGH Priority (Small Effort, Big Impact)

1. **IP diversity limits in k-buckets**
   - Current: no limits. Attacker from single /24 can fill multiple buckets.
   - Fix: max 2 nodes per /24 per bucket, max 10 per /24 for whole table (discv5 model).

2. **Test-before-evict in k-buckets**
   - Current: LRU eviction blindly removes oldest.
   - Fix: ping existing entry before evicting. Only evict if no response (Bitcoin 2015 fix).

3. **Disjoint parallel lookups (S/Kademlia)**
   - Current: `iterative_find_node` uses single path.
   - Fix: d=4 parallel disjoint paths. Even 20% adversarial = 99% lookup success.

4. **Outbound peer preference**
   - Current: no distinction between peers we found vs peers that found us.
   - Fix: track peer provenance. Prefer outbound-discovered peers for routing table.

