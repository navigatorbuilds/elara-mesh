### 11.28 Eclipse Attacks

**The attack:** An adversary surrounds a target node with malicious peers, controlling all its network connections. The target sees only the attacker's version of the DAM — a curated subset that excludes certain records or includes fabricated ones. Unlike Sybil attacks (fake identities), eclipse attacks manipulate network topology.

**Impact:** An eclipsed node might:
- Not receive revocation records (believing a compromised key is still valid)
- Not see conflicting claims (believing it has priority when it does not)
- Receive fabricated trust headers (believing records have more witnesses than they do)

**Defense 1: Diverse Peer Selection**

The Kademlia DHT (Section 11.14) provides natural eclipse resistance because peer selection is based on XOR distance in the key space, not network topology. An attacker would need to generate keys close to the target's key in Kademlia space — computationally expensive and detectable (anomalous key clustering).

Additional diversity enforcement:
- Each node maintains connections to peers in at least 3 different /16 IP subnets
- Each node maintains connections to peers in at least 2 different geographic regions (determined by IP geolocation)
- Outbound connections (initiated by the target) are prioritized over inbound (initiated by potential attackers)

**Defense 2: Anchor Node Pinning**

Every node maintains at least one persistent connection to a known anchor node. Anchor nodes are operated by identified, staked entities — eclipsing them requires compromising the anchor operator, not just manipulating network routing.

If all peer connections seem to agree but the anchor node disagrees, the node raises an **eclipse alert** — flagging a potential attack and refusing to accept trust headers that conflict with the anchor's view.

**Defense 3: Trust Header Cross-Validation**

Trust headers (Section 11.3) are signed by multiple anchor nodes. A legitimate trust header carries signatures from geographically distributed anchors. An eclipsed node that receives trust headers signed by only one anchor (or by unknown entities) detects the discrepancy and falls back to a trust-no-one mode — accepting only locally validated records until the eclipse is resolved.

**Defense 4: Out-of-Band Verification**

For high-stakes verification (large transactions, legal proceedings), the protocol supports out-of-band verification: the verifier queries a known anchor node directly (by domain name or IP, not through the DHT) to confirm a record's status. This bypasses any eclipse on the local network.

