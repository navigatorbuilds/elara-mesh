### MEDIUM Priority (Cross-Zone + Bootstrap)

5. **Zone topic advertisement**
   - Zone ID = `sha256("elara-zone:" || zone_name)` — zones as Kademlia regions
   - Nodes advertise zone membership in peer info
   - Cross-zone lookup = Kademlia lookup for nodes closest to target zone ID
   - Anchor nodes serve as zone gateways
   - Zone registry in epoch seals lists known active zones

6. **Signed bootstrap lists (EIP-1459 style)**
   - Genesis authority key signs Merkle tree of peer records
   - Content-hash subdomains prevent DNS poisoning
   - Can be served from DNS, IPFS, website, or embedded in binary
   - Removes dependency on specific IPs

7. **NAT relay protocol**
   - libp2p DCUtR achieves 70% hole-punching without centralized infra
   - Public-IP nodes relay for NATted peers (Circuit Relay v2 model)
   - Critical for inclusive participation (home devices, IoT)

