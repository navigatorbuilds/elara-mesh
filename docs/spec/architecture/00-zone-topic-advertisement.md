### Zone topic advertisement
- Zone ID = sha256("elara-zone:" || zone_path) → point in Kademlia space
- Each peer's info includes subscribed zones + node type
- Finding zone peers = Kademlia lookup for zone ID → filter by zone + tier
- Same approach as Ethereum discv5 topic advertisement

