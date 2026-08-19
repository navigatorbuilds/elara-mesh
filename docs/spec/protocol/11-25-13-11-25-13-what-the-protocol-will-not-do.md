#### 11.25.13 What the Protocol Will NOT Do

- It will not implement a centralized, default-shipped blacklist of forbidden content hashes. Hash-based blacklists are content-agnostic censorship mechanisms that will inevitably be abused. Operator-configured term filters on metadata text fields are a different mechanism — transparent, jurisdiction-specific, and under operator control.
- It will not allow retroactive deletion of validation records. Immutability is a core guarantee. Tombstoning suppresses propagation; it does not delete storage. Records that have been stored remain stored.
- It will not ship default content blocklist terms. The protocol does not encode a single cultural standard. Operators configure their own nodes according to their own legal obligations.

