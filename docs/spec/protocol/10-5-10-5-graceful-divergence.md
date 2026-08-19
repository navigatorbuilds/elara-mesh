### 10.5 Graceful Divergence

If zones cannot reach consensus on a cross-zone matter, the protocol supports **graceful divergence**:

1. The disagreeing zone announces a fork intention
2. A 90-day mediation period allows for compromise
3. If unresolved, the zone forks the protocol — maintaining DAG compatibility for historical records but diverging on the disputed feature
4. Cross-zone sync continues for shared historical data
5. New validations under the divergent rule are tagged with the fork identifier

This is not a failure state — it is a design feature. A protocol intended to span planets and centuries must survive political and philosophical disagreement without collapsing.

