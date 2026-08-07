## The Unified Node

Every node runs the same binary. Configuration determines behavior:

```toml
[node]
type = "witness"                          # leaf | relay | witness | archive | anchor
ram_budget = "256MB"                      # hard cap on in-memory data
zones = ["medical/eu/west", "finance/*"]  # what this node stores and witnesses
storage = "rocksdb"                       # rocksdb | sqlite (dev only)
```

