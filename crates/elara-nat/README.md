# elara-nat

NAT traversal for peer-to-peer nodes, with no heavyweight dependencies — just
`tokio` and `tracing`. STUN and UPnP are implemented directly over UDP sockets
(no `stun`/`igd` crate pulled in).

Extracted as a standalone crate from the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh)
node, where it lets a node discover whether it is reachable and open a port when
it is not.

## What it does

Three strategies, tried in order:

1. **STUN** (RFC 5389) — `stun_discover_external` finds your external
   `IP:port`; `detect_nat_type` classifies the NAT as full-cone,
   (port-)restricted-cone, or symmetric.
2. **UPnP / IGD** — `upnp_map_port` asks the gateway to forward your listen
   port; `upnp_renewal_loop` re-maps it periodically before the lease expires.
3. **Fallback** — `auto_detect_nat` runs the whole sequence and returns a
   `NatDetection` (external address, NAT type, whether a port was mapped, and
   whether the node should treat itself as behind NAT).

## Example

```rust
// Discover reachability and try to open the listen port.
let detection = elara_nat::auto_detect_nat(9473).await;
if detection.behind_nat {
    // fall back to more aggressive peer pulling, relays, etc.
}
```

`auto_detect_nat` and the UPnP calls are `async` (they do network I/O); the STUN
detection runs on a blocking task. You bring the tokio runtime.

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option. (The Elara node itself is
AGPL-3.0; this extracted library is permissively licensed for reuse.)
