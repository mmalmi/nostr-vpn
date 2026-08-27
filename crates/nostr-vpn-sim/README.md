# nostr-vpn-sim

Production-backed, in-process adversarial simulations for Nostr VPN.

The simulator runs real `FipsEndpoint` nodes over FIPS `SimNetwork` with the
production Nostr VPN control-pubsub runtime. It does not create TUN devices,
spawn daemons, or exercise the UI.

The default scenario runs 100 nodes with 20 attackers. It measures honest event
delivery before and after malformed pubsub datagrams and signed rating spam,
while reporting event-storage and simulated-network bounds. Honest nodes apply
trusted `fips.peer` ratings through `nostr-social-graph` and ignore ratings from
untrusted attackers.

```sh
cargo run -p nostr-vpn-sim
cargo test -p nostr-vpn-sim hundred_instance -- --ignored --nocapture
```

The 12-node full-path scenario runs in the normal test suite; the 100-node lane
is ignored unless selected explicitly.
