# Internet mode transitions

`cargo test -p nostr-vpn-app-core --lib all_internet_mode_switches` exercises
all 25 ordered pairs of Direct, Private VPN, WireGuard upstream, Paid Automatic,
and Paid Manual through native settings actions, persistence, reload, and UI
state. It also repeats the destination selection and checks that imported
WireGuard settings survive switching away.

`cargo test -p nvpn --bin nvpn paid_exit` includes cancellation of pending
Manual funding and Automatic-to-Manual handover on the same provider. Funding
already in progress must finish persisting its result without activating an
obsolete selection.

`./scripts/e2e-paid-exit-automatic-docker.sh` and
`./scripts/e2e-paid-exit-docker.sh` run the network integration coverage. After
the existing payment, renewal, and seller-upstream checks, the buyer traverses
all 25 mode pairs without resetting its daemon between transitions. Each step
checks DNS resolution, HTTP upload/download, and the source address observed by
the fixture server. Paid-to-paid transitions must preserve usable channel
credit and monotonic payments. A paused test mint also verifies that a wallet
result arriving after Manual-to-Direct is attached to its original session
while Direct stays selected.

These Docker tests use isolated configurations, generated identities, and test
mint funds. They require Docker network administration/TUN support and Internet
access for the configured encrypted DNS resolver. They do not exercise native
window clicks or change the host's selected Internet source.
