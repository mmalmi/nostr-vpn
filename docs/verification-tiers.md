# Verification Tiers And Managed Native Lab

Nostr VPN separates fast per-change confidence from scarce GUI, VM, simulator,
and physical-device confidence.

## Fast

Run this for every coherent change:

```sh
just verify-fast
```

It checks native-lab contracts, version parity, formatting, strict workspace
Clippy, focused dataplane/app-state safety, shared mobile Rust behavior, and
platform-tool contracts. It does not reserve or mutate a VM, GUI session,
simulator, or phone.

CI runs the same fast tier and, in parallel, the remaining workspace tests,
dataplane tooling contracts, release tooling contracts, web checks, and selected
platform compatibility jobs. A local fast pass is not the whole CI matrix.

## Health And Full Native Matrix

Preflight the managed lab without running tests:

```sh
just verify-health
```

Run the reserved native matrix at release boundaries or in scheduled lab work:

```sh
just verify-full
```

Configure `NVPN_WINDOWS_SSH_HOST` and, when automatic selection is unsuitable,
`NVPN_LAB_IOS_SIMULATOR`, `NVPN_LAB_IOS_DEVICE`, and
`NVPN_LAB_ANDROID_SERIAL`. Explicit IDs are preferable in unattended runs.

The full tier runs the fast tier unless `NVPN_VERIFY_SKIP_FAST=1`, checks all
required tools and targets, then locks the local Mac, Windows SSH host, selected
iOS simulator/device, and selected Android device as one managed run. It runs
the simulator and physical mobile VPN/TUN suites, followed by the release gate
with Linux, macOS, and Windows GUI lanes and the Windows WireGuard-exit lane
required.

The result defaults to
`artifacts/verification/full-native-result.json`. Exit 75 and
`status=infrastructure_unavailable` mean a target was missing, unhealthy, or
busy. A failing test on an available reserved matrix is
`status=product_failure` and retains the test exit code.

## Destructive Reset

Reset is disabled by default. On dedicated lab targets only:

```sh
NVPN_NATIVE_LAB_RESET=1 just verify-full
```

While holding the reservation, the wrapper erases the selected simulator,
uninstalls the app from the selected physical iOS device, and clears the Android
package before rebuilding. The helper also requires
`NVPN_NATIVE_LAB_ALLOW_RESET=1`; the full wrapper sets it only inside the
reservation. Never select a personal device whose Nostr VPN data must survive.

## Dataplane Work

`verify-fast` is the default entry point, not a replacement for path evidence.
Use the change-specific Docker, soak, roaming, host-pair, or native runner in
[the FIPS dataplane safety net](fips-dataplane-safety-net.md) when packet
movement, routing, discovery, performance, or cleanup behavior changes.
