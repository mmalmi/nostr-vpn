# iOS

The iOS app is a SwiftUI shell over `nostr-vpn-app-core`'s JSON C ABI. Its
NetworkExtension target connects `NEPacketTunnelFlow` to the Rust mobile tunnel;
the app also owns VPN consent, deep links, sharing, and live camera QR scanning.
The deployment target is iOS 17.

The source of truth for cross-platform behavior is the
[native UI parity matrix](../docs/native-ui-parity-matrix.md).

## Build and run

On macOS, install Xcode, XcodeGen, and the required Rust iOS targets, then run:

```sh
just ios-build
just ios-run
```

Both commands build simulator and device Rust libraries, create
`NostrVpnAppCore.xcframework`, and generate the Xcode project. `ios-build` builds
the simulator app; `ios-run` also installs and launches it.

## Smoke tests

```sh
just ios-smoke
```

This checks the simulator build, install, launch, UI gate, lifecycle behavior,
idle CPU, and screenshot capture. A simulator cannot validate VPN permission or
the Packet Tunnel dataplane.

For an iOS-only physical-device run of the current signed app:

```sh
./scripts/mobile-ios-smoke.sh device \
  --install --create-network --vpn-cycle
```

It installs the current build, creates an isolated test network, cycles the
Packet Tunnel, and validates native TUN traffic. Device and signing values belong
in the shell environment or ignored `.env.mobile.local`, never in the repository.
Evidence is written under `artifacts/mobile-ios/`.

`just mobile-test-kit-device` runs the corresponding physical Android and iOS
checks together. See the [mobile test kit](../docs/mobile-test-kit.md) for
requirements and the full WireGuard exit/DNS gate.
