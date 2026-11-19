# Mobile Test Kit

Use the smallest mode that proves the layer you changed. The recipes are defined
in the root `Justfile`; their implementation is `scripts/mobile-test-kit.sh`.

For mobile-sensitive changes, run `just mobile-test-kit`; simulator/device packet
paths use `just mobile-test-kit-sim` / `just mobile-test-kit-device`.

| Recipe                        | What it proves                                                                                                                                        | Requirements                                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `just mobile-test-kit-rust`   | Shared app-core tests and `nvpn` platform-routing tests                                                                                               | Rust toolchain                                                                                          |
| `just mobile-test-kit`        | Rust checks plus the Android debug build; also the iOS build on macOS                                                                                 | Android SDK/NDK; macOS/Xcode for iOS                                                                    |
| `just mobile-test-kit-sim`    | Fast kit, iOS simulator UI/lifecycle smoke, and Android adb launch smoke                                                                              | macOS, an iOS simulator, and one Android emulator or device                                             |
| `just mobile-test-kit-device` | Current physical Android and iOS builds/installs, local test-network creation, VPN lifecycle, native TUN traffic, and idle/lifecycle gates            | Both physical devices and iOS Ad Hoc profile access, or explicit development-signing mode               |
| `just mobile-test-kit-exit`   | Release-grade physical WireGuard exit, five DNS policies, HTTPS/forwarding, lifecycle, Direct-with-tunnel, disconnect recovery, and evidence receipts | Both physical devices, Docker or a configured fixture host, and the private release/signing environment |

`mobile-test-kit` skips the iOS build on non-macOS hosts. Simulator coverage
cannot prove Android `VpnService` or iOS NetworkExtension packet flow; use the
device or exit mode for dataplane claims.

## Device safety and recovery

Run `scripts/test-ios-private-exit.sh PROVIDER_SPEC.json` with the installed
Release app and runner from the iOS network preparation. The paired test provider
must stay online through cleanup and serve a fresh 32-character hexadecimal
challenge only behind its exit. The fixture JSON contains its `providerNpub`,
`challenge`, and `probeURL`. Use an HTTP target in the benchmarking range
`198.18.0.0/15` with the challenge as its query and response body. The runner
starts from “This device”, opens the private picker, finds the expected peer
before selection, verifies the returned challenge, and restores the source and
VPN switch. The app receives no test configuration.

On Android, run the joined Linux/Pixel release check with
`NVPN_TEST_ANDROID_PRIVATE_EXIT=1` on its isolated guest. After both join
directions pass, the guest offers its connection to the paired phone. The
Android test opens the production Internet picker, records the provider before
selection, verifies a fresh request on both devices and restores the original
settings. The network must contain only these two test devices.

Run simulator UI checks without physical devices. Before physical UI automation,
require a bounded fresh unlocked-state check.

For physical iOS XCTest, reuse the trusted destination runner. After one verified
pre-method `XCTFuture Code=1000` stall, recycle only the exact `testmanagerd` PID
once and retry the same `UseDestinationArtifacts` plan. Never reboot, broadly
restart, prime, reinstall or uninstall as recovery. An Apple UI Automation
passcode may still be required.

A failed startup that never touched the app must not trigger another UI
automation session for cleanup when fresh USB evidence preserves its stopped
baseline. Keep completed artifact-bound device receipts when resuming. For
release-specific evidence reuse and the attended device window, see
[release gate recovery](release-resume.md#iphone-testing-window).

## Local configuration

Copy `.env.mobile.example` to ignored `.env.mobile.local`, or export values in
the shell. At minimum, select devices with `NVPN_ANDROID_SERIAL` (or
`ANDROID_SERIAL`) and `NVPN_IOS_DEVICE` when automatic selection is ambiguous.
Keep device, signing, fixture, and account values out of tracked files.

The device kit creates a debug-only local network, so it proves the OS VPN/TUN
path without a peer. A reachable peer or exit is required to prove reply traffic;
the exit kit configures and verifies that production path. For a focused manual
probe, set `NVPN_ANDROID_TUN_PACKET_PROBE_REQUIRE_REPLY=1` or
`NVPN_IOS_TUN_PACKET_PROBE_REQUIRE_REPLY=1` and provide a reachable target.

Evidence is written beneath `artifacts/mobile-android/` and
`artifacts/mobile-ios/`; release-grade exit receipts use the release gate's
artifact directories. See the [Android](../android/README.md) and
[iOS](../ios/README.md) guides for direct platform commands.
