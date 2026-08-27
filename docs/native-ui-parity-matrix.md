# Native UI Parity

This document records the current native-shell contract and known platform
differences. It is a source snapshot, not a migration backlog. Product state,
validation, and policy belong in Rust; native code owns presentation, lifecycle,
permissions, and operating-system integrations.

## Architecture

| Platform | Native shell           | Core boundary              | VPN runtime                                         | Release package             |
| -------- | ---------------------- | -------------------------- | --------------------------------------------------- | --------------------------- |
| macOS    | SwiftUI/AppKit         | UniFFI typed state/actions | `nvpn` background service                           | DMG and updater app archive |
| Windows  | WPF/.NET 8             | JSON C ABI                 | Windows service with Wintun                         | Inno Setup executable       |
| Linux    | GTK4/libadwaita Rust   | Direct typed Rust API      | `nvpn` background service                           | Debian package              |
| Android  | Kotlin/Jetpack Compose | JSON C ABI over JNI        | `VpnService` + Rust mobile tunnel                   | AAB/APK, ARM64              |
| iOS      | SwiftUI/UIKit          | JSON C ABI                 | NetworkExtension Packet Tunnel + Rust mobile tunnel | App Store/TestFlight IPA    |

All shells consume the same `UiState`/native action model. The desktop shells
delegate long-running VPN work to `nvpn`; Android and iOS attach their platform
TUN packet APIs directly to the Rust mobile tunnel.

## Product parity

| Capability                                               | macOS                   | Windows                      | Linux                                    | Android                      | iOS                                          |
| -------------------------------------------------------- | ----------------------- | ---------------------------- | ---------------------------------------- | ---------------------------- | -------------------------------------------- |
| Create, join, activate, and remove networks              | Yes                     | Yes                          | Yes                                      | Yes                          | Yes                                          |
| Signed join-request approval and manual pairing          | Yes                     | Yes                          | Yes                                      | Yes                          | Yes                                          |
| Device detail, alias, endpoint hints, admin, and removal | Yes                     | Yes                          | Yes                                      | Yes                          | Yes                                          |
| Direct, WireGuard, and trusted-device Internet sources   | Yes                     | Yes                          | Yes                                      | Yes                          | Yes                                          |
| Exit leak protection and exit DNS policy                 | Yes                     | Yes                          | Yes                                      | Yes                          | Yes                                          |
| Diagnostics, relay, FIPS, and device settings            | Yes                     | Yes                          | Yes                                      | Yes                          | Yes                                          |
| Deep links into an already-running app                   | Yes                     | Yes                          | Yes                                      | Android task routing         | iOS scene routing                            |
| Desktop service and CLI management                       | Yes                     | Yes                          | Yes                                      | N/A                          | N/A                                          |
| Startup and tray/menu integration                        | LaunchAgent + menu bar  | Registry + notification area | desktop entry + StatusNotifier           | OS VPN/boot behavior         | OS VPN lifecycle                             |
| Update delivery                                          | Native verified updater | Native verified updater      | Download/open package                    | Release self-updater         | App Store/TestFlight                         |
| Join-request QR capture                                  | Live camera             | Image import                 | Camera with `zbarcam`, plus image import | Live camera and image import | Live camera; image import is test-build-only |

The Android `VpnService` and iOS Packet Tunnel packet loops are implemented, not
stubs. `just mobile-test-kit-device` exercises physical TUN traffic, and
`just mobile-test-kit-exit` verifies the production WireGuard exit/DNS path. See
[Mobile Test Kit](mobile-test-kit.md) for the evidence boundary.

## Intentional differences and remaining gaps

- iOS compiles the App Store edition without paid Internet/wallet features.
- Windows has QR image import but no live camera scanner.
- Linux live camera scanning depends on `zbarcam` and an available camera;
  image import remains available without either.
- Production iOS image import is disabled; the file-import path is built only
  for the release join test variant.
- Android currently packages only `arm64-v8a`.
- Mobile shells use store/OS lifecycle instead of desktop service, CLI, tray,
  and login-startup controls.

Keep additions behind the shared Rust state/action boundary. Update this file
only for user-visible parity or an intentional platform difference; build and
test instructions belong in the platform READMEs.
