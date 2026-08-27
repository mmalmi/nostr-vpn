# macOS

The macOS app is a SwiftUI/AppKit shell over `nostr-vpn-app-core` through
UniFFI. Rust owns state, configuration, and VPN actions; Swift owns presentation
and macOS integrations such as the menu-bar item, deep links, QR scanning,
startup registration, sharing, and update installation.

## Build and run

With Xcode and the Rust toolchain installed, run from the repository root:

```sh
just macos-build
just run-macos
```

The build regenerates the UniFFI bindings and xcframework, refreshes the Xcode
project when XcodeGen is available, and builds the unsigned development app.
`run-macos` rebuilds and launches it.

Use `just macos-gen-swift`, `just macos-rust`, `just macos-xcframework`, or
`just macos-xcodeproj` for focused work. Release signing, notarization, and DMG
creation are handled by the release workflow.

See the [native UI parity matrix](../docs/native-ui-parity-matrix.md) for the
shared platform contract.
