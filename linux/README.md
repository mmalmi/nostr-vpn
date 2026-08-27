# Linux

The Linux app is a Rust GTK4/libadwaita shell that uses
`nostr-vpn-app-core` directly. It includes native device, Internet, optional
wallet, settings, tray, deep-link, updater, and QR import/scanning surfaces.

## Development

Docker is required. From the repository root:

```sh
just run-linux
just linux-build
just linux-e2e-gui
```

The runner builds the development image, starts an Xvfb/Fluxbox desktop, and
runs commands inside the Linux workspace. With no explicit command it launches
the app. The Compose file publishes VNC on port `5902` on all host interfaces,
with the development password `nostrvpn`; use it only on a trusted development
host or firewall the port.

Run focused Cargo commands through the same environment:

```sh
./tools/run-linux cargo check
./tools/run-linux cargo test
```

Installed packages register `nvpn://` through the desktop entry. A development
deep link can be passed directly to the app:

```sh
./tools/run-linux cargo run -- nvpn://debug/tick
```

Live camera scanning uses `zbarcam` when a camera is available; QR image import
works without it. Release packaging currently produces a Debian package through
the release workflow.

See the [native UI parity matrix](../docs/native-ui-parity-matrix.md) for the
shared platform contract.
