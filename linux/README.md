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

Live camera scanning uses `zbarcam` when a camera is available. Use the Camera
dropdown in the scanner to select a built-in or external webcam. Cameras are
listed by name and device path; changing the selection restarts the scan.
QR image import works without a camera. Release packaging currently produces a
Debian package through the release workflow.

## Camera-selector fork installer

The `Linux desktop installer` GitHub Actions workflow builds a Debian 13
`amd64` package when the `camera-selector` branch is pushed. It also supports
manual runs. The workflow builds the daemon and desktop app, runs the QR scanner
tests, and checks that the package installs in Debian 13.

Open a successful run in the fork's **Actions** tab and download the
`nostr-vpn-debian13-amd64-camera-selector` artifact. Extract the ZIP, then run
these commands in the extracted directory:

```sh
sha256sum --check SHA256SUMS
sudo apt install ./nostr-vpn-debian13-amd64.deb
```

The artifact includes the source commit in `BUILD-INFO.txt` and is retained for
90 days. This is a development build of the camera-selector change.

See the [native UI parity matrix](../docs/native-ui-parity-matrix.md) for the
shared platform contract.
