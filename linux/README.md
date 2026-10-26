# Linux

The Linux app is a Rust GTK4/libadwaita shell that uses
`nostr-vpn-app-core` directly. It includes native device, Internet, optional
wallet, settings, tray, deep-link, updater, and QR import/scanning surfaces.

## Development

Background polling updates telemetry labels and relay indicators in place.
Traffic counters, latency, timestamps, and diagnostic updates do not rebuild
the page or replace open expanders and form controls. Navigation, configuration,
permissions, and roster changes still rebuild the page when necessary.

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

The GTK regression test uses a display, a D-Bus session, and `xdotool` to exercise
real device-row clicks with GTK critical messages treated as test failures.
These tools are included in the development image. In a headless native build
environment, run the tests with `xvfb-run -a dbus-run-session -- cargo test`.

Installed packages register `nvpn://` through the desktop entry. A development
deep link can be passed directly to the app:

```sh
./tools/run-linux cargo run -- nvpn://debug/tick
```

Live camera scanning uses `zbarcam` when a camera is available. Use the Camera
dropdown in the scanner to select a built-in or external webcam. Cameras are
listed by name and device path; changing the selection restarts the scan.
Only accessible video-capture nodes are listed; metadata-only nodes are hidden.
QR image import works without a camera. Release packaging currently produces a
Debian package through the release workflow.

See the [native UI parity matrix](../docs/native-ui-parity-matrix.md) for the
shared platform contract.
