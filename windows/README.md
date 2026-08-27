# Windows

The Windows app is a WPF/.NET 8 shell over `nostr-vpn-app-core`'s JSON C ABI.
It ships with `nvpn.exe` and Wintun, and owns Windows integrations including
service/UAC actions, the notification-area menu, startup registration,
single-instance deep-link routing, QR image import, and updates.

## Build and run

Use a Windows checkout with Rust, .NET 8, and LLVM installed:

```powershell
.\scripts\windows-build.ps1
.\scripts\windows-build.ps1 -Run
```

From Git Bash or a Windows environment with `just`:

```sh
just windows-build
just run-windows
```

The build compiles `nostr-vpn-app-core` and `nvpn`, then copies
`nostr_vpn_app_core.dll`, `nvpn.exe`, and `binaries\wintun.dll` into the WPF
output. Add `-Configuration Release -Publish` for a published directory.

The release workflow installs Inno Setup and invokes `-Installer` to produce the
release installer; ordinary development builds do not require Inno Setup.

See the [native UI parity matrix](../docs/native-ui-parity-matrix.md) for the
shared platform contract.
