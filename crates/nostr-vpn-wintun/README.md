# nostr-vpn-wintun

Windows-only helper that locates and loads the bundled `wintun.dll` from the
supported CLI/app layouts, falling back to the Cargo build artifact.

## Build input

Windows builds require the exact `wintun = "=0.5.1"` registry package. The build
script verifies the selected architecture's DLL against SHA-256 hashes committed
in `build.rs` before copying it to the existing target profile directory. Missing
or changed DLLs fail the build. Other versions and `wintun-bindings` packages are
ignored; multiple caches are accepted only when every matching DLL verifies.

The DLL pins come from the crate archive whose checksum is recorded in
`Cargo.lock`, not from a checksum downloaded with the DLL. To update Wintun,
review and pin the new dependency, verify its archive against the reviewed lockfile
checksum, then derive all four DLL hashes from that archive.

On the configured Windows development VM, run
`cargo check --locked -p nostr-vpn-wintun --jobs 2`. Then use Python 3.11 or newer
to exercise that candidate's compiled build script with isolated cache fixtures:

```text
python scripts/test-wintun-build-inputs.py --build-script <target>/debug/build/nostr-vpn-wintun-<hash>/build-script-build.exe --crate-archive <cargo-home>/registry/cache/<registry>/wintun-0.5.1.crate
```

This checks all four DLL pins, wrong versions, unrelated packages, changed and
conflicting bytes, missing inputs, and the unchanged output layout. It does not
load a driver or change the real Cargo cache.

## Source

https://github.com/mmalmi/nostr-vpn
