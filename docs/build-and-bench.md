# Platform builds and benchmarks

Read before platform builds or benchmarks. For release preparation, also follow
the [release workflow and recovery guide](release-resume.md).

## Daemon and benchmark setup

- Performance work builds the daemon only.
- macOS daemon: use `scripts/install-nvpn-test-daemon`. For the manual release
  path, use `scripts/build-output-path --raw nvpn --release`, clear xattrs and
  ad-hoc sign.
- After launchd environment, plist or codesign changes, use `bootout` followed by
  `bootstrap`; `kickstart` can keep the old environment.
- Remote Linux: use `scripts/build-nvpn-linux-musl <target>`. Native glibc builds
  require the same distro/glibc; never run ARMv7 on ARMv6.
- For Docker image binary swaps, use `scripts/docker-replace-nvpn-binary`. It
  rejects architecture mismatches that would run through Rosetta/QEMU and
  invalidate performance results.
- Benchmark both directions, including `iperf3 -R`. Use LAN MTU only with
  `mesh_mtu_profile = "lan"` or `NVPN_MESH_MTU_PROFILE=lan`.
- Before remote benchmarks, load SSH keys with
  `ssh-add --apple-use-keychain <key>`.

## Windows verification

Run build/test checks from the configured Windows dev VM checkout; do not use
local macOS/Linux `dotnet` as the verification path. Run this check there:

```powershell
dotnet build windows\NostrVpn.Windows\NostrVpn.Windows.csproj -p:EnableWindowsTargeting=true
```
