## Dataplane

- Goal: simple, fast, reliable FIPS/nvpn; high throughput; low latency, jitter, loss; observable failures.
- References: `wireguard-go`, then BoringTun.
- Delete concepts, LOC, unused code, stale tests, test-only APIs, and diagnostic scaffolding.
- Avoid knobs, wrappers, fallbacks, and duplicate paths.
- Keep the nvpn/FIPS adapter thin and canonical; leave dataplane policy, batching, queueing, priority, and liveness logic on the FIPS side when possible.
- Do not change FIPS protocol message types, byte values, wire record formats, routing semantics, or compatibility boundaries without explicit user approval. Performance work must preserve the FIPS protocol surface unless the user has approved a protocol change for that task.
- Measure bottlenecks: throughput, latency, loss, hard counters, CPU-sec/GB or cycles/Gbit.
- If architecture is sound, debug first bad perf rows before reverting. Large rewrites allowed.
- Build/test sparingly; use a separate test worktree for long runs.

## Build/Bench

- Perf: build daemon only.
- macOS daemon: `scripts/install-nvpn-test-daemon`; manual release path: `scripts/build-output-path --raw nvpn --release`; clear xattrs; ad-hoc sign.
- launchd env/plist/codesign: `bootout` + `bootstrap`; `kickstart` can keep old env.
- Linux remote: `scripts/build-nvpn-linux-musl <target>`; native glibc only same distro/glibc; never ARMv7 on ARMv6.
- Docker image binary swaps: use `scripts/docker-replace-nvpn-binary`; it rejects image/binary architecture mismatches that would run through Rosetta/QEMU and poison perf rows.
- Bench both directions: `iperf3 -R`; LAN MTU only with `mesh_mtu_profile = "lan"` / `NVPN_MESH_MTU_PROFILE=lan`.
- Remote bench: load SSH keys first (`ssh-add --apple-use-keychain <key>`).
- Avoid unittests unless very good reason, prefer integration test coverage

## Platforms

- Windows: run build/test checks from the configured Windows dev VM checkout; do not use local macOS/Linux `dotnet` as the verification path. Check `dotnet build windows\NostrVpn.Windows\NostrVpn.Windows.csproj -p:EnableWindowsTargeting=true` there.
- Mobile-sensitive: `just mobile-test-kit`; sim/device packet paths: `just mobile-test-kit-sim` / `just mobile-test-kit-device`.
- Physical iOS XCTest: reuse the trusted destination runner; after one verified pre-method `XCTFuture Code=1000` stall, recycle only the exact `testmanagerd` PID once and retry the same `UseDestinationArtifacts` plan; never reboot, broadly restart, prime, reinstall, or uninstall; one Apple UI Automation passcode may still be required.
- Run simulator UI checks without physical devices. Before physical UI automation, require a bounded fresh unlocked-state check. A failed startup that never touched the app must not trigger another UI automation session for cleanup when fresh USB evidence preserves its stopped baseline. Keep completed artifact-bound device receipts when resuming.
- FIPS protocol/routing/session/reconnect tests live in `fips`; Android/iOS VPN, FFI/JNI/C ABI, permissions, physical packet checks live here.
- Do not commit hostnames, device IDs, signing details, or local paths; use env vars.

## Release

- App Store availability: exclude France, keep China enabled, and never claim worldwide availability in metadata or review notes.
- Before release: `just release-gate`; Linux GTK: `( cd linux && cargo check )`.
- Bump: changelog `## X.Y.Z - YYYY-MM-DD`; root version; advance `ios/app-store-build-number` to an unused build number; run `node scripts/sync-versions.mjs`, then `--check`; gate.
- Before expensive builds, run `scripts/testflight-internal preflight` and `scripts/appstore-draft preflight`; both must agree on the intended marketing version/build. A new candidate must not reuse an already uploaded build.
- Stage the exact clean commit with `node scripts/local-release.mjs --stage-dir <dir>`; use `--reuse-gate-receipts` only after composing a complete artifact-bound receipt set.
- Publish with `--publish-staged-draft`, then `scripts/publish-release-refs.mjs`, then `--promote-draft --require-zapstore`. Direct `--publish` and `--final` modes are disabled.
