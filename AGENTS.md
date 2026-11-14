## Dataplane

- Goal: simple, fast, reliable FIPS/nvpn; high throughput; low latency, jitter, loss; observable failures.
- References: `wireguard-go`, then BoringTun.
- Delete concepts, LOC, unused code, stale tests, test-only APIs, and diagnostic scaffolding.
- Avoid knobs, wrappers, fallbacks, and duplicate paths.
- Keep the nvpn/FIPS adapter thin and canonical; leave dataplane policy, batching, queueing, priority, and liveness logic on the FIPS side when possible.
- Implement requested routing fixes within the existing trust boundaries and verify them with focused tests.
- Get explicit approval for changes to FIPS message types, byte values, wire formats, or interoperability, including during performance work. Also ask before widening which peers can see traffic, allowing traffic outside leak protection, or authorizing additional spending. A user request that explicitly covers the change is sufficient approval.
- Measure bottlenecks: throughput, latency, loss, hard counters, CPU-sec/GB or cycles/Gbit.
- If architecture is sound, debug first bad perf rows before reverting. Large rewrites allowed.
- Build/test sparingly; use a separate test worktree for long runs.

## Verification and Task Guides

- Prefer integration coverage; use unit tests only with a strong reason.
- FIPS protocol/routing/session/reconnect tests live in `fips`; Android/iOS VPN, FFI/JNI/C ABI, permissions, physical packet checks live here.
- Do not commit hostnames, device IDs, signing details, or local paths; use env vars.
- Before platform builds or benchmarks, read [build and benchmark procedures](docs/build-and-bench.md). Performance work builds the daemon only; Windows verification runs in the configured Windows dev VM.
- For mobile-sensitive changes or simulator/device checks, read [the mobile test kit](docs/mobile-test-kit.md), including device safety and recovery before physical automation. Run simulator UI checks without physical devices.
- Before release preparation, read [the release workflow and recovery guide](docs/release-resume.md); preserve its preflight, receipt and staged-publication gates.
- App Store availability: exclude France, keep China enabled, and never claim worldwide availability in metadata or review notes.
