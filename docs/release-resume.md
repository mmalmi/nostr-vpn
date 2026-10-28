# Release gate recovery

Keep one clean candidate checkout throughout a release. Inspect the failed phase
and retained evidence before restarting. Before physical-device evidence exists,
run the canonical `node scripts/local-release.mjs --stage-dir <stage-dir>` command
again after correcting a failed external condition. Once device checks have
passed, prefer completing the missing phases and validating their receipts as
described below. Do not create a fresh checkout or change the candidate merely
to restart a gate.

Docker readiness is checked before source validation, with a 15-second daemon
deadline and bounded image inspection/download requests. Restore the Docker
service after a readiness failure before resuming the candidate.
The preflight also asks Docker to copy every vendored Cargo manifest, catching
source-filter omissions before platform compilation.
Source validation compiles the app core without paid-exit features as well as
checking the default workspace, so App Store feature drift fails early.
The exact host-built Linux peer for desktop underlay checks is prepared alongside
platform builds. All preparation finishes before network or idle measurements;
a cold peer build must never overlap macOS recovery deadlines. Underlay runners
then revalidate and import that cached artifact.
Linux underlay cleanup collects evidence through the restored primary link;
the guest has already removed its temporary secondary network at that point.
The Automatic Spilman fixture owns the complete Internet mode-transition and
pending-funding matrices. The manual fixture retains its higher price and small
wallet for billing checks; running the same matrix there both duplicates work
and violates Automatic's price and funding prerequisites.

Before freezing a new release, advance `ios/app-store-build-number`, synchronize
versions, and run the TestFlight and App Store `preflight` commands. Both must
identify the intended version and unused build number; do this before compiling
or collecting physical-device evidence.

The gate automatically retains successful **source quality, Rust regression,
and Android static** checks in `artifacts/release-gate-state`. Reuse requires
matching source content and commit, local FIPS content, Cargo configuration,
initial environment and tool versions, and expires after 24 hours. Security
advisory checks always run again. An interrupted or failed check is never reused.
Generated-output, build, device, networking and timing phases still execute:
their state cannot be restored from a command's successful exit code.

This checkpoint cache is not publication evidence and cannot replace the
artifact-bound platform receipt validators. A complete existing receipt set can
still use the existing `--complete-gate-from-receipts` and
`--reuse-gate-receipts` paths. An incomplete platform set is not accepted by those
commands.

## Linux builder inputs

`Dockerfile.linux-vm-gate` is the established **native Linux amd64, Ubuntu
24.04** package builder. It keeps Rust/cargo **1.95.0**, cargo-deb **3.7.0**,
the `x86_64-unknown-linux-gnu` desktop/daemon target and the static
`x86_64-unknown-linux-musl` daemon target. GTK 4, libadwaita, OpenSSL, DBus,
Clang/bindgen, GCC and musl headers/linker come from its explicitly versioned
Ubuntu packages. The existing native-host admission, resource limits, source
checks, FIPS lock materialization, `--locked` fetch, `--frozen` build and
serialized retained-cache rules still apply. Do not substitute an emulated
builder or a Debian-built glibc artifact for this Ubuntu release gate.

Both Linux Dockerfiles pin their base images by SHA-256. The native builder
copies the Rust toolchain and proxies from the pinned official Rust image into
the established `/opt/rustup` and `/opt/cargo` locations; it does not run the
mutable rustup installation script. Its additional musl standard-library
archive is verified before extraction or execution. cargo-deb's source archive
and included Cargo.lock are verified before its locked installation.

APT uses only the **2026-10-27 00:00 UTC** repository snapshots listed in each
Dockerfile. After a successful signed index update, the exact InRelease SHA-256
checks must pass **before package installation**. Those committed hashes pin
the complete index-to-package SHA-256 chain, including transitive package
versions and checksums; direct package versions are also written explicitly.
APT's normal signature and package-hash checks remain enabled. The historical
snapshot alone is allowed to outlive its metadata expiry. There is no fallback
to a live mirror, a newer version, or an unchecked download. Updating these
pins is a reviewed source change, including when incorporating security fixes.

`Dockerfile.linux-release` is the separate Debian 13/trixie builder, now pinned
to Rust **1.95.0** and cargo-deb **3.7.0**. Its amd64/arm64 musl target must
match the container architecture. This recipe does not establish Ubuntu gate
compatibility or acceptance.

`scripts/build-nvpn-linux-musl` selects the immutable amd64 cross-builder for
each i686, x86_64, aarch64 or ARMv6 hard-float target from
`scripts/lib-linux-musl-image.sh`. It keeps the existing linker/include paths
and one serialized cache per image ID, target and user. The image contains its
own compiler/toolchain; record `rustc -vV`, Cargo, C compiler and OS versions
when qualifying that exact image. A verified registry manifest identifies
bytes, not a completed toolchain execution test. The ARM64 gate separately
uses a pinned native arm64 Ubuntu smoke image; the ARMv6 wrapper inherits the
canonical ARMv6 image, never an ARMv7 substitute.

The musl wrapper archives committed HEAD and builds the release `nvpn` binary
with default features, or the explicitly requested existing
`NVPN_LINUX_MUSL_NO_DEFAULT_FEATURES=1` selection. It fetches with `--locked`
and builds with `--frozen`. Local patches that require a lockfile change now
fail rather than resolving new dependencies during the build; prepare a
reviewed compatible lock first, or use the canonical native gate's validated
FIPS lock-materialization workflow. Dependency versions are not updated here.

Image overrides must use a registry digest or a full local image ID. A local
image ID is only an exact reuse reference: retain its source recipe, input
pins, build log and tool inventory in the release receipt. It does not prove
that an older, mutable recipe can recreate those bytes. Missing local images
fail without pulling a replacement. Preserve the previous image and retained
cache until the owner accepts and retires them; this source change does not
upgrade them in place.

Changing a Dockerfile changes the existing builder-environment cache key. The
next image build needs the normal native resource reservation, space budget,
tool-startup and package-build checks, followed by artifact/network acceptance.
Source/manifest verification alone is not that acceptance, an audit of every
dependency, or proof that a newly built package matches published bytes.

## Resource-constrained release hosts

Set `NVPN_RELEASE_GATE_SERIAL=1` when the allocated hosts cannot safely overlap
release lanes. The same phases, checks, logs and artifact receipts run in order;
this does not skip verification. Parallel execution remains the default.

The canonical Linux VM bundle builder accepts optional positive integer
`NVPN_HOST_LINUX_VM_BUILD_CPUS` and `NVPN_HOST_LINUX_VM_CARGO_JOBS` limits, plus
`NVPN_HOST_LINUX_VM_BUILD_MEMORY` in bytes or with a `k`, `m` or `g` suffix.
Both local Docker and remote native builds apply these limits. The memory limit
also caps total memory plus swap at the same value, so it permits no extra swap.
Keep host-specific values in the release process environment. These controls do
not replace host/device reservations, free-space checks or isolated measurements.

## iPhone testing window

Compile the signed test runner for the generic iOS destination. Selecting the
physical phone is only necessary when executing tests; compilation must not wait
for its development services to become available.
Preparation audits the frozen app and records the installed runner before the
first test starts. Preserve those receipts, the original test products and the
signed archive when a device service fails. Exact reuse verifies their hashes
and installed USB identities; a compiled runner alone is insufficient.
The Android and iPhone DNS lanes finish independently, so a failed phone does not
cancel the other phone's still-valid work. Radio recovery receives explicit
artifact and runner pins from the completed preparation.

A destination failure before any test method must not launch a second UI session
for cleanup when a fresh USB check proves the untouched tunnel is still stopped.
Cleanup remains mandatory after a method starts or the stopped proof is missing.

The full gate validates desktop seller evidence before phone work, then groups
physical idle, WireGuard/DNS, Android replacement, radio recovery and mobile/Mac
join checks together. It seals the frozen iOS archive's physical-test evidence
immediately afterward, before Windows/Android and Linux/Android joins and the
unattended Docker/performance tail. The local Rust QR-latency checks do not use a
phone and run after this window.

If a later check fails, keep `dist/ios/frozen/physical-gate-seal.json`, its bound
archive and receipts, and the original gate/join result directories. Complete
the missing checks, then use `--complete-gate-from-receipts` to validate the full
set before staging with `--reuse-gate-receipts`. The iOS seal alone does not pass
the release gate. Restarting the entire gate still reruns physical phases; it
does not automatically skip them based on this seal.

When a later harness change preserves all iOS product inputs, both export and
upload use a temporary checkout of the archive's original source. The publication
gate still validates the current release commit and the unchanged archive bytes.

An unlocked screen and Apple UI Automation authorization are separate conditions.
The release network and join runners check lock state with a bounded fresh query
and stop on an automation-authorization timeout. Enter the automation passcode on
the selected phone when Apple requests it. Preserve the exact installed runner and
completed evidence; do not reboot, reinstall, or repeat unchanged startup attempts
to chase the prompt. Grouping tests reduces idle gaps but does not guarantee a
single prompt. Simulator tests remain independent of physical devices and cannot
replace the real-device VPN evidence.

A device passcode is not mandatory for UI automation. For a dedicated test phone,
the owner can remove it in Settings > Face ID & Passcode > Turn Passcode Off.
[Apple's developer guidance](https://developer.apple.com/forums/thread/693273)
confirms that this removes the recurring automation passcode prompt; there is no
supported way to automate entering an enabled passcode. Removing it also removes
the phone's passcode protection. Do not change a personal phone's security
settings automatically. With a passcode retained, arrange an attended testing
window and start the prepared runner while the owner is ready to answer Apple's
prompt; an unlocked screen alone does not establish automation authorization.

## Inspecting and resuming a gate

Inspect actual phase status without reading long logs:

```sh
node scripts/release-gate-state.mjs status
```

The ledger identifies the candidate, elapsed time, running/failed/interrupted
phases, and reused checks. Serial and parallel phases write their status as they
execute. A checkout lock rejects overlapping gate attempts; managed native-lab
reservations remain responsible for coordinating devices across checkouts.

After two failed attempts with unchanged inputs, the gate refuses another run
before preparing artifacts or touching devices. First diagnose the failed phase
and run its focused check. If the fix was external (for example restoring a
fixture), record the concrete correction:

```sh
node scripts/release-gate-state.mjs retry "Describe the external condition corrected and its verification"
```

This grants one additional attempt, records the reason locally, and preserves
valid checkpoints. It refuses to reset while an owner process is alive. After a
crashed owner exits, this same command releases its stale checkout lock; no
process is killed. Do not reset the budget merely because a test failed.

Candidate edits invalidate cached checks. Changing the candidate while a gate
runs rejects completion. Keep optional release-tool improvements outside a
frozen release, and integrate them after publication.

Let the canonical publisher build and push Umbrel together. An extra cache-only
build while waiting for hosted checks does not retain an image for publication:
[BuildKit can reclaim that cache](https://docs.docker.com/build/cache/garbage-collection/)
before promotion, forcing the same compilation again.

## Cargo packages and maintained payment dependencies

The early release preflight builds the actual Cargo archives together, so new
workspace dependencies can be verified before any upload. A local `cargo check`
does not prove that the published package builds: Cargo removes workspace patches.

Already published payment dependencies are reused only after their original
manifest and every packaged source file match the local dependency. A changed
dependency needs a new version. The application archives then resolve the actual
registry checksums, preventing VCS metadata changes in a new app commit from
creating different archives for an existing dependency version.

The native 4.1.12 release is accompanied by the Cargo-only 4.1.13 correction at
`cargo-v4.1.13`. Its VPN and payment Rust sources match 4.1.12. The correction
publishes the maintained Cashu and Spilman packages explicitly; it does not
replace the signed native artifacts or the App Store submission. Keep those
publication results when resuming; do not repeat the 4.1.12 Cargo upload.


### Haps distribution

The final local release flow also publishes desktop/CLI packages using
`haps-release.json` and the same verified `release.json` assets. Drafts do not
publish Haps packages. Install Haps with the `import-release` subcommand and Python
3.9+ on the publisher. Set `HAPS_KEY_FILE` to an existing secret-key file matching
the public publisher pinned in the mapping (or provision the matching existing
Haps identity). Never generate a new release identity. The flow verifies
checksums and package layout before upload, then requires Nostr acknowledgement.
A Haps failure fails the final release; byte-identical retries reuse the signed
package versions. Iris Git, native updaters and Haps consume the same release
artifacts; Android/iOS and native installer channels retain their existing gates.
