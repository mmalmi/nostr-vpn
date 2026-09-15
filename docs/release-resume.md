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
