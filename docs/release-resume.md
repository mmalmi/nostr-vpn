# Release gate recovery

Keep one clean candidate checkout throughout a release. Inspect the failed phase
and retained evidence before restarting. Before physical-device evidence exists,
run the canonical `node scripts/local-release.mjs --stage-dir <stage-dir>` command
again after correcting a failed external condition. Once device checks have
passed, prefer completing the missing phases and validating their receipts as
described below. Do not create a fresh checkout or change the candidate merely
to restart a gate.

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
