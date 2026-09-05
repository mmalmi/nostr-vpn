# Release gate recovery

Keep one clean candidate checkout throughout a release. Run the canonical
`node scripts/local-release.mjs --stage-dir <stage-dir>` command again after
correcting a failed external condition; do not create a fresh checkout or change
the candidate merely to restart a gate.

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
