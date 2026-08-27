# Dataplane Experiments

This page is the active index for nvpn/FIPS performance and reliability work.
It intentionally does not carry commit-by-commit chronology.

## Current Runner Surface

Use the smallest production-like runner that exercises the changed boundary:

```sh
just dataplane-safety-fast harnesses comparison-dry-run

NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/<change-id> \
  ./scripts/e2e-fips-perf-regression-docker.sh

NVPN_SOAK_OUTPUT_DIR=artifacts/fips-soak/<change-id> \
  ./scripts/soak-fips-dataplane-docker.sh
```

The Docker perf gate currently runs `unimpaired-underlay`,
`constrained-underlay`, and `rx-maintenance-fault`. Use `--list-phases` rather
than copying an old phase list. For path changes, use the routed-UDP,
NAT-safe-MTU, or roaming e2e script that matches the behavior. For comparison
with userspace WireGuard on the same machines, use
`scripts/run-host-pair-comparison.sh`.

See [the safety net](fips-dataplane-safety-net.md) for validation by change
type. The scripts are the authority for supported options and thresholds.

## Evidence Contract

Every result worth keeping should record:

- exact nvpn commit and resolved FIPS crate versions
- runner, non-default environment values, duration, and platform
- forward and reverse throughput, retransmits, and latency/loss under load
- direct-path or selected-transport evidence, queue/backpressure failures, and
  recovery after load or an injected fault
- artifact directory or immutable artifact hash
- a decision: keep, revert, repeat, or investigate

Do not compare throughput from different hosts as if it were an A/B result.
Docker/Linux evidence is not real macOS Wi-Fi, screenshare, mobile, or Windows
evidence. Short runs are freshness checks, not replacement baselines.

## Durable Conclusions

- A healthy configured direct path must be proved with transport/byte progress,
  not inferred from tunnel reachability alone.
- Bounded queues and visible pressure are preferable to large buffers that hide
  latency or wedges.
- Both traffic directions and post-load recovery matter; a single headline
  throughput number is insufficient.
- Changes to batching, queueing, routing, discovery, rekey, MTU, or sender
  concurrency need before/after evidence on the affected path.
- Performance work must preserve the existing FIPS and nvpn protocol surfaces
  unless a protocol change is explicitly approved.

## Historical Records

These files are evidence from their stated dates, not current baselines or
instructions:

- [June 2026 dataplane chronology](archive/experiments-2026-06-dataplane.md)
- [May 2026 experiments](archive/experiments-2026-05-legacy.md)
- [2026-06-08 Docker baseline](baselines/fips-dataplane-2026-06-08-docker.md)
