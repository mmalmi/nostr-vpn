# FIPS Dataplane Safety Net

This is the current validation contract for changes that can affect nvpn/FIPS
packet movement, routing, discovery, or recovery. Runner scripts are canonical
for their supported options and thresholds.

## Invariants

- Only the active signed roster, plus explicit paid-route admissions, grants
  tunnel packet access. Discovery and bootstrap adjacency alone never does.
- Outbound routing uses an unambiguous longest-prefix match. Ambiguous routes
  and unavailable leak-protected exits fail closed.
- Inbound exit traffic is admitted only for locally originated flows and valid
  related errors; unsolicited or spoofed traffic is dropped before the TUN.
- Hot-path queues and work turns stay bounded. Bulk pressure may follow an
  explicit drop/backpressure policy, while control, rekey, liveness, and small
  control-shaped traffic retain progress.
- A healthy configured direct path must not silently drift to transit. Tests
  must prove selected transport and byte progress, not only ping success.
- Far-future or stale liveness timestamps, route metrics, and cached endpoint
  hints must not suppress recovery or steer traffic indefinitely.
- Underlay changes must invalidate stale path state and recover without leaving
  duplicate host routes, DNS state, forwarding rules, or tunnel ownership.
- One flow preserves order unless a tested sequencer deliberately changes that
  contract.
- Dataplane performance changes preserve the FIPS and nvpn protocol surfaces
  unless a protocol change is explicitly approved.

## Fast Checks

The normal per-change entry point is:

```sh
just verify-fast
```

For focused dataplane work, list and select the maintained suites:

```sh
./scripts/test-dataplane-safety-fast.sh list
just dataplane-safety-fast harnesses comparison-dry-run
just dataplane-safety-fast core nvpn app-state
```

Set `NVPN_FIPS_REPO_PATH=/path/to/fips` when nvpn tests must use unreleased
local FIPS crates. The `fips` suite also requires that path. These checks are
local and deterministic; they do not substitute for a real packet path.

## Production-Like Paths

Choose the runner that matches the changed behavior:

| Change                                                 | Required evidence                                                                        |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| Route/admission logic                                  | Focused `core`/`nvpn` suite plus the matching Docker e2e                                 |
| Queueing, batching, crypto handoff, sender concurrency | Docker perf gate before/after; soak when liveness or tails can drift                     |
| NAT, MTU, routed transit                               | `scripts/e2e-fips-nat-safe-mtu-docker.sh` or `scripts/e2e-fips-routed-udp-docker.sh`     |
| Path recovery or underlay change                       | `scripts/e2e-fips-roaming-docker.sh` plus a real affected platform when applicable       |
| Broad Linux profile change                             | `scripts/e2e-fips-platform-matrix-docker.sh`; its current built-in scenario is `default` |
| Long-run route, queue, rekey, FD, or CPU behavior      | `scripts/soak-fips-dataplane-docker.sh` or `scripts/soak-fips-dataplane-host-pair.sh`    |
| Release/platform behavior                              | `just verify-full` and `just release-gate` as required by the release workflow           |

The current Docker perf phases are discoverable with:

```sh
./scripts/e2e-fips-perf-regression-docker.sh --list-phases
```

They are presently `unimpaired-underlay`, `constrained-underlay`, and
`rx-maintenance-fault`; `clean-underlay` is only an accepted alias for
`unimpaired-underlay`.

To retain reviewable output:

```sh
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/<change-id> \
  ./scripts/e2e-fips-perf-regression-docker.sh

NVPN_SOAK_OUTPUT_DIR=artifacts/fips-soak/<change-id> \
  ./scripts/soak-fips-dataplane-docker.sh
```

The perf gate writes `phase-summary.tsv`, `failure-summary.tsv`, and raw probe,
pipeline, and host snapshots. The soak writes `samples.ndjson`, per-sample
status, and failure evidence. Treat those schemas and the harness parsers as
the observability contract; do not maintain a duplicate metric-name inventory
in this document.

## Evidence Rules

- Record exact nvpn and FIPS versions with every baseline or comparison.
- Compare before/after on the same host and topology in both directions.
- Include latency/loss during load, post-load recovery, retransmits, selected
  transport/direct-byte progress, hard pressure events, and CPU where relevant.
- A short smoke proves freshness and gross liveness, not a long-run baseline.
- Docker/Linux results do not prove macOS Wi-Fi, screenshare, Windows, or mobile
  behavior. Run the affected native path before making that claim.
- Do not loosen a threshold merely to accept a new result; explain and measure
  the changed envelope.

Stop and investigate route drift, unintentional drops, priority starvation,
post-load non-recovery, sustained latency/SRTT growth, stuck rekey or direct
probe state, FD growth, CPU runaway, or cleanup residue.

The [2026-06-08 baseline](baselines/fips-dataplane-2026-06-08-docker.md) and
[former safety-net inventory](archive/fips-dataplane-safety-net-2026-06.md) are
historical evidence, not current commands or acceptance baselines.
