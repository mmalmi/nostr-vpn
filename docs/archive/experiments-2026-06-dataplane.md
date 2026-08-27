# Historical Dataplane Experiments - June 2026

Historical running notes for nvpn/FIPS performance and reliability work.
Commands, paths, commit references, and "current" claims below describe June
2026 and are not maintained as present-day guidance. Entries were kept
short enough to compare later: date, build/commit, setup, result, and decision.
This is a chronological evidence log, not the current refactor status page.
Current safety scope and architecture status live in
[the maintained safety net](../fips-dataplane-safety-net.md) and
[dataplane architecture](../fips-dataplane-architecture-plan.md).

## Quiet Linux Docker short perf repeat - 2026-06-11

Summary:
- The FIPS `b1f94a7` / nvpn `27be7006` short local-FIPS Docker perf smoke was
  repeated on a quiet 8-vCPU Linux host after host snapshots were added to the
  artifact bundle.
- The host-start snapshot recorded `loadavg_1m_5m_15m=0.00 0.00 0.00`; the
  host-end snapshot recorded load from the test itself (`2.28 1.35 0.57`) with
  the two `nvpn` daemons as the top CPU consumers.
- This host has a lower absolute clean/rx Docker ceiling than the local macOS
  Docker runner, so it is not a replacement for the `~2.6 Gbps` same-host
  comparison. It is useful as a low-contention liveness and bottleneck-shape
  repeat.

Command:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety-bench \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/b1f94a7-session-install-linux-short-smoke \
PROJECT_NAME=nostr-vpn-e2e-fips-b1f94a7-linux-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

Result:

| Phase | Baseline Mbps | Load Mbps | Ping Loss | Direct Bytes |
| --- | ---: | ---: | --- | ---: |
| clean-underlay | `1646.1/1612.0` | `1649.8/1597.8` | `0%/0%`, post `0%` | `1698115935/1640074583` |
| constrained-underlay | `201.1/211.4` | `211.2/211.2` | `0%/0%`, post `0%` | `232254251/233382701` |
| worker-queue-pressure | `395.1/387.2` | `383.7/380.3` | `0%/0%`, post `0%` | `421869935/410481100` |
| rx-maintenance-fault | `1594.9/1555.2` | `1695.4/1666.6` | `0%/0%`, post `0%` | `1697516256/1658109951` |

Artifacts:
- `phase-summary.tsv` SHA-256:
  `26894bcfbef0f18e70971c9a1a1c9a03063ffe50699c0882a13aa6b00f4e85df`
- `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
- `raw/host-start.txt` SHA-256:
  `ae0730b199bf2cef364240ea690df7ff7ac7267862aa33838ec4eee4efe5fa2c`
- `raw/host-end.txt` SHA-256:
  `a81878a51c5382d56608d5208d8ef11c66cf2ec5d51c3cf5e73dc5ab4ca68d7d`

Interpretation:
- The local worker-pressure reverse-load dip to `73.9 Mbps` did not reproduce:
  the quiet Linux repeat held `380.3 Mbps` reverse load with `0%` ping loss.
  Treat that local dip as host/environment skew unless it repeats on a quiet
  same-host run.
- The high-rate queue-residence shape did reproduce. Raw pipeline snapshots
  still show receive-heavy `endpoint_event_wait` in the hundreds of
  microseconds: clean node-a `553.1us`, clean node-b `451.0us`,
  rx-maintenance node-a `529.1us`, and rx-maintenance node-b `487.0us` in
  representative high-rate samples. Constrained and worker-pressure phases
  stayed in low-single-digit microseconds for endpoint-event wait.
- Next performance work should target the high-rate endpoint/event/transport
  residence path. The low-contention repeat clears the pressure-phase reverse
  collapse as the immediate suspect, but does not clear the broader throughput
  goal.

## FIPS perf peak pipeline summaries - 2026-06-11

Summary:
- `scripts/e2e-fips-perf-regression-docker.sh` now selects the highest
  wait-bearing FIPS and nvpn pipeline lines for phase/failure summaries instead
  of blindly using the final pipeline line after a phase.
- This prevents idle post-load samples from hiding the high-rate
  `endpoint_event_wait`, `transport_queue_wait`, `fmp_worker_queue_wait`,
  `endpoint_command_wait`, or nvpn queue-wait sample that actually matters.
- Raw per-phase pipeline files are still written unchanged.

Verification:

```sh
bash -n scripts/e2e-fips-perf-regression-docker.sh
bash -n scripts/test-fips-perf-harness.sh
./scripts/test-fips-perf-harness.sh
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
git diff --check
```

Result:
- All lightweight harness checks passed.
- No Docker rerun was taken for this summary-selection change because it only
  changes how existing pipeline log lines are summarized.

Interpretation:
- This is an observability fix for stale/misleading metrics, not a dataplane
  behavior change. Future `phase-summary.tsv` rows should point directly at
  the queue-residence sample that needs attention.

## FIPS perf host snapshot artifacts - 2026-06-11

Summary:
- `scripts/e2e-fips-perf-regression-docker.sh` now writes host contention
  snapshots into the raw perf artifact directory when `NVPN_PERF_OUTPUT_DIR`
  is set.
- Successful runs produce `raw/host-start.txt` and `raw/host-end.txt`; failed
  runs produce `raw/host-start.txt` and `raw/host-failure-exit.txt` before
  Docker cleanup/debug collection.
- Each snapshot records a UTC timestamp, kernel, CPU count, load average or
  uptime, and the top CPU-consuming process names. This makes short perf
  checkpoints easier to interpret when local CPU contention may have skewed
  throughput.

Verification:

```sh
bash -n scripts/e2e-fips-perf-regression-docker.sh
bash -n scripts/test-fips-perf-harness.sh
./scripts/test-fips-perf-harness.sh
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
git diff --check
```

Result:
- All lightweight harness checks passed.
- No new Docker throughput run was taken for this harness-only change. The
  latest `b1f94a7` short smoke remains useful liveness evidence, but its
  `~2.4-2.5 Gbps` clean/rx-maintenance result should be repeated on a quiet
  host before treating it as a dataplane regression.

Interpretation:
- This is an observability improvement, not a dataplane behavior change. It
  closes a benchmark-evidence gap exposed by the recent CPU-contention caveat:
  future perf artifacts now carry enough host context to decide whether lower
  throughput is likely code, scheduler/queue behavior, or a noisy machine.

## Current local-FIPS Docker short perf checkpoint - 2026-06-10

Summary:
- A current-head short local-FIPS Docker perf smoke at nvpn `95d98162` plus
  FIPS `29ab97f` passed all four default phases after the session receive
  ownership batch.
- The run used local FIPS patching and short durations to refresh safety and
  bottleneck evidence, not to replace the longer default-duration Docker
  checkpoint.

Command:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/29ab97f-current-short-smoke \
PROJECT_NAME=nostr-vpn-e2e-fips-29ab97f-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

Result:

| Phase | Baseline Mbps | Load Mbps | Ping Loss | Direct Bytes |
| --- | ---: | ---: | ---: | ---: |
| clean-underlay | `2634.1/2654.8` | `2624.2/2550.0` | `0%/0%`, post `0%` | `2677984728/2621978960` |
| constrained-underlay | `158.4/155.8` | `166.2/166.9` | `0%/0%`, post `0%` | `178464264/178518223` |
| worker-queue-pressure | `235.7/233.8` | `230.2/237.4` | `0%/0%`, post `0%` | `241521947/242876669` |
| rx-maintenance-fault | `2585.5/2587.9` | `2620.1/2595.8` | `0%/0%`, post `0%` | `2660962580/2652076756` |

Artifacts:
- `artifacts/fips-perf/29ab97f-current-short-smoke/phase-summary.tsv`
  SHA-256:
  `9175c07158f67c9492c77d89702972af948dc52233b7fdebc7a17b22b3dcba89`
- `artifacts/fips-perf/29ab97f-current-short-smoke/failure-summary.tsv`
  SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`

Interpretation:
- No liveness regression was visible after the receive-ownership batch:
  all phases had `0%` load and post-load tunnel ping loss, direct UDP bytes
  advanced in every phase, and worker pressure still exposed expected
  queue-full/bulk-drop counters.
- The run does not prove Mac-to-Mac behavior and does not replace the longer
  default-duration Docker checkpoint. It does give a fresh current-head Linux
  short-smoke guard before the next larger peer/session runtime move.

## FIPS perf pipeline snapshot artifacts - 2026-06-10

Summary:
- `scripts/e2e-fips-perf-regression-docker.sh` now writes the same per-phase
  `node-a` / `node-b` pipeline tails it prints to console into
  `raw/<phase>-node-a-pipeline.txt` and `raw/<phase>-node-b-pipeline.txt` when
  `NVPN_PERF_OUTPUT_DIR` is set.
- This keeps queue-residence and drop-counter evidence durable alongside the
  existing raw iperf and ping artifacts.

Verification:

```sh
bash -n scripts/e2e-fips-perf-regression-docker.sh scripts/test-fips-perf-harness.sh
./scripts/test-fips-perf-harness.sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/pipeline-snapshot-artifact-smoke \
PROJECT_NAME=nostr-vpn-e2e-fips-pipeline-artifact-smoke \
./scripts/e2e-fips-perf-regression-docker.sh --phase worker-queue-pressure
```

Result:
- The harness self-test passed.
- The focused Docker smoke passed worker-queue-pressure with baseline
  `232.1/238.1 Mbps`, load `233.3/238.0 Mbps`, `0%/0%` load ping loss,
  post-load `0%` loss, and direct UDP bytes `237984788/244569057`.
- `failure-summary.tsv` contained only the header.
- Pipeline snapshots were written and hashed:
  - `raw/worker-queue-pressure-node-a-pipeline.txt`:
    `09cd541ac9c6299820330e822cdd9247a3e7dd5bb0f8b10ad34baa2e768b080a`
  - `raw/worker-queue-pressure-node-b-pipeline.txt`:
    `60ec0833e04f87b2bac862b77b23944ed1c3b78cea2693422b2c0f018aec5a14`

Interpretation:
- This is an observability improvement, not a dataplane behavior change. It
  makes the next bottleneck comparison more trustworthy because high-rate
  pipeline lines no longer have to be recovered from terminal scrollback.

## FIPS authenticated session dispatch owner - 2026-06-10

Summary:
- FIPS `29ab97f` moves local established-FSP message dispatch onto
  `AuthenticatedSessionDispatch::dispatch`. The typed dispatch envelope now
  consumes itself through reverse-route learning, message-type dispatch, and
  final commit finalization.
- `Node::handle_encrypted_session_msg` now builds the authenticated dispatch
  object and hands it to that owner instead of calling a `Node` helper that
  open-coded the same choreography.
- Behavior is intentionally unchanged: reverse-route learning still runs after
  the session borrow drops, EndpointData still drains the inner FSP header in
  place for delivery, application-data receive bookkeeping still runs before
  pending flush, and MMP reports still do not touch idle/traffic counters.

Result:
- Accepted as another receive-ownership cleanup. The future peer/session
  runtime now has one local established-FSP dispatch object to move, rather
  than a `Node` helper plus a separate commit/finalization edge.

Verification:

```sh
( cd /path/to/fips-dataplane-safety && cargo fmt --check )
( cd /path/to/fips-dataplane-safety && git diff --check )
( cd /path/to/fips-dataplane-safety && cargo check -p fips-core --release )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core session_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core endpoint_event_runtime -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core peer_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core forwarding -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_worker -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_failure -- --nocapture )
( cd /path/to/fips-dataplane-safety && cargo test -p fips-core -- --nocapture )
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn fips_private_mesh --features embedded-fips -- --nocapture
```

- Full FIPS result: `1507` passed, `2` ignored; doctests `2` ignored.
- nvpn local-FIPS result: `nvpn-hotpath` passed all six checks, and direct
  `fips_private_mesh` passed `59` tests.
- No Docker perf rerun was taken because this is a session-dispatch ownership
  cleanup, not a queueing, routing, crypto, sender, batching, or delivery
  semantic change. The latest full Docker perf checkpoint remains nvpn
  `941cefd1` plus FIPS `5721357`.

Interpretation:
- This is still not the endpoint-data fast-path rewrite. It is the safety
  precondition for that larger move: local FSP dispatch is now one typed owner
  that a peer/session runtime can consume when it eventually owns FMP receive,
  FSP open/replay, endpoint delivery, priority/bulk reserve, and observability
  together.

## FIPS session dispatch finalization owner - 2026-06-10

Summary:
- FIPS `40e3da7` moves the final post-dispatch step behind
  `SessionDispatchCommit::finalize`: record application-data receive progress
  when present, then flush pending packets for the same source peer.
- `handle_authenticated_session_dispatch` now dispatches the authenticated
  session message and hands finalization to the commit owner instead of
  manually sequencing receive bookkeeping plus pending flush.
- Behavior is intentionally unchanged: MMP reports still do not touch
  idle/traffic counters, and pending outbound packets are still flushed after
  dispatch for the authenticated source peer.

Result:
- Accepted as a small ownership cleanup. The established-FSP dispatch boundary
  now owns its finalization facts and finalization action, reducing the amount
  of packet-lifecycle sequencing a future peer/session runtime must preserve by
  hand.

Verification:

```sh
( cd /path/to/fips-dataplane-safety && cargo fmt --check )
( cd /path/to/fips-dataplane-safety && git diff --check )
( cd /path/to/fips-dataplane-safety && cargo check -p fips-core --release )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core session_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core endpoint_event_runtime -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core peer_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core forwarding -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_worker -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_failure -- --nocapture )
( cd /path/to/fips-dataplane-safety && cargo test -p fips-core -- --nocapture )
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn fips_private_mesh --features embedded-fips -- --nocapture
```

- Full FIPS result: `1507` passed, `2` ignored; doctests `2` ignored.
- nvpn local-FIPS result: `nvpn-hotpath` passed all six checks, and direct
  `fips_private_mesh` passed `59` tests.
- No Docker perf rerun was taken because this is a dispatch-finalization
  ownership cleanup, not a queueing, routing, crypto, sender, batching, or
  delivery semantic change. The latest full Docker perf checkpoint remains
  nvpn `941cefd1` plus FIPS `5721357`.

Interpretation:
- The established-FSP dispatch edge is now more coherent, but the larger goal
  still needs the future peer/session runtime to own FMP open, FSP open/replay,
  endpoint delivery, priority/bulk reserve, and observability together before
  deleting the endpoint-data rx-loop bounce.

## FIPS session receive dispatch bookkeeping owner - 2026-06-10

Summary:
- FIPS `47c7b85` moves established-FSP receive counter/touch mutation behind
  `SessionDispatchCommit::record_receive`. `Node` still owns the local dispatch
  call today, but the application-data-only receive bookkeeping rule no longer
  lives as an open-coded session-map mutation at the end of dispatch.
- The guard now proves that `EndpointData` receive completion increments
  session receive counters and updates `last_activity`, while SenderReport/MMP
  dispatch still records no application-data receive progress.
- Behavior is intentionally unchanged: MMP reports can still trigger pending
  flush through the commit source address, but they do not reset idle timers or
  traffic counters.

Result:
- Accepted as another small ownership step toward a peer/session runtime. The
  dispatch commit now owns both the facts and the receive-bookkeeping mutation,
  so future endpoint-data fast-path work has one less `Node` rule to preserve
  by hand.

Verification:

```sh
( cd /path/to/fips-dataplane-safety && cargo fmt --check )
( cd /path/to/fips-dataplane-safety && git diff --check )
( cd /path/to/fips-dataplane-safety && cargo check -p fips-core --release )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core session_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core endpoint_event_runtime -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core peer_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core forwarding -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_worker -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_failure -- --nocapture )
( cd /path/to/fips-dataplane-safety && cargo test -p fips-core -- --nocapture )
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn fips_private_mesh --features embedded-fips -- --nocapture
```

- Full FIPS result: `1507` passed, `2` ignored; doctests `2` ignored.
- nvpn local-FIPS result: `nvpn-hotpath` passed all six checks, and direct
  `fips_private_mesh` passed `59` tests.
- No Docker perf rerun was taken because this is a receive-bookkeeping
  ownership cleanup, not a queueing, routing, crypto, sender, batching, or
  delivery semantic change. The latest full Docker perf checkpoint remains
  nvpn `941cefd1` plus FIPS `5721357`.

Interpretation:
- This makes the dispatch edge less fragile but does not change the big
  architecture decision: continue toward a peer/session runtime that owns FMP
  open, FSP open/replay, endpoint delivery, priority/bulk reserve, and
  observability together before deleting the endpoint-data rx-loop bounce.

## FIPS authenticated session dispatch commit owner - 2026-06-10

Summary:
- FIPS `0471231` extracts post-open established-FSP local dispatch into
  `handle_authenticated_session_dispatch`, consuming the
  `AuthenticatedSessionDispatch` object instead of leaving route learning,
  message dispatch, receive accounting, and pending flush inline in
  `handle_encrypted_session_msg`.
- `SessionDispatchCommit` now owns the two post-dispatch facts that must stay
  coupled: the source peer whose pending packets are flushed and the optional
  application-data receive completion. MMP reports still flush pending packets
  but do not reset idle timers or traffic counters.
- Behavior is intentionally unchanged: same reverse-route learning, same CE
  propagation, same endpoint delivery, same session recv/touch policy, and same
  pending flush timing.

Result:
- Accepted as another incremental peer/session-runtime cleanup. The established
  FSP open path now hands a single authenticated dispatch object to one local
  dispatch owner, so a future runtime can move that boundary without also
  moving a loose pile of source/commit bookkeeping.

Verification:

```sh
( cd /path/to/fips-dataplane-safety && cargo fmt --check )
( cd /path/to/fips-dataplane-safety && git diff --check )
( cd /path/to/fips-dataplane-safety && cargo check -p fips-core --release )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core session_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core endpoint_event_runtime -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core peer_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core forwarding -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_worker -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_failure -- --nocapture )
( cd /path/to/fips-dataplane-safety && cargo test -p fips-core -- --nocapture )
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn fips_private_mesh --features embedded-fips -- --nocapture
```

- Full FIPS result: `1507` passed, `2` ignored; doctests `2` ignored.
- nvpn local-FIPS result: `nvpn-hotpath` passed all six checks, and direct
  `fips_private_mesh` passed `59` tests.
- No Docker perf rerun was taken because this is a typed dispatch/commit
  ownership cleanup, not a queueing, routing, crypto, sender, batching, or
  delivery semantic change. The latest full Docker perf checkpoint remains
  nvpn `941cefd1` plus FIPS `5721357`.

Interpretation:
- Continue incremental refactor. The code is cleaner, but the big architecture
  is still not "boring" enough until a peer/session runtime owns FMP open, FSP
  open/replay, endpoint delivery, priority/bulk reserve, and observability
  together and can delete the endpoint-data rx-loop bounce with benchmark and
  soak evidence.

## FIPS authenticated session dispatch context - 2026-06-10

Summary:
- FIPS `f10a737` wraps the post-open established-FSP local dispatch facts in
  `AuthenticatedSessionDispatch`: source node, authenticated previous-hop node,
  CE flag, authenticated session message, and receive-completion bookkeeping
  now move together inside the rx-loop dispatch edge.
- This is the next receive-owner slice after `AuthenticatedSessionMessage`, not
  a new worker fast path. Reverse-route learning, rx-loop message dispatch,
  endpoint-event delivery, CE propagation, session recv/touch, and pending
  flush behavior are intentionally unchanged.
- `receive_completion` is pinned to application data only
  (`DataPacket`/`EndpointData`), so MMP reports continue to avoid resetting
  idle timers or traffic counters.

Result:
- Accepted as an incremental architecture cleanup toward a future peer/session
  runtime owner. It removes another loose source/previous-hop/CE/completion
  fact cluster before any risky rx-loop-bounce removal.

Verification:

```sh
( cd /path/to/fips-dataplane-safety && cargo fmt --check )
( cd /path/to/fips-dataplane-safety && git diff --check )
( cd /path/to/fips-dataplane-safety && cargo check -p fips-core --release )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core session_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core endpoint_event_runtime -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core peer_runtime_receive -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core forwarding -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_worker -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core decrypt_failure -- --nocapture )
( cd /path/to/fips-dataplane-safety && cargo test -p fips-core -- --nocapture )
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn fips_private_mesh --features embedded-fips -- --nocapture
```

- Full FIPS result: `1507` passed, `2` ignored; doctests `2` ignored.
- nvpn local-FIPS result: `nvpn-hotpath` passed all six checks, and direct
  `fips_private_mesh` passed `59` tests.
- No Docker perf rerun was taken because this is a typed dispatch-boundary
  cleanup, not a queueing, routing, crypto, sender, batching, or delivery
  semantic change. The latest full Docker perf checkpoint remains nvpn
  `941cefd1` plus FIPS `5721357`.

Interpretation:
- The big-picture architecture decision remains incremental refactor with
  benchmark gates, not a blank-page rewrite. Compared with wireguard-go,
  Tailscale, and BoringTun, FIPS is getting closer to a single obvious
  peer/session owner, but the endpoint-data fast path should not skip the rx
  loop until one owner owns FMP open, FSP open/replay, endpoint delivery,
  priority/bulk reserve, and observability together.

## FIPS UDP receive batch timestamp reuse - 2026-06-10

Summary:
- FIPS `9ab39ea` adds an internal `ReceivedPacket::with_trace_timestamp`
  constructor and reuses one wall-clock receive timestamp plus one pipeline
  queue stamp per UDP receive batch. This trims per-packet clock reads in the
  Linux `recvmmsg` loop and connected-peer drain without changing packet order,
  queue-residence accounting, or public packet fields.

Result:
- Accepted. Local checks passed:

```sh
( cd /path/to/fips-dataplane-safety && cargo fmt --check )
( cd /path/to/fips-dataplane-safety && git diff --check )
( cd /path/to/fips-dataplane-safety && cargo check -p fips-core --release )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core received_packet_can_reuse_batch_timestamps -- --nocapture )
( cd /path/to/fips-dataplane-safety && \
  cargo test -p fips-core drain_delivers_packets_to_packet_tx -- --nocapture )
```

- Focused clean/rx Docker smoke:
  `artifacts/fips-perf/udp-batch-timestamp-clean-rx`. It passed
  clean-underlay and rx-maintenance-fault with `0%` load/post ping loss.
  Clean-underlay ran `2691.7/2692.8 Mbps` baseline and
  `2604.6/2644.0 Mbps` under load. Rx-maintenance ran
  `2663.1/2654.1 Mbps` baseline and `2611.8/2680.1 Mbps` under load.
  Phase summary hash:
  `0df6260514b00d53f0f247790a4190a18583193ba7cd118bfb9d51d76fdebb9f`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
- Full default-env Docker smoke:
  `artifacts/fips-perf/udp-batch-timestamp-full`. It passed all four phases
  with `0%` load/post ping loss, direct UDP byte progress on both nodes in
  every phase, and only the expected decrypt-worker queue-full/bulk-drop
  counters during worker-queue-pressure. Phase summary hash:
  `bb540d4a07ee576090ca7a2bd60e50e0cc847eb3820ea3e1b555b952f1f6cc98`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.

| Phase | Baseline TCP Mbps | Load TCP Mbps |
| --- | ---: | ---: |
| clean-underlay | `2641.5/2597.1` | `2617.9/2653.0` |
| constrained-underlay | `167.1/166.1` | `165.2/166.1` |
| worker-queue-pressure | `232.2/229.5` | `230.0/231.3` |
| rx-maintenance-fault | `2640.2/2668.4` | `2624.3/2618.6` |

Rejected probes:
- Reducing the nvpn mesh receive burst was tested and reverted. A Linux default
  `64` probe at `artifacts/fips-perf/mesh-recv-burst-64-clean-rx` passed
  thresholds, but did not improve receive-side endpoint residence: high-rate
  `endpoint_event_wait` still averaged about `484-501us` with
  `p95<=1.0ms` and `p99<=2.1ms`. Phase summary hash:
  `c7a4a5367e99f3a24a01a9f49216d95455fbc62356ff7c69aad7846550f888f2`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
- An opt-in `32` receive-burst probe at
  `artifacts/fips-perf/mesh-recv-burst-32-clean-rx` also passed thresholds,
  but worsened high-rate `endpoint_event_wait` into roughly the
  `630-700us` average band with `p50<=1.0ms` in several samples. Phase summary
  hash:
  `2bf7070d2c11bf9dcfb1f3d619d99ef1e1a8855a161c8040441533dd8bc1fdb9`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.

Interpretation:
- Timestamp reuse is a small accepted hot-path simplification: fewer clock
  reads per UDP receive batch, no new queue, and healthy Docker liveness.
- Smaller app-side mesh receive drains are rejected for now. They preserve
  liveness but do not reduce the visible endpoint-event bottleneck, so no
  runtime tuning knob was kept.
- Endpoint/transport/event queue residence remains the next bottleneck to
  explain. This is Linux/Docker evidence, not real Mac-to-Mac validation.

## FIPS Linux encrypt-worker batch tuning - 2026-06-10

Summary:
- Tuned the Linux FMP encrypt-worker drain batch from the old fixed `32` to a
  default `48`, with `FIPS_WORKER_BATCH` clamped to `1..=64` so the drain cap
  cannot exceed the UDP_GSO accounting limit.

Result:
- FIPS `d5404a6` uses `worker_batch_size()` for non-macOS encrypt workers.
  Linux defaults to `48`; other non-macOS Unix targets keep `32`; macOS still
  uses its separate conservative sender batch. The guard
  `worker_batch_size_parse_stays_within_sender_accounting_limit` is included in
  the nvpn `fips` fast selector.
- A default `64` probe was rejected. It reduced hot receive-side
  `fmp_worker_queue_wait`, but the targeted clean/rx Docker run fell to roughly
  `1.2 Gbps` with heavy TCP retransmits:
  `artifacts/fips-perf/worker-batch-64-clean-rx` passed thresholds but is not
  an acceptable default.
- `FIPS_WORKER_BATCH=48` recovered clean/rx throughput in the `2.5-2.6 Gbps`
  band with `0%` load/post ping loss, so `48` became the Linux default and then
  got a no-env full smoke.

Verification:

```sh
FIPS_SAFETY_WORKTREE=/path/to/fips-dataplane-safety
( cd "$FIPS_SAFETY_WORKTREE" && cargo fmt --check )
( cd "$FIPS_SAFETY_WORKTREE" && \
  cargo test -p fips-core encrypt_worker -- --nocapture )
( cd "$FIPS_SAFETY_WORKTREE" && \
  cargo check -p fips-core --release )
bash -n scripts/test-dataplane-safety-fast.sh
NVPN_FIPS_REPO_PATH="$FIPS_SAFETY_WORKTREE" \
  ./scripts/test-dataplane-safety-fast.sh fips
git diff --check
NVPN_PATCH_LOCAL_FIPS=1 \
  NVPN_FIPS_REPO_PATH="$FIPS_SAFETY_WORKTREE" \
  NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/worker-batch-48-full \
  PROJECT_NAME=nostr-vpn-worker-batch-48-full \
  ./scripts/e2e-fips-perf-regression-docker.sh
```

Docker perf artifact:
- `artifacts/fips-perf/worker-batch-48-full/phase-summary.tsv`
- `phase-summary.tsv` SHA-256:
  `3d68b13277a693bb1afe878030a56150f06d5a15b93e66846797ad03f3144b25`
- `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`

The full smoke passed clean-underlay, constrained-underlay,
worker-queue-pressure, and rx-maintenance-fault with `0%` load/post ping loss,
direct UDP byte progress in every phase, and only the expected explicit
decrypt-worker pressure counters during worker-queue-pressure. Rough TCP
throughput from the summary:

| Phase | Baseline TCP Mbps | Load TCP Mbps |
| --- | ---: | ---: |
| clean-underlay | `2552.0/2440.8` | `2490.6/2532.8` |
| constrained-underlay | `164.2/164.0` | `165.8/165.3` |
| worker-queue-pressure | `231.8/228.9` | `229.5/228.2` |
| rx-maintenance-fault | `2583.9/2629.2` | `2571.8/2586.3` |

Interpretation:
- This is a small Linux batching/sender tuning win, not a new queue design.
  Compared with the prior route-index smoke, the receive-heavy high-rate
  `fmp_worker_queue_wait` improved from about `176-181us` to about
  `139-145us` in clean/rx final samples while keeping full-matrix throughput
  and liveness healthy.
- The remaining bottleneck is now more clearly endpoint/transport/event queue
  residence, with receive-heavy `endpoint_event_wait` still reaching hundreds
  of microseconds in clean/rx samples. This remains Linux/Docker evidence, not
  real Mac-to-Mac validation.

## FIPS rx-loop side-queue progress reserve - 2026-06-10

Summary:
- Kept TUN outbound and endpoint command queues making bounded progress while
  the FIPS rx loop is busy with a hot inbound packet or decrypt-fallback stream.

Result:
- FIPS `0846db7` makes `packet_rx` drains interleave a small side-queue turn
  every 64 packets, after the existing decrypt-fallback interleave. Each turn
  gives endpoint commands and TUN outbound work half of a 64-item reserve so
  control-shaped endpoint sends and outbound tunnel packets do not wait for a
  one-second maintenance tick when `packet_rx` remains continuously ready.
- The biased decrypt-fallback select arms now also drain the same bounded side
  queues before returning to `select!`, so fallback pressure cannot monopolize
  the loop either.
- `scripts/test-dataplane-safety-fast.sh fips` now includes
  `packet_drain_cursor_interleaves_side_queues_after_fallback`, keeping the
  scheduling contract visible from nvpn's cross-repo fast selector.

Verification:

```sh
FIPS_SAFETY_WORKTREE=/path/to/fips-dataplane-safety
( cd "$FIPS_SAFETY_WORKTREE" && \
  cargo test -p fips-core packet_drain_cursor -- --nocapture )
( cd "$FIPS_SAFETY_WORKTREE" && \
  cargo test -p fips-core rx_loop -- --nocapture )
( cd "$FIPS_SAFETY_WORKTREE" && cargo fmt --check )
( cd "$FIPS_SAFETY_WORKTREE" && cargo check -p fips-core --release )
bash -n scripts/test-dataplane-safety-fast.sh
NVPN_FIPS_REPO_PATH="$FIPS_SAFETY_WORKTREE" \
  ./scripts/test-dataplane-safety-fast.sh fips
git diff --check
NVPN_PATCH_LOCAL_FIPS=1 \
  NVPN_FIPS_REPO_PATH="$FIPS_SAFETY_WORKTREE" \
  NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/fips-0846db7-rx-side-queue-nvpn-87de470d-smoke \
  ./scripts/e2e-fips-perf-regression-docker.sh
DURATION=8 WG_THREADS_LIST="1 4" \
  scripts/perf-docker-boringtun.sh \
  | tee artifacts/fips-perf/boringtun-docker-reference-20260610.log
```

Docker perf artifact:
- `artifacts/fips-perf/fips-0846db7-rx-side-queue-nvpn-87de470d-smoke/phase-summary.tsv`
- `phase-summary.tsv` SHA-256:
  `60d7c06e092eab52fb8cbc1a45458076ac154da39ca4af5a5e6f6a5bcdcf2aa8`
- `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`

The perf smoke passed clean-underlay, constrained-underlay,
worker-queue-pressure, and rx-maintenance-fault with `0%` load/post ping loss,
direct UDP byte progress in every phase, and only the expected explicit
decrypt-worker pressure counters during worker-queue-pressure. Rough TCP
throughput from the summary:

| Phase | Baseline TCP Mbps | Load TCP Mbps |
| --- | ---: | ---: |
| clean-underlay | `2556.0/2610.0` | `2637.0/2575.0` |
| constrained-underlay | `166.9/166.1` | `165.8/162.8` |
| worker-queue-pressure | `231.0/223.8` | `227.1/234.8` |
| rx-maintenance-fault | `2625.6/2640.6` | `2636.5/2548.9` |

BoringTun Docker reference, using the older `scripts/perf-docker-boringtun.sh`
shape rather than the host-pair comparison matrix:

| Backend | TCP single | TCP 4 streams | TCP 8 streams | Ping |
| --- | ---: | ---: | ---: | ---: |
| BoringTun `WG_THREADS=1` | `3369 Mbps` | `3247 Mbps` | `3350 Mbps` | `0% loss, 0.476 ms avg` |
| BoringTun `WG_THREADS=4` | `1416 Mbps` | `1316 Mbps` | `1164 Mbps` | `0% loss, 0.483 ms avg` |

This is a local Docker reference point, not a same-script replacement for the
FIPS perf regression and not a host-pair matrix row.

No live host-pair soak, host-pair userspace WireGuard/BoringTun matrix,
wireguard-go reference run, real mobile device packet-path check, captive Wi-Fi
login, launchd daemon swap, or Mac-to-Mac/screenshare validation was run for
this scheduler slice.

## macOS route selector runs captive-portal probe guards - 2026-06-10

Summary:
- Tightened the fast `macos-route` selector so it actually runs the focused
  captive-portal probe tests, including the Apple socket-binding smoke on
  Darwin.

Result:
- `scripts/test-dataplane-safety-fast.sh macos-route` now runs
  `cargo test -p nvpn captive_portal -- --nocapture` before the macOS
  underlay route throttling, captive repair deferral, and default-route parser
  tests.
- On macOS this includes
  `captive_portal_check_can_bind_to_loopback_interface_on_macos`, which proves
  the `IP_BOUND_IF` path used by interface-aware portal checks still executes.
- The fast runner now avoids expanding an empty `cargo_config_args[@]` under
  `set -u`, so macOS's stock Bash reaches the intended Cargo command instead
  of failing in selector plumbing. This safety branch still needs
  `NVPN_FIPS_REPO_PATH` for nvpn tests until the unreleased FIPS endpoint APIs
  are published.
- This keeps the route-repair/captive-portal safety selector aligned with the
  Starbucks captive-portal field report and Tailscale-style lesson that the
  normal default-route interface may be missing until portal login completes.

Verification:

```sh
bash -n scripts/test-dataplane-safety-fast.sh
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh macos-route
```

Additional macOS VM smoke:
- Synced this safety branch to a macOS VM and ran
  `./scripts/test-dataplane-safety-fast.sh macos-route` on Darwin 25.5.0
  arm64. The suite passed, including the macOS-only loopback
  `IP_BOUND_IF` captive-portal socket-binding test.

No real captive Wi-Fi login, launchd daemon swap, host-pair soak, userspace
WireGuard/BoringTun reference run, Docker perf run, or Mac-to-Mac/screenshare
validation was run for this selector slice.

## Host-pair comparison carries concrete pipeline hard events - 2026-06-10

Summary:
- Host-pair artifacts now preserve the exact pipeline hard-event names observed
  during a sample, instead of only carrying the broader
  `pipeline_log_checked` flag.

Result:
- `scripts/soak-fips-dataplane-host-pair.sh` appends a trailing
  `pipeline_hard_events` summary column and records the same list in
  `samples.ndjson` as `pipeline.hard_events`.
- `scripts/compare-host-pair-benchmarks.sh` propagates that list into
  `comparison.json` as `nvpn.safety_checks.pipeline_hard_events`.
- `scripts/summarize-host-pair-comparison-run.sh` appends
  `nvpn_pipeline_hard_events` to `matrix-summary.tsv` and turns each event into
  a reliability failure reason such as
  `pipeline_hard_event_endpoint_event_backlog_high`.
- This makes a slow endpoint consumer, decrypt bulk pressure, or similar
  concrete pipeline failure visible in saved matrix artifacts even after the
  live soak process exits.

Verification:

```sh
bash -n scripts/soak-fips-dataplane-host-pair.sh \
  scripts/compare-host-pair-benchmarks.sh \
  scripts/summarize-host-pair-comparison-run.sh \
  scripts/test-host-pair-harness.sh \
  scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-harness.sh
./scripts/test-host-pair-comparison-harness.sh
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, slow-consumer soak, or Mac-to-Mac/screenshare validation was run for
this artifact-propagation slice.

## Cross-repo FIPS endpoint backlog guard - 2026-06-10

Summary:
- Broadened the nvpn fast runner's `fips` selector from retry etiquette only to
  focused local-FIPS reliability/observability checks.

Result:
- `scripts/test-dataplane-safety-fast.sh fips` now also runs
  `endpoint_event_queue_owns_backlog_message_count` inside the sibling FIPS
  worktree. That guard pins the new FIPS endpoint-event queue owner: inbound
  endpoint event delivery keeps current no-blocking semantics, but queued
  endpoint messages are counted across single events and batches so
  `endpoint_event_backlog_high` can make a slow embedded consumer observable in
  pipeline traces.
- This is safety evidence before a riskier bounded inbound endpoint event
  rewrite. It does not change nvpn packet delivery semantics by itself.

Verification:

```sh
bash -n scripts/test-dataplane-safety-fast.sh
./scripts/test-dataplane-safety-fast.sh list
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh fips
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, slow-consumer soak, or Mac-to-Mac/screenshare validation was run for
this observability slice.

## Fast runner nvpn suite split - 2026-06-10

Summary:
- Split the nvpn fast safety selector into smaller hot-path, reliability, and
  macOS-route suites while keeping `nvpn` as the aggregate.

Result:
- `scripts/test-dataplane-safety-fast.sh` now exposes `nvpn-hotpath`,
  `nvpn-reliability`, and `macos-route`.
- `nvpn-hotpath` covers the current TUN queue, raw TUN write, endpoint send
  batch, TUN-pipeline send, and receive-buffer reuse guards.
- `nvpn-reliability` covers far-future FIPS liveness/ping recovery, static and
  recent non-roster transit etiquette, default-route non-transit policy, and
  the private roster admission gate.
- `macos-route` covers captive-portal probing, route-event throttling,
  captive-portal repair deferral, and macOS default-route parsing. This is
  still unit coverage, not a real captive-Wi-Fi login.

Verification:

```sh
bash -n scripts/test-dataplane-safety-fast.sh
./scripts/test-dataplane-safety-fast.sh list
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-reliability
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh macos-route
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn
git diff --check
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, captive Wi-Fi login, launchd daemon swap, or Mac-to-Mac/screenshare
validation was run for this workflow slice.

## Host-pair reliability verdict matrix - 2026-06-10

Summary:
- Host-pair comparison bundles now include a compact reliability verdict beside
  throughput/stress-delta summaries.

Result:
- `scripts/summarize-host-pair-comparison-run.sh` now writes
  `matrix-reliability.tsv` and `matrix-reliability.json`, and embeds the same
  rows in `matrix-summary.json`.
- Each mode/backend row gets `pass`, `warn`, or `fail` plus reason lists.
  Failures cover unchecked direct-path/pipeline/counter-progress safety
  coverage, TCP-collapse counts, missing FIPS/control/data liveness evidence,
  stuck rekey, and overdue direct probes. Warnings surface active rekey/drain,
  pending direct probes, and Nostr traversal failures/cooldown.
- This keeps long clean/stress host-pair runs reviewable as reliability
  evidence without asking the operator to manually scan dozens of columns.

Verification:

```sh
./scripts/test-host-pair-comparison-harness.sh
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, or Mac-to-Mac/screenshare validation was run for this reporting
slice.

## Cross-repo FIPS retry fast suite - 2026-06-10

Summary:
- Added a `fips` selector to the nvpn dataplane safety fast runner so retry
  etiquette fixes in a sibling FIPS worktree can be verified from the same
  iteration command surface.

Result:
- `scripts/test-dataplane-safety-fast.sh fips` requires
  `NVPN_FIPS_REPO_PATH` and runs the focused FIPS `non_reconnect` and
  `active_fallback` test selectors inside that worktree.
- The nvpn `all` suite remains convenient without a sibling FIPS checkout, but
  includes the FIPS selector automatically when `NVPN_FIPS_REPO_PATH` is set.
- This covers the shared-mesh retry-storm policy boundary: roster/opt-in peers
  can keep fast active direct refresh, while non-reconnect transit peers do not
  sit in a one-second retry loop after cap/backpressure failures.

Verification:

```sh
bash -n scripts/test-dataplane-safety-fast.sh
./scripts/test-dataplane-safety-fast.sh list
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh fips
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh all
```

No live shared-mesh TCP cap reproduction, host-pair soak, userspace
WireGuard/BoringTun reference run, Docker perf run, or Mac-to-Mac/screenshare
validation was run for this harness-discoverability slice.

## Mobile endpoint outbound batching - 2026-06-10

Summary:
- Mobile FIPS send now drains bounded outbound bursts and batches consecutive
  packets for the same resolved peer.

Result:
- The mobile send task drains up to 64 ready OS-outbound packets per wake,
  preserving order by flushing the current FIPS run before MagicDNS, WireGuard
  upstream fallback, or a different peer.
- Consecutive mesh packets for the same roster-resolved `PeerIdentity` use FIPS
  `send_batch_to_peer`; unresolved endpoint-npub fallback sends remain
  one-by-one.
- The real local FIPS endpoint exit-node test now sends two outbound packets
  back-to-back before waiting on the exit endpoint, proving the mobile outbound
  burst path still delivers both packets through FIPS and into exit-node
  admission.

Verification:

```sh
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_fips_exit_node_routes_default_traffic_to_selected_member -- --nocapture
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_ -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh all
cargo fmt --check
git diff --check
```

No live mobile device packet-path check, host-pair soak, userspace
WireGuard/BoringTun reference run, Docker perf run, or Mac-to-Mac/screenshare
validation was run for this outbound-loop cleanup.

## Mobile endpoint receive batching - 2026-06-10

Summary:
- Mobile FIPS receive now drains bounded endpoint batches with a reusable
  message buffer instead of awaiting one endpoint message at a time.

Result:
- The mobile receive task uses FIPS `recv_batch_into` with a 64-message bound,
  mirroring the daemon endpoint-data receive shape while keeping mobile runtime
  scheduling responsive.
- Per-message control-frame decoding, roster/capability handling, node-address
  admission, owned packet movement, checksum finalization, and inbound-channel
  shutdown behavior remain centralized in one helper.
- The real local FIPS endpoint exit-node test now sends two back-to-back replies
  from the exit endpoint and accepts them in either order, proving the batched
  receive path still delivers multiple inbound endpoint packets through the
  mobile tunnel.

Verification:

```sh
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_fips_exit_node_routes_default_traffic_to_selected_member -- --nocapture
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_ -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh all
cargo fmt --check
git diff --check
```

No live mobile device packet-path check, host-pair soak, userspace
WireGuard/BoringTun reference run, Docker perf run, or Mac-to-Mac/screenshare
validation was run for this receive-loop cleanup.

## Mobile owned inbound packet admission - 2026-06-10

Summary:
- Mobile FIPS receive now moves endpoint packet bytes through mesh admission
  instead of cloning them after admission.

Result:
- The mobile receive task now calls
  `receive_endpoint_data_owned_from_node_addr` after non-control endpoint
  messages pass control-frame decoding.
- Presence accounting snapshots the original message length before moving the
  packet bytes, then the admitted packet is checksummed and written to the
  mobile inbound channel.
- The real local FIPS endpoint exit-node test now covers both directions: client
  outbound packet delivery to the exit endpoint and exit reply delivery back
  through the mobile tunnel inbound channel.

Verification:

```sh
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_fips_exit_node_routes_default_traffic_to_selected_member -- --nocapture
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_ -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh all
cargo fmt --check
git diff --check
```

No live mobile device packet-path check, host-pair soak, userspace
WireGuard/BoringTun reference run, Docker perf run, or Mac-to-Mac/screenshare
validation was run for this packet-ownership cleanup.

## Mobile owned packet routing - 2026-06-10

Summary:
- Mobile FIPS routing now keeps packet bytes single-owner on the mesh send path.

Result:
- `FipsMeshRuntime::route_outbound_packet_peer` exposes route target metadata
  without cloning packet bytes.
- The mobile tunnel send task uses that metadata-only route lookup, clones only
  the small participant/endpoint identifiers needed after dropping the mesh lock,
  and moves the original packet `Vec<u8>` into `send_mobile_endpoint_data`.
- Non-mesh packets still keep the original `Vec<u8>` for the WireGuard upstream
  fallback path, preserving the previous mesh-vs-WG routing behavior.

Verification:

```sh
cargo test -p nostr-vpn-core outbound_packet -- --nocapture
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_ -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh all
cargo fmt --check
git diff --check
```

No live mobile device packet-path check, host-pair soak, userspace
WireGuard/BoringTun reference run, Docker perf run, or Mac-to-Mac/screenshare
validation was run for this packet-ownership cleanup.

## Mobile roster identity sends - 2026-06-10

Summary:
- Mobile roster-owned endpoint sends now use FIPS `PeerIdentity` instead of
  reparsing human-facing endpoint npubs on each send.

Result:
- `MobileTunnel` keeps a roster-derived participant -> `PeerIdentity` map beside
  the mesh runtime and refreshes it when a signed roster applies.
- Mobile tunnel data, peer pings, capability broadcasts, and signed-roster sync
  use `send_to_peer` for roster-known peers, falling back to legacy
  `send(endpoint_npub, data)` only if identity parsing failed.
- Pending join requests stay on the endpoint-npub path because they are
  intentionally pre-roster/admin-targeted control messages.

Verification:

```sh
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_peer_identity_map_resolves_endpoint_identities_and_skips_invalid_npubs -- --nocapture
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_ -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh all
cargo fmt --check
git diff --check
```

No live mobile device packet-path check, host-pair soak, userspace
WireGuard/BoringTun reference run, Docker perf run, or Mac-to-Mac/screenshare
validation was run for this API-shape slice.

## nvpn/FIPS host-pair preflight - 2026-06-10

Summary:
- Host-pair comparison runs now fail fast on nvpn/FIPS setup blockers before
  launching long soak or userspace WireGuard reference rows.

Result:
- `scripts/soak-fips-dataplane-host-pair.sh` accepts
  `NVPN_HOST_PAIR_PREFLIGHT=1` and exits after checking local tools, remote
  SSH/tool availability, daemon-status shape, peer selection, tunnel IP
  presence, and expected direct-path reachability.
- The preflight writes `preflight.tsv` in the configured artifact directory
  with `ok`/`missing` check names plus local operational details for peer
  selection, path, SRTT, and SRTT freshness.
- `scripts/run-host-pair-comparison.sh` runs the nvpn/FIPS preflight before
  each nvpn row by default. Set
  `NVPN_HOST_PAIR_COMPARISON_NVPN_PREFLIGHT=0` only to skip it for a known-good
  operator-local setup.

Verification:

```sh
bash -n scripts/soak-fips-dataplane-host-pair.sh \
  scripts/run-host-pair-comparison.sh \
  scripts/test-host-pair-harness.sh \
  scripts/test-host-pair-comparison-runner.sh
./scripts/test-host-pair-harness.sh
./scripts/test-host-pair-comparison-runner.sh
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, or Mac-to-Mac/screenshare validation was run for this harness slice.

## Peer presence future timestamp guard - 2026-06-10

Summary:
- FIPS peer presence, ping cadence, daemon state projection, native/app-core
  labels, and mobile runtime state no longer treat far-future timestamps as
  freshness.

Result:
- CLI embedded-FIPS liveness and ping cadence now use an explicit two-second
  future-skew tolerance instead of `saturating_sub`; far-future peer presence
  no longer marks a peer connected, and a far-future `last_ping_sent_at` no
  longer suppresses liveness pings indefinitely.
- Live peer capability TTLs use the same future-skew rule so far-future
  capability receive times cannot keep stale routes or endpoint hints alive.
- Daemon runtime-state projection drops far-future FIPS/control/data last-seen
  timestamps before writing state, and CLI status text hides far-future
  last-seen ages instead of printing `last=0s`.
- App-core native state labels and persisted mobile runtime-state loading now
  reject far-future presence/runtime timestamps. Mobile tunnel state preserves
  old past last-seen values for display, but does not export absurd future
  last-seen/handshake values or use them for roster sends.

Verification:

```sh
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn future -- --nocapture
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core future -- --nocapture
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_ -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh all
cargo fmt --check
git diff --check
```

No live clock-jump reproduction, launchd/service restart, host-pair soak,
userspace WireGuard/BoringTun reference run, Docker perf run, or
Mac-to-Mac/screenshare validation was run for this narrow liveness slice.

## Roster-scoped fast reconnect - 2026-06-10

Summary:
- Fast FIPS reconnect remains for nvpn roster peers, but transit-only
  bootstrap/recent peers now use bounded retry etiquette.

Result:
- FIPS now honors `PeerConfig.auto_reconnect = false` in the active-fallback
  direct-refresh path. Auto-connect peers with that flag disabled no longer get
  converted into due fast-refresh retry entries while they are already active
  over a transit/fallback path.
- nvpn desktop already marked static bootstrap/transit seeds and recent
  authenticated non-roster transit seeds with `auto_reconnect = false`; mobile
  now uses the same policy. Peers derived from the private roster keep
  `auto_reconnect = true`.
- The endpoint-peer signature includes the reconnect/transit policy so runtime
  updates notice a peer changing between transit-only and roster-owned policy.
- This keeps quick recovery inside the private nvpn roster while avoiding
  indefinite fast retries against shared/public FIPS TCP listeners when those
  listeners are already applying connection caps.

Verification:

```sh
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_config_seeds_bootstrap_transit_peers -- --nocapture
cargo test --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nostr-vpn-app-core mobile_fips_config_keeps_hinted_non_roster_peers -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh all
cargo fmt --check
git diff --check
```

No live shared-mesh TCP cap reproduction, host-pair soak, userspace
WireGuard/BoringTun reference run, Docker perf run, or Mac-to-Mac/screenshare
validation was run for this policy slice.

## Direct-probe retry policy telemetry - 2026-06-10

Summary:
- FIPS/nvpn status now exposes whether a pending direct probe is bounded or an
  unlimited auto-reconnect, plus retry count and expiry.

Result:
- `FipsEndpointPeer` and nvpn peer status carry
  `direct_probe_retry_count`, `direct_probe_auto_reconnect`, and
  `direct_probe_expires_at_ms` beside the existing pending/after fields.
- CLI daemon state, app-core state, mobile runtime state, and native participant
  state preserve those fields with zero/false/absent defaults for older JSON.
- Docker and host-pair soak samples, failure reports, summary TSVs, comparison
  TSV/JSON, and matrix summary TSV/JSON now keep the retry-policy fields.
- This gives retry-storm investigations a direct signal for "bounded
  transit-only retry" versus "nvpn roster-owned fast reconnect" without reading
  debug logs.

Verification:

```sh
cargo test -p fips-core endpoint_peer_conversion_preserves_rekey_state -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh app-state
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
./scripts/test-fips-soak-harness.sh
```

No live shared-mesh TCP cap reproduction, host-pair soak, userspace
WireGuard/BoringTun reference run, Docker perf run, or Mac-to-Mac/screenshare
validation was run for this telemetry slice.

## Daemon state future timestamp guard - 2026-06-10

Summary:
- The state-file daemon status fallback no longer treats far-future
  `updated_at` timestamps as fresh.

Result:
- `daemon_state_is_fresh` now rejects zero timestamps, accepts timestamps within
  the existing max-age window, tolerates only a two-second same-host future
  skew, and rejects larger future timestamps explicitly.
- This closes a small time-poisoning hole where `now.saturating_sub(updated_at)`
  made a future state file look fresh until wall time caught up, keeping
  state-file status mode in "running" too long after clock jumps or corrupted
  state.

Verification:

```sh
cargo test \
  --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn daemon_state_freshness_allows_pid_namespace_status -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh all
cargo fmt --check
git diff --check
```

No live daemon state-file mode reproduction, launchd/service restart, host-pair
soak, userspace WireGuard/BoringTun reference run, Docker perf run, or
Mac-to-Mac/screenshare validation was run for this narrow liveness slice.

## CPU-stress host-pair comparison deltas - 2026-06-10

Summary:
- Host-pair comparison-run summaries now compute clean-vs-stress degradation
  directly for each reference backend.

Result:
- `scripts/summarize-host-pair-comparison-run.sh` now writes
  `matrix-stress-deltas.tsv` beside `matrix-summary.tsv` and
  `matrix-summary.json`.
- The root JSON now includes `stress_deltas[]` entries for each backend with
  matching `clean` and `stress` rows. Each entry reports nvpn and reference
  forward/reverse Mbps under stress as a percentage of clean, p99 ping deltas,
  CPU deltas, and the change in nvpn Mbps as a percentage of the reference row.
- This makes CPU-contention host-pair bundles answer whether nvpn degrades more
  than BoringTun/wireguard-go on the same underlay, without manually comparing
  rows in a spreadsheet.

Verification:

```sh
bash -n scripts/summarize-host-pair-comparison-run.sh \
  scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-harness.sh
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
git diff --check
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker perf
run, or Mac-to-Mac/screenshare validation was run for this artifact-shape slice.

## Interface-aware captive portal probing - 2026-06-10

Summary:
- macOS/iOS captive-portal detection now probes physical-ish candidate
  interfaces directly before falling back to the default-route probe.

Result:
- Tailscale's `net/captivedetection` package documents the key macOS lesson:
  the default-route interface may be missing until the user accepts the captive
  portal alert, so detection should try interfaces that resemble Wi-Fi/underlay
  links and skip tunnel/virtual/cellular interfaces.
- nvpn now mirrors that narrow model for the existing HTTP checks: enumerate
  up, non-loopback, non-tunnel interfaces with IPv4 addresses; skip
  prefixes such as `utun`, `awdl`, `bridge`, `pdp`, `tailscale`, `docker`,
  `wg`, and `ipsec`; and on Apple bind each probe socket to the interface index
  with `IP_BOUND_IF`/`IPV6_BOUND_IF`.
- If any candidate interface sees a captive-looking response, detection returns
  `Some(true)` and macOS route repair remains deferred. If candidates get at
  least one clean response and no portal response, detection returns
  `Some(false)`. If candidate probing is inconclusive, nvpn falls back to the
  previous default-route probe.
- A macOS-only unit smoke now binds the HTTP captive-portal probe to the
  loopback interface index, proving the Apple `IP_BOUND_IF` path executes in CI
  or VM runs without requiring a live captive portal.

Verification:

```sh
cargo test \
  --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn captive_portal -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn
cargo fmt --check
git diff --check
git diff -- Cargo.lock
```

Additional macOS VM smoke:
- On a Darwin 25.5.0 arm64 VM, after syncing nvpn/FIPS/hashtree worktrees by git
  bundle, the local-FIPS-patched `cargo test -p nvpn captive_portal --
  --nocapture` passed 4 tests, including
  `captive_portal_check_can_bind_to_loopback_interface_on_macos`.

No real captive Wi-Fi login, launchd daemon swap, or Mac-to-Mac/screenshare
validation was run for this probe-routing slice.

## Captive Wi-Fi route-repair deferral - 2026-06-10

Summary:
- macOS underlay default-route repair now defers while captive-portal probing
  has confirmed an active portal.

Result:
- A field report from the current release showed a launchd/root daemon with
  `launch_on_startup = true` and `autoconnect = true` repeatedly logging
  `restored missing macOS underlay default route`, `refreshing tunnel after
  macOS underlay repair`, and macOS tunnel interface application while a
  Starbucks captive portal was opening and closing.
- The daemon and explicit `connect` path now run captive-portal detection
  before macOS underlay default-route repair. When the probe returns
  `Some(true)`, route repair/DHCP renewal is deferred. A `false` or inconclusive
  result preserves the previous repair behavior.
- The periodic macOS network watcher refreshes the captive-portal signal before
  route repair on network/sleep events, and refreshes it again after a
  successful repair.
- This is intentionally narrow: it stops nvpn from fighting known portal
  onboarding, without disabling repairs when the portal probe cannot prove a
  portal is present.

Verification:

```sh
cargo test \
  --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn macos_underlay_route -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn
cargo fmt --check
git diff --check
git diff -- Cargo.lock
```

No real captive Wi-Fi login, launchd daemon swap, or Mac-to-Mac/screenshare
validation was run for this code-policy slice.

## Rekey/probe/traversal state in comparison artifacts - 2026-06-10

Summary:
- Host-pair summaries and benchmark comparisons now preserve latest nvpn rekey,
  direct-probe, and Nostr traversal state.

Result:
- `scripts/soak-fips-dataplane-host-pair.sh` appends current local/remote rekey
  state, direct-probe state/counters, and Nostr traversal failure/cooldown/skew
  state to each `summary.tsv` row. The row writer now uses an array instead of
  a fixed-width `printf`, making future summary fields less brittle.
- `scripts/compare-host-pair-benchmarks.sh` reads those optional fields from
  newer nvpn host-pair artifacts, writes them to `comparison.tsv`, and exposes
  structured `nvpn.rekey`, `nvpn.direct_probe`, and `nvpn.nostr_traversal`
  blocks in `comparison.json`.
- `scripts/summarize-host-pair-comparison-run.sh` appends the same fields to
  root `matrix-summary.tsv`; `matrix-summary.json` preserves the full
  normalized nvpn object per row.
- Older artifacts without those columns still normalize with empty TSV fields
  and JSON nulls.
- This makes clean/stress BoringTun/wireguard-go benchmark bundles show whether
  throughput was accompanied by active rekey churn, direct-probe backlog, or
  Nostr traversal cooldown/skew state.

Verification:

```sh
bash -n scripts/soak-fips-dataplane-host-pair.sh \
  scripts/test-host-pair-harness.sh \
  scripts/compare-host-pair-benchmarks.sh \
  scripts/summarize-host-pair-comparison-run.sh \
  scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-harness.sh
./scripts/test-host-pair-comparison-harness.sh
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
git diff --check
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, or Mac-to-Mac/screenshare validation was run for this artifact-shape
slice.

## Route/progress flags in host-pair comparison artifacts - 2026-06-10

Summary:
- Host-pair comparison bundles now preserve nvpn path/progress safety flags
  beside throughput, latency, CPU, and FIPS freshness.

Result:
- `scripts/compare-host-pair-benchmarks.sh` reads optional nvpn host-pair
  `summary.tsv` fields for `direct_path_checked`, `pipeline_log_checked`,
  `counter_progress_checked`, `iperf_forward_collapse_count`, and
  `iperf_reverse_collapse_count`.
- `comparison.tsv` carries those fields on the nvpn row and leaves them empty
  for userspace WireGuard reference rows.
- `comparison.json` exposes them as `nvpn.safety_checks`.
- `scripts/summarize-host-pair-comparison-run.sh` appends the same fields to
  root `matrix-summary.tsv`; `matrix-summary.json` already preserves the full
  normalized nvpn object.
- The normalizer now treats `1`/`0` summary flags as booleans in JSON, matching
  the host-pair soak summary format.
- This makes a clean/stress BoringTun/wireguard-go comparison row show whether
  nvpn stayed on the intended direct path, checked pipeline/counter progress,
  and avoided TCP-collapse samples, instead of reporting only Mbps ratios.

Verification:

```sh
bash -n scripts/compare-host-pair-benchmarks.sh \
  scripts/summarize-host-pair-comparison-run.sh \
  scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-harness.sh
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
git diff --check
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, or Mac-to-Mac/screenshare validation was run for this artifact-shape
slice.

## FIPS liveness in host-pair comparison artifacts - 2026-06-10

Summary:
- Host-pair comparison bundles now preserve nvpn FIPS/control/data liveness
  evidence beside throughput and latency.

Result:
- `scripts/compare-host-pair-benchmarks.sh` reads optional nvpn host-pair
  `summary.tsv` fields for `fips_liveness_checked`,
  `fips_control_liveness_checked`, `fips_data_liveness_checked`, and each
  local/remote last-seen age.
- `comparison.tsv` carries those fields on the nvpn row and leaves them empty
  for userspace WireGuard reference rows.
- `comparison.json` exposes `nvpn.fips_liveness`,
  `nvpn.fips_control_liveness`, and `nvpn.fips_data_liveness`.
- `scripts/summarize-host-pair-comparison-run.sh` appends the same liveness
  flags and ages to root `matrix-summary.tsv`, while `matrix-summary.json`
  already preserves the full normalized nvpn object per row.
- This keeps clean/stress BoringTun/wireguard-go comparison bundles from
  becoming pure Mbps scoreboards; each nvpn row can also show whether
  FIPS/control/data freshness stayed within the soak policy.

Verification:

```sh
bash -n scripts/compare-host-pair-benchmarks.sh \
  scripts/summarize-host-pair-comparison-run.sh \
  scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-harness.sh
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
git diff --check
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, or Mac-to-Mac/screenshare validation was run for this artifact-shape
slice.

## Selectable dataplane safety fast runner - 2026-06-10

Summary:
- Added a local selectable runner for fast dataplane safety checks and
  benchmark-matrix command mapping.

Result:
- New `scripts/test-dataplane-safety-fast.sh` supports `harnesses`,
  `comparison-dry-run`, `core`, `nvpn`, `app-state`, `all`, and `list`.
- The default `harnesses comparison-dry-run` path runs shell syntax checks,
  local harness self-tests, and a side-effect-free dry-run of the intended
  clean/stress x BoringTun/wireguard-go host-pair comparison matrix.
- Cargo suites can be selected only when needed. If `NVPN_FIPS_REPO_PATH` is
  set for unreleased local FIPS crates, the runner snapshots and restores
  `Cargo.lock` after cargo tests so safety iteration does not leave lockfile
  churn behind.
- `just dataplane-safety-fast` exposes the selectable runner. `just
  dataplane-host-pair-comparison` defaults live host-pair benchmark runs to
  `NVPN_HOST_PAIR_COMPARISON_BACKENDS=boringtun,wireguard-go` and
  `NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES=clean,stress`; the live target
  still requires operator-local SSH and underlay IP env. `just
  dataplane-host-pair-comparison-dry-run` verifies the same mapping with
  documentation-reserved placeholder addresses.

Verification:

```sh
bash -n scripts/test-dataplane-safety-fast.sh
./scripts/test-dataplane-safety-fast.sh list
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
just --dry-run dataplane-safety-fast
just --dry-run dataplane-safety-fast harnesses comparison-dry-run
just dataplane-host-pair-comparison-dry-run
git diff --check
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, or Mac-to-Mac/screenshare validation was run for this discoverability
slice.

## FIPS data liveness soak gate - 2026-06-10

Summary:
- Docker and host-pair soaks now fail when FIPS bulk data freshness is missing
  or stale after measured bidirectional tunnel traffic.

Result:
- `scripts/soak-fips-dataplane-docker.sh` samples peer status after ping/iperf,
  while still checking the direct path before traffic. This makes a one-sample
  Docker smoke able to prove `last_fips_data_seen_at` from the traffic it just
  measured instead of inheriting `null` from the pre-traffic status snapshot.
- Docker adds `NVPN_SOAK_MAX_FIPS_DATA_LAST_SEEN_AGE_SECS`, defaulting to the
  generic FIPS last-seen budget, and gates both nodes with
  `last_fips_data_seen_at`.
- Host-pair adds `NVPN_HOST_PAIR_MAX_FIPS_DATA_LAST_SEEN_AGE_SECS`, records the
  threshold in `metadata.json` / `failure.json`, appends
  `fips_data_liveness_checked` to `summary.tsv`, and gates both sides after its
  existing post-traffic status sample.
- Docker adds `NVPN_SOAK_SKIP_BUILD=1` for operator-local reruns against an
  already-built compose project image, useful when Docker Hub metadata lookup is
  flaky and the nvpn image itself is known current enough for a script-policy
  check.

Verification:

```sh
bash -n scripts/soak-fips-dataplane-docker.sh scripts/soak-fips-dataplane-host-pair.sh \
  scripts/test-fips-soak-harness.sh scripts/test-host-pair-harness.sh
./scripts/test-fips-soak-harness.sh
./scripts/test-host-pair-harness.sh
./scripts/test-host-pair-comparison-harness.sh
git diff --check
```

Live Docker evidence:

```sh
NVPN_SOAK_SKIP_BUILD=1 \
NVPN_SOAK_OUTPUT_DIR=artifacts/fips-soak/data-liveness-smoke-reuse \
PROJECT_NAME=nostr-vpn-soak-control-liveness-smoke \
NVPN_SOAK_DURATION_SECS=1 \
NVPN_SOAK_INTERVAL_SECS=1 \
NVPN_SOAK_PING_COUNT=3 \
NVPN_SOAK_IPERF_DURATION_SECS=1 \
./scripts/soak-fips-dataplane-docker.sh
```

The skip-build smoke passed using the previously built local-FIPS-patched
compose images. Its first sample recorded data ages of `0s` and `2s`, control
ages of `1s` and `5s`, `0%` tunnel ping loss both ways, and TCP iperf
`2589.5/2544.5 Mbps`. A normal rebuild attempt immediately before this failed
before containers started because Docker Hub metadata lookup for the base images
timed out; that was external build evidence, not dataplane evidence.

## Host-pair comparison matrix summary - 2026-06-10

Summary:
- Host-pair comparison bundles now get root summary artifacts across every
  mode/backend row.

Result:
- New helper `scripts/summarize-host-pair-comparison-run.sh` reads a runner
  `manifest.tsv` plus each listed `comparison.json`.
- It writes `matrix-summary.tsv` and `matrix-summary.json` at the bundle root,
  flattening mode, backend, CPU-stress flag, nvpn/reference throughput,
  retransmits, p99 ping, CPU samples, and nvpn Mbps as a percentage of the
  reference row.
- `scripts/run-host-pair-comparison.sh` calls the summarizer after live runs;
  dry-run remains side-effect-free.
- This makes a clean/stress BoringTun/wireguard-go bundle directly inspectable
  without hand-opening four per-row comparison directories.

Verification:

```sh
bash -n scripts/run-host-pair-comparison.sh scripts/summarize-host-pair-comparison-run.sh \
  scripts/test-host-pair-comparison-harness.sh scripts/test-host-pair-comparison-runner.sh \
  scripts/bench-userspace-wg-host-pair.sh scripts/test-userspace-wg-host-pair-harness.sh
./scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-runner.sh
./scripts/test-userspace-wg-host-pair-harness.sh
git diff --check
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, or Mac-to-Mac/screenshare validation was run for this artifact-summary
slice.

## Clean/stress host-pair comparison sweep - 2026-06-10

Summary:
- The host-pair comparison runner can now run a clean baseline and
  CPU-contention row in one benchmark bundle.

Result:
- `scripts/run-host-pair-comparison.sh` accepts
  `NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES=clean,stress`.
- Without the new env, single-mode behavior is unchanged:
  `NVPN_HOST_PAIR_COMPARISON_CPU_STRESS=0` runs a clean comparison and `=1`
  runs a stressed comparison.
- With multiple CPU-stress modes, the runner preflights each requested
  backend/mode pair, runs one nvpn/FIPS row per mode, then compares each
  userspace WireGuard backend against the matching nvpn row. Artifacts are
  written under `clean/` and `stress/` subdirectories, and `manifest.tsv`
  records mode, backend, CPU-stress setting, and paths.
- The intended operator-local benchmark shape for CPU-contention questions is:
  `NVPN_HOST_PAIR_COMPARISON_BACKENDS=boringtun,wireguard-go` plus
  `NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES=clean,stress`, so nvpn can be
  interpreted against both userspace WG baselines in both clean and stressed
  same-window conditions.

Verification:

```sh
bash -n scripts/run-host-pair-comparison.sh scripts/test-host-pair-comparison-runner.sh \
  scripts/bench-userspace-wg-host-pair.sh scripts/test-userspace-wg-host-pair-harness.sh \
  scripts/compare-host-pair-benchmarks.sh scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-runner.sh
./scripts/test-host-pair-comparison-harness.sh
./scripts/test-userspace-wg-host-pair-harness.sh
git diff --check
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, or Mac-to-Mac/screenshare validation was run for this orchestration
slice.

## Multi-backend host-pair comparison runner - 2026-06-10

Summary:
- The host-pair comparison runner can now compare one nvpn/FIPS row against
  multiple userspace WireGuard references in one bundle.

Result:
- `scripts/run-host-pair-comparison.sh` accepts
  `NVPN_HOST_PAIR_COMPARISON_BACKENDS=boringtun,wireguard-go`.
- Single-backend runs keep the existing `reference/` and `comparison/`
  subdirectories for compatibility.
- Multi-backend runs preflight each requested reference, run the nvpn/FIPS
  host-pair row once, then write `reference-<backend>/`,
  `comparison-<backend>/`, and a root `manifest.tsv`. This is the repeatable
  operator-local benchmark shape for interpreting nvpn throughput and CPU
  contention against both BoringTun and wireguard-go under the same underlay,
  ping/iperf knobs, and CPU-stress settings.

Verification:

```sh
bash -n scripts/run-host-pair-comparison.sh scripts/test-host-pair-comparison-runner.sh \
  scripts/bench-userspace-wg-host-pair.sh scripts/test-userspace-wg-host-pair-harness.sh \
  scripts/compare-host-pair-benchmarks.sh scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-runner.sh
./scripts/test-host-pair-comparison-harness.sh
./scripts/test-userspace-wg-host-pair-harness.sh
git diff --check
```

No live host-pair soak, userspace WireGuard/BoringTun reference run, Docker
perf run, or Mac-to-Mac/screenshare validation was run for this orchestration
slice.

## Pipeline summary freshness soak guard - 2026-06-10

Summary:
- Docker and host-pair FIPS soaks now fail when an established pipeline summary
  stream stops advancing between long-soak samples.

Result:
- Docker soak pipeline samples include `line_count` beside latest/recent raw
  summaries and queue-wait metrics.
- Host-pair soak samples and failure reports include FIPS/nvpn pipeline summary
  line counts for local and remote logs.
- Once a pipeline stream has produced at least one `[pipe ...]` or
  `[nvpn-pipe ...]` line, the matching-line count must keep advancing. Docker
  and host-pair soaks fail after more than two consecutive stale samples by
  default, configurable with `NVPN_SOAK_MAX_CONSECUTIVE_PIPELINE_STALE_SAMPLES`
  and `NVPN_HOST_PAIR_MAX_CONSECUTIVE_PIPELINE_STALE_SAMPLES`. Optional/missing
  pipeline logs still follow the existing `NVPN_HOST_PAIR_REQUIRE_PIPELINE_LOGS`
  policy. This makes stale pipeline evidence fail clearly instead of silently
  reusing old queue/drop summaries, without punishing intentionally fast samples
  that run before the next log reporter tick.

Verification:

```sh
bash -n scripts/soak-fips-dataplane-docker.sh scripts/soak-fips-dataplane-host-pair.sh \
  scripts/test-fips-soak-harness.sh scripts/test-host-pair-harness.sh \
  scripts/test-userspace-wg-host-pair-harness.sh \
  scripts/test-host-pair-comparison-harness.sh \
  scripts/test-host-pair-comparison-runner.sh
./scripts/test-fips-soak-harness.sh
./scripts/test-host-pair-harness.sh
./scripts/test-userspace-wg-host-pair-harness.sh
./scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-runner.sh
git diff --check
```

No live Docker soak, host-pair soak, userspace WireGuard/BoringTun reference
run, or Mac-to-Mac/screenshare validation was run for this harness-policy
slice.

## Direct-probe overdue soak guard - 2026-06-10

Summary:
- Docker and host-pair FIPS soaks now fail when direct UDP probing remains
  eligible across too many consecutive samples without clearing.

Result:
- `scripts/soak-fips-dataplane-docker.sh` accepts
  `NVPN_SOAK_MAX_CONSECUTIVE_DIRECT_PROBE_OVERDUE_SAMPLES` and defaults to
  `2`.
- `scripts/soak-fips-dataplane-host-pair.sh` accepts
  `NVPN_HOST_PAIR_MAX_CONSECUTIVE_DIRECT_PROBE_OVERDUE_SAMPLES` and defaults
  to `2`.
- A sample with `direct_probe_pending=true` increments the side's pending
  counter. It increments the overdue counter only when `direct_probe_after_ms`
  is missing/non-numeric or no later than the sample's Unix epoch ms; an
  inactive sample resets both counters. The default fails on the third
  consecutive overdue sample, which catches stalled direct-path probing without
  failing intentional backoff/cooldown windows.
- Docker and host-pair `samples.ndjson` now include direct-probe pending and
  overdue counts; host-pair `failure.json` and `metadata.json` include the
  overdue threshold.

Verification:

```sh
bash -n scripts/soak-fips-dataplane-docker.sh scripts/soak-fips-dataplane-host-pair.sh \
  scripts/test-fips-soak-harness.sh scripts/test-host-pair-harness.sh
./scripts/test-fips-soak-harness.sh
./scripts/test-host-pair-harness.sh
git diff --check
```

No live Docker soak, host-pair soak, or Mac-to-Mac/screenshare validation was
run for this harness-policy slice.

## Host-pair comparison run orchestrator - 2026-06-10

Summary:
- Added an optional runner that launches nvpn/FIPS host-pair and userspace
  WireGuard/BoringTun reference rows with shared underlay/CPU-stress settings,
  then invokes the comparison artifact helper.

Result:
- `scripts/run-host-pair-comparison.sh` maps
  `NVPN_HOST_PAIR_COMPARISON_*` settings into
  `scripts/soak-fips-dataplane-host-pair.sh`,
  `scripts/bench-userspace-wg-host-pair.sh`, and
  `scripts/compare-host-pair-benchmarks.sh`.
- The runner writes one bundle under
  `artifacts/host-pair-comparison-runs/<timestamp>/` with `nvpn/`,
  `reference/`, and `comparison/` subdirectories.
- `NVPN_HOST_PAIR_COMPARISON_DRY_RUN=1` prints the exact mapped commands without
  creating directories, SSHing, using sudo, or creating TUN devices. The local
  self-test pins that command mapping on macOS-compatible Bash.
- This is operator-local orchestration only. It does not prove any live
  throughput/reliability result until someone runs it against actual hosts and
  records the generated artifacts.

Verification:

```sh
bash -n scripts/run-host-pair-comparison.sh \
  scripts/test-host-pair-comparison-runner.sh \
  scripts/compare-host-pair-benchmarks.sh \
  scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-runner.sh
./scripts/test-host-pair-comparison-harness.sh
git diff --check
```

All focused checks passed. No live nvpn host-pair soak, userspace WireGuard
reference run, Docker perf run, or Mac-to-Mac/screenshare validation was run for
this runner slice.

## Host-pair reference comparison artifact helper - 2026-06-10

Summary:
- Added a small artifact-only helper that normalizes an nvpn/FIPS host-pair row
  and a userspace WireGuard/BoringTun reference row into one comparison bundle.

Result:
- `scripts/compare-host-pair-benchmarks.sh` reads an existing
  `scripts/soak-fips-dataplane-host-pair.sh` artifact directory and an existing
  `scripts/bench-userspace-wg-host-pair.sh` artifact directory.
- The helper writes `comparison.tsv`, `ratios.tsv`, and `comparison.json` under
  `artifacts/host-pair-comparisons/<timestamp>/` by default.
- Normalized rows preserve forward/reverse TCP Mbps, retransmits, ping p95/p99,
  CPU-stress settings, and CPU samples. Ratio output reports nvpn forward and
  reverse Mbps as a percentage of the reference row, so host-pair numbers can be
  interpreted against the same underlay and CPU-contention shape.
- The helper does not run daemons, create TUN devices, SSH to remote hosts, or
  decide pass/fail policy; it only makes existing benchmark artifacts easier to
  compare.

Verification:

```sh
bash -n scripts/compare-host-pair-benchmarks.sh \
  scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-harness.sh
git diff --check
```

All focused checks passed. No live nvpn host-pair soak, userspace WireGuard
reference run, Docker perf run, or Mac-to-Mac/screenshare validation was run for
this artifact-helper slice.

## Nostr traversal state in soak evidence - 2026-06-10

Summary:
- FIPS endpoint peer snapshots now expose Nostr traversal failure/cooldown/skew
  state, and nvpn carries it into daemon status plus Docker/host-pair soak
  artifacts.

Result:
- `FipsEndpointPeer` now includes `nostr_traversal_consecutive_failures`,
  `nostr_traversal_in_cooldown`, `nostr_traversal_cooldown_until_ms`, and
  `nostr_traversal_last_observed_skew_ms`, matching the existing
  `show_peers.nostr_traversal` semantics.
- nvpn `MeshPeerStatus`, CLI daemon JSON, and app-core daemon/mobile state carry
  the same fields as `fips_nostr_traversal_*`.
- Docker soak `samples.ndjson` records direct-probe and Nostr traversal state
  for both nodes. Host-pair `samples.ndjson` and `failure.json` record the same
  state for both sides. This is observability only; no traversal cooldown hard
  gate was added in this slice.

Verification:

```sh
cargo fmt --check
cargo test -p fips-core endpoint_peer -- --nocapture
cargo --config 'patch.crates-io.fips-core.path="<fips-safety-worktree>/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="<fips-safety-worktree>/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="<fips-safety-worktree>/crates/fips-identity"' \
  test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture
cargo --config 'patch.crates-io.fips-core.path="<fips-safety-worktree>/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="<fips-safety-worktree>/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="<fips-safety-worktree>/crates/fips-identity"' \
  test -p nvpn fips_runtime_state_counts_direct_roster_and_other_peers \
  --features embedded-fips -- --nocapture
cargo --config 'patch.crates-io.fips-core.path="<fips-safety-worktree>/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="<fips-safety-worktree>/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="<fips-safety-worktree>/crates/fips-identity"' \
  test -p nostr-vpn-app-core mobile_runtime_state -- --nocapture
bash -n scripts/soak-fips-dataplane-docker.sh scripts/soak-fips-dataplane-host-pair.sh \
  scripts/test-host-pair-harness.sh scripts/test-fips-soak-harness.sh
./scripts/test-host-pair-harness.sh
./scripts/test-fips-soak-harness.sh
git diff --check
```

All focused checks passed. The local FIPS patch Cargo runs temporarily rewrote
`Cargo.lock`; the lockfile was restored after verification. No live Docker
soak, host-pair soak, or Mac-to-Mac/screenshare validation was run for this
observability slice.

## Stuck-rekey soak guard - 2026-06-10

Summary:
- Docker and host-pair FIPS soaks now fail when link-layer rekey state stays
  active across too many consecutive samples.

Result:
- `scripts/soak-fips-dataplane-docker.sh` accepts
  `NVPN_SOAK_MAX_CONSECUTIVE_REKEY_SAMPLES` and defaults to `2`.
- `scripts/soak-fips-dataplane-host-pair.sh` accepts
  `NVPN_HOST_PAIR_MAX_CONSECUTIVE_REKEY_SAMPLES` and defaults to `2`.
- A sample with `rekey_in_progress` or `rekey_draining` true increments the
  side's stuck-rekey counter; an inactive sample resets it. The default fails
  on the third consecutive active sample, which turns multi-minute rekey churn
  into a long-run reliability failure while allowing a single sampled transition.
- Docker and host-pair `samples.ndjson` now include the current stuck-rekey
  count; host-pair `failure.json` and `metadata.json` include the threshold.

Verification:

```sh
bash -n scripts/soak-fips-dataplane-docker.sh scripts/soak-fips-dataplane-host-pair.sh \
  scripts/test-fips-soak-harness.sh scripts/test-host-pair-harness.sh
./scripts/test-fips-soak-harness.sh
./scripts/test-host-pair-harness.sh
git diff --check
```

All focused checks passed. No live Docker soak, host-pair soak, or
Mac-to-Mac/screenshare validation was run for this harness-policy slice.

## FIPS rekey state in nvpn soak evidence - 2026-06-10

Summary:
- FIPS endpoint peer snapshots now expose link-layer rekey state, and nvpn
  carries it through daemon status into Docker/host-pair soak samples.

Result:
- `FipsEndpointPeer` now includes `rekey_in_progress`, `rekey_draining`, and
  optional `current_k_bit`; disconnected retry-only peers report no current
  key bit instead of a fake false key state.
- nvpn `MeshPeerStatus` and daemon JSON expose those values as
  `fips_rekey_in_progress`, `fips_rekey_draining`, and `fips_current_k_bit`.
- Docker soak `samples.ndjson`, host-pair `samples.ndjson`, and host-pair
  `failure.json` record the rekey fields beside SRTT, byte counters, CPU, and
  queue-wait evidence. This does not yet fail a run for stuck rekey state; it
  makes the condition observable before adding policy.

Verification:

```sh
cargo fmt --check
cargo test -p fips-core endpoint_peer -- --nocapture
cargo --config 'patch.crates-io.fips-core.path="<fips-safety-worktree>/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="<fips-safety-worktree>/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="<fips-safety-worktree>/crates/fips-identity"' \
  test -p nvpn endpoint_peer --features embedded-fips -- --nocapture
cargo --config 'patch.crates-io.fips-core.path="<fips-safety-worktree>/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="<fips-safety-worktree>/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="<fips-safety-worktree>/crates/fips-identity"' \
  test -p nvpn fips_runtime_state_counts_direct_roster_and_other_peers \
  --features embedded-fips -- --nocapture
cargo --config 'patch.crates-io.fips-core.path="<fips-safety-worktree>/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="<fips-safety-worktree>/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="<fips-safety-worktree>/crates/fips-identity"' \
  test -p nostr-vpn-app-core mobile_runtime_state_marks_authenticated_endpoint_peer_reachable \
  -- --nocapture
bash -n scripts/soak-fips-dataplane-docker.sh scripts/soak-fips-dataplane-host-pair.sh \
  scripts/test-fips-soak-harness.sh scripts/test-host-pair-harness.sh
./scripts/test-fips-soak-harness.sh
./scripts/test-host-pair-harness.sh
git diff --check
```

All focused checks passed. The local FIPS patch Cargo runs temporarily rewrote
`Cargo.lock`; the lockfile was restored after verification. No live Docker
soak, host-pair soak, or Mac-to-Mac/screenshare validation was run for this
observability slice.

## Connected-UDP fd-budget skip observability - 2026-06-10

Summary:
- FIPS now reports connected-UDP fd-budget exhaustion as
  `connected_udp_fd_budget_skipped`, a policy/scale signal separate from
  `connected_udp_activation_failed`.

Result:
- The activation tick checks the fd budget before opening a connected UDP
  socket. When the budget is exhausted, it records one skip count covering the
  current and remaining activation candidates, leaving those peers on wildcard
  UDP without making large-mesh fd policy look like socket activation failure.
- Docker soak artifact parsing now carries the new event in rate, max-rate,
  total, and seen fields. Clean soak hard-event policy still treats
  `connected_udp_activation_failed` as a hard event, while peer-cap/fd-budget
  skips remain observable policy evidence.

Verification:

```sh
cargo fmt --check
cargo test -p fips-core fd_budget -- --nocapture
cargo test -p fips-core connected_udp -- --nocapture
bash -n scripts/soak-fips-dataplane-docker.sh scripts/soak-fips-dataplane-host-pair.sh \
  scripts/test-fips-soak-harness.sh scripts/test-host-pair-harness.sh
./scripts/test-fips-soak-harness.sh
./scripts/test-host-pair-harness.sh
git diff --check
```

All focused checks passed. No live Docker perf, Docker soak, host-pair soak, or
Mac-to-Mac/screenshare validation was run for this observability slice.

## CPU-contention reference harness wiring - 2026-06-10

Summary:
- Added opt-in CPU-stress knobs to the nvpn/FIPS host-pair soak and the
  userspace WireGuard host-pair reference harness so future reliability runs can
  compare nvpn against `wireguard-go` or `boringtun-cli` under the same local
  host/VM CPU pressure.

Result:
- `scripts/soak-fips-dataplane-host-pair.sh` accepts
  `NVPN_HOST_PAIR_CPU_STRESS=1`,
  `NVPN_HOST_PAIR_CPU_STRESS_SIDES=local|remote|both`, and
  `NVPN_HOST_PAIR_CPU_STRESS_WORKERS=auto|N`. The stress starts after the
  already-configured peers and tunnel IPs are resolved, metadata records the
  stress side and worker counts, and the EXIT trap stops stress workers.
- `scripts/bench-userspace-wg-host-pair.sh` accepts matching
  `NVPN_WG_HOST_PAIR_CPU_STRESS*` knobs and records stress state in both
  `summary.tsv` and `metadata.json`.
- `auto` caps each stressed side at four busy workers so occasional reference
  comparisons stay bounded and reproducible enough for operator-local use.
- Follow-up local artifact self-tests now exercise the summary/metadata writers
  directly. They caught and fixed a `jq -n` metadata bug where top-level fields
  such as peer IDs, tunnel IPs, backend, and summary path were emitted as
  `null` while CPU-stress fields were populated.

Verification:

```sh
bash -n scripts/soak-fips-dataplane-host-pair.sh scripts/test-host-pair-harness.sh \
  scripts/bench-userspace-wg-host-pair.sh scripts/test-userspace-wg-host-pair-harness.sh
./scripts/test-host-pair-harness.sh
./scripts/test-userspace-wg-host-pair-harness.sh
git diff --check
```

All checks passed. No live nvpn host-pair soak, userspace WireGuard reference
run, Docker perf run, or real Mac-to-Mac/screenshare validation was run for
this harness wiring.

## Dataplane rewrite gate log - 2026-06-08

Summary:
- On `2026-06-08`, the safety work moved from building the gate to using it for
  guarded ownership-boundary refactors. This entry records the evidence trail:
  fixed tight-pressure rows, a green default local-FIPS matrix, a 30-minute
  Docker soak, subsequent FIPS ownership slices through `103cc36`, the
  `2026-06-09` current-head audit at nvpn `f8381429` plus FIPS `f17ab93`, and
  later ownership/workflow slices through FIPS `12c775a`.
- The validation scope recorded here is Linux/Docker and host/VM-style safety
  evidence. Real Mac-to-Mac Wi-Fi/screenshare soak remains operator-local
  follow-up on actual Macs.

Setup:
- Safety work is split across the nvpn and FIPS `codex/dataplane-safety-net`
  branches.
- Raw commands, artifact paths, and hashes live in
  `docs/baselines/fips-dataplane-2026-06-08-docker.md`.
- Safety scope and commands live in `docs/fips-dataplane-safety-net.md`.
- Architecture direction lives in `docs/fips-dataplane-architecture-plan.md`.

Result:
- The safety net now covers queue pressure/no-wedge behavior, priority lanes,
  TCP-over-tunnel under constrained UDP/backpressure, direct-route sanity, MMP
  stale/bogus metric robustness, Docker soak, host/VM soak evidence, and
  platform-matrix knobs for connected UDP, worker counts, and tight pressure.
- FIPS `ae874b2` fixed IPv4 tunnel-ping classification so IPv4 ICMP now uses
  the priority, non-droppable lane.
- A focused `tight-send-backpressure` matrix row at nvpn `02a1ae2` plus FIPS
  `ae874b2` passed all phases, including the former `rx-maintenance-fault`
  tunnel-ping loss row.
- The full matrix at those heads remained red in a more useful place:
  `tight-send-backpressure` failed clean-underlay forward TCP at `93.3 Mbps`
  against the `100 Mbps` floor, and `tight-backpressure` failed clean-underlay
  forward TCP at `11.7 Mbps`.
- FIPS `24bff11` bounds the non-macOS encrypt-worker fast lane to one per-flow
  burst plus fair budget. The new deterministic guard would have failed on the
  previous three-burst behavior.
- A focused local-FIPS matrix at nvpn `4073298` plus FIPS `24bff11` passed both
  known tight-pressure rows. `tight-send-backpressure` passed all phases with
  clean-underlay forward/reverse TCP at `321.8` / `310.9 Mbps`;
  `tight-backpressure` passed all phases with clean-underlay forward/reverse TCP
  at `136.2` / `116.2 Mbps`. Both rows kept load/post tunnel-ping loss at `0%`
  while queue-full/drop pressure stayed visible.
- The full default local-FIPS matrix at the same heads passed
  `connected-udp-on`, `connected-udp-off`, `single-encrypt-worker`, and
  `tight-send-backpressure`. It remains red on `tight-backpressure` during the
  `rx-maintenance-fault` phase: reverse TCP was `98.9 Mbps` against the
  `100 Mbps` floor. Earlier phases in that row kept tunnel-ping loss at `0%`,
  direct UDP bytes advanced, and expected decrypt queue-full/bulk-drop pressure
  stayed visible.
- A focused `tight-backpressure`/`rx-maintenance-fault` rerun at nvpn
  `81359bf` plus FIPS `24bff11` passed with forward/reverse TCP
  `113.5` / `123.5 Mbps`, `0%` load/post tunnel-ping loss, direct UDP byte
  progress, and expected decrypt queue-full/bulk-drop pressure.
- Three repeated full `tight-backpressure` scenario attempts at the same heads
  then passed all phases. The prior `98.9 Mbps` full-matrix miss now looks
  borderline/intermittent rather than a deterministic wedge.
- The full default local-FIPS matrix rerun at nvpn `81359bf` plus FIPS
  `24bff11` passed all five scenarios: `connected-udp-on`,
  `connected-udp-off`, `single-encrypt-worker`, `tight-send-backpressure`, and
  `tight-backpressure`. The tight combined row stayed green but close enough to
  watch: clean-underlay forward/reverse TCP was `123.7` / `120.2 Mbps`, and
  `rx-maintenance-fault` forward/reverse load TCP was `121.0` /
  `133.5 Mbps`, with `0%` load/post tunnel-ping loss.
- The current 30-minute Docker soak at nvpn `a9bfbcd` plus FIPS `24bff11`
  passed `33` samples from `2026-06-08T16:03:13Z` through
  `2026-06-08T16:33:09Z`. The direct Docker underlay path stayed selected,
  tunnel ping loss was `0%` both ways, FIPS SRTT stayed within `1-3 ms`,
  tunnel-ping max stayed below `8 ms`, and hard queue/drop/backpressure events
  stayed absent. Iperf had one Docker-host dip to `448.2 Mbps` forward and then
  recovered without path drift, latency drift, or no-progress counters.
- FIPS `cda112a` introduces `DecryptWorkerShard`, moving the existing
  decrypt-worker session map behind an explicit owner without changing the
  public worker API or moving additional state. The new deterministic guard
  `decrypt_worker_shard_owns_register_and_unregister_state` is in the default
  Linux safety runner. Verification passed: `cargo fmt --check`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  the full `./scripts/test-dataplane-safety-linux-docker.sh`, and a short
  local-FIPS perf smoke against nvpn `85be91d`. The smoke passed all four
  phases with `0%` load/post tunnel-ping loss and direct UDP byte progress.
- FIPS `c33996e` adds an explicit FMP worker-send reservation value owning the
  cloned cipher, reserved counter, and header together. The worker path now
  resolves the UDP worker target before consuming the counter, so fallback
  inline encryption remains the sole counter owner when the worker target is
  unavailable. New guards: `fmp_worker_send_reservation_owns_counter_header_and_cipher`
  and `fmp_worker_target_fallback_consumes_one_inline_counter`. Verification
  passed: `cargo fmt --check`, focused local and Linux-container guards,
  `cargo test -p fips-core decrypt_worker -- --nocapture`, full
  `cargo test -p fips-core`, and a short local-FIPS perf smoke against nvpn
  `de4342ac`. The smoke passed all four phases with `0%` load/post
  tunnel-ping loss, direct UDP byte progress, expected worker-pressure
  queue-full/bulk-drop counters, and clean `rx-maintenance-fault` load TCP
  at `2214.5` / `2231.1 Mbps`.
- FIPS `b02eb10` makes the FMP recv-side open/replay operation explicit on the
  worker-owned session state. `OwnedSessionState::open_fmp_in_place` now owns
  replay check, AEAD open, and replay accept as one operation. New guard:
  `owned_session_state_open_fmp_owns_replay_acceptance`. Verification passed:
  `cargo fmt --check`, local `cargo test -p fips-core decrypt_worker -- --nocapture`,
  full local `cargo test -p fips-core`, the full default Linux deterministic
  runner, and a short local-FIPS perf smoke against nvpn `03f96c48`. The smoke
  passed all four phases with `0%` load/post tunnel-ping loss, direct UDP byte
  progress, expected worker-pressure queue-full/bulk-drop counters, and
  `rx-maintenance-fault` load TCP at `2146.1` / `2147.8 Mbps`.
- FIPS `a93cd50` makes the FSP recv-side open/replay operation explicit on the
  session entry. `SessionEntry::open_fsp_established_frame` now owns live-epoch
  selection plus replay check, AEAD open, and replay accept for the
  current/pending/previous FSP epochs. New guard:
  `open_fsp_established_frame_failed_all_epochs_does_not_consume_replay`.
  Verification passed: `cargo fmt --check`, focused local epoch tests, full
  local `cargo test -p fips-core`, focused and full default Linux deterministic
  runner, and a short local-FIPS perf smoke against nvpn `201d3c97`. The smoke
  passed all four phases with `0%` load/post tunnel-ping loss, direct UDP byte
  progress, expected worker-pressure queue-full/bulk-drop counters, and
  `rx-maintenance-fault` load TCP at `2158.2` / `2262.7 Mbps`.
- FIPS `4fa502b` makes the FSP worker-send reservation explicit on the
  established endpoint-data path. `SessionEntry::reserve_fsp_worker_send` now
  owns the cloned cipher, reserved FSP counter, and FSP header together before
  the worker seals the packet. New guard:
  `reserve_fsp_worker_send_owns_counter_header_and_cipher`. Verification
  passed: `cargo fmt --check`, focused local send/recv counter guards, full
  local `cargo test -p fips-core`, focused and full default Linux deterministic
  runner, and a short local-FIPS perf smoke against nvpn `f330cfe9`. The smoke
  passed all four phases with `0%` load/post tunnel-ping loss, direct UDP byte
  progress, expected worker-pressure queue-full/bulk-drop counters, and
  `rx-maintenance-fault` load TCP at `2275.4` / `2219.7 Mbps`.
- FIPS `c4c3895` makes the selected send target explicit on `FmpSendJob`.
  `SelectedSendTarget` carries the UDP socket, optional connected socket,
  destination sockaddr, and computed target key through worker dispatch, fair
  admission, macOS ordered flow lookup, and flush grouping. New guard:
  `selected_send_target_key_drives_dispatch_and_admission`. Verification
  passed: `cargo fmt --check`, local unix FSP preseal coverage, focused Linux
  send-target/fair-admission/dispatch/batch-routing guards, full local
  `cargo test -p fips-core`, the full default Linux deterministic runner, and
  a short local-FIPS perf smoke against nvpn `dd866d34`. The smoke passed all
  four phases with `0%` load/post tunnel-ping loss, direct UDP byte progress,
  expected worker-pressure queue-full/bulk-drop counters, and
  `rx-maintenance-fault` load TCP at `2169.1` / `1870.2 Mbps`.
- FIPS `480b549` makes selected send-batch ownership explicit. The Unix batch
  grouping helper now owns one selected target, FIFO wire-packet list, and
  aggregate drop-on-backpressure policy per target key; if any packet in a
  target batch is non-droppable, the whole batch retries instead of silently
  switching to bulk-drop behavior. New guard:
  `selected_send_batch_owns_target_fifo_and_drop_policy`. Verification passed:
  `cargo fmt --check`, focused local send-path guards, focused Linux-container
  send-target/batch/send-backpressure guards, full local
  `cargo test -p fips-core`, the full default Linux deterministic runner, and a
  short local-FIPS Docker perf smoke against nvpn `e4e86055`. The smoke passed
  all four phases with `0%` load/post tunnel-ping loss, direct UDP byte
  progress, expected worker-pressure queue-full/bulk-drop counters, and
  `rx-maintenance-fault` load TCP at `2198.6` / `1367.0 Mbps`.
- FIPS `3bb9d64` makes Linux send-batch attempts explicit. The Linux send path
  now moves a selected batch into one owner for the selected target, remaining
  packet cursor, send backpressure pacer, and current-packet bulk-drop
  decision. New guard:
  `linux_send_batch_attempt_owns_cursor_and_backpressure_policy`.
  Verification passed: `cargo fmt --check`, focused local send-path guards,
  focused Linux-container send-attempt/target/batch/backpressure guards, full
  local `cargo test -p fips-core`, the full default Linux deterministic runner,
  and a short local-FIPS Docker perf smoke against nvpn `7d29592f`. The smoke
  passed all four phases with `0%` load/post tunnel-ping loss, direct UDP byte
  progress, expected worker-pressure queue-full/bulk-drop counters, and
  `rx-maintenance-fault` load TCP at `2257.4` / `2028.0 Mbps`.
- FIPS `40ce258` makes non-Linux direct-send attempts explicit. The
  macOS/BSD direct sender now moves a selected batch into one owner for the
  selected target, remaining packet cursor, send backpressure pacer, and
  current-packet bulk-drop decision. New guard:
  `direct_send_batch_attempt_owns_cursor_and_backpressure_policy`.
  Verification passed: `cargo fmt --check`, focused local direct-send and
  backpressure guards, full local `mac_queue_tests`, focused Linux-container
  send-path guards, full local `cargo test -p fips-core`, release check, and a
  short local-FIPS Docker no-regression smoke against nvpn `589a8cf6`. The
  Docker smoke passed all four phases with `0%` load/post tunnel-ping loss,
  direct UDP byte progress, and expected
  worker-pressure queue-full/bulk-drop counters. That Docker smoke does not
  exercise the non-Linux direct sender; real Mac-to-Mac Wi-Fi/screenshare soak
  remains operator-local.
- FIPS `cb3640d` makes fair admission reservations explicit on the non-macOS
  encrypt-worker path. The reservation token owns the selected send target key
  from admission through enqueue/drain, and release consumes that token instead
  of recomputing flow identity later. New guard:
  `fair_admission_reservation_owns_release_key`. Verification passed:
  `cargo fmt --check`, focused Linux-container reservation/target/priority
  guards, full local `cargo test -p fips-core`, `cargo check -p fips-core
  --release`, the full default Linux deterministic runner, and a short
  local-FIPS Docker smoke against nvpn `1ad2ab8e`. The smoke passed all four
  phases with `0%` load/post tunnel-ping loss, direct UDP byte progress, and
  expected worker-pressure queue-full/bulk-drop counters.
- FIPS `7fad0e4` introduces `EncryptWorkerShard`, making the encrypt worker's
  local batch drain/flush-error cleanup an explicit owner behind the existing
  worker API. New guard:
  `encrypt_worker_shard_owns_batch_drain_and_flush_error`. Verification
  passed: `cargo fmt --check`, focused local shard and macOS queue coverage,
  focused Linux-container shard/dispatch/batch/send-attempt guards, full local
  `cargo test -p fips-core`, `cargo check -p fips-core --release`, the full
  default Linux deterministic runner, and a short local-FIPS Docker smoke
  against nvpn `aa84aa32`. The smoke passed all four phases with `0%`
  load/post tunnel-ping loss, direct UDP byte progress, expected
  worker-pressure queue-full/bulk-drop counters, and `rx-maintenance-fault`
  load TCP at `2230.3` / `2245.7 Mbps`.
- FIPS `7a9b3de5` makes the seal-to-send packet boundary explicit inside the
  encrypt worker. `SealedSendPacket` owns the selected send target, final
  sealed wire packet, and drop-on-backpressure policy after optional FSP seal
  plus outer FMP seal, before macOS completions or Unix send batching consume
  it. New guard: `sealed_send_packet_owns_target_wire_and_drop_policy`.
  Verification passed: `cargo fmt --check`, focused local sealed-packet and
  shard guards, focused Linux-container send-path guards, local
  `mac_queue_tests`, full local `cargo test -p fips-core`, `cargo check -p
  fips-core --release`, the full default Linux deterministic runner, and a
  short local-FIPS Docker smoke against nvpn `e93b94d9`. The smoke passed all
  four phases with `0%` load/post tunnel-ping loss, direct UDP byte progress,
  expected worker-pressure queue-full/bulk-drop counters, and
  `rx-maintenance-fault` load TCP at `2219.4` / `2336.5 Mbps`.
- FIPS `8792215a` makes the queued encrypt-worker message boundary explicit.
  `QueuedFmpSendJob` now snapshots the selected target key and priority/bulk
  lane when it is constructed, so dispatch hashing, fair admission, queue
  selection, and worker drain consume one message-owned routing/admission
  identity instead of deriving it later from mutable job fields. New guard:
  `queued_fmp_send_job_owns_lane_and_target_key`. Verification passed:
  `cargo fmt --check`, focused local queued-message/sealed-packet/shard guards,
  focused Linux-container send-path/admission/no-wedge guards, local
  `mac_queue_tests`, full local `cargo test -p fips-core`, `cargo check -p
  fips-core --release`, the full default Linux deterministic runner, and a
  short local-FIPS Docker smoke against nvpn `61d4ad10`. The smoke passed all
  four phases with `0%` load/post tunnel-ping loss, direct UDP byte progress,
  expected worker-pressure queue-full/bulk-drop counters, and
  `rx-maintenance-fault` load TCP at `1866.4` / `1803.8 Mbps`.
- FIPS `e2254b8` carries the queued send-target key through the seal-to-batch
  boundary. `SealedSendPacket` now owns the queued target key alongside the
  selected target, final wire packet, and drop policy, and `SelectedSendBatch`
  groups using that handed-off key instead of deriving it again. New guard:
  `queued_target_key_survives_seal_and_batch_grouping`, included in the default
  Linux deterministic runner. Verification passed: `cargo fmt --check`,
  focused local queued-key/sealed-packet guards, local `mac_queue_tests`, full
  local `cargo test -p fips-core` before the helper cleanup, `cargo check -p
  fips-core --release`, and a focused Linux-container rerun for queued-key,
  sealed-packet, selected-batch, Linux send-attempt, and fair-dispatch guards
  after the cleanup. No new nvpn perf smoke was run because this is a pure
  ownership handoff with no intended queue, routing, or send-policy change.
- FIPS `758f3bb` adds `scripts/test-dataplane-ownership-fast.sh`, a reusable
  fast tier for pure ownership/type-boundary changes. The default run passed:
  `cargo fmt --check`, focused local ownership guards, local `mac_queue_tests`,
  `cargo check -p fips-core --release`, and the focused Linux Docker ownership
  slice. This is workflow evidence, not a dataplane performance claim.
- FIPS `95bc769` makes queued send scheduling weight ownership explicit.
  `QueuedFmpSendJob` now snapshots the clamped non-macOS fair-admission weight
  at construction time, so fair admission does not derive it later from the
  wrapped send job. New guard:
  `queued_fmp_send_job_owns_clamped_scheduling_weight`, included in the default
  Linux deterministic runner and the fast ownership tier. Verification passed:
  `bash -n` for the safety scripts and the default
  `scripts/test-dataplane-ownership-fast.sh` run. No nvpn perf smoke was run
  because queue, route, and send policy were unchanged.
- FIPS `fa80ef4` makes queued decrypt-job lane ownership explicit.
  `DecryptJob` now snapshots the priority/bulk lane when rx loop builds the
  worker message, and dispatch consumes that queued value instead of deriving it
  later from packet bytes. New guard:
  `decrypt_job_owns_lane_selected_at_construction`, included in the default
  Linux deterministic runner and fast ownership tier. Verification passed:
  focused local guard, `bash -n` for safety scripts, `cargo fmt`, and the
  default `scripts/test-dataplane-ownership-fast.sh` run. No nvpn perf smoke was
  run because queue, route, and send policy were unchanged.
- FIPS `7bdf1e1` makes decrypt fallback event lane ownership explicit.
  `DecryptFallback` now snapshots the priority/bulk lane when the worker creates
  the rx-loop fallback event, and fallback enqueue consumes that queued value.
  New guard: `decrypt_fallback_event_owns_lane_selected_at_construction`,
  included in the default Linux deterministic runner and fast ownership tier.
  Verification passed: focused local guard, `bash -n` for safety scripts,
  `cargo fmt --check`, and the default `scripts/test-dataplane-ownership-fast.sh`
  run. No nvpn perf smoke was run because queue, route, and send policy were
  unchanged.
- FIPS `1da4102` makes macOS ordered-sender completion ownership explicit.
  `MacCompletionGroup` now snapshots the selected flow key and consumes itself
  when handing FIFO completion items to the owning send flow. New local macOS
  guard: `mac_completion_group_owns_flow_key_and_fifo_items`, included in the
  local side of the fast ownership tier. Verification passed: focused local
  guard, `bash -n` for safety scripts, `cargo fmt`, and the default
  `scripts/test-dataplane-ownership-fast.sh` run. This is macOS unit/logic
  coverage only; no real Mac-to-Mac Wi-Fi/screenshare validation was claimed.
- nvpn `c4ecdace` strengthens the host/VM soak harness self-test for route/path
  sanity. `scripts/test-host-pair-harness.sh` now directly pins
  `assert_peer_path`: the expected direct underlay IP passes, a different
  transport address fails unless `ALLOW_NON_DIRECT=1`, and an unreachable peer
  fails. Verification passed: `bash -n` for the host-pair scripts and
  `./scripts/test-host-pair-harness.sh`. This is source-safe harness coverage,
  not a live host/VM soak run.
- FIPS `f908f32` starts the rewrite phase with a small rx-loop ownership slice,
  not a broad dataplane replacement. `PriorityBulkDrainCursor` now owns the
  selected priority/bulk head item plus remaining drain budget for endpoint
  commands and decrypt-worker fallback events. New guard:
  `priority_bulk_drain_cursor_owns_selected_head_and_budget`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed:
  focused endpoint/fallback/cursor guards, `bash -n` for safety scripts,
  `cargo fmt --check`, `git diff --check`, and the filtered fast ownership tier
  for the new guard. This is code simplification and ownership-boundary
  evidence; no throughput improvement is claimed yet.
- A focused Docker perf smoke for FIPS `f908f32` with local-FIPS patching passed
  the two phases most tied to rx-loop drain progress:
  `worker-queue-pressure` and `rx-maintenance-fault`. Artifact:
  `artifacts/fips-perf/f908f32-rx-loop-drain-cursor-smoke/phase-summary.tsv`.
  `worker-queue-pressure` stayed recoverable with forward/reverse TCP
  `214.5/201.4 Mbps`, concurrent forward/reverse load `216.8/233.1 Mbps`, `0%`
  ping loss during both load directions, post-load ping p99 `13.3 ms`, and
  direct underlay byte deltas on both nodes. The phase observed expected
  decrypt-worker queue-full/bulk-drop counters under synthetic pressure.
  `rx-maintenance-fault` stayed well above the floor with forward/reverse TCP
  `2122.1/1998.5 Mbps`, concurrent forward/reverse load `1984.9/2092.5 Mbps`,
  `0%` ping loss, during-load ping p99 `7.46/4.04 ms`, post-load p99 `3.24 ms`,
  and direct underlay byte deltas on both nodes. This clears the next small
  ownership slice for Linux/Docker scope; it is not real Mac-to-Mac validation.
- FIPS `853a2fe` carries the same measured rewrite approach into the raw packet
  receiver-drain boundary. `PacketDrainCursor` now owns the selected first
  packet, remaining bounded packet budget, and fallback interleave point before
  `drain_packet_rx` calls packet processing or fallback drain. New guard:
  `packet_drain_cursor_owns_first_packet_budget_and_interleave`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed:
  focused packet/priority/fallback cursor guards, `bash -n` for safety scripts,
  `cargo fmt --check`, `git diff --check`, leak scan, and the filtered fast
  ownership tier for the new guard.
- A focused Docker perf smoke for FIPS `853a2fe` with local-FIPS patching passed
  `worker-queue-pressure` and `rx-maintenance-fault`. Artifact:
  `artifacts/fips-perf/853a2fe-packet-drain-cursor-smoke/phase-summary.tsv`.
  `worker-queue-pressure` stayed recoverable with forward/reverse TCP
  `216.3/201.4 Mbps`, concurrent forward/reverse load `213.1/221.7 Mbps`, `0%`
  ping loss during both load directions, post-load ping p99 `5.21 ms`, and
  direct underlay byte deltas on both nodes. The phase observed expected
  decrypt-worker queue-full/bulk-drop counters under synthetic pressure.
  `rx-maintenance-fault` stayed above the floor with forward/reverse TCP
  `2104.6/2191.8 Mbps`, concurrent forward/reverse load `1970.1/2125.3 Mbps`,
  `0%` ping loss, during-load ping p99 `17.2/32.7 ms`, post-load p99 `2.93 ms`,
  and direct underlay byte deltas on both nodes. This clears the next small
  ownership slice for Linux/Docker scope; it is not real Mac-to-Mac validation.
- FIPS `4d321ed` applies the same owned-drain shape to the TUN outbound boundary.
  `TunOutboundDrainCursor` owns the selected first TUN packet and remaining
  bounded packet budget before `drain_tun_outbound` hands packets to endpoint
  send. New guard: `tun_outbound_drain_cursor_owns_first_packet_and_budget`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: focused TUN/packet/priority cursor guards, `bash -n` for
  safety scripts, `cargo fmt --check`, `git diff --check`, leak scan, and the
  filtered fast ownership tier for the new guard.
- A focused Docker perf smoke for FIPS `4d321ed` with local-FIPS patching passed
  `worker-queue-pressure` and `rx-maintenance-fault`. Artifact:
  `artifacts/fips-perf/4d321ed-tun-outbound-drain-cursor-smoke/phase-summary.tsv`.
  `worker-queue-pressure` stayed recoverable with forward/reverse TCP
  `31.4/88.5 Mbps`, concurrent forward/reverse load `116.0/94.7 Mbps`, `0%`
  ping loss during both load directions, post-load ping p99 `1.93 ms`, and
  direct underlay byte deltas on both nodes. The phase observed expected
  decrypt-worker queue-full/bulk-drop counters under synthetic pressure.
  `rx-maintenance-fault` stayed above the floor with forward/reverse TCP
  `1527.4/2023.8 Mbps`, concurrent forward/reverse load `2096.8/1843.5 Mbps`,
  `0%` ping loss, during-load ping p99 `4.03/4.69 ms`, post-load p99
  `5.09 ms`, and direct underlay byte deltas on both nodes. This clears the
  next small ownership slice for Linux/Docker scope; it is not real Mac-to-Mac
  validation.
- FIPS `e637420` makes the rx-loop data-drain result explicit. The maintenance
  tick now receives one `RxLoopDataDrainStats` value owning packet, TUN, and
  endpoint drain counts, total drained work, and the data-pressure decision used
  to bound slow maintenance. New guard:
  `rx_loop_data_drain_stats_owns_counts_total_and_pressure`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed:
  focused stats/packet/priority/TUN cursor guards, `bash -n` for safety scripts,
  `cargo fmt --check`, `git diff --check`, leak scan, and the filtered fast
  ownership tier for the new guard.
- A focused Docker perf smoke for FIPS `e637420` with local-FIPS patching first
  produced useful red evidence in `rx-maintenance-fault`: forward-load tunnel
  ping p99 hit `252 ms` against the `80 ms` ceiling while TCP still held
  `1912.3/1885.5 Mbps`, the forward probe held `1611.6 Mbps`, ping loss stayed
  `0%`, and direct underlay bytes advanced on both nodes. Artifact:
  `artifacts/fips-perf/e637420-rx-loop-data-drain-stats-smoke/failure-summary.tsv`.
  An immediate rerun passed `worker-queue-pressure` and `rx-maintenance-fault`.
  Rerun artifact:
  `artifacts/fips-perf/e637420-rx-loop-data-drain-stats-smoke-rerun/phase-summary.tsv`.
  `worker-queue-pressure` stayed recoverable with forward/reverse TCP
  `172.1/197.2 Mbps`, concurrent forward/reverse load `191.6/186.3 Mbps`, `0%`
  ping loss during both load directions, post-load ping p99 `5.37 ms`, and
  direct underlay byte deltas on both nodes. `rx-maintenance-fault` stayed above
  the floor on rerun with forward/reverse TCP `1908.4/1857.9 Mbps`, concurrent
  forward/reverse load `1928.7/1863.2 Mbps`, `0%` ping loss, during-load ping
  p99 `6.14/10.8 ms`, post-load p99 `3.78 ms`, and direct underlay byte deltas
  on both nodes. Treat the first red row as an intermittent maintenance-tail
  watch item, not a deterministic regression; this is still Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `8a23f25` makes the rx-loop maintenance state explicit. The loop now
  stores recent data activity and the sticky slow-maintenance timeout flag in
  `RxLoopMaintenanceState`, and maintenance consumes that owner for the
  data-pressure and skip-slow decisions. New guard:
  `rx_loop_maintenance_state_owns_activity_window_and_timeout_skip`, included
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: focused maintenance-state/stats/packet/TUN cursor guards, `bash -n`
  for safety scripts, `cargo fmt --check`, `git diff --check`, leak scan, and
  the filtered fast ownership tier for the new guard.
- A focused Docker perf smoke for FIPS `8a23f25` with local-FIPS patching passed
  `worker-queue-pressure` and `rx-maintenance-fault`. Artifact:
  `artifacts/fips-perf/8a23f25-rx-loop-maintenance-state-smoke/phase-summary.tsv`.
  `worker-queue-pressure` stayed recoverable with forward/reverse TCP
  `228.2/220.5 Mbps`, concurrent forward/reverse load `217.3/226.6 Mbps`, `0%`
  ping loss during both load directions, post-load ping p99 `1.85 ms`, and
  direct underlay byte deltas on both nodes. The phase observed expected
  decrypt-worker queue-full/bulk-drop counters under synthetic pressure.
  `rx-maintenance-fault` stayed above the floor with forward/reverse TCP
  `2150.9/2111.1 Mbps`, concurrent forward/reverse load `2206.1/2183.2 Mbps`,
  `0%` ping loss, during-load ping p99 `2.98/3.68 ms`, post-load p99
  `2.67 ms`, and direct underlay byte deltas on both nodes. This keeps the
  intermittent maintenance-tail row as a watch item, but this slice did not
  reproduce it. This is Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `cb953f0` makes the rx-loop maintenance plan explicit. The loop now
  builds one `RxLoopMaintenancePlan` from owned drain stats, recent activity,
  and sticky timeout state, then the maintenance tick consumes that plan for
  data-pressure logging, slow-maintenance skipping, and idle/busy timeout
  selection. New guard:
  `rx_loop_maintenance_plan_owns_pressure_skip_and_timeout_budget`, included in
  the fast ownership tier and Linux Docker safety runner. Verification passed:
  focused local guard, `bash -n` for safety scripts, `cargo fmt --check`,
  `git diff --check`, leak scan, and the filtered fast ownership tier for the
  new guard through local test, release compile, and Linux Docker. No perf
  smoke was run for this ownership-only slice because no queue, route, timeout,
  or send-policy threshold changed.
- FIPS `f17ab93` gates full-mode session-layer MMP route changes on valid
  route-quality evidence. A fresh accepted loss/goodput delta with invalid RTT
  still updates the session metrics, but it no longer marks the direct session
  path degraded, schedules a direct reprobe, starts fallback discovery, or moves
  payload routing to a learned fallback. The existing valid-loss route-change
  test now proves full-mode degradation has a valid RTT sample. New guard:
  `test_fresh_bogus_session_metrics_without_valid_rtt_do_not_change_route_choice`,
  included in the Linux Docker safety runner. Verification passed: focused
  local new/valid-loss/stale-session tests, focused Linux Docker new/valid-loss
  and stale-session tests, `cargo check -p fips-core --release`, `bash -n`,
  `cargo fmt --check`, `git diff --check`, and leak scan. No perf smoke was run
  because this is deterministic route/MMP policy coverage, not a throughput or
  queue-threshold change.
- FIPS `470becb` makes outbound endpoint commands own the priority/bulk lane
  selected from the original payload at construction. `FipsEndpoint::send` and
  `blocking_send` now build the queued command first, then choose the command
  channel from the command-owned lane instead of reclassifying raw payload bytes
  at dispatch. New guard:
  `endpoint_command_owns_lane_selected_at_construction`, included in the fast
  ownership tier and Linux Docker safety runner. Verification passed: the guard
  failed first against the old shape, then passed locally and in Linux Docker;
  the full default `./scripts/test-dataplane-ownership-fast.sh` tier passed;
  `bash -n`, `cargo fmt --check`, `git diff --check`, and leak scan passed. No
  perf smoke was run because this is an ownership-only message-boundary slice,
  not a queue, route, timeout, or send-policy threshold change.
- FIPS `4a3d2d8` makes the outbound endpoint send message explicit.
  `EndpointSendCommand` now owns the remote peer, payload, priority/bulk lane,
  and queue timestamp shared by `Send` and `SendOneway`; the rx-loop command
  handler consumes that one owner through a shared send path instead of
  duplicating the fields and perf accounting in each enum arm. New guard:
  `endpoint_send_command_owns_payload_lane_and_queue_stamp`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed: the
  guard failed first against the old shape, then passed locally and in Linux
  Docker; the full default `./scripts/test-dataplane-ownership-fast.sh` tier
  passed; `bash -n`, `cargo fmt --check`, `git diff --check`, and leak scan
  passed. No perf smoke was run because this is an ownership-only
  message-boundary slice, not a queue, route, timeout, or send-policy threshold
  change.
- FIPS `129543f` makes endpoint payload policy explicit. `EndpointDataPayload`
  now owns the payload bytes plus the priority/bulk lane and
  drop-on-backpressure policy selected at app ingress; `EndpointSendCommand`,
  pending endpoint queues, and the pipelined send path consume that one owner
  instead of reclassifying raw payload bytes later. New guard:
  `endpoint_data_payload_owns_drop_policy_selected_at_construction`, included
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: the guard failed first because the owner did not exist, then passed
  locally and in Linux Docker; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed on the final tree;
  `bash -n`, `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/type-boundary slice, not a queue, route, timeout, or
  send-policy threshold change.
- FIPS `36b365b` makes endpoint data send ownership explicit. `EndpointDataSend`
  now owns the destination node address, destination public key, and classified
  endpoint payload policy; `EndpointSendCommand` carries that owner, and the
  rx-loop send-or-queue path consumes it when registering identity, sending
  immediately, or queueing for session recovery. New guard:
  `endpoint_data_send_owns_remote_identity_and_payload_policy`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed: the
  guard failed first because the owner did not exist, then passed locally and in
  Linux Docker; the full default `./scripts/test-dataplane-ownership-fast.sh`
  tier passed; `bash -n`, `cargo fmt --check`,
  `cargo check -p fips-core --release`, `git diff --check`, and leak scan
  passed. No perf smoke was run because this is an ownership/type-boundary
  slice, not a queue, route, timeout, or send-policy threshold change.
- FIPS `662f0dc` makes the pending endpoint data queue explicit.
  `PendingEndpointDataQueue` now owns the per-destination endpoint payload
  backlog and its bounded drop-oldest admission result; the node still owns the
  destination map and existing configured caps, but consumes the queue admission
  result instead of open-coding the `VecDeque` drop policy. New guard:
  `pending_endpoint_data_queue_owns_drop_oldest_policy`, included in the fast
  ownership tier and Linux Docker safety runner. Verification passed: the guard
  failed first because the owner did not exist, then passed locally and in Linux
  Docker; the full default `./scripts/test-dataplane-ownership-fast.sh` tier
  passed; `bash -n`, `cargo fmt --check`,
  `cargo check -p fips-core --release`, `git diff --check`, and leak scan
  passed. No perf smoke was run because this is an ownership/type-boundary
  slice, not a queue, route, timeout, or send-policy threshold change.
- FIPS `95ace56` makes the pending TUN packet queue explicit.
  `PendingTunPacketQueue` now owns the per-destination TUN packet backlog and
  its bounded drop-oldest admission result; the node still owns the destination
  map and existing configured caps, but consumes the queue admission result
  instead of open-coding the `VecDeque` drop policy. New guard:
  `pending_tun_packet_queue_owns_drop_oldest_policy`, included in the fast
  ownership tier and Linux Docker safety runner. Verification passed: the guard
  failed first because the owner did not exist, then passed locally and in Linux
  Docker; the full default `./scripts/test-dataplane-ownership-fast.sh` tier
  passed; `bash -n`, `cargo fmt --check`,
  `cargo check -p fips-core --release`, `git diff --check`, and leak scan
  passed. No perf smoke was run because this is an ownership/type-boundary
  slice, not a queue, route, timeout, or send-policy threshold change.
- FIPS `a2371b6` makes the combined pending session traffic queues explicit.
  `PendingSessionTrafficQueues` now owns the TUN and endpoint backlog maps,
  destination-cap admission, per-destination bounded enqueue delegation, and
  destination cleanup; the node still consumes the same configured caps and
  records the same perf counters, but callers no longer mutate the two maps
  directly. New guard:
  `pending_session_traffic_queues_own_destination_admission`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed: the
  guard failed first because the owner did not exist, then passed locally and in
  Linux Docker; focused pending-session, discovery-timeout, and direct-link
  teardown tests passed; the full default `./scripts/test-dataplane-ownership-fast.sh`
  tier passed; `bash -n`, `cargo fmt --check`,
  `cargo check -p fips-core --release`, `git diff --check`, and leak scan
  passed. No perf smoke was run because this is an ownership/type-boundary
  slice, not a queue, route, timeout, or send-policy threshold change.
- FIPS `6a0c304` makes pending discovery lookup admission explicit.
  `PendingDiscoveryLookups` now owns in-flight lookup dedupe and queue-full
  admission before route-repair lookups start; existing backoff, bloom
  reachability, retry, and timeout behavior stays in place, but callers no
  longer open-code the pending lookup map's admission rules. New guard:
  `pending_discovery_lookup_queue_owns_dedup_and_capacity`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed: the
  guard failed first because the owner did not exist, then passed locally and in
  Linux Docker; focused pending-lookup timeout and queued-TUN route-repair tests
  passed; the full default `./scripts/test-dataplane-ownership-fast.sh` tier
  passed; `bash -n`, `cargo fmt --check`,
  `cargo check -p fips-core --release`, `git diff --check`, and leak scan
  passed. No perf smoke was run because this is an ownership/type-boundary
  slice, not a route-choice, timeout, queue capacity, or send-policy threshold
  change.
- FIPS `1a7c444` makes reverse-path discovery request caching explicit.
  `RecentDiscoveryRequests` now owns request-id dedupe, cache capacity, expiry,
  reverse-hop retention, and one-shot response-forward claims for
  `LookupResponse` routing; lookup request/response handlers keep the same
  stats, MTU folding, proof verification, and route caching behavior, but no
  longer open-code the recent-request map's admission or forwarded-response
  state. New guard:
  `recent_discovery_requests_own_reverse_path_dedup_capacity_and_expiry`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the owner did not exist,
  then passed locally and in Linux Docker; focused request/response discovery
  and recent-request expiry tests passed; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed; `bash -n`,
  `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/type-boundary slice, not a route-choice, timeout, queue
  capacity, or send-policy threshold change.
- FIPS `73e2315` makes pending route retry scheduling explicit.
  `PendingRouteRetries` now owns the retry-entry map, expired-entry removal,
  deterministic due ordering, reconnect retry budget, and active direct-path
  refresh budget; `process_pending_retries` keeps the same reconnect, direct
  refresh, advert-stale, and local-route retry behavior, but no longer
  open-codes expired-entry removal or due-set sorting/budgeting in the
  maintenance tick. New guard:
  `pending_route_retries_own_expiry_due_order_and_budgets`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed: the
  guard failed first because the owner did not exist, then passed locally and
  in Linux Docker; focused `retry`, `process_pending_retries`, `link_dead`, and
  `open_discovery` tests passed; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed; `bash -n`,
  `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/type-boundary slice, not a route-choice, timeout, queue
  capacity, or send-policy threshold change.
- FIPS `0cd30aa` makes local send failure liveness signals explicit.
  `LocalSendFailures` now owns the per-peer local-route-failure timestamps,
  peer-scoped fast-dead timeout selection, success clearing, non-local error
  ignoring, and stale-signal expiry. `note_local_send_outcome`,
  `local_send_failure_dead_timeout_for_peer`, and
  `purge_expired_local_send_failures` keep the same public behavior, but no
  longer mutate or query a raw `HashMap` directly. New guard:
  `local_send_failures_own_peer_scoped_fast_dead_clear_and_expiry`, included in
  the fast ownership tier and Linux Docker safety runner. Verification passed:
  the guard failed first because the owner did not exist, then passed locally
  and in Linux Docker; focused `local_send_failure` and unrelated-peer
  route-failure tests passed; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed; `bash -n`,
  `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/type-boundary slice, not a route-choice, timeout, queue
  capacity, or send-policy threshold change.
- FIPS `750b81f` makes session direct degradation state explicit.
  `SessionDirectDegradation` owns the per-destination degraded-until map, hold
  extension, expiry cleanup, and clear behavior used by direct payload
  blocking. Existing `Node` helpers keep the same route-degradation semantics,
  but no longer mutate or query a raw `HashMap` directly. New guard:
  `session_direct_degradation_owns_hold_extension_expiry_and_clear`, included
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: the guard failed first because the owner did not exist, then passed
  locally and in Linux Docker; focused `session_direct`, fresh-bogus session
  metrics, and session receiver-loss fallback tests passed; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed; `bash -n`,
  `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/type-boundary slice, not a route-choice, timeout, queue
  capacity, or send-policy threshold change.
- FIPS `24f2c5b` makes discovery fallback-transit eligibility explicit.
  `DiscoveryFallbackTransit` owns the peer block/unblock set plus the
  direct-target exception and bootstrap-transport exclusion used by
  reply-learned lookup fanout. Existing `Node` helpers keep the same configured
  policy and promotion behavior, but the discovery handler no longer open-codes
  fallback peer eligibility or queries a raw blocked-peer `HashSet` directly.
  New guard:
  `discovery_fallback_transit_owns_target_exception_block_and_bootstrap_policy`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the owner did not exist,
  then passed locally and in Linux Docker; focused open-discovery promotion and
  disabled-transit origin/forward fanout tests passed; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed; `bash -n`,
  `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/type-boundary slice, not a route-choice, timeout, queue
  capacity, or send-policy threshold change.
- FIPS `0f3de2b` makes learned-route fallback exploration pacing explicit.
  `LearnedRouteFallbackExploration` owns the selected-count interval gate,
  duplicate suppression, disabled-interval behavior, and cleanup when learned
  routes expire. `LearnedRouteTable` keeps the same route selection and
  exploration semantics, but no longer owns or mutates a raw last-explored map
  directly. New guard:
  `learned_route_fallback_exploration_owns_interval_dedup_and_expiry`, included
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: the guard failed first because the owner did not exist, then passed
  locally and in Linux Docker; focused `learned_routes` and reply-learned
  coordinate-exploration tests passed; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed; `bash -n`,
  `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/type-boundary slice, not a route-choice, timeout, queue
  capacity, or send-policy threshold change.
- FIPS `440cafe` makes bootstrap transport bookkeeping explicit.
  `BootstrapTransports` owns adopted bootstrap transport-id membership plus the
  originating peer npub used for protocol-mismatch cooldown. Adoption registers
  both together, cleanup removes both together, and callers no longer mutate a
  raw bootstrap transport `HashSet` plus npub `HashMap` separately. New guard:
  `bootstrap_transports_own_membership_peer_npub_and_cleanup`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed: the
  guard failed first because the owner did not exist, then passed locally and
  in Linux Docker; focused `bootstrap` tests passed, covering adopted traversal
  cleanup, primary-path racing, protocol-mismatch cooldown filtering, and
  bootstrap-transit discovery fanout; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed; `bash -n`,
  `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/type-boundary slice, not a route-choice, timeout, queue
  capacity, or send-policy threshold change.
- FIPS `019d7fe` makes transport kernel-drop tracking explicit.
  `TransportDropTracker` owns per-transport cumulative drop samples,
  rising-edge congestion-event detection, current dropping state, and cleanup.
  `detect_congestion` and `sample_transport_congestion` keep the same behavior,
  but no longer inspect or mutate a raw drop-state map directly. New guard:
  `transport_drop_tracker_owns_rising_edge_state_and_cleanup`, included in the
  fast ownership tier and Linux Docker safety runner. Verification passed: the
  guard failed first because the owner did not exist, then passed locally and
  in Linux Docker; focused forwarding tests passed; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed; `bash -n`,
  `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/observability boundary slice, not a route-choice, timeout,
  queue capacity, or send-policy threshold change.
- FIPS `e634608` makes pending outbound handshake dispatch explicit.
  `PendingOutboundHandshakes` owns msg2 lookup by exact `(transport_id,
  our_index)`, unique cross-transport index fallback for equivalent/adopted UDP
  replies, ambiguity rejection, and cleanup. `handle_msg2` keeps the same
  behavior, but no longer open-codes the fallback scan across a raw
  pending-outbound map. New guard:
  `pending_outbound_handshakes_own_msg2_index_matching_and_cleanup`, included
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: the guard failed first because the owner did not exist, then passed
  locally and in Linux Docker; focused handshake tests and
  `handle_msg2_matches_pending_outbound_by_index_when_reply_transport_id_changes`
  passed; the full default `./scripts/test-dataplane-ownership-fast.sh` tier
  passed on the final tree; `bash -n`, `cargo fmt --check`,
  `cargo check -p fips-core --release`, `git diff --check`, and leak scan
  passed. No perf smoke was run because this is an ownership/dispatch boundary
  slice, not a route-choice, timeout, queue capacity, send-policy threshold, or
  throughput change.
- FIPS `400f7ec` makes active session-index dispatch explicit.
  `SessionIndexRegistry` owns active `(transport_id, our_index) -> NodeAddr`
  receiver-index lookup, stale-owner replacement, remove-return owner, and
  peer-has-other-index membership used by connected-UDP cleanup.
  `handle_encrypted_frame`, current-session registration repair, and
  deregistration keep the same behavior, but no longer inspect or mutate a raw
  receiver-index map directly. New guard:
  `session_index_registry_owns_lookup_replace_remove_and_peer_membership`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the owner did not exist,
  then passed locally and in Linux Docker; focused handshake,
  `decrypt_failure`, and peer-index tracking tests passed; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed on the final tree;
  `bash -n`, `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/dispatch boundary slice, not a route-choice, timeout, queue
  capacity, send-policy threshold, throughput, or Mac sender behavior change.
- FIPS `6f44c93` makes the decrypt-worker registration mirror explicit.
  `DecryptSessionRegistrations` owns the rx-loop mirror of sessions accepted by
  decrypt-worker shards. Rx-loop dispatch now asks that owner whether a session
  is worker-owned, registration only marks a session after `register_session`
  succeeds, and deregistration only asks the worker to evict sessions that were
  locally registered. New guard:
  `decrypt_session_registrations_own_worker_acceptance_and_unregister_gate`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the owner did not exist,
  then passed locally and in Linux Docker; focused promotion, handshake,
  `decrypt_failure`, and session-index tests passed; the full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed on the final tree;
  `bash -n`, `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, and leak scan passed. No perf smoke was run because this
  is an ownership/dispatch boundary slice, not a route-choice, timeout, queue
  capacity, send-policy threshold, throughput, or Mac sender behavior change.
- FIPS `103cc36` makes the identity cache explicit.
  `IdentityCache` owns FipsAddress/NodeAddr prefix derivation, public-key
  validation, rejected-claim preservation, lookup LRU touch, LRU eviction, and
  npub/pubkey views for discovery proof verification and endpoint delivery.
  Node cache helpers keep the same behavior, but no longer inspect or mutate a
  raw prefix map directly. New guard:
  `identity_cache_owns_prefix_validation_lru_touch_and_lookup_views`, included
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: the guard failed first because the owner did not exist, then passed
  locally and in Linux Docker; focused `identity_cache` and `discovery` tests
  passed; the full default `./scripts/test-dataplane-ownership-fast.sh` tier
  passed on the final tree; `bash -n`, `cargo fmt --check`,
  `cargo check -p fips-core --release`, `git diff --check`, and leak scan
  passed. No perf smoke was run because this is an ownership/type-boundary
  slice, not a route-choice, timeout, queue capacity, send-policy threshold,
  throughput, or Mac sender behavior change.
- nvpn `91f41ca1` strengthens the FIPS perf harness artifact trail. When
  `NVPN_PERF_OUTPUT_DIR` is set, `scripts/e2e-fips-perf-regression-docker.sh`
  now writes raw per-step probe files under `<dir>/raw/`: baseline
  forward/reverse iperf JSON, concurrent-load iperf JSON/stderr, concurrent
  ping output, and post-load ping output. This preserves the raw evidence behind
  future p95/p99 tail failures such as the intermittent `e637420`
  maintenance-tail row. Verification passed: `bash -n` for the perf harness and
  self-test scripts, `./scripts/test-fips-perf-harness.sh`, `git diff --check`,
  and public leak scan.
- nvpn adds `scripts/bench-userspace-wg-host-pair.sh`, an environment-driven
  userspace WireGuard host-pair reference harness for BoringTun or wireguard-go.
  It creates a temporary two-peer WG tunnel, records ping both ways, TCP iperf
  forward/reverse, retransmits, `wg show` snapshots, backend CPU, backend logs,
  and a sanitized `summary.tsv` under `artifacts/userspace-wg-host-pair/`.
  This gives the local-to-Linux/VM path a boring userspace-WG comparison row
  without committing hostnames, SSH aliases, underlay IPs, keys, or interface
  choices. Verification passed: `bash -n`,
  `./scripts/test-userspace-wg-host-pair-harness.sh`, `git diff --check`, and
  public leak scan. No live host-pair run was performed from this thread because
  local address/route setup needs operator sudo.
- The userspace-WG host-pair harness now has `NVPN_WG_HOST_PAIR_PREFLIGHT=1`,
  which checks local/remote command availability, remote sudo/TUN readiness,
  underlay env presence, backend availability, and local sudo/root/helper
  readiness without creating keys, interfaces, routes, backend processes, or
  remote temp directories. It writes a sanitized `preflight.tsv` with only
  `ok`/`missing` check names. A non-invasive preflight against the configured
  Linux/VM target found the expected blockers for a live row from this thread:
  underlay IP env was not supplied and local address/route setup still needs
  operator-local privilege setup. Remote SSH, `wg`, `iperf3`, `ip`,
  passwordless sudo, TUN, and the selected backend binary were present.
- The userspace-WG host-pair harness now supports
  `NVPN_WG_HOST_PAIR_LOCAL_PRIV_HELPER` for native host-pair runs where a
  narrow root-owned local helper is preferable to broad passwordless sudo. The
  helper action set is limited to check, configure local interface, `wg set`,
  `wg show`, and cleanup; the private key is passed over stdin for `wg set`.
  Helper availability is recorded by sanitized preflight check names. Privileged
  helper actions reject an untrusted helper path or command binary path unless
  the file and parent directories are root-owned and not group/world-writable.
  The self-test now covers helper validation, trusted-path rejection, and
  fake-helper command wiring. No live host-pair baseline row was produced by
  this change.

Logged decision:
- Move toward the Tailscale/BoringTun-shaped model by using them as references
  for a boring dataplane: narrow owner, bounded work per wake, visible
  backpressure, and non-packet jobs kept off the hot path.
- Count progress by removing a named red target or strengthening a harness that
  would catch a known failure; when there is no current red row, count progress
  by making a named hot-path owner/message boundary explicit while preserving
  the safety evidence.
- Record experiment results here, but keep current readiness and next-step
  guidance in `docs/fips-dataplane-architecture-plan.md`.

Audit follow-up on `2026-06-09`:
- Current nvpn safety branch `f8381429` plus FIPS safety branch `f17ab93` still
  satisfies the source-safe and deterministic safety tiers. Verification passed:
  `bash -n` for perf/soak/platform/host-pair/userspace-WG harness scripts,
  `./scripts/test-fips-perf-harness.sh`,
  `./scripts/test-fips-soak-harness.sh`,
  `./scripts/test-host-pair-harness.sh`,
  `./scripts/test-userspace-wg-host-pair-harness.sh`,
  `./scripts/test-fips-platform-matrix-harness.sh`,
  `cargo test -p nvpn full_tun_to_mesh_queue_drops_bulk_without_waiting`,
  FIPS `./scripts/test-dataplane-ownership-fast.sh`, and the full FIPS
  `./scripts/test-dataplane-safety-linux-docker.sh`.
- A current-head short local-FIPS Docker perf smoke also passed:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH="$FIPS_SAFETY_WORKTREE" \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=/tmp/nvpn-fips-current-smoke-20260609T031737 \
PROJECT_NAME=nostr-vpn-e2e-fips-current-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `ca6e43ba389d158707666dddc39e2416b9a00cdc59f15ba2b70cd92907623487`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay ran at roughly
  `2166/2192 Mbps`, constrained-underlay at `130/128 Mbps`,
  worker-queue-pressure at `127/128 Mbps`, and rx-maintenance-fault at
  `2229/2253 Mbps`. All load and post-load tunnel-ping loss was `0%`, direct
  UDP underlay counters advanced in every phase, and worker pressure exposed the
  expected decrypt queue-full/bulk-drop counters without a wedge.
- This audit was recorded as support for continuing guarded architecture slices.
  It did not claim a one-shot rewrite, a clean local-to-Linux/VM throughput
  baseline, or real Mac-to-Mac Wi-Fi/screenshare validation.

Ownership follow-up on `2026-06-09`:
- FIPS `739c3cd` makes configured peer send weights explicit.
  `ConfiguredPeerSendWeights` owns configured-peer identity parsing, invalid
  identity skipping, the explicit configured-peer scheduling weight, and the
  default fallback weight used for unconfigured peers. Node construction,
  identity-preserving construction, and live peer reload all rebuild the same
  owner; the hot send path delegates lookup to that owner. New guard:
  `configured_peer_send_weights_own_identity_parse_and_default_policy`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the owner did not exist,
  then passed locally and in Linux Docker; `bash -n`, `cargo fmt --check`,
  `cargo check -p fips-core --release`, `git diff --check`, leak scan, and the
  full default `./scripts/test-dataplane-ownership-fast.sh` tier passed. No
  perf smoke was run because this is an ownership/type-boundary slice, not a
  route-choice, timeout, queue capacity, send-weight threshold, throughput, or
  Mac sender behavior change.
- FIPS `5b4249a` makes the link-address reverse lookup explicit and speeds up
  the fast ownership tier. `LinkAddressIndex` owns `(transport_id,
  remote_addr) -> link_id` insertion, replacement, lookup, and stale-safe
  removal. `Node::remove_link` now removes an address entry only when it still
  points to the link being removed, preserving cross-connection winner entries
  against stale loser cleanup. New guard:
  `link_address_index_owns_lookup_replace_and_stale_safe_remove`, included in
  the fast ownership tier and Linux Docker safety runner. The same commit
  batches the default `scripts/test-dataplane-ownership-fast.sh` run through
  `_own` plus the non-matching no-wedge groups, while `--no-batch-defaults`
  keeps exact per-filter replay available. Verification passed: the guard
  failed first because the owner did not exist, then passed locally and in
  Linux Docker; focused `handshake` coverage passed; `bash -n`,
  `cargo fmt --check`, `cargo check -p fips-core --release`, `git diff
  --check`, leak scan, and the accelerated full default fast ownership tier
  passed in about 22 seconds on warm artifacts. No perf smoke was run because
  this is an ownership/dispatch boundary and workflow-speed slice, not a
  route-choice, timeout, queue capacity, send-weight threshold, throughput, or
  Mac sender behavior change.
- FIPS `aa020d0` makes link storage and reverse address dispatch a single
  owner. `LinkRegistry` owns the active `Link` map and the
  `(transport_id, remote_addr) -> link_id` index together, so insertion updates
  both, replacement clears the replaced link's stale address entry, and removal
  only clears address dispatch if it still points to the removed link. This is
  the first larger ownership slice toward a peer/session runtime shape; it
  removes the separate `Node::addr_to_link` field instead of only wrapping a
  helper map. New guard:
  `link_registry_owns_storage_address_index_and_stale_safe_cleanup`, included
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: the guard failed first because the owner did not exist, then passed
  locally; focused `handshake`, `spanning_tree`, and `_own` coverage passed;
  `bash -n`, `cargo fmt --check`, warning-clean `cargo check -p fips-core
  --release`, `git diff --check`, leak scan, and the accelerated full default
  `./scripts/test-dataplane-ownership-fast.sh` tier passed, including the
  Linux Docker ownership slice. No perf smoke was run because this is a
  route/dispatch ownership boundary, not a route-choice, timeout, queue
  capacity, send-weight threshold, throughput, or Mac sender behavior change.
- FIPS `4481951` makes active peer storage and receiver-index dispatch a single
  owner. `ActivePeerRegistry` owns the `NodeAddr -> ActivePeer` map and active
  `(transport_id, our_index) -> NodeAddr` dispatch together, removes the
  separate `Node::peers_by_index` field, and preserves existing peer-map call
  sites through a small compatibility API. New guard:
  `active_peer_registry_owns_storage_session_index_and_stale_safe_cleanup`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the owner did not exist,
  then passed locally; focused `handshake`, `rekey`, `decrypt_failure`, and
  ownership coverage passed; `cargo fmt --check`, `cargo check -p fips-core
  --release`, `git diff --check`, leak scan, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier passed, including Linux
  Docker. No perf smoke was run because this is peer/session dispatch
  ownership groundwork, not a route-choice, timeout, queue capacity,
  throughput, or Mac sender behavior change.
- FIPS `5198191` makes pending handshake connection storage and active peer
  storage a single lifecycle owner. `PeerLifecycleRegistry` owns the `LinkId ->
  PeerConnection` map plus `ActivePeerRegistry`; `Node::connections` is gone,
  and pending connection call sites now go through explicit lifecycle methods.
  New guard: `peer_lifecycle_registry_owns_connection_and_active_peer_storage`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the owner did not exist,
  then passed locally; focused `test_node_connection`, `handshake`, `timeout`,
  `cross_connection`, and ownership coverage passed; `cargo fmt --check`,
  warning-clean `cargo check -p fips-core --release`, `git diff --check`, leak
  scan, and the full `./scripts/test-dataplane-ownership-fast.sh` tier passed,
  including Linux Docker. No perf smoke was run because this is lifecycle
  ownership groundwork toward `PeerRuntime`, not a route-choice, timeout, queue
  capacity, throughput, or Mac sender behavior change.
- FIPS `ab74260` gives end-to-end FSP session storage a single owner.
  `SessionRegistry` wraps the `NodeAddr -> SessionEntry` table and preserves
  existing session-map call sites through a small compatibility API. New guard:
  `session_registry_owns_endpoint_session_storage_replace_and_cleanup`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the owner did not exist,
  then passed locally; focused `session`, `handshake`, and `_own` coverage
  passed; `cargo fmt --check`, warning-clean `cargo check -p fips-core
  --release`, `git diff --check`, private-string scan, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier passed, including Linux
  Docker. No perf smoke was run because this is endpoint session ownership
  groundwork toward `PeerRuntime`, not a route-choice, timeout, queue capacity,
  throughput, or Mac sender behavior change.
- FIPS `aaad4ef` folds the decrypt-worker registration mirror into
  `SessionRegistry`. The owner now carries endpoint session storage plus the
  rx-loop mirror of worker-accepted decrypt sessions, and
  `Node::decrypt_registered_sessions` is removed. New guard:
  `session_registry_owns_endpoint_session_storage_and_worker_registration_mirror`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because `SessionRegistry` lacked
  worker-registration APIs, then passed locally; focused worker-registration,
  `test_promote_registers_decrypt_worker`, `handshake`, `rekey`, `unit`, and
  ownership coverage passed; `cargo fmt --check`, warning-clean `cargo check -p
  fips-core --release`, `git diff --check`, private-string scan, the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker, and
  targeted Linux Docker
  `test_deregister_session_index_preserves_connected_udp_on_rekey_drain`
  passed. No perf smoke was run because this is ownership-boundary work, not a
  route, queue-cap, sender, or throughput change.
- FIPS `0416b80` makes session-index removal state a peer-lifecycle owner
  decision. `PeerLifecycleRegistry` now removes an active receiver-index entry
  and returns the removed owner plus whether that owner still has another index;
  `Node::deregister_session_index` consumes that result instead of removing and
  separately querying membership for connected-UDP cleanup. New guard:
  `peer_lifecycle_registry_owns_session_index_removal_and_remaining_owner_state`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the atomic removal API
  did not exist, then passed locally; focused session-index, active-peer, and
  lifecycle guards passed; `unit`, `handshake`, and `rekey` filters passed;
  `cargo fmt --check`, warning-clean `cargo check -p fips-core --release`,
  `git diff --check`, private-string scan, the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker, and
  targeted Linux Docker
  `test_deregister_session_index_preserves_connected_udp_on_rekey_drain`
  passed. No perf smoke was run because this is ownership-boundary work, not a
  route, queue-cap, sender, or throughput change.
- FIPS `d4b30ec` makes active-peer teardown indices a peer-lifecycle owner
  decision. `PeerLifecycleRegistry::remove_with_session_indices` now removes
  the active peer and returns a typed teardown plan for current, rekey, pending,
  and previous receiver-index keys; `Node::remove_active_peer` consumes that
  plan instead of reading every `ActivePeer` index slot. New guard:
  `peer_lifecycle_registry_owns_active_peer_teardown_session_indices`, included
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: the guard failed first because the teardown API and index-kind types
  did not exist, then passed locally; focused teardown, disconnect, and
  decrypt-failure coverage passed; `unit` passed; `cargo fmt --check`,
  warning-clean `cargo check -p fips-core --release`, `git diff --check`,
  private-string scan, and the full `./scripts/test-dataplane-ownership-fast.sh`
  tier with Linux Docker passed. No perf smoke was run because this is
  ownership-boundary work, not a route, queue-cap, sender, or throughput change.
- FIPS `2507693` makes active-peer insertion plus current receiver-index
  registration a peer-lifecycle owner decision.
  `PeerLifecycleRegistry::insert_with_current_session_index` now installs active
  peer storage and registers the current `(transport_id, our_index)` dispatch
  key as one operation, returning the replaced active peer and replaced
  session-index owner for observability. Initial promotion and
  cross-connection-winner promotion consume it instead of separately inserting
  active peer storage and receiver-index dispatch. New guard:
  `peer_lifecycle_registry_owns_active_peer_insert_and_current_session_index`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API/result
  type did not exist, then passed locally; focused peer-lifecycle ownership
  coverage, `handshake`, and `unit` passed; `cargo fmt --check`, warning-clean
  `cargo check -p fips-core --release`, `git diff --check`, private-string
  scan, and the full `./scripts/test-dataplane-ownership-fast.sh` tier with
  Linux Docker passed. No perf smoke was run because this is ownership-boundary
  work, not a route, queue-cap, sender, or throughput change.
- FIPS `582a50f` makes active-peer current session/path replacement a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::replace_current_session_and_path` now replaces the
  active peer Noise session, current indices, link id, transport/address,
  optional remote epoch, and connected timestamp as one operation. It registers
  the new current receiver index before returning the old current index to
  `Node` for decrypt-worker/connected-UDP teardown, so old-index removal can
  atomically see that the peer still owns the new index. The msg2 outbound
  alternate-path refresh and outbound cross-connection-winner paths consume it
  instead of separately mutating the peer, deregistering the old index, and
  inserting the new current index. New guard:
  `peer_lifecycle_registry_owns_current_session_replacement_and_index_handoff`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did not
  exist, then passed locally; focused peer-lifecycle ownership, `handshake`,
  and `unit` passed; `cargo fmt --check`, warning-clean `cargo check -p
  fips-core --release`, `git diff --check`, private-string scan, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `049aaa7` makes pending FMP rekey session installation a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::install_pending_rekey_session_and_index` now stores
  the pending Noise session, pending local/remote indices, optional remote
  epoch, peer-initiated rekey dampening, and pending receiver-index dispatch as
  one operation. The rekey msg1 responder path and rekey msg2 initiator path
  consume it instead of separately mutating `ActivePeer` pending-session state
  and inserting the pending receiver index. New guard:
  `peer_lifecycle_registry_owns_pending_rekey_session_and_index_registration`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did not
  exist, then passed locally; focused peer-lifecycle ownership, `rekey`,
  `handshake`, and `unit` passed; `cargo fmt --check`, warning-clean
  `cargo check -p fips-core --release`, `git diff --check`, private-string
  scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `5196ed8` makes authenticated FMP receive bookkeeping a peer-lifecycle
  owner decision.
  `PeerLifecycleRegistry::record_authenticated_fmp_receive` now owns decrypt
  failure reset, authenticated path rotation, link receive stats, peer
  liveness touch, MMP receiver counters, spin-bit observation, and the
  connected-UDP clear signal returned to `Node`. The encrypted-frame handler
  consumes it after worker-owned decrypt returns authenticated plaintext instead
  of separately mutating the active peer. New guard:
  `peer_lifecycle_registry_owns_authenticated_fmp_receive_bookkeeping`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did not
  exist, then passed locally; focused peer-lifecycle ownership, `encrypted`,
  `rekey`, and `unit` passed; `cargo fmt --check`, warning-clean
  `cargo check -p fips-core --release`, `git diff --check`, private-string
  scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `6ce47d9` makes link-dead direct-path degradation a peer-lifecycle
  owner decision.
  `PeerLifecycleRegistry::mark_link_dead_direct_path` now owns active-peer
  stale marking, degraded-link reporting, and connected-UDP socket/drain
  teardown for the link-dead path. `Node::remove_link_dead_peer` consumes the
  typed result for logging and keeps the separate session-direct-degradation
  and queued-packet policy owners intact. New guard:
  `peer_lifecycle_registry_owns_link_dead_direct_path_degradation`, included
  in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did not
  exist, then passed locally; focused peer-lifecycle ownership, `link_dead`,
  `disconnect`, and `unit` passed; `cargo fmt --check`, warning-clean
  `cargo check -p fips-core --release`, `git diff --check`, private-string
  scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `96a2f5f` makes current receiver-index registration repair a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::ensure_current_session_index_registered` now owns
  missing/stale `(transport_id, our_index)` dispatch repair for an active peer
  and returns a typed registration result. `Node` consumes that result for
  logging only, instead of separately reading active peer state, checking the
  session-index registry, and repairing the dispatch map at the call site. New
  guard: `peer_lifecycle_registry_owns_current_session_index_repair`, included
  in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API and
  result type did not exist, then passed locally; focused peer-lifecycle
  ownership, `rekey`, `handshake`, `encrypted`, and `unit` passed;
  `cargo fmt --check`, warning-clean `cargo check -p fips-core --release`,
  `git diff --check`, private-string scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `ea3c79d` makes FMP send bookkeeping a peer-lifecycle owner decision.
  `PeerLifecycleRegistry::record_fmp_send_bookkeeping` now owns active-peer
  link send stats plus MMP sender counters for FMP wire sends. The normal
  worker-send path, inline fallback send path, and pipelined session/datagram
  send path consume that owner instead of open-coding `ActivePeer` stats and
  MMP sender mutation at each call site. New guard:
  `peer_lifecycle_registry_owns_fmp_send_bookkeeping`, included in the fast
  ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API and
  result type did not exist, then passed locally; focused peer-lifecycle
  ownership, `fmp_worker`, `pipelined`, `selected_send`,
  `reserve_fsp_worker_send`, `unit`, and broad `session` filters passed;
  `cargo fmt --check`, warning-clean `cargo check -p fips-core --release`,
  `git diff --check`, private-string scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `5bf1714` makes FSP send bookkeeping a session-registry owner decision.
  `SessionRegistry::record_fsp_send_bookkeeping` now owns FSP data counters,
  MMP sender counters, idle-touch policy, and optional outbound next-hop
  recording for session data, endpoint data, pipelined session/datagram,
  session-control, and standalone CoordsWarmup sends. New guard:
  `session_registry_owns_fsp_send_bookkeeping`, included in the fast ownership
  tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the registry API and
  result type did not exist, then passed locally; focused session-registry
  ownership, `pipelined`, broad `session`, formatting, warning-clean release
  check, diff check, private-string scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work. The next perf
  checkpoint should be after the current ownership batch or before/after any
  sender, queue, batching, route, connected-UDP, maintenance-timing, or
  peer-runtime behavior change.
- Post-ownership-batch perf checkpoint: a short local-FIPS Docker smoke at
  nvpn `428c821f` plus FIPS `5bf1714` passed all four phases:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH="$FIPS_SAFETY_WORKTREE" \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=/tmp/nvpn-fips-5bf1714-smoke-20260609Tperf-checkpoint \
PROJECT_NAME=nostr-vpn-e2e-fips-5bf1714-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `e2578b092b856d66c5201a8b73007885dd888453dc7069b05d6d0c53c28c1e17`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay ran at roughly
  `2147/2275 Mbps`; constrained-underlay at `136.9/136.6 Mbps`;
  worker-queue-pressure at `122.0/120.9 Mbps` with load at
  `126.6/129.1 Mbps`; rx-maintenance-fault at `2242.8/2222.9 Mbps` with load
  at `2294.9/2235.0 Mbps`. Load and post-load tunnel-ping loss stayed `0%` in
  every phase, direct UDP underlay counters advanced in every phase, and the
  worker-pressure phase exposed expected decrypt queue-full/bulk-drop counters
  without a wedge.
- FIPS `1241961` makes connected-UDP activation planning a peer-lifecycle owner
  decision. `PeerLifecycleRegistry::connected_udp_activation_plan` now owns the
  active-peer scan for healthy established UDP peers, the already-installed
  connected-UDP count, and the stable configured-peer-before-discovered
  activation order. The connected-UDP handler still owns async transport
  resolution, socket open, and drain spawn, but it consumes the lifecycle
  owner-produced plan instead of walking active peer storage and reparsing
  configured peers per candidate. New guard:
  `peer_lifecycle_registry_owns_connected_udp_activation_plan`, included in
  the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did
  not exist, then passed locally; focused peer-lifecycle ownership,
  `connected_udp`, and broad `unit` filters passed; `cargo fmt --check`,
  warning-clean `cargo check -p fips-core --release`, `git diff --check`,
  private-string scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run for this slice because it is ownership-boundary work;
  at that point, the most recent perf checkpoint was the nvpn `428c821f` plus
  FIPS `5bf1714` short Docker smoke above.
- FIPS `e80a482` makes connected-UDP socket/drain install and clear a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::install_connected_udp_if_eligible` now owns the
  final eligibility recheck and `ActivePeer` socket/drain mutation, while
  `PeerLifecycleRegistry::clear_connected_udp_for_peer` owns idempotent clear
  results. The connected-UDP handler still owns async transport resolution,
  socket open, drain spawn, perf/log emission, and budget checks, but consumes
  typed lifecycle results instead of mutating `ActivePeer` connected-UDP state
  directly. New guard:
  `peer_lifecycle_registry_owns_connected_udp_install_and_clear`, included in
  the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API/result
  types did not exist, then passed locally; focused `connected_udp` and
  peer-lifecycle ownership filters passed; broad `unit` passed with `169`
  tests; formatting, warning-clean release check, diff check, private-string
  scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  A follow-up short local-FIPS Docker perf checkpoint at nvpn `9fa7ae91` plus
  FIPS `e80a482` passed all four phases:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=/tmp/nvpn-fips-e80a482-smoke-20260609Tperf-checkpoint \
PROJECT_NAME=nostr-vpn-e2e-fips-e80a482-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `f72dd4fd7f8bbc0ead59825a5679a45d3e8c4911364778d3cac3128434ae8681`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay ran at roughly
  `2192/2119 Mbps`; constrained-underlay at `134.7/135.0 Mbps`;
  worker-queue-pressure at `146.5/152.2 Mbps` with load at
  `150.2/140.2 Mbps`; rx-maintenance-fault at `2216.1/2176.7 Mbps` with load
  at `2255.5/2212.2 Mbps`. Load and post-load tunnel-ping loss stayed `0%` in
  every phase, direct UDP underlay counters advanced in every phase, and the
  worker-pressure phase exposed expected decrypt queue-full/bulk-drop counters
  without a wedge. This remains Linux/Docker evidence, not real Mac-to-Mac
  validation.
- FIPS `750ebb4` makes FMP send preparation and inline/worker seal reservation
  a peer-lifecycle owner decision.
  `PeerLifecycleRegistry::prepare_fmp_send` now snapshots the transport ID,
  current transport address, receiver index, flags, payload length, timestamp,
  and connected UDP socket without consuming a Noise send counter.
  `reserve_prepared_fmp_worker_send` owns the worker-side counter/header/cipher
  reservation, and `seal_prepared_fmp_inline_send` owns inline counter/header
  reservation plus AEAD seal. `Node::send_encrypted_link_message_with_ce` still
  owns transport readiness, worker-target resolution, dispatch, actual send,
  and send bookkeeping. New guard:
  `peer_lifecycle_registry_owns_fmp_send_preparation_and_seal_paths`, included
  in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle APIs did
  not exist, then passed locally; focused `fmp_worker`, the default local
  ownership tier, warning-clean release check, bash syntax check, diff check,
  private-string scan, and a focused Linux Docker slice for the new/adjacent
  FMP guards passed.
  Because this slice touches send hot-path preparation, it got an exact
  short-smoke perf checkpoint using the same knobs as the prior `e80a482`
  checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/750ebb4-short-smoke-20260609Tperf-checkpoint \
PROJECT_NAME=nostr-vpn-e2e-fips-750ebb4-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `f0bde446cf106d7a265a01bc213f87a818f0f1bfe2359dba858884f024418d16`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay ran at roughly
  `2261/2278 Mbps`; constrained-underlay at `131.2/132.7 Mbps`;
  worker-pressure baseline `129.3/133.0 Mbps` with load
  `128.7/129.2 Mbps`; rx-maintenance baseline `2260.6/2296.3 Mbps` with load
  `2272.4/2149.1 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  is broadly healthy versus the previous checkpoint; the constrained and
  worker-pressure rows are lower, but within expected Docker-run variance and
  still far above floors.
  A heavier connected-UDP-on platform-matrix row also passed with default
  `4s`/`6s` phase durations and `60` ping samples. Artifact:
  `artifacts/fips-platform-matrix/20260609T102301Z/connected-udp-on-perf/phase-summary.tsv`;
  phase summary SHA-256
  `08d22f71655bfcc7760b81488518390125cf7eec1f9f46baaebe938b9a417f79`;
  failure summary SHA-256
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`;
  log SHA-256
  `0d654886bdd8bb492fea1569e4d82183cd27a618d9284884e8b4a71c136d3564`.
  That row passed clean, constrained, worker-pressure, and rx-maintenance
  phases with `0%` load/post tunnel-ping loss. It is a stronger health check,
  not an exact A/B with the shorter `e80a482` smoke.
- FIPS `9c14552` makes FMP worker packet preparation a peer-lifecycle owner
  decision. `PeerLifecycleRegistry::prepare_fmp_worker_send` now owns the
  worker-side payload-length check, counter/header/cipher reservation, FMP wire
  buffer layout, timestamp/plaintext placement, and predicted byte count for
  worker sends. `Node::send_encrypted_link_message_with_ce` still owns
  transport readiness, worker-target resolution, dispatch, actual send, and
  send bookkeeping. The existing guard
  `peer_lifecycle_registry_owns_fmp_send_preparation_and_seal_paths` was
  extended and failed first because the lifecycle API and mismatch error did
  not exist, then passed locally and in a focused Linux Docker slice.
  Verification passed: focused guard, adjacent `fmp_worker` tests, default
  local ownership fast tier, focused Linux Docker FMP slice, broad local
  `unit`, warning-clean release check, bash syntax check, diff check, and
  private-string scan.
  Because this slice touches send hot-path packet preparation, it got an exact
  short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/9c14552-short-smoke-20260609Tperf-checkpoint \
PROJECT_NAME=nostr-vpn-e2e-fips-9c14552-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `ccff9d128ce1d2077407181a07b0e63c1a83e21ab06346ee08460225a97aa926`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay ran at roughly
  `2354/2283 Mbps`; constrained-underlay at `130.2/132.6 Mbps`;
  worker-pressure baseline `126.3/127.7 Mbps` with load
  `132.3/129.8 Mbps`; rx-maintenance baseline `2316.5/2270.6 Mbps` with load
  `2271.9/2281.4 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge.
- FIPS `cb59aab` makes pipelined endpoint/FSP FMP worker reservation a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::reserve_prepared_fmp_worker_send` now owns the FMP
  worker counter, header, cipher reservation, and predicted outer wire bytes for
  both plain FMP worker sends and pipelined endpoint-data sends.
  `PeerLifecycleRegistry::fmp_worker_send_available` preserves the previous
  counter-safety invariant by checking worker-cipher availability before the
  endpoint path reserves an FSP counter.
  `try_send_session_endpoint_data_pipelined` still owns route lookup,
  MTU/FSP reservation, wire layout around reserved headers, worker-target
  dispatch, and send policy. The guard
  `peer_lifecycle_registry_owns_fmp_send_preparation_and_seal_paths` failed
  first because the pipelined reservation API did not exist, then passed.
  Verification passed: focused guard, focused pipelined wire guard, adjacent
  `fmp_worker` and `pipelined` filters, default local ownership fast tier,
  focused Linux Docker ownership slice, broad local `unit`, warning-clean
  release check, `cargo fmt --check`, bash syntax check, diff check, and
  private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/cb59aab-short-smoke-20260609Tperf-checkpoint \
PROJECT_NAME=nostr-vpn-e2e-fips-cb59aab-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `876e0693da982761985e22c3d0ef12faa56657c599d6facedb3a7b1a40a609aa`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2244.8/2086.7 Mbps` with load `2138.2/2245.7 Mbps`;
  constrained-underlay baseline at `136.6/134.9 Mbps` with load
  `135.6/134.6 Mbps`; worker-pressure baseline `123.0/151.4 Mbps` with load
  `112.0/133.9 Mbps`; rx-maintenance baseline `2072.8/2089.8 Mbps` with load
  `1347.0/2191.3 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `49c9db1` makes endpoint-data FSP worker reservation a session-registry
  owner decision. `SessionRegistry::reserve_endpoint_data_fsp_worker_send` owns
  source path-MTU seeding, established-session validation, and FSP
  counter/header/cipher reservation for pipelined endpoint-data sends.
  `try_send_session_endpoint_data_pipelined` still owns route lookup, FMP
  preparation/reservation, wire construction around reserved headers,
  worker-target dispatch, and send policy. The guard
  `session_registry_owns_endpoint_fsp_worker_reservation_and_path_mtu_seed`
  failed first because the input/error types and registry API did not exist,
  then passed. Verification passed: focused guard, `session_registry_owns`,
  `pipelined`, `fsp_worker`, prior peer-lifecycle FMP guard, default local
  ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), warning-clean release check, `cargo fmt --check`, bash
  syntax check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/49c9db1-short-smoke-20260609Tperf-checkpoint \
PROJECT_NAME=nostr-vpn-e2e-fips-49c9db1-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `29cb58491d63b06a1afd7c3ae880265fc3639d59da4b03bf8b553d5d8ef4c6aa`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2318.1/2098.1 Mbps` with load `2279.4/2215.4 Mbps`;
  constrained-underlay baseline at `138.1/137.1 Mbps` with load
  `135.7/135.2 Mbps`; worker-pressure baseline `123.8/121.8 Mbps` with load
  `119.9/124.8 Mbps`; rx-maintenance baseline `2310.5/2191.0 Mbps` with load
  `2178.7/2283.9 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `3a746bb` makes pipelined endpoint wire payload sizing and nested
  worker seal offsets an owned wire-plan boundary.
  `PipelinedEndpointWirePlan` owns link plaintext length and FMP payload length
  calculation, while `PipelinedEndpointWire::into_worker_wire` owns the
  FMP/FSP reservation-to-worker-wire handoff and `FspSealJob` offsets.
  `try_send_session_endpoint_data_pipelined` still owns route lookup, transport
  target resolution, peer/session reservation ordering, FMP/FSP bookkeeping,
  backpressure/drop policy, and worker dispatch. The guard
  `pipelined_endpoint_wire_plan_owns_payload_sizing_and_worker_offsets` failed
  first because the plan and worker-wire owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, and `fsp_worker` filters, default local ownership
  fast tier, focused Linux Docker ownership slice, broad local `unit` (`171`
  tests), warning-clean release check, `cargo fmt --check`, bash syntax check,
  diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/3a746bb-short-smoke-20260609Tperf-checkpoint \
PROJECT_NAME=nostr-vpn-e2e-fips-3a746bb-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `aba2e194c4eae6eec3d7f3c53ad1de4a1481f664e2fba234d976b9e260f765e1`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2289.3/2226.0 Mbps` with load `2155.9/2221.0 Mbps`;
  constrained-underlay baseline at `138.5/137.6 Mbps` with load
  `136.2/135.2 Mbps`; worker-pressure baseline `124.3/131.8 Mbps` with load
  `131.5/120.4 Mbps`; rx-maintenance baseline `2198.9/2265.3 Mbps` with load
  `2215.3/2205.4 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `2fb3fbd` makes pipelined endpoint dispatch policy an owned plan.
  `PipelinedEndpointDispatchPlan` owns endpoint FSP payload length, FSP worker
  reservation input, FSP send bookkeeping input, bulk/control worker lane
  policy, direct-path degradation drop suppression, drop-on-backpressure, and
  scheduling weight handoff. `try_send_session_endpoint_data_pipelined` still
  owns route lookup, transport target resolution, peer/session reservation
  ordering, FMP bookkeeping, and worker dispatch. The guard
  `pipelined_endpoint_dispatch_plan_owns_worker_policy_and_bookkeeping` failed
  first because the dispatch plan owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, and `fsp_worker` filters, default local ownership
  fast tier, focused Linux Docker ownership slice, broad local `unit` (`171`
  tests), warning-clean release check, `cargo fmt --check`, bash syntax check,
  diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/2fb3fbd-short-smoke-20260609Tperf-checkpoint \
PROJECT_NAME=nostr-vpn-e2e-fips-2fb3fbd-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `b677a5ecea6390c224e95d30c6d190850269494104d8bdd4c32d2f47ef9e37e4`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2238.9/2126.0 Mbps` with load `2160.6/2189.9 Mbps`;
  constrained-underlay baseline at `137.9/137.3 Mbps` with load
  `136.9/136.1 Mbps`; worker-pressure baseline `130.3/122.5 Mbps` with load
  `125.0/123.1 Mbps`; rx-maintenance baseline `2072.3/2031.9 Mbps` with load
  `2092.3/2172.6 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `10fdb8a` makes pipelined endpoint send-target resolution an owned
  boundary. `PipelinedEndpointSendTarget::resolve` owns connected-UDP
  preference, wildcard fallback remote-address resolution, async UDP socket
  availability, and selected-target handoff. Connected sockets win without
  resolving the fallback address; wildcard UDP still resolves the prepared
  fallback address. `try_send_session_endpoint_data_pipelined` still sequences
  route lookup, peer/session reservation ordering, FMP/FSP bookkeeping owners,
  dispatch-plan construction, and worker dispatch. The guard
  `pipelined_endpoint_send_target_owns_connected_udp_preference_and_fallback`
  failed first because the send-target owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, `fmp_worker`, and `connected_udp` filters, default
  local ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), release check, `cargo fmt --check`, bash syntax check,
  diff check, and private-string scan with a harmless `.local_addr()` false
  positive.
  Because this touches connected-UDP/path target selection on the pipelined
  endpoint/FSP send hot path, it got an exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/10fdb8a-short-smoke-20260609Tperf-checkpoint \
PROJECT_NAME=nostr-vpn-e2e-fips-10fdb8a-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `2b8bc98ecf7622ff3daf375c77bb80d9abad2e7a5791e4848d02db92db806611`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2264.2/2295.0 Mbps` with load `2057.2/2196.1 Mbps`;
  constrained-underlay baseline at `131.7/133.2 Mbps` with load
  `129.3/127.7 Mbps`; worker-pressure baseline `126.2/128.1 Mbps` with load
  `121.8/127.7 Mbps`; rx-maintenance baseline `2183.3/2219.1 Mbps` with load
  `2181.8/2219.6 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `34bc3f2` makes the pipelined endpoint send-plan handoff an owned
  boundary. `PipelinedEndpointSendPlan` now groups the wire plan, dispatch
  policy, selected send target handoff, FMP/FSP reservations, worker-job
  construction, FMP bookkeeping facts, FSP bookkeeping input, and originated
  byte accounting into one prepared send. `try_send_session_endpoint_data_pipelined`
  still sequences route lookup, path-MTU discovery, transport lookup, registry
  reservation calls, bookkeeping application, and worker dispatch, but no
  longer assembles the wire, send policy, worker job, and bookkeeping facts in
  one open-coded block. The guard
  `pipelined_endpoint_send_plan_owns_worker_job_and_bookkeeping_handoff`
  failed first because the send-plan owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, `fmp_worker`, and `connected_udp` filters, default
  local ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), warning-clean release check, `cargo fmt --check`, bash
  syntax check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/34bc3f2-short-smoke-20260609Tlarger-send-plan \
PROJECT_NAME=nostr-vpn-e2e-fips-34bc3f2-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `8794347cac2b71309a1b13b52948423d2f7f45210f69b03b5fc8f6204b9e85a0`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2289.4/2187.3 Mbps` with load `2185.5/2231.1 Mbps`;
  constrained-underlay baseline at `137.1/136.9 Mbps` with load
  `138.2/133.8 Mbps`; worker-pressure baseline `123.4/121.9 Mbps` with load
  `121.8/125.5 Mbps`; rx-maintenance baseline `2165.2/2242.8 Mbps` with load
  `2138.9/2216.4 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `58f36c0` makes the pipelined endpoint runtime send plan an owned
  boundary. `PipelinedEndpointRoutePlan` owns selected route facts, source and
  next-hop addresses, path MTU, default TTL, scheduling weight, and direct-path
  block state. `PipelinedEndpointRuntimeSendPlan` combines route planning,
  `PipelinedEndpointSendPlan`, and `FmpSendPreparation`, rejects mismatched FMP
  payload preparation, and leaves `try_send_session_endpoint_data_pipelined` as
  a coordinator around transport lookup, worker availability, reservation
  calls, bookkeeping commit, and dispatch. The guard
  `pipelined_endpoint_runtime_send_plan_owns_route_and_fmp_preparation` failed
  first because the route/runtime send-plan owners did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, `fmp_worker`, and `connected_udp` filters, default
  local ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), warning-clean release check, `cargo fmt`, bash syntax
  check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short-smoke perf attempt:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/58f36c0-short-smoke-20260609Truntime-send-plan \
PROJECT_NAME=nostr-vpn-e2e-fips-58f36c0-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `f709bc24cced4ddfa6c10033c198a541f492d4d8d5b6392617abc24e588736f7`;
  `failure-summary.tsv` SHA-256:
  `2ac82a41cfe0a73734ac99e7db2db6cf718cc08113af00ddee15fe096459a85e`.
  Clean-underlay passed: baseline roughly `2176.4/2265.0 Mbps`, load
  `2233.1/2017.8 Mbps`, load/post tunnel-ping loss `0%`, and direct UDP
  underlay counters advanced both ways. The run then failed in
  constrained-underlay because reverse TCP reached `94.4 Mbps` against the
  `100 Mbps` floor; forward TCP was `127.3 Mbps`, direct UDP counters advanced
  both ways, and the remaining phases were not reached. Treat this as a
  watchlist signal for the next sender/runtime boundary, not as a green
  checkpoint. This remains Linux/Docker evidence, not real Mac-to-Mac
  validation.
- FIPS `a8ece85` makes the pipelined endpoint runtime dispatch an owned
  boundary. `PipelinedEndpointRuntimeSendDispatch` owns the runtime send plan,
  resolved send target, prepared FMP worker reservation, and FSP worker
  reservation through prepared-send construction and commit. The hot-path
  coordinator now clones the worker pool, prepares the runtime send plan,
  prepares the runtime dispatch, and commits it; transport lookup, target
  resolution, worker availability, reservation calls, prepared-send
  construction, and dispatch handoff are grouped under one runtime operation.
  The guard
  `pipelined_endpoint_runtime_dispatch_owns_target_reservations_and_prepared_send`
  failed first because the dispatch owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, `fmp_worker`, and `connected_udp` filters, default
  local ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), warning-clean release check, `cargo fmt`, bash syntax
  check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/a8ece85-short-smoke-20260609Truntime-dispatch \
PROJECT_NAME=nostr-vpn-e2e-fips-a8ece85-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `627f3babc838330def60fce4fc90ed0dfb882e49aa3fb5552b8947f9b4e840b8`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2251.1/2263.6 Mbps` with load `2220.6/2139.9 Mbps`;
  constrained-underlay baseline `137.4/135.7 Mbps` with load
  `137.0/136.6 Mbps`; worker-pressure baseline `133.9/118.8 Mbps` with load
  `124.7/126.4 Mbps`; rx-maintenance baseline `2151.2/1991.3 Mbps` with load
  `2105.2/2234.0 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `f1689c7` introduces the first peer-runtime send snapshot boundary.
  `PeerRuntimeSendSnapshot` owns the peer address, prepared FMP metadata, and
  FMP worker-send availability from one active-peer read. Runtime dispatch now
  uses that snapshot for worker availability and FMP reservation instead of
  rereading peer state after route/FMP preparation. The guard
  `peer_runtime_send_snapshot_owns_fmp_metadata_and_worker_availability`
  failed first because the snapshot/reservation API did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `peer_lifecycle_registry_owns`, `session_registry_owns`, `fmp_worker`, and
  `connected_udp` filters, default local ownership fast tier, focused Linux
  Docker ownership slice, broad local `unit` (`172` tests), warning-clean
  release check, `cargo fmt`, bash syntax check, diff check, and private-string
  scan. Because this touches the pipelined endpoint/FSP send hot path, it got
  an exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/f1689c7-short-smoke-20260609Tpeer-runtime-snapshot \
PROJECT_NAME=nostr-vpn-e2e-fips-f1689c7-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `8c91b6bf54d9ea607155a29db29de8828490dffa33829f6601090ad3031303f6`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2220.8/2144.8 Mbps` with load `2133.7/2091.4 Mbps`;
  constrained-underlay baseline `137.5/137.8 Mbps` with load
  `136.6/135.9 Mbps`; worker-pressure baseline `122.9/136.3 Mbps` with load
  `154.9/154.7 Mbps`; rx-maintenance baseline `2189.3/2029.4 Mbps` with load
  `2247.4/2202.8 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `f4eefe6` grows the peer-runtime send snapshot into a route snapshot.
  `PeerRuntimeRouteSnapshot` owns the next-hop peer address,
  transport/current-address path-MTU seed, prepared-FMP inputs, and FMP
  worker-send availability from one active-peer read. Runtime send preparation
  now derives both route planning and the FMP send snapshot from that captured
  view instead of reading active peer state once for path MTU and again for
  FMP/worker metadata. The guard
  `peer_runtime_route_snapshot_owns_path_seed_and_send_snapshot_inputs` failed
  first because the route-snapshot API did not exist, then passed.
  Verification passed: focused guard, previous send-snapshot guard, adjacent
  `pipelined`, `peer_lifecycle_registry_owns`, `session_registry_owns`,
  `fmp_worker`, and `connected_udp` filters, default local ownership fast tier,
  focused Linux Docker ownership slice, broad local `unit` (`173` tests),
  warning-clean release check, `cargo fmt`, bash syntax check, diff check, and
  private-string scan. Because this touches the pipelined endpoint/FSP send hot
  path, it got an exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/f4eefe6-short-smoke-20260609Tpeer-runtime-route-snapshot \
PROJECT_NAME=nostr-vpn-e2e-fips-f4eefe6-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  `phase-summary.tsv` SHA-256:
  `6eda85cfa108c991d6e84cec088a9e94bb3d1cf18a273f1f7595dcb62e4ae072`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2256.1/2146.5 Mbps` with load `2210.0/2129.1 Mbps`;
  constrained-underlay baseline `129.3/128.6 Mbps` with load
  `128.2/129.5 Mbps`; worker-pressure baseline `131.7/144.1 Mbps` with load
  `154.0/145.4 Mbps`; rx-maintenance baseline `2242.8/2199.6 Mbps` with load
  `2204.6/2129.4 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `0fd7817` makes the runtime handoff from peer-route snapshot explicit.
  `PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot` owns the
  conversion from route plan plus send plan plus `PeerRuntimeRouteSnapshot` into
  the runtime send plan, derives the FMP send snapshot internally, and rejects a
  route next-hop that does not match the captured peer snapshot address. The
  guard `pipelined_endpoint_runtime_send_plan_owns_peer_route_snapshot_handoff`
  failed first because the constructor and mismatch error did not exist, then
  passed. Verification passed: focused guard, adjacent `pipelined`,
  previous route-snapshot, `peer_lifecycle_registry_owns`, and
  `session_registry_owns` filters, default local ownership fast tier, focused
  Linux Docker ownership slice, broad local `unit` (`173` tests),
  warning-clean release check, `cargo fmt`, bash syntax check, diff check, and
  private-string scan. Because this touches the pipelined endpoint/FSP send hot
  path, it got an exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/0fd7817-short-smoke-20260609Truntime-route-handoff \
PROJECT_NAME=nostr-vpn-e2e-fips-0fd7817-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `6806bf50` plus FIPS `0fd7817`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `a358faf7df417bde52f4ff9fefbe336d8937e3d9999d49c36bdb119e6ee56502`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2210.5/2226.2 Mbps` with load `2168.9/2120.4 Mbps`;
  constrained-underlay baseline `130.1/131.2 Mbps` with load
  `129.1/128.4 Mbps`; worker-pressure baseline `124.7/123.0 Mbps` with load
  `122.8/122.0 Mbps`; rx-maintenance baseline `2153.2/2229.2 Mbps` with load
  `2264.2/2237.9 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `685c852` makes peer-runtime route/send planning an owned boundary.
  `PipelinedEndpointPeerRuntimeRoute` carries the captured
  `PeerRuntimeRouteSnapshot` together with path MTU, default TTL, scheduling
  weight, and direct-path bulk-drop policy. It builds the route plan and
  runtime send plan as one handoff, so `Node` prepares one peer-runtime route
  and consumes it instead of separately assembling route plan, send plan, and
  peer snapshot. The guard
  `pipelined_endpoint_peer_runtime_route_owns_snapshot_route_policy_and_send_plan`
  failed first because the owner did not exist, then passed. Verification
  passed: focused guard, `pipelined`, previous route-snapshot,
  `peer_lifecycle_registry_owns`, `session_registry_owns`, default local
  ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`173` tests), warning-clean release check, `cargo fmt`, bash syntax
  check, diff check, and private-string scan. Because this touches the
  pipelined endpoint/FSP send hot path, it got an exact short-smoke perf
  checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/685c852-short-smoke-20260609Tpeer-runtime-route-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-685c852-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `3d3780aa` plus FIPS `685c852`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `9a0a82999e31f68479f2190acdd60bc1e0134c66db4eb3c40e9412ea76c3c463`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2195.1/2196.5 Mbps` with load `2244.5/2105.5 Mbps`;
  constrained-underlay baseline `130.3/132.0 Mbps` with load
  `129.8/130.2 Mbps`; worker-pressure baseline `131.3/129.4 Mbps` with load
  `127.8/129.1 Mbps`; rx-maintenance baseline `2192.3/2299.1 Mbps` with load
  `2278.0/2238.3 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `4886c47` makes the pipelined endpoint runtime send attempt an owned
  boundary. `PipelinedEndpointRuntimeSendAttempt` carries the resolved send
  target plus runtime send plan and owns the FSP/FMP reservation handoff. The
  guard `pipelined_endpoint_runtime_send_attempt_owns_target_and_reservations`
  failed first because the owner did not exist, then passed. It verifies the
  happy path reserves both counters exactly once and the unavailable-FMP-worker
  path returns `None` without consuming additional session or peer counters.
  Verification passed: focused guard, `pipelined`, `peer_lifecycle_registry_owns`,
  `session_registry_owns`, broad local `unit` (`173` tests), default local
  ownership fast tier, focused Linux Docker ownership slice, warning-clean
  release check, `cargo fmt`, bash syntax check, diff check, and private-string
  scan. Because this touches the pipelined endpoint/FSP send hot path, it got
  an exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/4886c47-short-smoke-20260609Truntime-send-attempt \
PROJECT_NAME=nostr-vpn-e2e-fips-4886c47-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `cfcd36c2` plus FIPS `4886c47`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `bfcde4ec579ce1d9d5633e7e18eb28f294791d0142dfc0613da308752de5e0cb`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2201.5/2280.3 Mbps` with load `2226.8/2222.7 Mbps`;
  constrained-underlay baseline `131.5/129.7 Mbps` with load
  `128.3/128.5 Mbps`; worker-pressure baseline `128.3/122.3 Mbps` with load
  `127.8/128.5 Mbps`; rx-maintenance baseline `2235.6/2232.5 Mbps` with load
  `2290.1/2286.3 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `ca694b0` makes the pipelined endpoint runtime send dispatch an owned
  boundary. `PipelinedEndpointRuntimeSend` carries the runtime send plan, owns
  transport lookup plus UDP send-target resolution, and delegates the FSP/FMP
  reservation handoff to `PipelinedEndpointRuntimeSendAttempt`. The guard
  `pipelined_endpoint_runtime_send_owns_transport_target_and_reservation_handoff`
  failed first because the owner did not exist, then passed. It verifies the
  happy path resolves transport/target and reserves both counters exactly once,
  and the missing-transport path fails before consuming additional session or
  peer counters. Verification passed: focused guard, `pipelined`,
  `peer_lifecycle_registry_owns`, `session_registry_owns`, broad local `unit`
  (`173` tests), default local ownership fast tier, focused Linux Docker
  ownership slice, warning-clean release check, `cargo fmt`, diff check, and
  private-string scan. Because this touches the pipelined endpoint/FSP send hot
  path, it got an exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/ca694b0-short-smoke-20260609Truntime-send-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-ca694b0-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `e864a3a1` plus FIPS `ca694b0`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `4902cab636db32a8fa17b13000322d41e78b96e28c27affbd20f3c975b5356c2`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2309.9/2283.6 Mbps` with load `2258.0/2243.6 Mbps`;
  constrained-underlay baseline `129.0/130.0 Mbps` with load
  `128.2/130.0 Mbps`; worker-pressure baseline `139.3/140.2 Mbps` with load
  `125.1/130.7 Mbps`; rx-maintenance baseline `2240.8/2206.1 Mbps` with load
  `2197.5/2238.5 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `f3d28ab` makes the pipelined endpoint peer-runtime send dispatch an
  owned boundary. `PipelinedEndpointPeerRuntimeSend` carries the original
  endpoint send plus peer-runtime route, owns runtime send-plan construction,
  and delegates transport lookup, UDP target resolution, and FSP/FMP
  reservation handoff to `PipelinedEndpointRuntimeSend`. The guard
  `pipelined_endpoint_peer_runtime_send_owns_route_plan_and_runtime_dispatch`
  failed first because the owner did not exist, then passed. It verifies the
  happy path builds the runtime plan, resolves transport/target, and reserves
  both counters exactly once; it also verifies the missing-transport path fails
  before consuming additional session or peer counters. Verification passed:
  focused guard, `pipelined`, `peer_lifecycle_registry_owns`,
  `session_registry_owns`, broad local `unit` (`173` tests), default local
  ownership fast tier, focused Linux Docker ownership slice, warning-clean
  release check, `cargo fmt`, diff check, and private-string scan. Because this
  touches the pipelined endpoint/FSP send hot path, it got an exact short-smoke
  perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/f3d28ab-short-smoke-20260609Tpeer-runtime-send-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-f3d28ab-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `a2c71ace` plus FIPS `f3d28ab`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `1f54df01b7e3c6c759b5111d226e43727b211039b5e2d02995fe0765fb8cbfbe`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2310.3/2229.3 Mbps` with load `2220.8/2198.3 Mbps`;
  constrained-underlay baseline `129.6/129.7 Mbps` with load
  `129.2/130.5 Mbps`; worker-pressure baseline `120.6/126.6 Mbps` with load
  `128.1/121.4 Mbps`; rx-maintenance baseline `2231.7/2229.7 Mbps` with load
  `2218.9/2131.2 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `c043dd7` moves peer-runtime path-MTU ownership into the peer-runtime
  send facade. `PipelinedEndpointPeerRuntimeRoute` now carries the captured
  peer-route snapshot plus route policy, while
  `PipelinedEndpointPeerRuntimeSend` resolves the selected transport and
  derives path MTU from the transport/current-address pair before building the
  runtime send plan. The guard
  `pipelined_endpoint_peer_runtime_send_owns_transport_path_mtu_route_plan_and_runtime_dispatch`
  failed first on the old constructor/API, then passed. Verification passed:
  focused guard, `pipelined`, route-snapshot, peer/session registry guards,
  broad local `unit` (`173` tests), default local ownership fast tier, focused
  Linux Docker ownership slice, warning-clean release check, `cargo fmt`, diff
  check, and private-string scan. Because this touches the pipelined
  endpoint/FSP send hot path, it got an exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/c043dd7-short-smoke-20260609Tpath-mtu-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-c043dd7-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `bf325005` plus FIPS `c043dd7`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `70a2f9a3daecfc3b7aeed8525e94bc60dee5a42974c88dc1344f23bc778c972f`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2249.2/2205.6 Mbps` with load `2291.4/2217.0 Mbps`;
  constrained-underlay baseline `128.1/131.6 Mbps` with load
  `132.1/132.8 Mbps`; worker-pressure baseline `122.9/129.4 Mbps` with load
  `132.3/129.0 Mbps`; rx-maintenance baseline `2166.9/2212.3 Mbps` with load
  `2289.1/2172.3 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `0e70c02` makes the peer-runtime route request an owned boundary.
  `PipelinedEndpointPeerRuntimeRouteRequest` carries source/destination/default
  TTL/time inputs, resolves the next hop, asks `PeerLifecycleRegistry` for the
  captured peer-route snapshot, applies configured send weight, and carries
  direct-path degradation into explicit bulk-drop policy. The guard
  `pipelined_endpoint_peer_runtime_route_request_owns_next_hop_snapshot_and_policy`
  failed first because the owner and typed request error did not exist, then
  passed. Verification passed: focused guard, `pipelined`, route-snapshot,
  peer/session registry guards, broad local `unit` (`173` tests), default local
  ownership fast tier, focused Linux Docker ownership slice, warning-clean
  release check, `cargo fmt`, diff check, and private-string scan. Because this
  touches the pipelined endpoint/FSP send hot path, it got an exact short-smoke
  perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/0e70c02-short-smoke-20260609Troute-request-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-0e70c02-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `fe80aa8a` plus FIPS `0e70c02`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `f4b4a2f2f28fb8b4d4922fb05b980308558baa814b14474e0487fae3c778202c`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2287.5/2309.1 Mbps` with load `2166.1/2230.4 Mbps`;
  constrained-underlay baseline `127.7/127.7 Mbps` with load
  `131.9/132.2 Mbps`; worker-pressure baseline `127.4/127.0 Mbps` with load
  `120.1/129.1 Mbps`; rx-maintenance baseline `2241.4/2278.8 Mbps` with load
  `2132.2/2240.2 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `b889083` makes the peer-runtime send request an owned boundary.
  `PipelinedEndpointPeerRuntimeSendRequest` carries the endpoint send plus
  route request, resolves next-hop/snapshot/policy, and owns dispatch
  preparation through runtime send planning, UDP target resolution, and FSP/FMP
  reservation handoff. The guard
  `pipelined_endpoint_peer_runtime_send_request_owns_route_request_and_dispatch`
  failed first because the owner and typed request error did not exist, then
  passed. Verification passed: focused guard, `pipelined`, route-snapshot,
  peer/session registry guards, broad local `unit` (`173` tests), default local
  ownership fast tier, focused Linux Docker ownership slice, warning-clean
  release check, `cargo fmt`, diff check, and private-string scan. Because this
  touches the pipelined endpoint/FSP send hot path, it got an exact short-smoke
  perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/b889083-short-smoke-20260609Tsend-request-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-b889083-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `a31bef33` plus FIPS `b889083`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `27de17d6db64d7099b59a9a5c83251e5bcceff32a6422af178bb380bc11269f3`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2207.4/2254.1 Mbps` with load `2214.2/2185.8 Mbps`;
  constrained-underlay baseline `128.4/132.4 Mbps` with load
  `130.7/131.1 Mbps`; worker-pressure baseline `128.5/127.2 Mbps` with load
  `127.9/128.1 Mbps`; rx-maintenance baseline `2296.6/2221.6 Mbps` with load
  `2203.6/2294.0 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `62249d0` makes peer-runtime send request execution an owned boundary.
  `PipelinedEndpointPeerRuntimeSendRequest::execute` now resolves dispatch and
  commits the prepared worker job, so the request owns FSP/FMP counter
  reservation, session traffic bookkeeping, outbound next-hop recording, peer
  link send stats, and forwarding originated counters. The guard
  `pipelined_endpoint_peer_runtime_send_request_owns_commit_bookkeeping` failed
  first because `execute` did not exist, then passed. Verification passed:
  focused guard, `pipelined`, peer/session registry and route-snapshot guards,
  default local ownership fast tier, broad local unit coverage, focused Linux
  Docker ownership slice, release check, `cargo fmt`, diff check, and
  private-string scan. Because this touches the endpoint/FSP send hot path, it
  got an exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/62249d0-short-smoke-20260609Tsend-execution-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-62249d0-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `ba10816a` plus FIPS `62249d0`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `334683239154443580b96caea59910b4ae3743a553264d5c79d5e527db3ff246`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2256.2/2228.2 Mbps` with load `2235.3/2166.2 Mbps`;
  constrained-underlay baseline `130.6/130.2 Mbps` with load
  `133.1/131.9 Mbps`; worker-pressure baseline `132.7/131.5 Mbps` with load
  `124.9/130.1 Mbps`; rx-maintenance baseline `2216.2/2249.0 Mbps` with load
  `2188.5/2281.0 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `2871149` makes peer-runtime route choice an owned decision boundary.
  `PeerRuntimeRouteDecision` now carries next-hop selection, peer-route
  snapshot capture, configured send weight, and direct-path bulk-drop
  eligibility together. `PipelinedEndpointPeerRuntimeRouteRequest` consumes that
  decision instead of interleaving route lookup, active-peer snapshot reads,
  route config, and direct-path policy inline. The guard
  `peer_runtime_route_decision_owns_next_hop_snapshot_weight_and_policy` failed
  first because the boundary did not exist, then passed. Verification passed:
  focused guard, `peer_runtime_route`, `pipelined`, default local ownership fast
  tier, broad local unit coverage, focused Linux Docker ownership slice, release
  check, `cargo fmt`, diff check, and private-string scan. Because this touches
  the endpoint/FSP send route decision hot path, it got an exact short-smoke
  perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/2871149-short-smoke-20260609Troute-decision-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-2871149-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `10849b8e` plus FIPS `2871149`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `a0a60dc1f7c643577a8b0fa5f0dde8eab72fff003281990cb316080c24b6d8a1`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2299.7/2294.0 Mbps` with load `2253.2/2256.4 Mbps`;
  constrained-underlay baseline `127.6/128.3 Mbps` with load
  `132.6/133.8 Mbps`; worker-pressure baseline `130.5/126.8 Mbps` with load
  `126.3/130.3 Mbps`; rx-maintenance baseline `2304.4/2258.3 Mbps` with load
  `2187.9/2259.7 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `e8d42c7` makes endpoint/FSP send enter the peer-runtime owner through
  one `Node` facade. `Node::execute_peer_runtime_endpoint_send` now owns the
  transition from endpoint payload send into route decision, UDP target
  resolution, FSP/FMP reservation, and prepared worker-job commit. The guard
  `peer_runtime_endpoint_send_facade_owns_route_dispatch_and_commit` failed
  first because the facade did not exist, then passed. Verification passed:
  focused guard, `peer_runtime`, `pipelined`, broad local `unit` (`174` tests),
  default local ownership fast tier, focused Linux Docker ownership slice,
  warning-clean release check, `cargo fmt`, diff check, and private-string
  scan. Because this touches the endpoint/FSP send hot path, it got an exact
  short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/e8d42c7-short-smoke-20260609Tendpoint-send-facade \
PROJECT_NAME=nostr-vpn-e2e-fips-e8d42c7-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `6ede678e` plus FIPS `e8d42c7`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `3803e015e348ae459b194c14fd5ed6ac080fc2926bfdcebed6fc00d79f189aaf`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2265.0/2223.4 Mbps` with load `2216.6/2247.7 Mbps`;
  constrained-underlay baseline `130.1/131.2 Mbps` with load
  `133.4/133.4 Mbps`; worker-pressure baseline `127.9/129.8 Mbps` with load
  `128.4/128.2 Mbps`; rx-maintenance baseline `2297.0/2210.0 Mbps` with load
  `2238.4/2330.6 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `534beee` makes the session datagram runtime route an owned boundary.
  `SessionDatagramRuntimeRoute` now owns next-hop resolution output, datagram
  path-MTU writes, source-side MMP path-MTU seeding, route-failure marking,
  outbound next-hop recording, and forwarding-originated stats for the
  encrypted link-send path. The guard
  `session_datagram_runtime_route_owns_next_hop_path_mtu_and_bookkeeping`
  failed first because the runtime-route owner did not exist, then passed.
  Verification passed: focused guard, `session_datagram`, broad local `_own`
  (`78` tests), broad local `unit` (`174` tests), default local ownership fast
  tier, focused Linux Docker ownership slice, warning-clean release check,
  `cargo fmt`, diff check, and private-string scan. Because this touches the
  session datagram link-send hot path, it got an exact short-smoke perf
  checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/534beee-short-smoke-20260609Tsession-datagram-route \
PROJECT_NAME=nostr-vpn-e2e-fips-534beee-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `34a40938` plus FIPS `534beee`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `9d83f0542ed61faee0a870b9920aec59023956e0aae379283f7475500610e1f9`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2235.2/2168.9 Mbps` with load `2286.5/2213.5 Mbps`;
  constrained-underlay baseline `127.0/129.6 Mbps` with load
  `131.1/132.7 Mbps`; worker-pressure baseline `133.0/127.8 Mbps` with load
  `130.7/127.4 Mbps`; rx-maintenance baseline `2211.1/2067.6 Mbps` with load
  `2196.9/2226.3 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `12c775a` makes non-worker FSP send construction an owned boundary.
  `SessionFspSendPlan` owns flags, coords, plaintext, timestamp, and
  data/control bookkeeping before sealing. `SealedSessionFspSend` owns the
  reserved counter, ciphertext length, final FSP payload, and bookkeeping
  before datagram assembly. The guard
  `session_fsp_send_plan_owns_flags_coords_wire_and_bookkeeping` failed first
  because the plan/bookkeeping owner did not exist, then passed. Verification
  passed: focused guard, `session_datagram`, broad local `_own` (`79` tests),
  broad local `session` (`227` tests), broad local `endpoint` (`50` tests),
  broad local `unit` (`174` tests), default local ownership fast tier, focused
  Linux Docker ownership slice, warning-clean release check, `cargo fmt`, diff
  check, and private-string scan. Because this touches the non-worker FSP send
  hot path, it got an exact short-smoke perf checkpoint:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/12c775a-short-smoke-20260609Tsession-fsp-send-plan \
PROJECT_NAME=nostr-vpn-e2e-fips-12c775a-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  At nvpn `42f13785` plus FIPS `12c775a`, the smoke passed all four phases.
  `phase-summary.tsv` SHA-256:
  `47fc4d8e9930929cac8055e7b8ef2ed9340d6640a73cb9c6530c159b30911b95`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`
  and contained only the header. Clean-underlay baseline ran at roughly
  `2223.2/2280.3 Mbps` with load `2246.3/2205.6 Mbps`;
  constrained-underlay baseline `127.4/136.1 Mbps` with load
  `132.7/132.9 Mbps`; worker-pressure baseline `119.3/130.2 Mbps` with load
  `130.0/124.0 Mbps`; rx-maintenance baseline `2245.9/2260.5 Mbps` with load
  `2198.2/2188.6 Mbps`. Load and post-load tunnel-ping loss stayed `0%`,
  direct UDP underlay counters advanced in every phase, and worker pressure
  exposed expected decrypt queue-full/bulk-drop counters without a wedge. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- nvpn `86199a9f` plus the uncommitted route-index/Unix receive-burst
  dataplane diff got matched before/after short-smoke evidence before treating
  the hot-path change as safe. The diff keeps exact `/32` and `/128` peer
  routes in an ambiguity-preserving hash index and drains up to `64` ready
  mesh receive events per Unix wake while preserving per-packet cooperation and
  yielding after a full burst. The baseline command used the clean
  `86199a9f` tree and wrote
  `artifacts/fips-perf/86199a9f-before-hotpath-route-recv-burst`; the after
  command used the same knobs and wrote
  `artifacts/fips-perf/86199a9f-after-hotpath-route-recv-burst`:

```sh
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/86199a9f-before-hotpath-route-recv-burst \
PROJECT_NAME=nostr-vpn-e2e-hotpath-before \
./scripts/e2e-fips-perf-regression-docker.sh

NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/86199a9f-after-hotpath-route-recv-burst \
PROJECT_NAME=nostr-vpn-e2e-hotpath-after \
./scripts/e2e-fips-perf-regression-docker.sh
```

  Both runs passed all four phases, and both `failure-summary.tsv` files
  contained only the header. Baseline `phase-summary.tsv` SHA-256:
  `c169bc9cbb36f9a5e49c93001528dfbd69f91e18330992e6ec8aa16474de3514`;
  after `phase-summary.tsv` SHA-256:
  `90a4151530d176f2b744a9972e1e4451cdc66c3d40e5384534f2415c3ac84615`.
  The shared empty-failure summary SHA-256 was
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Clean-underlay before/after was roughly `2183.7/2204.7 Mbps` vs
  `2178.1/2267.3 Mbps`, load `2223.7/2129.4 Mbps` vs
  `2235.5/2240.3 Mbps`; constrained-underlay stayed near the shaped
  `180 Mbit` ceiling at `129.4/130.8 Mbps` vs `129.8/126.5 Mbps`, load
  `129.0/130.7 Mbps` vs `129.4/129.8 Mbps`; worker pressure stayed green at
  `435.1/462.6 Mbps` vs `495.8/443.8 Mbps`, load `449.6/471.3 Mbps` vs
  `412.8/475.9 Mbps`; rx-maintenance stayed green at `2024.6/2199.3 Mbps` vs
  `2122.3/2211.2 Mbps`, load `2247.0/2247.5 Mbps` vs
  `2193.1/2159.8 Mbps`. Load and post-load tunnel-ping loss stayed `0%` in
  every phase, and direct UDP underlay counters advanced in every phase. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- nvpn `4dbcc6c9` plus the uncommitted immutable mesh-runtime snapshot diff got
  matched before/after short-smoke evidence. The diff replaces the
  packet-path `RwLock<FipsMeshRuntime>` with `ArcSwap<FipsMeshRuntime>`: rare
  config updates store a new route-table snapshot, while tunnel send,
  endpoint-data receive, and control/status lookups load the current snapshot
  without taking the old route-table lock. It also removes one duplicate Unix
  `cfg` attribute near the mesh-send helper. The baseline command used clean
  `4dbcc6c9` and wrote
  `artifacts/fips-perf/4dbcc6c9-before-immutable-mesh-runtime`; the after
  command used the same knobs and wrote
  `artifacts/fips-perf/4dbcc6c9-after-immutable-mesh-runtime`:

```sh
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/4dbcc6c9-before-immutable-mesh-runtime \
PROJECT_NAME=nostr-vpn-e2e-immutable-before \
./scripts/e2e-fips-perf-regression-docker.sh

NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/4dbcc6c9-after-immutable-mesh-runtime \
PROJECT_NAME=nostr-vpn-e2e-immutable-after \
./scripts/e2e-fips-perf-regression-docker.sh
```

  Both full runs passed all four phases, and both `failure-summary.tsv` files
  contained only the header. Baseline `phase-summary.tsv` SHA-256:
  `0f035d6f914b51ae8708c307e42e2ec5bf0164701b0a3310bb7eef51923bc4a2`;
  after `phase-summary.tsv` SHA-256:
  `e48b1e101f06e5e2355baa51dbc31dea64c96d78596f129d5560274b78f7c527`.
  The shared empty-failure summary SHA-256 was
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Clean-underlay before/after was roughly `2138.6/2193.7 Mbps` vs
  `2214.3/2187.5 Mbps`, load `2138.3/2149.8 Mbps` vs
  `2121.6/2178.9 Mbps`; constrained-underlay stayed near the shaped
  `180 Mbit` ceiling at `129.8/129.8 Mbps` vs `131.0/130.9 Mbps`, load
  `128.6/128.4 Mbps` vs `129.3/127.0 Mbps`; worker pressure stayed green at
  `449.0/410.5 Mbps` vs `517.1/473.0 Mbps`, load `453.6/438.6 Mbps` vs
  `436.5/488.2 Mbps`; rx-maintenance was noisy before and clean after:
  `2136.9/1261.2 Mbps` vs `2144.7/2258.7 Mbps`, load
  `715.2/1689.6 Mbps` vs `2228.8/2141.8 Mbps`. Load and post-load
  tunnel-ping loss stayed `0%` in every baseline phase. In the first after
  run, worker-pressure reverse-load ping loss was `12.5%`, under that phase's
  deliberate `20%` during-load threshold, and post-load recovery was `0%`.
  A focused after worker-pressure rerun wrote
  `artifacts/fips-perf/4dbcc6c9-after-immutable-mesh-runtime-worker-rerun`,
  passed with `0%` load/post-load tunnel-ping loss, and recorded
  `404.2/430.4 Mbps` baseline TCP with `403.7/335.2 Mbps` load TCP. Its
  `phase-summary.tsv` SHA-256 was
  `66e5b22762ad42eedf3a5040ff058ac5277d7ce8a2d1f1e585b156db7c7be794`;
  its `failure-summary.tsv` SHA-256 was the same empty-failure hash above.
  Direct UDP underlay counters advanced in every phase. This remains
  Linux/Docker evidence, not real Mac-to-Mac validation.
- nvpn `bc35016d` plus the uncommitted configured-peer activity accounting diff
  got matched before/after short-smoke evidence. The diff moves configured-peer
  `tx_bytes`, `rx_bytes`, and `last_seen_at` updates from the per-packet
  `presence` write lock into an `ArcSwap` roster snapshot of per-peer atomics.
  `replace_peers` preserves counters for peers that remain configured and drops
  removed peers; status and ping-cadence reads consult the activity snapshot
  first and fall back to `presence` for ping RTT/error state and non-roster
  peers. Local checks before Docker perf were `cargo fmt --check`,
  `cargo test -p nvpn fips_private_mesh`,
  `cargo test -p nostr-vpn-core fips_mesh`, and `git diff --check`.

```sh
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/bc35016d-before-peer-activity-atomics \
PROJECT_NAME=nostr-vpn-e2e-activity-before \
./scripts/e2e-fips-perf-regression-docker.sh

NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/bc35016d-after-peer-activity-atomics \
PROJECT_NAME=nostr-vpn-e2e-activity-after \
./scripts/e2e-fips-perf-regression-docker.sh
```

  Both full runs passed all four phases, and both `failure-summary.tsv` files
  contained only the header. Baseline `phase-summary.tsv` SHA-256:
  `71c27031df21bd4a216af5c4012f72227dad04311b95ee228fb441fcda69ddfb`;
  after `phase-summary.tsv` SHA-256:
  `f5716144c45aabb59887bda80082979908987a3aa5e81312dfaa71326ed85e1d`.
  The shared empty-failure summary SHA-256 was
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Clean-underlay before/after was noisy at `2107.2/1938.0 Mbps` vs
  `1312.0/1524.8 Mbps`, with load `1680.0/1968.0 Mbps` vs
  `1788.8/1418.8 Mbps`; constrained-underlay stayed near the shaped ceiling at
  `129.8/131.6 Mbps` vs `129.4/129.1 Mbps`, load `130.7/130.4 Mbps` vs
  `129.3/130.8 Mbps`; worker pressure stayed green at `345.7/358.2 Mbps` vs
  `384.7/288.3 Mbps`, load `376.4/372.4 Mbps` vs `133.8/432.1 Mbps`; and
  rx-maintenance stayed green at `1957.9/2120.7 Mbps` vs
  `1957.2/1999.1 Mbps`, load `1772.4/1944.3 Mbps` vs
  `1644.5/1754.9 Mbps`. Load and post-load tunnel-ping loss stayed `0%` in
  every full-run phase, and direct UDP underlay counters advanced in every
  phase. Because the first after worker-pressure load sample was low but still
  green, a focused worker-pressure rerun wrote
  `artifacts/fips-perf/bc35016d-after-peer-activity-atomics-worker-rerun`,
  passed with `0%` load/post-load tunnel-ping loss, and recorded
  `407.7/367.0 Mbps` baseline TCP with `393.7/403.5 Mbps` load TCP. Its
  `phase-summary.tsv` SHA-256 was
  `4f8a283770adfc11ea5f1edd483eac42e292de2208773261fb857d6ad1cb916e`;
  its `failure-summary.tsv` SHA-256 was the same empty-failure hash above.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- nvpn `1ec16d94` plus the uncommitted borrowed inbound packet-source diff got
  matched before/after short-smoke evidence. The diff factors endpoint-data
  admission into one helper, adds a borrowed-source accepted packet form for
  daemon use, keeps the public `PrivatePacket` receive APIs unchanged, and
  changes the daemon-private `FipsPrivateMeshEvent::Packet` to carry only raw
  bytes after `note_rx` consumes the borrowed participant key. Local checks were
  `cargo fmt --check`, `cargo test -p nostr-vpn-core fips_mesh`,
  `cargo test -p nvpn fips_private_mesh`, and `git diff --check`.

```sh
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/1ec16d94-before-borrowed-rx-source \
PROJECT_NAME=nostr-vpn-e2e-rxsource-before \
./scripts/e2e-fips-perf-regression-docker.sh

NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/1ec16d94-after-borrowed-rx-source-full-rerun \
PROJECT_NAME=nostr-vpn-e2e-rxsource-after-full-rerun \
./scripts/e2e-fips-perf-regression-docker.sh
```

  Both recorded full runs passed all four phases, and both
  `failure-summary.tsv` files contained only the header. Baseline
  `phase-summary.tsv` SHA-256:
  `26bc2de507367bd5d9087bd9596b8bc8f95d43da829fcd3abf5082c8b3ab0c5d`;
  after `phase-summary.tsv` SHA-256:
  `77742c5a3a96f8f04aa2311d1d32a83327d5c516b7d2ec370af5e81df28fe18d`.
  The shared empty-failure summary SHA-256 was
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Clean-underlay before/after was noisy at `735.1/557.4 Mbps` vs
  `1511.0/1469.2 Mbps`, load `974.7/597.1 Mbps` vs
  `1304.1/1463.5 Mbps`; constrained-underlay stayed near the shaped ceiling at
  `128.5/132.7 Mbps` vs `134.0/137.1 Mbps`, load `132.0/131.5 Mbps` vs
  `134.4/137.0 Mbps`; worker pressure stayed green at
  `432.6/460.5 Mbps` vs `206.1/351.2 Mbps`, load
  `450.7/425.5 Mbps` vs `375.0/349.0 Mbps`; and rx-maintenance stayed green
  at `2234.5/2212.8 Mbps` vs `1724.1/2120.2 Mbps`, load
  `2185.8/2215.8 Mbps` vs `1944.9/2046.0 Mbps`. Load and post-load
  tunnel-ping loss stayed `0%` in every full-run phase, and direct UDP
  underlay counters advanced in every phase. The first edited full run and
  first focused constrained rerun hit below-threshold constrained throughput
  samples; a clean `HEAD` focused constrained rerun on the same host passed
  with `137.3/137.4 Mbps` baseline and `134.9/137.7 Mbps` load
  (`phase-summary.tsv` SHA-256
  `e4a7023bb90338d761555e407ab0b68bc5d828bc3b3a88baea89395871e0b38b`),
  then the edited focused constrained rerun passed with `138.1/135.2 Mbps`
  baseline and `135.5/134.4 Mbps` load (`phase-summary.tsv` SHA-256
  `56cde8c5057b129296f6467a6bc1bcc612880481171329f2bf98614f2e2016dd`).
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- nvpn `ca315dc2` plus the uncommitted borrowed outbound route diff got
  matched constrained and full-run evidence before commit. The diff adds
  borrowed-peer outbound routing APIs to core, keeps the existing owned
  `OutgoingFipsPacket` APIs for app-core/mobile callers, and changes the daemon
  hot path to account TX bytes with the borrowed participant key after sending.
  The daemon still clones `endpoint_npub` because the FIPS endpoint send API
  owns the command target. Local checks were `cargo fmt --check`,
  `cargo test -p nostr-vpn-core fips_mesh`,
  `cargo test -p nvpn fips_private_mesh`, and `git diff --check`.

```sh
NVPN_PERF_PHASES=constrained-underlay \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/ca315dc2-baseline-outbound-route-constrained-current-host \
PROJECT_NAME=nostr-vpn-e2e-outbound-route-baseline-constrained \
./scripts/e2e-fips-perf-regression-docker.sh

NVPN_PERF_PHASES=constrained-underlay \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/ca315dc2-after-borrowed-outbound-route-revised-constrained \
PROJECT_NAME=nostr-vpn-e2e-outbound-route-after-revised-constrained \
./scripts/e2e-fips-perf-regression-docker.sh

NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/ca315dc2-after-borrowed-outbound-route-revised-full \
PROJECT_NAME=nostr-vpn-e2e-outbound-route-after-revised-full \
./scripts/e2e-fips-perf-regression-docker.sh
```

  All three recorded runs passed, and all `failure-summary.tsv` files contained
  only the header. Clean `HEAD` constrained baseline on the current host was
  `116.4/127.3 Mbps`, load `133.1/137.2 Mbps` (`phase-summary.tsv` SHA-256
  `2af8c974333f750cd005ecc5909709afb08243664ffcb4c2418d55053e530e19`).
  The edited focused constrained rerun was `133.1/130.9 Mbps`, load
  `131.4/130.4 Mbps` (`phase-summary.tsv` SHA-256
  `d57511d2fb6554d54f7296e34a3da515dfba9fcc1ec01be4e87dfbb319afcfed`).
  The edited full run passed all four phases with clean-underlay
  `1874.7/2016.5 Mbps`, load `2095.1/1789.7 Mbps`; constrained-underlay
  `129.7/132.0 Mbps`, load `131.3/128.6 Mbps`; worker pressure
  `389.3/461.0 Mbps`, load `434.7/383.0 Mbps`; and rx-maintenance
  `2016.1/1854.5 Mbps`, load `2055.4/2023.5 Mbps` (`phase-summary.tsv`
  SHA-256
  `adfd9bcef5558c332fbc578409ca559d6fa11c61b0912dd88c15dccfda3e2029`).
  The shared empty-failure summary SHA-256 was
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  An earlier edited shape that cloned an `Arc<FipsPeerActivity>` before await
  failed constrained load twice (`90.8 Mbps` and `89.0 Mbps` forward load);
  that shape was discarded before the green revised runs. This remains
  Linux/Docker evidence, not real Mac-to-Mac validation.
- nvpn `b3a9e17a` plus the uncommitted burst RX timestamp diff got full-run
  evidence before commit. The diff keeps the public `recv_mesh_event` and
  `try_recv_mesh_event` behavior unchanged, but lets the Linux/macOS and
  Windows nonblocking endpoint-drain loops reuse one UNIX-second timestamp for
  an already-ready burst instead of sampling the wall clock for each drained
  packet. The awaited first event in each wake still gets a fresh timestamp.
  Local checks were `cargo fmt --check`, `cargo test -p nvpn fips_private_mesh`,
  and `git diff --check`.

```sh
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/b3a9e17a-after-burst-rx-timestamp-full \
PROJECT_NAME=nostr-vpn-e2e-burst-rx-timestamp-after-full \
./scripts/e2e-fips-perf-regression-docker.sh
```

  The recorded full run passed all four phases and its `failure-summary.tsv`
  contained only the header. The previous full-run comparison point is
  `artifacts/fips-perf/ca315dc2-after-borrowed-outbound-route-revised-full`
  (`phase-summary.tsv` SHA-256
  `adfd9bcef5558c332fbc578409ca559d6fa11c61b0912dd88c15dccfda3e2029`).
  This slice wrote `phase-summary.tsv` SHA-256
  `17a85459314336a97265910ff2feadf3de229d0345c8848693dd525bc1fa30e9`; the
  shared empty-failure summary SHA-256 was
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Clean-underlay was `2205.2/2106.0 Mbps`, load `1731.8/1818.7 Mbps`;
  constrained-underlay was `136.1/137.1 Mbps`, load `133.9/136.4 Mbps`;
  worker pressure was `417.3/360.1 Mbps`, load `362.6/370.0 Mbps`; and
  rx-maintenance was `2004.6/1801.7 Mbps`, load `1988.7/2003.2 Mbps`.
  Load and post-load tunnel-ping loss stayed `0%` in every phase, and direct
  UDP underlay counters advanced in every phase. This remains Linux/Docker
  evidence, not real Mac-to-Mac validation.
- nvpn `c5ce68bf` plus FIPS safety commit `fa7891e` got a coupled
  PeerIdentity-send API/consumer run before commit. FIPS exposes
  `FipsEndpoint::send_to_peer(PeerIdentity, data)` and the nvpn daemon keeps a
  resolved `PeerIdentity` snapshot beside the mesh route table, so configured
  endpoint-data sends can avoid per-packet endpoint npub cloning, endpoint
  cache lookup, and `PeerIdentity::from_npub` parsing. Invalid endpoint npubs
  are intentionally omitted from the snapshot and still fall back to the old
  `send(endpoint_npub, data)` path so existing error behavior is preserved.
  Local checks were FIPS `cargo fmt --check`, FIPS `cargo test -p fips-core
  endpoint`, FIPS `git diff --check`, nvpn `cargo fmt --check`, nvpn `cargo
  test -p nvpn fips_private_mesh` with `--config patch.crates-io.*.path=...`
  pointing at the FIPS safety worktree, and nvpn `git diff --check`. This nvpn
  slice requires the FIPS safety branch or a future FIPS crate release/public
  dependency update; do not compare it against published FIPS crates without
  that dependency shape.

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=<fips-safety-worktree> \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/c5ce68bf-after-peer-identity-send-full \
PROJECT_NAME=nostr-vpn-e2e-peer-identity-send-after-full \
./scripts/e2e-fips-perf-regression-docker.sh

NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=<fips-safety-worktree> \
NVPN_PERF_PHASES=worker-queue-pressure \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/c5ce68bf-after-peer-identity-send-worker-rerun \
PROJECT_NAME=nostr-vpn-e2e-peer-identity-send-worker-rerun \
./scripts/e2e-fips-perf-regression-docker.sh

NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=<fips-safety-worktree> \
NVPN_PERF_PHASES=worker-queue-pressure \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/c5ce68bf-baseline-local-fips-worker-rerun \
PROJECT_NAME=nostr-vpn-e2e-peer-identity-baseline-worker-rerun \
./scripts/e2e-fips-perf-regression-docker.sh
```

  The full coupled run passed all four phases and its `failure-summary.tsv`
  contained only the header. It wrote `phase-summary.tsv` SHA-256
  `92beeba580358d38b057012663eb1e2ef4309c391b12d6f8b14bf406c0627f9f`;
  the shared empty-failure summary SHA-256 was
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Clean-underlay was `1765.2/1730.4 Mbps`, load `1669.6/1548.1 Mbps`;
  constrained-underlay was `138.0/137.5 Mbps`, load `136.2/139.8 Mbps`;
  worker pressure in that full run was `68.5/78.9 Mbps`, load
  `88.3/102.7 Mbps`; and rx-maintenance was `1707.9/1593.6 Mbps`, load
  `1817.4/1916.1 Mbps`. Load and post-load tunnel-ping loss stayed `0%` in
  every phase, and direct UDP underlay counters advanced in every phase.
  Because worker-pressure absolute throughput was much lower than the previous
  full run's `417.3/360.1 Mbps`, a same-window worker-only baseline was run
  against old nvpn `c5ce68bf` plus the same local FIPS patch. That baseline
  produced only `51.5/46.1 Mbps`, load `49.2/20.3 Mbps`
  (`phase-summary.tsv` SHA-256
  `f96d15fd023d60f1dc34fdbcb8bf8cf95bae8a6a94fa8f618e0859737daebc34`),
  while the PeerIdentity worker-only rerun produced `133.6/132.8 Mbps`, load
  `132.6/143.1 Mbps` (`phase-summary.tsv` SHA-256
  `d9f4bb87f4a0314f964be4e8ff2a08fe1d23fba6efc07ba3b9d7ba924b780b4c`).
  Both worker-only `failure-summary.tsv` files contained only the header with
  SHA-256 `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Interpretation: the worker-pressure phase is very sensitive to host/Docker
  CPU scheduling and is only comparable within the same phase/window. It is
  not comparable to clean-underlay results near `2 Gbps`, but the same-window
  baseline does not show a PeerIdentity-send regression. This remains
  Linux/Docker evidence, not real Mac-to-Mac validation.
- nvpn `d5a672ec` plus the FIPS mesh prefix-route-index diff keeps exact peer
  routes in the existing ambiguity-preserving hash index and builds separate
  IPv4/IPv6 fallback indexes only for non-exact routes. Fallback lookup now
  scans longest prefixes first, breaks once a lower prefix cannot beat the
  winner, and preserves equal-prefix ambiguity by participant pubkey. The
  focused guard
  `fallback_prefix_index_skips_exact_routes_and_preserves_longest_prefix` pins
  exact-route exclusion, longest-prefix fallback, IPv4/IPv6 sorting, and
  default-route behavior, and is now included in the `core` fast tier.
  Verification passed with `cargo fmt --check`, the focused
  `nostr-vpn-core fips_mesh` test filter, bash syntax, the `core` fast tier,
  `cargo check -p nostr-vpn-core --release`, and `git diff --check`. Cargo
  wanted to refresh local hashtree path dependency versions in `Cargo.lock`;
  that unrelated churn was not kept.

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/nvpn-prefix-route-index-fips-0846db7-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  The Docker smoke used FIPS `0846db7` and passed all four phases. Its
  `failure-summary.tsv` contained only the header. Clean-underlay was
  `2674.4/2580.9 Mbps`, load `2638.9/2606.5 Mbps`; constrained-underlay was
  `172.3/173.9 Mbps`, load `174.2/174.3 Mbps`; worker pressure was
  `230.9/231.3 Mbps`, load `231.9/230.1 Mbps`; and rx-maintenance was
  `2619.0/2609.2 Mbps`, load `2646.6/2595.2 Mbps`. Load and post-load
  tunnel-ping loss stayed `0%` in every phase, direct UDP underlay counters
  advanced in every phase, and worker pressure exposed the expected decrypt
  queue-full/bulk-drop counters. Phase summary hash:
  `3dd0f33194cf4667dcdce43312db736301d3bd23901767e74f3591278a97a446`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Interpretation: default/exit traffic no longer scans exact per-peer routes,
  but this is a route-lookup cleanup, not a queue or sender rewrite. The
  high-rate reverse side still shows `fmp_worker_queue_wait` around
  `176.7us` clean and `181.7us` under rx-maintenance, so the next dataplane
  bottleneck remains the FIPS worker handoff/ordered send path. This remains
  Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `cb2d944` introduces the first receive-side peer-runtime boundary:
  `PeerRuntimeReceive` parses authenticated FMP plaintext, owns receive
  metadata, applies `PeerLifecycleRegistry` bookkeeping, and returns the
  dispatch tuple that `Node::process_authentic_fmp_plaintext` consumes. This
  preserves the existing worker-bounce/session semantics while moving the
  post-authenticated receive transition toward the same peer-owned shape as
  the send-side runtime helpers. Focused local checks passed:
  `cargo fmt --check`, `cargo test -p fips-core peer_runtime_receive`,
  `cargo test -p fips-core peer_lifecycle_registry_owns_authenticated_fmp_receive_bookkeeping`,
  `cargo test -p fips-core authenticated_lower_priority_packet_does_not_rotate_configured_static_path`,
  `cargo check -p fips-core --release`, and `git diff --check`.

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/cb2d944-peer-runtime-receive-full \
./scripts/e2e-fips-perf-regression-docker.sh
```

  The Docker full run used nvpn `2320c727` plus FIPS `cb2d944` and passed
  clean-underlay, constrained-underlay, worker-queue-pressure, and
  rx-maintenance-fault. Clean-underlay was `2620.9/2557.3 Mbps`, load
  `2610.0/2572.3 Mbps`; constrained-underlay was `162.4/163.1 Mbps`, load
  `164.5/165.5 Mbps`; worker pressure was `233.3/233.0 Mbps`, load
  `228.9/231.8 Mbps`; and rx-maintenance was `2652.8/2630.4 Mbps`, load
  `2626.7/2612.1 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct UDP
  underlay counters advanced in every phase, worker pressure exposed only the
  expected decrypt queue-full/bulk-drop counters, and `failure-summary.tsv`
  contained only the header. Phase summary hash:
  `3371d4abc1211b5630036bd7d2262e1927b289406ec7ac081e94fa2a4b778756`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Interpretation: this is an accepted architecture slice, not a throughput
  optimization; endpoint/event residence is still visible in the hundreds of
  microseconds, so the next larger step remains moving endpoint-data delivery
  behind a worker/peer-runtime owner that can delete the rx-loop bounce with
  safety evidence. This remains Linux/Docker evidence, not real Mac-to-Mac
  validation.
- FIPS `22f9dbf` moves endpoint-event sender, rx-loop batch scope, and backlog
  accounting into `EndpointEventRuntime`, leaving `Node` as a facade for the
  existing receive-loop call sites. This is the delivery-side companion to
  `PeerRuntimeReceive`: the current rx loop still owns the runtime, but the
  endpoint-data delivery state is now one object that a future peer/shard
  receive owner can move instead of three ambient `Node` fields. Focused local
  checks passed: `cargo fmt --check`,
  `cargo test -p fips-core endpoint_event_runtime`,
  `cargo test -p fips-core endpoint_event_batch_scope`,
  `cargo test -p fips-core endpoint_event_queue_owns_backlog_message_count`,
  `cargo test -p fips-core endpoint`, `cargo test -p fips-core node::tests::session`,
  `cargo check -p fips-core --release`, and `git diff --check`.

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/22f9dbf-endpoint-event-runtime-full \
./scripts/e2e-fips-perf-regression-docker.sh
```

  The Docker full run used nvpn `034bab8b` plus FIPS `22f9dbf` and passed all
  four phases. Clean-underlay was `2688.4/2570.2 Mbps`, load
  `2656.4/2640.5 Mbps`; constrained-underlay was `166.0/163.7 Mbps`, load
  `165.5/164.1 Mbps`; worker pressure was `234.5/232.6 Mbps`, load
  `231.3/228.6 Mbps`; and rx-maintenance was `2629.9/2699.0 Mbps`, load
  `2653.3/2679.5 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct UDP
  underlay counters advanced in every phase, worker pressure exposed only the
  expected decrypt queue-full/bulk-drop counters, and `failure-summary.tsv`
  contained only the header. Phase summary hash:
  `f6dda023104ebcf3bbbb899f54b55551e5c554e505b61e39dee28a33a96c296b`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Interpretation: this is accepted delivery-ownership cleanup with neutral
  same-harness perf, not a solved queue-residence issue. High-rate
  clean/rx-maintenance still show endpoint-event wait in the hundreds of
  microseconds on the receive-heavy side, so the next bigger runtime step
  should make endpoint-data delivery worker/shard-owned and delete the rx-loop
  bounce only with before/after evidence. This remains Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `5721357` extracts the established FSP receive/open path into
  `SessionRuntimeReceive`. The new owner keeps FSP open/replay, K-bit cutover,
  decrypt-failure recovery gating, MMP receive/path-MTU bookkeeping,
  authenticated remote identity lookup, and dispatch metadata in one movable
  boundary, while `Node::handle_encrypted_session_msg` remains the post-borrow
  dispatcher. This is the FSP-side companion to `PeerRuntimeReceive` and
  `EndpointEventRuntime`; it does not add a queue or change the current
  decrypt-worker bounce. Focused local checks passed: `cargo fmt --check`,
  `cargo test -p fips-core session_runtime_receive`,
  `cargo test -p fips-core node::handlers::session`,
  `cargo test -p fips-core endpoint`,
  `cargo test -p fips-core node::tests::session`,
  `cargo check -p fips-core --release`, `git diff --check`, and full
  `cargo test -p fips-core` (`1504` passed, `2` ignored; doctests `2` ignored).
  nvpn local-FIPS checks passed with the same FIPS worktree:
  `cargo test -p nvpn endpoint_data_runtime_sends_and_receives_raw_packet_batch --features embedded-fips`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips` (`59`
  passed).

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/session-runtime-receive-full \
./scripts/e2e-fips-perf-regression-docker.sh
```

  The Docker full run used nvpn `941cefd1` plus FIPS `5721357` and passed all
  four phases. Clean-underlay was `2686.7/2665.1 Mbps`, load
  `2676.0/2708.4 Mbps`; constrained-underlay was `166.5/167.0 Mbps`, load
  `166.9/165.7 Mbps`; worker pressure was `231.9/233.5 Mbps`, load
  `233.6/235.1 Mbps`; and rx-maintenance was `2664.0/2721.9 Mbps`, load
  `2674.4/2653.9 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct UDP
  underlay counters advanced in every phase, worker pressure exposed only the
  expected decrypt queue-full/bulk-drop counters, and `failure-summary.tsv`
  contained only the header. Phase summary hash:
  `d7d20dfeb60af299d313995b61bb9ede5f71e034f06b6099d94d94e986dbbfe9`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Interpretation: this is accepted FSP receive ownership cleanup with healthy
  same-harness performance. It is not a solved queue-residence issue:
  high-rate clean/rx-maintenance still show endpoint-event wait around
  `375-391us` on the receive-heavy side, so the next larger runtime step
  should move FMP+FSP receive state and endpoint-data delivery behind the
  worker/shard owner before deleting the rx-loop bounce. This remains
  Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `e524e14` replaces the decrypt-worker session state's optional
  `source_npub` string with an authenticated `source_peer: PeerIdentity`
  copied from the active peer during worker registration. This is a small
  ownership cleanup, not a dataplane algorithm change: the worker still owns
  only FMP open/replay and still bounces all authenticated link messages back
  to the rx loop for FSP/session dispatch. The value of the slice is
  architectural: future endpoint-data direct delivery can now reuse the
  worker-owned source identity that matches `FipsEndpointMessage` rather than
  reparsing or trusting an optional display string. Focused checks passed:
  `cargo fmt --check`,
  `cargo test -p fips-core owned_session_state_carries_authenticated_source_peer -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo check -p fips-core --release`, `git diff --check`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks passed with the same FIPS
  worktree:
  `cargo test -p nvpn endpoint_data_runtime_sends_and_receives_raw_packet_batch --features embedded-fips`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips` (`59`
  passed). No Docker perf rerun was taken because no per-packet queueing,
  routing, crypto, sender, or delivery semantics changed; the latest full
  Docker perf checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `1b20991` continues the same worker-handoff cleanup: `DecryptFallback`
  and `DecryptFailureReport` now carry authenticated `source_peer:
  PeerIdentity`, and `DecryptJob` no longer carries a raw `source_node_addr`
  just to echo it back to the rx loop. The rx loop still derives the peer's
  node address at the processing edge and still owns FSP/session dispatch, so
  the current FMP-only worker bounce semantics are preserved. This makes the
  worker-to-rx event shape match endpoint delivery's source-peer model and
  trims one address field from the per-packet worker job. Focused checks
  passed: `cargo fmt --check`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo check -p fips-core --release`, `git diff --check`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks passed with the same FIPS
  worktree:
  `cargo test -p nvpn endpoint_data_runtime_sends_and_receives_raw_packet_batch --features embedded-fips`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips` (`59`
  passed). No Docker perf rerun was taken because no queueing, routing, crypto,
  sender, or delivery semantics changed; the latest full Docker perf checkpoint
  remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `b995327` replaces the loose canonical post-FMP receive helper arguments
  with an `AuthenticatedFmpPlaintext` envelope carrying authenticated
  `source_peer: PeerIdentity`, transport/path facts, packet length, FMP counter,
  FMP flags, and the borrowed plaintext slice. `PeerRuntimeReceive` now derives
  its node address and CE/SP flags from that envelope, so worker fallback,
  pending-K-bit, and synchronous test-mode FMP receive all enter the same typed
  source-peer boundary without changing current rx-loop FSP/session dispatch.
  Focused checks passed: `cargo fmt --check`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core authenticated_lower_priority_packet_does_not_rotate_configured_static_path -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, `git diff --check`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks passed with the same FIPS
  worktree:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and
  `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker perf checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `12b9b53` carries the same authenticated handoff below
  `PeerRuntimeReceive`: `PeerRuntimeReceiveDispatch` now converts non-empty FMP
  link plaintext into an `AuthenticatedLinkMessage` carrying source peer,
  message type, payload, and CE flag, and `dispatch_link_message` consumes that
  typed envelope instead of loose node-address/raw-bytes/CE arguments. Empty
  link messages still drop before dispatch, and the existing rx-loop
  link/session handlers still own FSP/session dispatch, so this is a boundary
  simplification rather than a behavior change. Focused checks passed:
  `cargo fmt --check`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo check -p fips-core --release`, `git diff --check`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks passed with the same FIPS
  worktree:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and
  `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker perf checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `a25bd87` carries the authenticated handoff through the SessionDatagram
  edge: the 0x00 link-dispatch arm now turns `AuthenticatedLinkMessage` into an
  `AuthenticatedSessionDatagram` with previous-hop peer identity, payload, and
  CE flag, and `handle_session_datagram` consumes that envelope instead of loose
  previous-hop/raw-bytes/CE arguments. Forwarding/local delivery, route
  learning, FSP receive, and endpoint delivery behavior are intentionally
  unchanged; this is another typed ownership boundary needed before deleting
  the rx-loop bounce. Focused checks passed: `cargo fmt --check`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, `git diff --check`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks passed with the same FIPS
  worktree:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and
  `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker perf checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `138661f` extends the same receive boundary into local session payload
  delivery and established encrypted-FSP receive: `LocalSessionPayload` carries
  source node, authenticated previous-hop peer, payload, path MTU, and CE flag,
  then converts to `EncryptedSessionPayload` for FSP open/replay. Session setup,
  route learning, endpoint delivery, CE marking, and rx-loop dispatch behavior
  are intentionally unchanged; this removes another loose source/payload/MTU/
  CE/previous-hop argument cluster before the future worker/shard runtime
  deletes the endpoint-data bounce. Focused checks passed: `cargo fmt --check`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, `git diff --check`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks passed with the same FIPS
  worktree:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and
  `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker perf checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `fb278ad` carries endpoint-data delivery as one source-attributed
  envelope after established FSP receive: `EndpointDataDelivery` now owns the
  authenticated source peer plus payload, `EndpointEventRuntime` consumes that
  object through `deliver_endpoint_data`, and the embedded endpoint facade tests
  build the same delivery object for internal batches. Endpoint event batching,
  backlog accounting, rx-loop dispatch, and the no-extra-allocation
  endpoint-data receive path are intentionally unchanged; this removes the last
  loose source-peer/payload pair at the endpoint delivery edge before a future
  peer/session runtime can move delivery off the rx-loop bounce. Focused checks
  passed: `cargo fmt --check`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core endpoint_event_batch_scope -- --nocapture`,
  `cargo test -p fips-core endpoint_event_queue_owns_backlog_message_count -- --nocapture`,
  `cargo test -p fips-core recv_batch_into_splits_internal_endpoint_batches_without_reordering -- --nocapture`,
  `cargo test -p fips-core try_recv_drains_pending_internal_endpoint_batch_tail -- --nocapture`,
  `cargo test -p fips-core blocking_recv_drains_pending_internal_endpoint_batch_tail -- --nocapture`,
  `cargo test -p fips-core recv_batch_drains_ready_loopback_endpoint_data -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, `git diff --check`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks passed with the same FIPS
  worktree:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and
  `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker perf checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `b8f3471` carries the post-open established-FSP dispatch as one
  `AuthenticatedSessionMessage`: source peer, plaintext, inner msg type,
  inner flags, and timestamp now return from `SessionRuntimeReceive` as one
  object instead of five loose values. The rx loop still dispatches the same
  message types and still learns the same reverse route after the session borrow
  drops, but endpoint-data delivery conversion now lives on the authenticated
  message object and trims the inner header in place before building
  `EndpointDataDelivery`. Focused checks passed: `cargo fmt --check`,
  `cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, `git diff --check`, and full
  `cargo test -p fips-core -- --nocapture` (`1506` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks passed with the same FIPS
  worktree:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and
  `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker perf checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- Reference-source recheck: wireguard-go `f333402`, BoringTun `cdf3b24`, and
  Tailscale `7a43e41a2` still support the architecture plan's direction.
  wireguard-go uses bounded global crypto/handshake queues plus per-peer
  sequential send/receive queues, with Linux/Android batching and Darwin
  single-packet UDP/TUN fallbacks. Tailscale splits packet crypto from
  endpoint/path selection and keeps Linux batching behind a narrow optional API.
  BoringTun keeps peer tunnel state and pending packets near the peer, caps
  handshake-blocked packet queues, uses bounded fd/event work, and makes
  connected UDP optional per runtime/config. These are design inputs for
  `LinkRegistry`, `ActivePeerRegistry`, `PeerLifecycleRegistry`, future
  `PeerRuntime`, bounded lanes, Linux batching, and a simple macOS sender
  pending real Mac-to-Mac soak evidence.

## Periodic architecture checkpoint - 2026-06-10

Summary:
- Rechecked the big-picture shape against the current FIPS receive/session
  code, local reference-source lessons, and the comparison harness gate.

Evidence:

```sh
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
```

Result:
- The lightweight safety/comparison harness gate passed: bash syntax checks,
  Docker perf/platform/soak harness self-tests, host-pair soak harness
  self-test, host-pair comparison harness self-test, comparison runner
  self-test, userspace WireGuard host-pair harness self-test, and clean/stress
  BoringTun + wireguard-go dry-run matrix mapping.
- Current source shape still matches the architecture-plan diagnosis. FIPS now
  has strong typed receive and dispatch envelopes
  (`PeerRuntimeReceive`, `AuthenticatedLinkMessage`,
  `SessionRuntimeReceive`, `AuthenticatedSessionMessage`,
  `AuthenticatedSessionDispatch`, and `EndpointDataDelivery`), but the packet
  mover is not yet as simple as wireguard-go or BoringTun. The decrypt worker
  owns FMP open/replay and then bounces every authenticated link message back
  to the rx loop so the old FSP/session dispatch path remains authoritative.
- wireguard-go remains the clearest reference for bounded global worker queues
  plus per-peer sequential send/receive ownership; BoringTun remains the
  reference for keeping tunnel state, timers, replay, endpoint, and pending
  packets near the peer owner; Tailscale remains the reference for keeping
  path/liveness/rebind/status outside the packet crypto mover but observable.
- Recommendation: do a bounded larger refactor next, not a blank-page rewrite
  and not more envelope-only cleanup. The next slice should introduce a real
  peer/session runtime owner for one behavior surface and be accepted only if it
  deletes the worker-to-rx-loop bounce, a duplicate hot path, or scattered
  mutable map peeks while preserving priority/bulk reserves, direct-route
  continuity, MMP/rekey/liveness progress, and machine-readable pressure
  evidence.

No live host-pair reference row, wireguard-go throughput row, long soak,
Docker perf rerun, mobile packet-path check, or real Mac-to-Mac/screenshare
validation was run for this architecture checkpoint.

## Session registry owns established FSP open - 2026-06-10

Summary:
- Moved the established-FSP hot receive lookup/open edge behind
  `SessionRegistry`.

Result:
- FIPS `dd8f3e3` adds `EstablishedFspReceive` and
  `SessionRegistry::open_established_fsp_frame`, so the rx loop supplies parsed
  wire facts but no longer performs the direct `sessions.get_mut(src_addr)`
  borrow for established FSP open/replay, K-bit cutover, decrypt-failure
  accounting, MMP receive/path-MTU bookkeeping, and dispatch metadata.
- `SessionDispatchCommit` now records application-data receive completion
  through `SessionRegistry::record_receive_completion`, keeping counter/touch
  mutation behind the same session owner.
- The new guard
  `session_registry_owns_established_fsp_open_lookup_and_bookkeeping` proves
  the registry-owned success path resets decrypt-failure accounting, records
  inbound-frame time, returns the authenticated endpoint-data message, and
  returns `UnknownSession` without caller-side map access.

Verification:

```sh
cargo fmt --check
git diff --check
cargo check -p fips-core --release
cargo test -p fips-core session_registry_owns_established_fsp_open_lookup_and_bookkeeping -- --nocapture
cargo test -p fips-core session_runtime_receive -- --nocapture
cargo test -p fips-core authenticated_session_dispatch -- --nocapture
cargo test -p fips-core authenticated_session_message -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test \
  --config 'patch.crates-io.fips-core.path="/path/to/fips-dataplane-safety/crates/fips-core"' \
  --config 'patch.crates-io.fips-endpoint.path="/path/to/fips-dataplane-safety/crates/fips-endpoint"' \
  --config 'patch.crates-io.fips-identity.path="/path/to/fips-dataplane-safety/crates/fips-identity"' \
  -p nvpn fips_private_mesh --features embedded-fips -- --nocapture
```

Full FIPS package result: `1508` passed, `2` ignored; doctests `2` ignored.
Direct nvpn embedded-FIPS mesh result with local FIPS patch config: `59`
passed.

No Docker perf rerun was taken because this is an ownership-boundary change
around the existing session-registry lookup and receive bookkeeping, not a
queueing, routing, crypto algorithm, sender, batching, or delivery semantic
change. The latest Docker perf checkpoint remains the current throughput/
liveness checkpoint until the next behavior-touching runtime slice.

## Established FSP wire receive owner - 2026-06-10

Summary:
- FIPS `66b460a` moves established encrypted-FSP wire parsing into
  `EstablishedFspWire`.
- The new owner parses the FSP encrypted header, owns the CP-coordinate
  ciphertext offset, carries optional coord-cache warmup, and converts to
  `EstablishedFspReceive` for the session registry open/replay edge.
- `Node::handle_encrypted_session_msg` now chooses between parse errors,
  applies coord warmup, and hands the typed receive object to
  `SessionRegistry`; it no longer open-codes encrypted coordinate parsing or
  mutates `coord_cache` directly on this hot edge.

Result:
- Accepted as a small but real ownership slice, not envelope-only cleanup. It
  removes one packet parser/cache mutation responsibility from the rx loop
  while preserving the same established-FSP wire format, FSP open/replay path,
  MMP receive bookkeeping, endpoint delivery, and failure logging.
- The architecture decision remains: continue bounded larger peer/session
  runtime refactors with benchmark gates; do not start a blank-page rewrite.
  The next larger change should delete the worker-to-rx-loop bounce, a duplicate
  hot path, or scattered mutable map peeks for one behavior surface.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core established_fsp_wire_owns_ciphertext_offset_and_coord_warmup -- --nocapture
cargo test -p fips-core session_registry_owns_established_fsp_open_lookup_and_bookkeeping -- --nocapture
cargo test -p fips-core test_coord_cache_warming_encrypted_msg_with_coords -- --nocapture
cargo test -p fips-core session_runtime_receive -- --nocapture
cargo test -p fips-core authenticated_session_dispatch -- --nocapture
cargo test -p fips-core authenticated_session_message -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo check -p fips-core --release
cargo test -p fips-core -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
```

Full FIPS package result: `1509` passed, `2` ignored; doctests `2` ignored.
nvpn local-FIPS result: `nvpn-hotpath` passed all six checks.
Comparison dry-run result: harness syntax/self-tests passed and the clean/stress
BoringTun + wireguard-go matrix mapping passed.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing encrypted-FSP parsing/coord-cache
warmup, not a queueing, routing, crypto algorithm, sender, batching, or delivery
semantic change. The latest Docker perf checkpoint remains the current
throughput/liveness checkpoint until the next behavior-touching runtime slice.

## Early encrypted-data handshake resend owner - 2026-06-10

Summary:
- FIPS `166b226` moves early-encrypted-data handshake resend budget decisions
  into `SessionRegistry`.
- `SessionRegistry::prepare_handshake_resend_after_early_encrypted_data` now
  owns the session lookup, stored payload check, resend-budget check, and
  budget-exhausted payload clear. `SessionRegistry::record_handshake_resend`
  owns the post-send resend counter/timer mutation.
- `Node::resend_handshake_after_early_encrypted_data` now only asks for a
  resend decision, sends the fresh `SessionDatagram`, and records successful
  send completion through the registry.

Result:
- Accepted as a control-path ownership slice for session/rekey continuity under
  reordered traffic. It removes direct session-entry peeks/mutations from the
  rx-loop early-data slow path while preserving the same resend behavior,
  budget exhaustion logging, stored-payload clearing, and post-send accounting.
- This is still not the endpoint-data fast-path rewrite and does not claim a
  throughput change. It is one more registry-owned control surface that a
  future peer/session runtime can consume before deleting the worker-to-rx-loop
  bounce.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core session_registry_owns_early_encrypted_handshake_resend_budget -- --nocapture
cargo test -p fips-core session_registry_owns_established_fsp_open_lookup_and_bookkeeping -- --nocapture
cargo test -p fips-core session_runtime_receive -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core timeout -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Full FIPS package result: `1510` passed, `2` ignored; doctests `2` ignored.
nvpn local-FIPS result: `nvpn-hotpath` passed all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing handshake-resend control state, not
a queueing, routing, crypto algorithm, sender, batching, or delivery semantic
change. The latest Docker perf checkpoint remains the current throughput/
liveness checkpoint until the next behavior-touching runtime slice.

## Timeout session handshake resend owner - 2026-06-10

Summary:
- FIPS `bf00971` moves timeout-driven session handshake selection, established
  resend-budget cleanup, and successful resend accounting into
  `SessionRegistry`.
- `SessionRegistry::timed_out_pending_handshakes` now owns pending-handshake
  timeout selection, `exhaust_established_handshake_resend_budgets` owns
  established/rekey resend exhaustion cleanup, and
  `due_session_handshake_resends` plus
  `record_scheduled_session_handshake_resend` own the periodic resend decision
  and backoff accounting.
- `Node::resend_pending_session_handshakes` now removes timed-out sessions,
  sends queued datagrams, and logs outcomes without directly peeking/mutating
  session entries for timeout/resend policy.

Result:
- Accepted as a control/liveness ownership slice. It preserves the existing
  timeout thresholds, resend budget, backoff math, stale pending-session removal,
  direct-fallback degradation, and rekey-abandon behavior while reducing the
  rx-loop/session-timeout handler to orchestration.
- This is still not a throughput claim. It makes the next peer/session runtime
  refactor easier by putting one more handshake-continuity policy surface behind
  the session owner before deleting larger bounces or duplicate hot paths.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core session_registry_owns_timeout_handshake_selection_and_resend_accounting -- --nocapture
cargo test -p fips-core session_registry_owns_exhausted_established_handshake_cleanup -- --nocapture
cargo test -p fips-core timeout -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo check -p fips-core --release
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused timeout tests passed; full FIPS package result: `1512` passed, `2`
ignored; doctests `2` ignored. nvpn local-FIPS result: `nvpn-hotpath` passed
all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing timeout/resend control state, not a
queueing, routing, crypto algorithm, sender, batching, or delivery semantic
change. The latest Docker perf checkpoint remains the current throughput/
liveness checkpoint until the next behavior-touching runtime slice.

## FSP rekey msg3 resend owner - 2026-06-10

Summary:
- FIPS `2bf6ab1` moves FSP rekey SessionMsg3 due-resend selection,
  max-budget exhaustion cleanup, and successful resend accounting into
  `SessionRegistry`.
- `SessionRegistry::exhaust_due_rekey_msg3_resend_budgets` now owns the
  "due and out of budget" abort decision, `due_rekey_msg3_resends` owns the
  retained msg3 payload selection, and
  `record_scheduled_rekey_msg3_resend` owns the backoff counter/timer update.
- `Node::resend_pending_session_msg3` now sends the selected `SessionDatagram`
  and logs outcomes without directly iterating/mutating session entries for
  rekey msg3 resend policy.

Result:
- Accepted as a rekey-continuity ownership slice. It preserves the existing
  due-time check, resend budget, backoff math, retained msg3 payload behavior,
  and `abandon_rekey` cleanup while reducing the rekey tick path to
  orchestration.
- This is not a throughput claim and does not touch queueing, routing, crypto,
  sender, batching, or endpoint delivery. It makes the next peer/session
  runtime step simpler by putting another FSP rekey policy surface behind the
  session owner.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core session_registry_owns_rekey_msg3_resend_selection_and_accounting -- --nocapture
cargo test -p fips-core session_registry_owns_exhausted_rekey_msg3_cleanup -- --nocapture
cargo test -p fips-core rekey -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core timeout -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused rekey tests passed; full FIPS package result: `1514` passed, `2`
ignored; doctests `2` ignored. nvpn local-FIPS result: `nvpn-hotpath` passed
all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing FSP rekey msg3 control state, not a
queueing, routing, crypto algorithm, sender, batching, or delivery semantic
change. The latest Docker perf checkpoint remains the current throughput/
liveness checkpoint until the next behavior-touching runtime slice.

## FSP rekey tick owner - 2026-06-10

Summary:
- FIPS `3e803f7` moves periodic FSP rekey tick planning, due cutover mutation,
  and due drain completion behind `SessionRegistry`.
- `SessionRegistry::plan_session_rekey_tick` now owns cutover, drain, and
  fresh-rekey initiation selection. `cutover_due_session_rekey` and
  `complete_due_session_rekey_drain` re-check due conditions before mutating
  session state.
- `Node::check_session_rekey` now supplies timing/config inputs, logs completed
  cutover/drain actions, and initiates registry-selected new rekeys. It no
  longer directly iterates session entries to choose FSP rekey tick policy.

Result:
- Accepted as a rekey-continuity ownership slice. It preserves the current
  cutover delay, drain-window behavior, dampening check, msg3-in-flight guard,
  jittered timer trigger, send-counter trigger, and the existing behavior where
  an expired drain may also be eligible for a fresh rekey in the same tick.
- This is still not a throughput claim. It reduces one more periodic
  control-path policy surface to a session-owner decision before any larger
  peer/session runtime move.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core session_registry_owns_rekey_tick_selection -- --nocapture
cargo test -p fips-core session_registry_owns_rekey_tick_cutover_and_drain_mutation -- --nocapture
cargo test -p fips-core rekey -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core timeout -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused rekey tests passed; full FIPS package result: `1516` passed, `2`
ignored; doctests `2` ignored. nvpn local-FIPS result: `nvpn-hotpath` passed
all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing FSP rekey tick control state, not a
queueing, routing, crypto algorithm, sender, batching, or delivery semantic
change. The latest Docker perf checkpoint remains the current throughput/
liveness checkpoint until the next behavior-touching runtime slice.

## FSP rekey initiation owner - 2026-06-10

Summary:
- FIPS `cdefb80` moves direct FSP session rekey initiation eligibility and the
  successful post-send state install behind `SessionRegistry`.
- `SessionRegistry::prepare_session_rekey_initiation` now owns established
  session eligibility, missing-session handling, in-progress rekey suppression,
  pending-new-session suppression, and the remote public key used to build the
  rekey initiator handshake.
- `SessionRegistry::record_session_rekey_initiated` now owns installing the
  rekey handshake, initiator flag, resend payload/timer, and decrypt-failure
  reset after the SessionMsg1 send succeeds. Route availability remains a
  `Node`/route-owner concern before session rekey initiation is attempted.

Result:
- Accepted as another rekey-continuity ownership slice. It keeps route lookup,
  handshake construction, SessionMsg1 wire creation, and send policy unchanged
  while removing another direct session-entry policy/mutation surface from
  `Node::initiate_session_rekey`.
- This is not a throughput claim. It is a control-state ownership cleanup that
  makes the eventual peer/session runtime less likely to lose rekey progress
  under contention or route churn.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core session_registry_owns_session_rekey_initiation_eligibility -- --nocapture
cargo test -p fips-core session_registry_owns_session_rekey_initiation_state_install -- --nocapture
cargo test -p fips-core rekey -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core timeout -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused rekey initiation guards passed; focused rekey/session/timeout/
decrypt-failure/forwarding/peer-runtime/decrypt-worker/endpoint-event checks
passed; full FIPS package result: `1518` passed, `2` ignored; doctests `2`
ignored. nvpn local-FIPS result: `nvpn-hotpath` passed all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing FSP rekey initiation control
state, not a queueing, routing, crypto algorithm, sender, batching, or delivery
semantic change. The latest Docker perf checkpoint remains the current
throughput/liveness checkpoint until the next behavior-touching runtime slice.

## FMP rekey tick owner - 2026-06-10

Summary:
- FIPS `373c867` moves periodic FMP link rekey tick planning, initiator-side
  cutover mutation, and drain completion mutation behind
  `PeerLifecycleRegistry`.
- `PeerLifecycleRegistry::plan_fmp_rekey_tick` now owns active-peer selection
  for FMP cutover, drain completion, and fresh FMP rekey initiation, including
  healthy/session gating, responder-pending cutover suppression, dampening,
  jittered age trigger, and send-counter trigger.
- `cutover_due_fmp_rekey` and `complete_due_fmp_rekey_drain` defensively
  re-check due conditions before mutating active peer state. `Node` still owns
  the external side effects after those mutations: current-session worker
  registration, old session-index deregistration, index free, and logging.

Result:
- Accepted as a rekey-continuity ownership slice. It keeps FMP msg1 creation,
  send policy, pending-outbound dispatch registration, decrypt-worker/session
  index cleanup side effects, and existing responder K-bit behavior unchanged
  while removing the raw active-peer rekey tick policy loop from
  `Node::check_rekey`.
- This is not a throughput claim. It is a control-state ownership cleanup that
  moves another long-run liveness/rekey surface toward the peer lifecycle owner
  before any larger peer/session runtime rewrite.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core peer_lifecycle_registry_owns_fmp_rekey_tick_selection -- --nocapture
cargo test -p fips-core peer_lifecycle_registry_owns_fmp_rekey_tick_cutover_and_drain_mutation -- --nocapture
cargo test -p fips-core fmp_rekey -- --nocapture
cargo test -p fips-core rekey -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core timeout -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused FMP rekey tick guards passed; focused FMP rekey/rekey/session/timeout/
decrypt-failure/forwarding/peer-runtime/decrypt-worker/endpoint-event checks
passed; full FIPS package result: `1520` passed, `2` ignored; doctests `2`
ignored. nvpn local-FIPS result: `nvpn-hotpath` passed all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing FMP rekey tick control state, not
a queueing, routing, crypto algorithm, sender, batching, or delivery semantic
change. The latest Docker perf checkpoint remains the current throughput/
liveness checkpoint until the next behavior-touching runtime slice.

## FMP rekey msg1 resend owner - 2026-06-10

Summary:
- FIPS `4ac092a` moves FMP rekey msg1 due-resend selection, exhausted-budget
  selection, abandon mutation, and successful resend accounting behind
  `PeerLifecycleRegistry`.
- `due_fmp_rekey_msg1_resends` snapshots the transport id, current remote
  address, and msg1 payload needed for a retry without leaving `Node` to loop
  over raw active-peer policy.
- `exhaust_fmp_rekey_msg1_resend_budgets` clears exhausted in-progress rekeys
  and returns the pending cleanup facts. `Node` still owns the transport send,
  pending-outbound removal, session-index deregistration, index free, and
  logging side effects.

Result:
- Accepted as a rekey-continuity ownership slice. It keeps resend timing,
  backoff, max-resend policy, transport dispatch, and cleanup side effects
  behaviorally unchanged while removing another long-run FMP rekey policy loop
  from `Node::resend_pending_rekeys`.
- This is not a throughput claim. It is another small control-state boundary
  that makes the eventual peer/session runtime less likely to strand rekey
  progress under CPU contention, path drift, or route churn.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core peer_lifecycle_registry_owns_fmp_rekey_msg1_resend_selection_and_accounting -- --nocapture
cargo test -p fips-core peer_lifecycle_registry_owns_exhausted_fmp_rekey_msg1_cleanup -- --nocapture
cargo test -p fips-core fmp_rekey -- --nocapture
cargo test -p fips-core rekey -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core timeout -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused FMP msg1 resend owner guards passed; focused FMP rekey/rekey/session/
timeout/decrypt-failure/forwarding/peer-runtime/decrypt-worker/endpoint-event
checks passed; full FIPS package result: `1522` passed, `2` ignored; doctests
`2` ignored. nvpn local-FIPS result: `nvpn-hotpath` passed all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing FMP rekey msg1 resend control
state, not a queueing, routing, crypto algorithm, sender, batching, or delivery
semantic change. The latest Docker perf checkpoint remains the current
throughput/liveness checkpoint until the next behavior-touching runtime slice.

## FMP rekey initiation owner - 2026-06-10

Summary:
- FIPS `46e2c8e` moves FMP rekey initiation target selection and successful
  post-send state installation behind `PeerLifecycleRegistry`.
- `prepare_fmp_rekey_initiation` now owns the active-peer snapshot used to
  initiate an FMP link rekey: transport id, current remote address, link id,
  and authenticated peer public key.
- `record_fmp_rekey_initiated` now owns installing the in-progress rekey
  handshake, rekey session index, msg1 payload, resend timer, and resend count
  reset after msg1 has been sent. `Node` still owns index allocation/free,
  Noise msg1 construction, transport send, pending-outbound registration, and
  logging.

Result:
- Accepted as a rekey-continuity ownership slice. It keeps FMP msg1 wire
  construction, send policy, missing transport/address behavior, pending
  outbound dispatch registration, and decrypt-failure recovery behavior
  unchanged while removing another raw active-peer peek/mutation pair from
  `Node::initiate_rekey`.
- This is not a throughput claim. It closes the FMP-side symmetry with the
  existing FSP rekey initiation owner and makes the eventual peer/session
  runtime less likely to lose rekey progress during CPU contention, traversal
  churn, or path drift.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core peer_lifecycle_registry_owns_fmp_rekey_initiation_target_snapshot -- --nocapture
cargo test -p fips-core peer_lifecycle_registry_owns_fmp_rekey_initiation_state_install -- --nocapture
cargo test -p fips-core fmp_rekey -- --nocapture
cargo test -p fips-core rekey -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core timeout -- --nocapture
cargo test -p fips-core decrypt_failure -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo test -p fips-core decrypt_worker -- --nocapture
cargo test -p fips-core endpoint_event_runtime -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused FMP rekey initiation owner guards passed; focused FMP rekey/rekey/
session/timeout/decrypt-failure/forwarding/peer-runtime/decrypt-worker/
endpoint-event checks passed; full FIPS package result: `1524` passed, `2`
ignored; doctests `2` ignored. nvpn local-FIPS result: `nvpn-hotpath` passed
all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing FMP rekey initiation control
state, not a queueing, routing, crypto algorithm, sender, batching, or delivery
semantic change. The latest Docker perf checkpoint remains the current
throughput/liveness checkpoint until the next behavior-touching runtime slice.

## MMP receiver report owner - 2026-06-10

Summary:
- FIPS `0661713` moves link-layer MMP ReceiverReport peer-state processing
  behind `PeerLifecycleRegistry`.
- `process_mmp_receiver_report` now owns active-peer lookup, MMP-enabled
  gating, session-relative timestamp lookup, metrics processing, SRTT report
  interval feedback, and reverse-delivery update.
- `Node::handle_receiver_report` still owns wire decode, malformed/unknown
  logging, processed trace logging, and the first-RTT parent/tree side effects:
  parent/root evaluation, declaration signing, discovery backoff reset, tree
  announce, and bloom update marking.

Result:
- Accepted as a path/liveness ownership slice. It keeps MMP wire format, stale
  metric rejection, SRTT interval feedback, reverse-delivery accounting, and
  first-RTT parent selection behavior unchanged while removing another raw
  active-peer MMP mutation from `Node`.
- This is not a throughput claim. It makes the eventual peer/session runtime
  less likely to strand liveness-quality updates or mix stale metric state with
  unrelated rx-loop side effects under path drift, traversal churn, or CPU
  contention.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core peer_lifecycle_registry_owns_mmp_receiver_report_processing -- --nocapture
cargo test -p fips-core peer_lifecycle_registry_owns_mmp_receiver_report_skip_paths -- --nocapture
cargo test -p fips-core mmp -- --nocapture
cargo test -p fips-core routing -- --nocapture
cargo test -p fips-core spanning_tree -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused MMP ReceiverReport owner guards passed; focused MMP/routing/
spanning-tree/forwarding/peer-runtime-receive checks passed; full FIPS package
result: `1526` passed, `2` ignored; doctests `2` ignored. nvpn local-FIPS
result: `nvpn-hotpath` passed all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing MMP path/liveness state, not a
queueing, routing algorithm, crypto algorithm, sender, batching, or delivery
semantic change. The latest Docker perf checkpoint remains the current
throughput/liveness checkpoint until the next behavior-touching runtime slice.

## MMP link report collection owner - 2026-06-10

Summary:
- FIPS `4f59bde` moves periodic link-layer MMP report collection and metric-log
  cadence behind `PeerLifecycleRegistry`.
- `collect_due_mmp_link_reports` now owns active-peer iteration, MMP-enabled
  filtering, Full/Lightweight/Minimal mode gating, due SenderReport and
  ReceiverReport checks, report building/interval reset, metric snapshot
  creation, and `mark_logged` cadence mutation.
- `Node::check_mmp_reports` now only asks the peer owner for due work, renders
  peer display names for logs, and sends the already-encoded reports over the
  existing encrypted link-message path.
- The unused `PeerLifecycleRegistry::iter_mut` wrapper was removed after this
  move deleted the last mutable active-peer iteration from that call site.

Result:
- Accepted as the companion link-MMP liveness ownership slice after
  ReceiverReport processing. Periodic MMP sender/receiver report generation
  remains behaviorally unchanged, but report interval reset and operator log
  cadence are no longer open-coded in `Node`.
- This is not a throughput claim. It reduces the chance that the eventual
  peer/session runtime will strand liveness-report progress or duplicate MMP
  cadence rules when the rx-loop bounce is eventually removed.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core peer_lifecycle_registry_owns_due_mmp_link_report_collection -- --nocapture
cargo test -p fips-core peer_lifecycle_registry_mmp_link_report_collection_respects_modes -- --nocapture
cargo test -p fips-core mmp -- --nocapture
cargo test -p fips-core routing -- --nocapture
cargo test -p fips-core spanning_tree -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused MMP link-report owner guards passed; focused MMP/routing/spanning-tree/
forwarding/peer-runtime-receive checks passed; full FIPS package result:
`1528` passed, `2` ignored; doctests `2` ignored. nvpn local-FIPS result:
`nvpn-hotpath` passed all six checks.

No Docker perf rerun or live host-pair reference row was taken because this is
an ownership-boundary change around existing MMP report/liveness state, not a
queueing, routing algorithm, crypto algorithm, encrypted transport send,
batching, or delivery semantic change. The latest Docker perf checkpoint
remains the current throughput/liveness checkpoint until the next
behavior-touching runtime slice.

## Session MMP liveness registry bundle - 2026-06-11

Summary:
- FIPS `c345089` bundles three bounded liveness-owner slices: session
  ReceiverReport processing behind `SessionRegistry`, periodic session-MMP
  report/PMTU collection plus send-result accounting behind `SessionRegistry`,
  and link-heartbeat/dead-peer planning plus heartbeat-sent bookkeeping behind
  `PeerLifecycleRegistry`.
- `Node::handle_session_receiver_report` now decodes and keeps the
  direct-path degradation/fallback side effects, while the session owner owns
  session lookup, MMP-enabled gating, receiver-report metrics mutation, SRTT
  report-interval feedback, path-MTU notification interval feedback,
  reverse-delivery update, loss sample extraction, and route-quality
  eligibility classification.
- `Node::check_session_mmp_reports` now asks the session owner for encoded due
  SenderReport/ReceiverReport/PathMtuNotification work, metric snapshots, and
  compact send-result accounting. The session owner owns mode gating, interval
  reset, `mark_logged`, path-MTU notification construction, per-destination
  success deduplication, failure backoff, and resumed-reporting facts.
- `Node::check_link_heartbeats` now computes effective dead timeouts from local
  send-failure and traversal policy, then asks the peer owner to plan
  heartbeat/dead/deferred-dead outcomes. The peer owner owns MMP last-receive
  liveness checks, heartbeat due checks, rekey-budget suppression, deferred
  dead conversion into heartbeat probes, and heartbeat-sent timestamp
  mutation; `Node` keeps path teardown, reprobe scheduling, fallback lookup,
  encrypted heartbeat sends, and logging.

Result:
- Accepted as a faster three-slice liveness ownership bundle. The shape is now
  more regular: link-MMP and session-MMP both use collect-then-send batches,
  and link heartbeat/dead planning is a typed peer-owner plan instead of open
  active-peer iteration in the node tick.
- This is not a throughput claim. It simplifies long-run liveness/control
  progress ownership without changing queueing, routing algorithm, crypto,
  batching, or encrypted transport delivery semantics. The latest Docker perf
  checkpoint remains the current throughput/liveness checkpoint until the next
  behavior-touching runtime slice.

Verification:

```sh
cargo fmt --check
git diff --check
cargo test -p fips-core session_registry_owns_session_receiver_report_processing -- --nocapture
cargo test -p fips-core session_registry_session_receiver_report_processing_reports_skip_reasons -- --nocapture
cargo test -p fips-core session_registry_owns_due_session_mmp_report_collection -- --nocapture
cargo test -p fips-core session_registry_session_mmp_report_collection_respects_modes -- --nocapture
cargo test -p fips-core session_registry_owns_session_mmp_send_result_accounting -- --nocapture
cargo test -p fips-core peer_lifecycle_registry_owns_link_heartbeat_planning_and_sent_bookkeeping -- --nocapture
cargo test -p fips-core peer_lifecycle_registry_owns_link_dead_and_deferred_heartbeat_planning -- --nocapture
cargo test -p fips-core link_dead -- --nocapture
cargo test -p fips-core mmp -- --nocapture
cargo test -p fips-core routing -- --nocapture
cargo test -p fips-core forwarding -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core spanning_tree -- --nocapture
cargo test -p fips-core peer_runtime_receive -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
cargo test -p fips-core -- --nocapture
```

Focused new owner guards passed; existing link-dead integration-style checks
passed; focused MMP/routing/forwarding/session/spanning-tree/
peer-runtime-receive checks passed; release check passed. Full FIPS package
result: `1535` passed, `2` ignored; doctests `2` ignored. nvpn local-FIPS
result: `nvpn-hotpath` passed all six checks.

## Session PMTU and route-error warmup registry owner - 2026-06-11

Summary:
- FIPS `a8f96b7` moves proactive PathMtuNotification application, reactive
  MtuExceeded PMTU application, and route-error coords-warmup policy behind
  `SessionRegistry`.
- `Node` still owns wire decode, packet-too-big parsing, route/cache side
  effects, `path_mtu_lookup` mirroring, coords-warmup sends, rate limiting, and
  logging. The session owner now owns session lookup, MMP-enabled gating,
  PMTU-state mutation, changed/unchanged classification, established-session
  send eligibility, and warmup-counter reset mutation.
- This keeps behavior intentionally boring: PathMtuNotification still refuses
  to loosen a tighter learned value, MtuExceeded still mirrors the reported
  bottleneck into the lookup even if no session/MMP state accepted it, and
  route-error handlers still send warmup before resetting the warmup counter.

Result:
- Accepted as a small ownership cleanup. The registry now owns another
  session-local liveness/PMTU policy surface that would otherwise keep the
  future peer/session runtime tied to `Node` internals.
- Perf cadence decision: run lightweight perf/harness sanity every few
  ownership-boundary commits, and run full Docker or live host-pair comparison
  when touching dataplane behavior: queue policy, batching, crypto, sender
  concurrency, connected UDP, route selection, runtime dispatch, delivery, or
  anything expected to change throughput/latency. This slice took the
  lightweight comparison dry-run and nvpn hotpath checks, but no full
  throughput benchmark because steady-state packet moving did not change.

Verification:

```sh
cargo test -p fips-core session_registry_owns_session_path_mtu_signal_application -- --nocapture
cargo test -p fips-core session_registry_session_path_mtu_signal_reports_skip_reasons -- --nocapture
cargo test -p fips-core session_registry_owns_route_error_coords_warmup_policy -- --nocapture
cargo fmt --check
git diff --check
cargo test -p fips-core path_mtu_notification -- --nocapture
cargo test -p fips-core mtu_exceeded -- --nocapture
cargo test -p fips-core coords_required -- --nocapture
cargo test -p fips-core path_broken -- --nocapture
cargo test -p fips-core path_mtu -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core mmp -- --nocapture
cargo test -p fips-core routing -- --nocapture
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
cargo test -p fips-core -- --nocapture
```

Focused new owner guards passed; focused path-MTU notification, MtuExceeded,
coords-required, path-broken, path-MTU, session, MMP, and routing checks
passed; release check passed. Full FIPS package result: `1538` passed,
`2` ignored; doctests `2` ignored. nvpn local-FIPS result: `nvpn-hotpath`
passed all six checks. The selectable safety runner's harness/comparison
dry-run passed, proving benchmark-script mapping still works before the next
real benchmark point.

## Session FSP send-state registry owner - 2026-06-11

Summary:
- FIPS `2470a3f` moves established-FSP send context, coords-warmup slot
  consumption, FSP sealing, session-datagram source PMTU seeding, and outbound
  next-hop bookkeeping behind `SessionRegistry`.
- `Node` still owns coord-fit decisions, standalone coords warmup sends,
  route/transport sends, pending queue fallback, path recovery probes, and
  logging. The session owner now owns timestamp/spin/K-bit/warmup reads, the
  warmup-counter mutation, established-session validation for sealing, FSP
  counter consumption/encryption, source PMTU seeding, and next-hop
  bookkeeping.
- This is a hot-edge ownership cleanup rather than a new send algorithm:
  packet format, routing, priority/bulk queues, and fallback behavior are
  intentionally unchanged.

Result:
- Accepted as a meaningful step toward the peer/session runtime target:
  the established FSP send path now consumes one session-owned context instead
  of rereading session timestamp, MMP spin bit, K-bit, and warmup state at
  scattered `Node` call sites.
- Because this touches the FSP send hot edge, a short local-FIPS Docker perf
  smoke was run in addition to focused correctness and nvpn hotpath checks.
  It does not replace a full-duration host-pair/reference comparison, but it
  is current throughput/liveness evidence for this refactor slice.

Verification:

```sh
cargo test -p fips-core session_registry_ -- --nocapture
cargo test -p fips-core endpoint_data -- --nocapture
cargo test -p fips-core tun_outbound -- --nocapture
cargo test -p fips-core session_datagram -- --nocapture
cargo test -p fips-core path_mtu -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core mmp -- --nocapture
cargo test -p fips-core routing -- --nocapture
cargo fmt --check
git diff --check
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
cargo test -p fips-core -- --nocapture
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/2470a3f-fsp-send-context-short-smoke \
PROJECT_NAME=nostr-vpn-e2e-fips-2470a3f-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

Focused owner guards passed; endpoint-data, TUN outbound, session-datagram,
path-MTU, session, MMP, and routing checks passed; release check passed. Full
FIPS package result: `1541` passed, `2` ignored; doctests `2` ignored. nvpn
local-FIPS `nvpn-hotpath` passed all six checks, and the selectable safety
runner's harness/comparison dry-run passed.

Short local-FIPS Docker perf result:

| Phase | Baseline Mbps | Load Mbps | Ping Loss | Direct Bytes |
| --- | ---: | ---: | --- | ---: |
| clean-underlay | `2415.2/2385.1` | `2322.3/2514.7` | `0%/0%`, post `0%` | `2420676184/2493470966` |
| constrained-underlay | `174.8/174.1` | `169.9/173.1` | `0%/0%`, post `0%` | `186651162/186396319` |
| worker-queue-pressure | `225.6/229.0` | `220.2/225.7` | `0%/0%`, post `0%` | `231874198/231490526` |
| rx-maintenance-fault | `2567.3/2552.0` | `2360.1/2495.4` | `0%/0%`, post `0%` | `2500139713/2570561288` |

Artifacts:
- `artifacts/fips-perf/2470a3f-fsp-send-context-short-smoke/phase-summary.tsv`
  SHA-256:
  `04acd4ce6dfa26a10efe63902cc3b277534dc44ecf28dc491f463c5549033a9a`
- `artifacts/fips-perf/2470a3f-fsp-send-context-short-smoke/failure-summary.tsv`
  SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`

Interpretation:
- The short smoke showed no liveness regression: all phases had `0%` load and
  post-load tunnel ping loss, direct UDP bytes advanced in every phase, and
  worker pressure exposed expected queue-full/bulk-drop counters without
  wedging priority/control progress.
- This remains Linux/Docker evidence. It should be followed by a full-duration
  Docker or live host-pair comparison when a later slice changes queue policy,
  sender concurrency, batching, route selection, delivery semantics, or another
  behavior expected to change throughput/latency.

## Outbound session decision registry owner - 2026-06-11

Summary:
- FIPS `cb74e46` moves outbound established/pending/missing session decisions,
  TUN learned-PMTU admission, duplicate session-initiation suppression, and
  discovery-retry pending restart policy behind `SessionRegistry`.
- `Node` still owns route lookup, session initiation side effects, queue
  admission, ICMP Packet Too Big emission, discovery triggering, and logging.
  The session owner now owns the local state classification that decides
  whether those outer effects should run.
- Behavior is intentionally unchanged: established outbound sends still send,
  pending sessions still queue and may discover, missing sessions still initiate,
  learned PMTU still generates ICMPv6 Packet Too Big only after the tighter
  session PMTU is known, and discovery retries still rebuild stale pending
  sessions with fresh route knowledge.

Result:
- Accepted as a small ownership cleanup. This reduces another cluster of raw
  `Node` peeks into session entries before the larger peer/session runtime
  boundary.
- Perf cadence stays explicit: run lightweight perf/harness sanity every few
  ownership-boundary commits, and run full Docker or live host-pair comparison
  when touching dataplane behavior such as queue policy, batching, crypto,
  sender concurrency, connected UDP, route selection, runtime dispatch,
  delivery, or expected throughput/latency.
- No Docker perf rerun was taken for this slice because it changes ownership of
  existing outbound decision policy, not steady-state queueing, routing,
  crypto, batching, sender, or delivery semantics. The latest short local-FIPS
  Docker hot-edge evidence remains FIPS `2470a3f`.

Verification:

```sh
cargo test -p fips-core session_registry_ -- --nocapture
cargo test -p fips-core endpoint_data -- --nocapture
cargo test -p fips-core tun_outbound -- --nocapture
cargo test -p fips-core discovery_restarts_stale_pending_session -- --nocapture
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core routing -- --nocapture
cargo test -p fips-core path_mtu -- --nocapture
cargo fmt --check
git diff --check
cargo check -p fips-core --release
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
cargo test -p fips-core -- --nocapture
```

Focused owner guards passed; endpoint-data, TUN outbound, stale pending-session
discovery retry, full session, routing, and path-MTU checks passed; release
check passed. Full FIPS package result: `1543` passed, `2` ignored; doctests
`2` ignored. nvpn local-FIPS `nvpn-hotpath` passed all six checks, and the
selectable safety runner's harness/comparison dry-run passed.

## Handshake session-install registry owner - 2026-06-11

Summary:
- FIPS `b1f94a7` moves session-entry installation behind `SessionRegistry` for
  initial initiating sessions, responder awaiting-msg3 entries, established
  initiator/responder sessions, rekey responder awaiting-msg3 state,
  initiator/responder pending rekey installs, and rekey abandon.
- `Node` still owns wire decode, Noise XK read/write, SessionDatagram sends,
  identity registration, coord-cache writes, pending flushes, and logging.
  This is intentionally an ownership cleanup around session storage, not a
  handshake-protocol rewrite.

Result:
- Accepted as a larger but still bounded owner-boundary step. The handshake
  path now has less hand-built `SessionEntry` storage choreography in `Node`;
  remaining raw session storage operations are concentrated in msg2/msg3
  take/restore error paths and the incoming-msg1 decision block.
- Fresh short local-FIPS Docker perf says current throughput is in the same
  `~2.4-2.5 Gbps` clean/rx-maintenance class, not an improvement past the
  previous `~2.6 Gbps` short-smoke ceiling. The host was not quiet during the
  run, so this is not enough to claim a regression. Liveness stayed clean.
  Under worker queue pressure, reverse bulk dipped to `73.9 Mbps` while ping
  loss remained `0%`; that is within the pressure-phase contract, but it is the
  next bottleneck clue to re-check under a quieter host before blaming code.

Verification:

```sh
cargo test -p fips-core session_registry_owns -- --nocapture
cargo fmt --check
cargo test -p fips-core node::tests::session -- --nocapture
cargo test -p fips-core rekey -- --nocapture
cargo test -p fips-core endpoint_data -- --nocapture
cargo test -p fips-core tun_outbound -- --nocapture
cargo test -p fips-core handshake -- --nocapture
git diff --check
cargo check -p fips-core --release
cargo test -p fips-core routing -- --nocapture
cargo test -p fips-core path_mtu -- --nocapture
cargo test -p fips-core -- --nocapture
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/b1f94a7-session-install-short-smoke \
PROJECT_NAME=nostr-vpn-e2e-fips-b1f94a7-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

Focused registry owner guards passed; full session, rekey, endpoint-data, TUN
outbound, handshake, routing, and path-MTU checks passed; release check passed.
Full FIPS package result: `1545` passed, `2` ignored; doctests `2` ignored.
nvpn local-FIPS `nvpn-hotpath` passed all six checks, and the selectable
safety runner's harness/comparison dry-run passed.

Short local-FIPS Docker perf result:

| Phase | Baseline Mbps | Load Mbps | Ping Loss | Direct Bytes |
| --- | ---: | ---: | --- | ---: |
| clean-underlay | `2472.5/2500.9` | `2505.5/2507.0` | `0%/0%`, post `0%` | `2545114982/2569228102` |
| constrained-underlay | `173.6/178.0` | `174.9/175.9` | `0%/0%`, post `0%` | `186635794/188559107` |
| worker-queue-pressure | `219.7/213.5` | `202.4/73.9` | `0%/0%`, post `0%` | `218925155/160382223` |
| rx-maintenance-fault | `2384.3/2338.4` | `2469.4/2492.2` | `0%/0%`, post `0%` | `2481804633/2470630803` |

Artifacts:
- `artifacts/fips-perf/b1f94a7-session-install-short-smoke/phase-summary.tsv`
  SHA-256:
  `527147b9dc8f8d33a8d6cc30677728d5a24e4fe07d197475046b8d6ba6ddfe3d`
- `artifacts/fips-perf/b1f94a7-session-install-short-smoke/failure-summary.tsv`
  SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`

Interpretation:
- The current dataplane is not yet proven equal to or better than the reference
  target; this run is safety/liveness evidence plus a bottleneck signal, not a
  victory lap or a definitive regression claim.
- Clean and rx-maintenance phases stayed in the previous short-smoke band, with
  direct UDP bytes advancing and no load/post-load tunnel ping loss.
- The worker-pressure reverse-load dip should be repeated on a quieter host. If
  it reproduces, the next performance work should look at pressure asymmetry and
  queue/worker scheduling, not more handshake ownership cleanup, once the
  remaining msg1/msg2/msg3 decision extraction is no longer blocking
  architectural clarity.

## Legacy Experiments

Older May 2026 experiments were moved to `docs/archive/experiments-2026-05-legacy.md` so this file stays focused on the current dataplane safety-net and ownership-refactor chronology. The archived notes are historical evidence, not current status.

The durable lessons kept in the active docs are: macOS sender/backpressure behavior needs real-device soak, direct-path routing must be proven by byte counters, MMP samples with bogus RTT must not drive route choice, and large hidden queues are not an acceptable reliability strategy.
