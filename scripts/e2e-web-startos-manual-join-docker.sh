#!/usr/bin/env bash
# Drive both manual-join roles through the shipped web control panel, then
# prove the exact signed roster crosses two live production nvpn runtimes and
# its durable application receipt consumes the admin outbox. StartOS packages
# this exact Umbrel Dockerfile and web/daemon split.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="${NVPN_WEB_STARTOS_JOIN_PROJECT:-nostr-vpn-web-startos-join-$$}"
COMPOSE_FILE="$ROOT_DIR/umbrel/docker-compose.manual-join.yml"
IMAGE="${NVPN_WEB_STARTOS_JOIN_IMAGE:-nostr-vpn-web-startos-manual-join:local}"
ARTIFACT_DIR="${NVPN_WEB_STARTOS_JOIN_ARTIFACT_DIR:-${ARTIFACT_ROOT:-$ROOT_DIR/artifacts}/web-startos-manual-join}"
PLAYWRIGHT_SPEC="${NVPN_WEB_STARTOS_JOIN_SPEC:-e2e/manual-join-runtime.spec.ts}"
JOIN_LABEL="${NVPN_WEB_STARTOS_JOIN_LABEL:-manual join}"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-web-startos-manual-join.XXXXXX")"
RUNTIME_TIMEOUT_SECS="${NVPN_WEB_STARTOS_JOIN_RUNTIME_TIMEOUT_SECS:-15}"
NETWORK_OCTET="${NVPN_WEB_STARTOS_JOIN_NETWORK_OCTET:-$((100 + ($$ % 100)))}"
CURRENT_NODE_A_DATA=""
CURRENT_NODE_B_DATA=""
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

export NVPN_WEB_STARTOS_JOIN_IMAGE="$IMAGE"
export NVPN_WEB_STARTOS_JOIN_SUBNET="${NVPN_WEB_STARTOS_JOIN_SUBNET:-10.254.${NETWORK_OCTET}.0/24}"
export NVPN_WEB_STARTOS_JOIN_NODE_A_IP="${NVPN_WEB_STARTOS_JOIN_NODE_A_IP:-10.254.${NETWORK_OCTET}.10}"
export NVPN_WEB_STARTOS_JOIN_NODE_B_IP="${NVPN_WEB_STARTOS_JOIN_NODE_B_IP:-10.254.${NETWORK_OCTET}.11}"
export NVPN_WEB_STARTOS_JOIN_NODE_A_WEB_IP="${NVPN_WEB_STARTOS_JOIN_NODE_A_WEB_IP:-10.254.${NETWORK_OCTET}.20}"
export NVPN_WEB_STARTOS_JOIN_NODE_B_WEB_IP="${NVPN_WEB_STARTOS_JOIN_NODE_B_WEB_IP:-10.254.${NETWORK_OCTET}.21}"

COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE")

dump_debug() {
  set +e
  echo "web/StartOS manual-join e2e failed, collecting debug output..." >&2
  "${COMPOSE[@]}" ps >&2 || true
  "${COMPOSE[@]}" logs --no-color --tail 240 >&2 || true
  for service in node-a-daemon node-b-daemon; do
    echo "--- $service state ---" >&2
    "${COMPOSE[@]}" exec -T "$service" sh -lc \
      'cat /data/config/nvpn/daemon.state.json 2>/dev/null || true' >&2 || true
  done
}

cleanup() {
  local status=$?
  if ((status != 0)); then
    dump_debug
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker run --rm \
      -v "$TMP_ROOT:/cleanup" \
      --entrypoint sh \
      "$IMAGE" \
      -c "find /cleanup ! -type s -exec chown $HOST_UID:$HOST_GID {} +" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_ROOT"
  exit "$status"
}

return_runtime_data_to_host() {
  local service
  for service in node-a-daemon node-b-daemon; do
    "${COMPOSE[@]}" exec -T "$service" sh -c \
      "find /data/config/nvpn ! -type s -exec chown $HOST_UID:$HOST_GID {} +"
  done
}
trap cleanup EXIT

reserve_web_ports() {
  python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(2):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
}

wait_for_http() {
  local base_url="$1"
  local deadline=$((SECONDS + 30))
  while ((SECONDS < deadline)); do
    if curl --fail --silent --show-error --max-time 2 \
      "$base_url/api/health" >/dev/null 2>&1 \
      && curl --fail --silent --show-error --max-time 2 \
        -X POST "$base_url/api/tick" >/dev/null 2>&1
    then
      return 0
    fi
    sleep 0.2
  done
  echo "timed out waiting for shipped web control panel at $base_url" >&2
  return 1
}

read_result() {
  local result="$1"
  local field="$2"
  python3 - "$result" "$field" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])
PY
}

wait_for_runtime_receipt() {
  local fixture="$1"
  local result="$2"
  local admin_data="$3"
  local joiner_data="$4"
  local deadline=$((SECONDS + RUNTIME_TIMEOUT_SECS))
  while ((SECONDS < deadline)); do
    if "$fixture" verify-runtime \
      --admin-data-dir "$admin_data" \
      --joiner-data-dir "$joiner_data" \
      --result "$result" >/dev/null 2>&1
    then
      return 0
    fi
    sleep 0.1
  done
  "$fixture" verify-runtime \
    --admin-data-dir "$admin_data" \
    --joiner-data-dir "$joiner_data" \
    --result "$result"
  echo "signed roster was not durably applied and acknowledged within ${RUNTIME_TIMEOUT_SECS}s" >&2
  return 1
}

capture_runtime_artifacts() {
  local direction_dir="$1"
  local result="$2"
  mkdir -p "$direction_dir"
  cp "$result" "$direction_dir/result.json"
  for side in node-a node-b; do
    local data_var
    local daemon_service
    if [[ "$side" == "node-a" ]]; then
      data_var="$CURRENT_NODE_A_DATA"
      daemon_service="node-a-daemon"
    else
      data_var="$CURRENT_NODE_B_DATA"
      daemon_service="node-b-daemon"
    fi
    "${COMPOSE[@]}" logs --no-color "$daemon_service" \
      >"$direction_dir/$side-daemon.log"
    cp "$data_var/daemon.state.json" "$direction_dir/$side-daemon.state.json"
  done
  "${COMPOSE[@]}" logs --no-color >"$direction_dir/compose.log"
}

run_direction() {
  local direction="$1"
  local fixture="$2"
  local ports
  ports="$(reserve_web_ports)"
  read -r NVPN_WEB_STARTOS_JOIN_NODE_A_PORT NVPN_WEB_STARTOS_JOIN_NODE_B_PORT <<<"$ports"
  export NVPN_WEB_STARTOS_JOIN_NODE_A_PORT
  export NVPN_WEB_STARTOS_JOIN_NODE_B_PORT

  CURRENT_NODE_A_DATA="$TMP_ROOT/$direction/node-a"
  CURRENT_NODE_B_DATA="$TMP_ROOT/$direction/node-b"
  export NVPN_WEB_STARTOS_JOIN_NODE_A_DATA="$CURRENT_NODE_A_DATA"
  export NVPN_WEB_STARTOS_JOIN_NODE_B_DATA="$CURRENT_NODE_B_DATA"
  mkdir -p "$CURRENT_NODE_A_DATA" "$CURRENT_NODE_B_DATA"

  local admin_data joiner_data admin_endpoint joiner_endpoint
  local admin_base_url joiner_base_url admin_daemon joiner_daemon
  if [[ "$direction" == "node-a-admin" ]]; then
    admin_data="$CURRENT_NODE_A_DATA"
    joiner_data="$CURRENT_NODE_B_DATA"
    admin_endpoint="$NVPN_WEB_STARTOS_JOIN_NODE_A_IP:25110"
    joiner_endpoint="$NVPN_WEB_STARTOS_JOIN_NODE_B_IP:25111"
    admin_base_url="http://127.0.0.1:$NVPN_WEB_STARTOS_JOIN_NODE_A_PORT"
    joiner_base_url="http://127.0.0.1:$NVPN_WEB_STARTOS_JOIN_NODE_B_PORT"
    admin_daemon="node-a-daemon"
    joiner_daemon="node-b-daemon"
  else
    admin_data="$CURRENT_NODE_B_DATA"
    joiner_data="$CURRENT_NODE_A_DATA"
    admin_endpoint="$NVPN_WEB_STARTOS_JOIN_NODE_B_IP:25111"
    joiner_endpoint="$NVPN_WEB_STARTOS_JOIN_NODE_A_IP:25110"
    admin_base_url="http://127.0.0.1:$NVPN_WEB_STARTOS_JOIN_NODE_B_PORT"
    joiner_base_url="http://127.0.0.1:$NVPN_WEB_STARTOS_JOIN_NODE_A_PORT"
    admin_daemon="node-b-daemon"
    joiner_daemon="node-a-daemon"
  fi

  local result="$TMP_ROOT/$direction/result.json"
  local fixture_args=(
    --admin-data-dir "$admin_data"
    --joiner-data-dir "$joiner_data"
    --result "$result"
    --admin-endpoint "$admin_endpoint"
    --joiner-endpoint "$joiner_endpoint"
    --direction "$direction"
  )
  "$fixture" prepare "${fixture_args[@]}"

  "${COMPOSE[@]}" up -d node-a-daemon node-b-daemon node-a-web node-b-web
  wait_for_http "$admin_base_url"
  wait_for_http "$joiner_base_url"

  NVPN_WEB_STARTOS_JOIN_ADMIN_BASE_URL="$admin_base_url" \
    NVPN_WEB_STARTOS_JOIN_JOINER_BASE_URL="$joiner_base_url" \
    NVPN_WEB_STARTOS_JOIN_RESULT="$result" \
    PLAYWRIGHT_WORKERS=1 \
    env -u NO_COLOR pnpm --dir "$ROOT_DIR/web/control-panel" exec playwright test \
      "$PLAYWRIGHT_SPEC"

  return_runtime_data_to_host

  "$fixture" capture-delivery "${fixture_args[@]}"
  local joiner_hex
  joiner_hex="$(read_result "$result" joinerHex)"
  local started_ms finished_ms elapsed_ms
  started_ms="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  wait_for_runtime_receipt "$fixture" "$result" "$admin_data" "$joiner_data"
  "${COMPOSE[@]}" exec -T "$joiner_daemon" \
    /usr/local/bin/nvpn reload --config /data/config/nvpn/config.toml
  "${COMPOSE[@]}" exec -T "$admin_daemon" \
    /usr/local/bin/nvpn reload --config /data/config/nvpn/config.toml
  return_runtime_data_to_host
  "$fixture" verify-runtime \
    --admin-data-dir "$admin_data" \
    --joiner-data-dir "$joiner_data" \
    --result "$result"
  finished_ms="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  elapsed_ms=$((finished_ms - started_ms))
  if ((elapsed_ms > RUNTIME_TIMEOUT_SECS * 1000)); then
    echo "$direction durable roster receipt took ${elapsed_ms}ms" >&2
    return 1
  fi

  local admin_runtime_log="$TMP_ROOT/$direction/admin-runtime.log"
  "${COMPOSE[@]}" logs --no-color "$admin_daemon" >"$admin_runtime_log"
  grep -Fq \
    "delivered and applied one signed join roster over FIPS-TCP to $joiner_hex" \
    "$admin_runtime_log" || {
      echo "$direction admin runtime log lacks the exact durable receipt" >&2
      tail -n 200 "$admin_runtime_log" >&2 || true
      return 1
    }

  local direction_dir="$ARTIFACT_DIR/$direction"
  return_runtime_data_to_host
  capture_runtime_artifacts "$direction_dir" "$result"
  python3 - "$direction_dir/timings.json" "$direction" "$elapsed_ms" \
    "$((RUNTIME_TIMEOUT_SECS * 1000))" <<'PY'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(
        {
            "direction": sys.argv[2],
            "uiCompletionToDurableAckMs": int(sys.argv[3]),
            "ceilingMs": int(sys.argv[4]),
        },
        handle,
        indent=2,
    )
    handle.write("\n")
PY

  return_runtime_data_to_host
  "${COMPOSE[@]}" down -v --remove-orphans
  ! find "$CURRENT_NODE_A_DATA" "$CURRENT_NODE_B_DATA" -type s \
    -name 'join-*.sock' -print -quit | grep -q . || {
    echo "daemon shutdown left its join-request socket behind" >&2
    return 1
  }
  echo "$direction real web/StartOS $JOIN_LABEL passed in ${elapsed_ms}ms"
}

grep -Fq "dockerfile: './umbrel/Dockerfile'" "$ROOT_DIR/startos/manifest/index.ts" || {
  echo "StartOS must package the exact Umbrel image exercised by this gate" >&2
  exit 1
}
grep -Fq "NVPN_EXTERNAL_DAEMON: 'true'" "$ROOT_DIR/startos/main.ts" || {
  echo "StartOS no longer uses the daemon/web split exercised by this gate" >&2
  exit 1
}
grep -Fq "'--paused'," "$ROOT_DIR/startos/main.ts" || {
  echo "StartOS no longer starts the production daemon in the mode exercised by this gate" >&2
  exit 1
}

mkdir -p "$ARTIFACT_DIR"
rm -rf "$ARTIFACT_DIR/node-a-admin" "$ARTIFACT_DIR/node-b-admin"

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}" \
  cargo build --quiet --manifest-path "$ROOT_DIR/Cargo.toml" \
    -p nostr-vpn-core --example desktop_manual_join_e2e_fixture
TARGET_DIR="$(
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}" \
    cargo metadata --manifest-path "$ROOT_DIR/Cargo.toml" --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])'
)"
FIXTURE="$TARGET_DIR/debug/examples/desktop_manual_join_e2e_fixture"

export NVPN_WEB_STARTOS_JOIN_NODE_A_DATA="$TMP_ROOT/build-node-a"
export NVPN_WEB_STARTOS_JOIN_NODE_B_DATA="$TMP_ROOT/build-node-b"
export NVPN_WEB_STARTOS_JOIN_NODE_A_PORT=1
export NVPN_WEB_STARTOS_JOIN_NODE_B_PORT=2
mkdir -p "$NVPN_WEB_STARTOS_JOIN_NODE_A_DATA" "$NVPN_WEB_STARTOS_JOIN_NODE_B_DATA"

case "${NVPN_WEB_STARTOS_JOIN_IMAGE_READY:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
  *) "${COMPOSE[@]}" build node-a-daemon ;;
esac

chromium_executable="$(pnpm --dir "$ROOT_DIR/web/control-panel" exec node \
  -p 'require("@playwright/test").chromium.executablePath()')"
if [[ ! -x "$chromium_executable" ]]; then
  env -u NO_COLOR pnpm --dir "$ROOT_DIR/web/control-panel" exec playwright install chromium
fi

run_direction node-a-admin "$FIXTURE"
run_direction node-b-admin "$FIXTURE"

python3 - "$ARTIFACT_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for direction in ("node-a-admin", "node-b-admin"):
    result = json.loads((root / direction / "result.json").read_text(encoding="utf-8"))
    expected = {
        "phase": "runtime-verified",
        "direction": direction,
        "transportMode": "direct",
        "exactSignedRosterDurablyApplied": True,
        "adminOutboxConsumedByExactJoinRosterAck": True,
        "directProductionRuntime": True,
    }
    for field, value in expected.items():
        if result.get(field) != value:
            raise SystemExit(f"{direction} result has {field}={result.get(field)!r}, expected {value!r}")
PY

echo "WEB_STARTOS_JOIN_RUNTIME_E2E_OK"
echo "Artifacts: $ARTIFACT_DIR"
