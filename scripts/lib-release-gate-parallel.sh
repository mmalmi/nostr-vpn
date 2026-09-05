#!/usr/bin/env bash

# Small Bash 3-compatible lane runner for release-gate work that is genuinely
# resource-isolated. Callers remain responsible for keeping measurements and
# shared devices out of concurrent lanes.

RELEASE_GATE_PARALLEL_PIDS=()
RELEASE_GATE_PARALLEL_PGIDS=()
RELEASE_GATE_PARALLEL_LABELS=()
RELEASE_GATE_PARALLEL_LOGS=()
RELEASE_GATE_PARALLEL_STARTED_AT=()
RELEASE_GATE_PARALLEL_LAST_INDEX=""
RELEASE_GATE_PARALLEL_LOG_DIR=""
RELEASE_GATE_PARALLEL_TERM_GRACE_SECONDS="${RELEASE_GATE_PARALLEL_TERM_GRACE_SECONDS:-2}"
RELEASE_GATE_PARALLEL_SUCCESS_LOG_LINES="${RELEASE_GATE_PARALLEL_SUCCESS_LOG_LINES:-80}"
RELEASE_GATE_PARALLEL_FAILURE_LOG_LINES="${RELEASE_GATE_PARALLEL_FAILURE_LOG_LINES:-200}"

release_gate_parallel_init() {
  RELEASE_GATE_PARALLEL_LOG_DIR="$1"
  mkdir -p "$RELEASE_GATE_PARALLEL_LOG_DIR"
}

release_gate_parallel_log_name() {
  printf '%s' "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//'
}

release_gate_parallel_start() {
  local label="$1"
  shift
  if (($# == 0)); then
    printf 'release gate parallel lane failed: missing command for %s\n' "$label" >&2
    return 2
  fi
  if [[ -z "$RELEASE_GATE_PARALLEL_LOG_DIR" ]]; then
    printf 'release gate parallel lane failed: runner was not initialized\n' >&2
    return 2
  fi

  local index="${#RELEASE_GATE_PARALLEL_PIDS[@]}"
  local log_name log_path monitor_was_enabled pid pgid actual_pgid caller_pgid
  log_name="$(release_gate_parallel_log_name "$label")"
  log_path="$RELEASE_GATE_PARALLEL_LOG_DIR/${log_name:-lane}-$index.log"
  monitor_was_enabled=0
  [[ "$-" == *m* ]] && monitor_was_enabled=1
  # Bash 3 has no portable `setsid`, but monitor mode gives each background
  # job a dedicated process group. Every descendant stays in that group even
  # if it forks during TERM grace or its wrapper exits.
  set -m
  (
    # The parent has already placed this wrapper in its own group. Disable
    # monitor mode inside it so nested background jobs inherit that same group
    # instead of escaping into child-specific process groups.
    set +m
    set -euo pipefail
    "$@"
  ) </dev/null >"$log_path" 2>&1 &
  pid=$!
  ((monitor_was_enabled)) || set +m

  pgid="$pid"
  actual_pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
  caller_pgid="$(ps -o pgid= -p "$$" 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ -n "$actual_pgid" && "$actual_pgid" != "$pgid" ]] \
    || [[ -n "$caller_pgid" && "$pgid" == "$caller_pgid" ]]; then
    kill -s KILL "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    printf 'release gate parallel lane failed: no dedicated process group for %s\n' \
      "$label" >&2
    return 2
  fi

  RELEASE_GATE_PARALLEL_PIDS[$index]="$pid"
  RELEASE_GATE_PARALLEL_PGIDS[$index]="$pgid"
  RELEASE_GATE_PARALLEL_LABELS[$index]="$label"
  RELEASE_GATE_PARALLEL_LOGS[$index]="$log_path"
  RELEASE_GATE_PARALLEL_STARTED_AT[$index]="$(date +%s)"
  RELEASE_GATE_PARALLEL_LAST_INDEX="$index"
  printf 'Started release-gate lane: %s (log: %s)\n' "$label" "$log_path"
}

release_gate_parallel_pid_live_in_group() {
  local pid="$1"
  local expected_pgid="$2"
  [[ -n "$pid" && -n "$expected_pgid" ]] || return 1
  ps -o pgid=,stat= -p "$pid" 2>/dev/null \
    | awk -v expected="$expected_pgid" '
        $1 == expected && $2 !~ /^Z/ { found = 1 }
        END { exit !found }
      '
}

release_gate_parallel_group_alive() {
  local pgid="$1"
  [[ -n "$pgid" ]] || return 1
  ps -axo pgid=,stat= 2>/dev/null \
    | awk -v expected="$pgid" '
        $1 == expected && $2 !~ /^Z/ { found = 1 }
        END { exit !found }
      '
}

release_gate_parallel_group_snapshot() {
  local pgid="$1"
  [[ -n "$pgid" ]] || return 0
  ps -axo pid=,ppid=,pgid=,stat=,comm= 2>/dev/null \
    | awk -v expected="$pgid" '$3 == expected { print }'
}

release_gate_parallel_wait_group_gone() {
  local pgid="$1"
  local attempts=0
  while ((attempts < 100)); do
    release_gate_parallel_group_alive "$pgid" || return 0
    sleep 0.02
    attempts=$((attempts + 1))
  done
  ! release_gate_parallel_group_alive "$pgid"
}

release_gate_parallel_terminate_group() {
  local pgid="$1"
  local deadline
  [[ -n "$pgid" ]] || return 0

  if release_gate_parallel_group_alive "$pgid"; then
    kill -s TERM -- "-$pgid" >/dev/null 2>&1 || true
  fi
  deadline=$((SECONDS + RELEASE_GATE_PARALLEL_TERM_GRACE_SECONDS))
  while ((SECONDS < deadline)); do
    release_gate_parallel_group_alive "$pgid" || return 0
    sleep 0.05
  done
  if release_gate_parallel_group_alive "$pgid"; then
    kill -s KILL -- "-$pgid" >/dev/null 2>&1 || true
  fi
  # Descendants are no longer our direct children after their lane wrapper is
  # reaped. Do not let callers observe a just-killed group as an escaped lane.
  release_gate_parallel_wait_group_gone "$pgid"
}

release_gate_parallel_cancel_all() {
  local index pid pgid deadline any_running cleanup_failed=0
  for index in "${!RELEASE_GATE_PARALLEL_PIDS[@]}"; do
    pgid="${RELEASE_GATE_PARALLEL_PGIDS[$index]:-}"
    if release_gate_parallel_group_alive "$pgid"; then
      kill -s TERM -- "-$pgid" >/dev/null 2>&1 || true
    fi
  done
  deadline=$((SECONDS + RELEASE_GATE_PARALLEL_TERM_GRACE_SECONDS))
  while ((SECONDS < deadline)); do
    any_running=0
    for index in "${!RELEASE_GATE_PARALLEL_PGIDS[@]}"; do
      pgid="${RELEASE_GATE_PARALLEL_PGIDS[$index]:-}"
      if release_gate_parallel_group_alive "$pgid"; then
        any_running=1
        break
      fi
    done
    ((any_running)) || break
    sleep 0.05
  done
  for index in "${!RELEASE_GATE_PARALLEL_PGIDS[@]}"; do
    pgid="${RELEASE_GATE_PARALLEL_PGIDS[$index]:-}"
    if release_gate_parallel_group_alive "$pgid"; then
      kill -s KILL -- "-$pgid" >/dev/null 2>&1 || true
    fi
  done
  for index in "${!RELEASE_GATE_PARALLEL_PIDS[@]}"; do
    pid="${RELEASE_GATE_PARALLEL_PIDS[$index]:-}"
    if [[ -n "$pid" ]]; then
      wait "$pid" >/dev/null 2>&1 || true
      RELEASE_GATE_PARALLEL_PIDS[$index]=""
    fi
  done
  for index in "${!RELEASE_GATE_PARALLEL_PGIDS[@]}"; do
    pgid="${RELEASE_GATE_PARALLEL_PGIDS[$index]:-}"
    if [[ -n "$pgid" ]] \
      && ! release_gate_parallel_wait_group_gone "$pgid"
    then
      printf 'release gate parallel cleanup failed: process group %s survived TERM/KILL\n' \
        "$pgid" >&2
      cleanup_failed=1
    fi
    RELEASE_GATE_PARALLEL_PGIDS[$index]=""
  done
  return "$cleanup_failed"
}

release_gate_parallel_wait() {
  local index="$1"
  local pid="${RELEASE_GATE_PARALLEL_PIDS[$index]:-}"
  local label="${RELEASE_GATE_PARALLEL_LABELS[$index]:-lane-$index}"
  local log_path="${RELEASE_GATE_PARALLEL_LOGS[$index]:-}"
  local started_at="${RELEASE_GATE_PARALLEL_STARTED_AT[$index]:-$(date +%s)}"
  if [[ -z "$pid" ]]; then
    printf 'release gate parallel lane failed: unknown or completed lane %s\n' "$index" >&2
    return 2
  fi

  local status=0
  if wait "$pid"; then
    status=0
  else
    status=$?
  fi
  RELEASE_GATE_PARALLEL_PIDS[$index]=""

  local orphaned_group=0
  local orphan_cleanup_failed=0
  local pgid="${RELEASE_GATE_PARALLEL_PGIDS[$index]:-}"
  if ((status == 0)) && release_gate_parallel_group_alive "$pgid"; then
    # SSH ProxyCommand and pipe helpers can still be closing after their lane
    # wrapper has been reaped. Give normal process teardown the same short
    # grace used after TERM before treating a persistent child as an orphan.
    if ! release_gate_parallel_wait_group_gone "$pgid"; then
      orphaned_group=1
      release_gate_parallel_group_snapshot "$pgid" >&2 || true
      release_gate_parallel_terminate_group "$pgid" || orphan_cleanup_failed=1
    fi
  fi

  local duration=$(( $(date +%s) - started_at ))
  if type release_gate_timing_record >/dev/null 2>&1; then
    release_gate_timing_record \
      parallel "$label" "$started_at" "$((started_at + duration))" "$status" \
      || return 1
  fi
  local log_lines="$RELEASE_GATE_PARALLEL_SUCCESS_LOG_LINES"
  ((status == 0 && orphaned_group == 0)) \
    || log_lines="$RELEASE_GATE_PARALLEL_FAILURE_LOG_LINES"
  [[ "$log_lines" =~ ^[1-9][0-9]*$ ]] || {
    printf 'release gate parallel lane failed: invalid log line limit %s\n' \
      "$log_lines" >&2
    return 2
  }
  printf '\n===== release-gate lane: %s (%ss) =====\n' "$label" "$duration"
  if [[ -n "$log_path" && -f "$log_path" ]]; then
    local total_lines
    total_lines="$(wc -l <"$log_path" | tr -d '[:space:]')"
    if [[ "$total_lines" =~ ^[0-9]+$ && "$total_lines" -gt "$log_lines" ]]; then
      printf '[showing final %s of %s lines; complete log: %s]\n' \
        "$log_lines" "$total_lines" "$log_path"
      tail -n "$log_lines" "$log_path"
    else
      cat "$log_path"
    fi
  fi
  printf '===== end release-gate lane: %s =====\n\n' "$label"

  if ((status != 0)); then
    if release_gate_parallel_group_alive "$pgid"; then
      release_gate_parallel_terminate_group "$pgid" \
        || orphan_cleanup_failed=1
    fi
    RELEASE_GATE_PARALLEL_PGIDS[$index]=""
    printf 'Release-gate lane failed: %s (exit %s, log: %s)\n' \
      "$label" "$status" "$log_path" >&2
    ((orphan_cleanup_failed == 0)) || return 1
    return "$status"
  fi
  if ((orphaned_group)); then
    if ((orphan_cleanup_failed)); then
      printf 'Release-gate lane failed: %s exited successfully but process group %s survived TERM/KILL cleanup (log: %s)\n' \
        "$label" "$pgid" "$log_path" >&2
    else
      printf 'Release-gate lane failed: %s exited successfully with orphaned process-group descendants (log: %s)\n' \
        "$label" "$log_path" >&2
    fi
    RELEASE_GATE_PARALLEL_PGIDS[$index]=""
    return 1
  fi
  RELEASE_GATE_PARALLEL_PGIDS[$index]=""
  printf 'Release-gate lane passed: %s in %ss\n' "$label" "$duration"
}

release_gate_parallel_wait_group() {
  local remaining=("$@")
  local first_failure=0
  if ((${#remaining[@]} == 0)); then
    return 0
  fi

  # Bash 3 has no `wait -n`. Poll only the lane wrapper PIDs, then reap and
  # report each lane as soon as it finishes. Fail fast: sibling lanes can own
  # shared VM caches and must not survive a failed release attempt or race the
  # next exact-candidate run.
  while ((${#remaining[@]})); do
    local pending=()
    local index pid status group_failed=0
    for index in "${remaining[@]}"; do
      pid="${RELEASE_GATE_PARALLEL_PIDS[$index]:-}"
      if [[ -z "$pid" ]]; then
        if ((first_failure == 0)); then
          first_failure=2
        fi
        continue
      fi
      if kill -0 "$pid" >/dev/null 2>&1; then
        pending+=("$index")
        continue
      fi
      if release_gate_parallel_wait "$index"; then
        :
      else
        status=$?
        if ((first_failure == 0)); then
          first_failure="$status"
        fi
        group_failed=1
        break
      fi
    done
    if ((group_failed)); then
      release_gate_parallel_cancel_all || first_failure=1
      remaining=()
      break
    fi
    # Bash 3 treats "${pending[@]}" as an unbound expansion under `set -u`
    # when every lane was reaped in this poll.
    if ((${#pending[@]})); then
      remaining=("${pending[@]}")
    else
      remaining=()
    fi
    if ((${#remaining[@]})); then
      sleep 0.1
    fi
  done
  return "$first_failure"
}
