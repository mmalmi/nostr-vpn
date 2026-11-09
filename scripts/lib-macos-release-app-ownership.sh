#!/usr/bin/env bash

# Caller-owned values:
# MACOS_RELEASE_APP_STATE_DIR, MACOS_RELEASE_APP_INSTALLED_EXE,
# MACOS_RELEASE_APP_GATE_EXE, and MACOS_RELEASE_APP_PROCESS_NAME.

macos_release_app_process_args() {
  ps -ww -p "$1" -o args= 2>/dev/null \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

macos_release_app_reap_if_terminated() {
  local pid="$1" state
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    wait "$pid" >/dev/null 2>&1 || true
    return 0
  fi
  state="$(
    ps -ww -p "$pid" -o stat= 2>/dev/null \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]].*$//'
  )"
  [[ "$state" == Z* ]] || return 1
  wait "$pid" >/dev/null 2>&1 || true
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

macos_release_app_poll_pid_gone() {
  local pid="$1"
  local remaining=30
  while ((remaining > 0)); do
    macos_release_app_reap_if_terminated "$pid" && return 0
    sleep 0.1
    remaining=$((remaining - 1))
  done
  macos_release_app_reap_if_terminated "$pid"
}

macos_release_stop_owned_child() {
  local pid="$1" owner_pid="${2:-$$}" parent
  macos_release_app_reap_if_terminated "$pid" && return 0
  parent="$(ps -ww -p "$pid" -o ppid= 2>/dev/null | tr -d '[:space:]')"
  [[ "$parent" == "$owner_pid" ]] || {
    echo "refusing to stop a process not owned by this shell" >&2
    return 1
  }
  kill -TERM "$pid" >/dev/null 2>&1 || true
  macos_release_app_poll_pid_gone "$pid" && return 0
  parent="$(ps -ww -p "$pid" -o ppid= 2>/dev/null | tr -d '[:space:]')"
  [[ "$parent" == "$owner_pid" ]] || {
    echo "refusing to KILL a process no longer owned by this shell" >&2
    return 1
  }
  kill -KILL "$pid" >/dev/null 2>&1 || true
  macos_release_app_poll_pid_gone "$pid"
}

macos_release_app_stop_pid() {
  local pid="$1" expected_args="$2" current_args
  macos_release_app_reap_if_terminated "$pid" && return 0
  [[ "$(macos_release_app_process_args "$pid")" == "$expected_args" ]] || {
    echo "refusing to stop an app process not owned by this gate" >&2
    return 1
  }
  if ! kill -TERM "$pid" >/dev/null 2>&1; then
    macos_release_app_poll_pid_gone "$pid" && return 0
    echo "failed to send TERM to the gate-owned app process" >&2
    return 1
  fi
  macos_release_app_poll_pid_gone "$pid" && return 0

  current_args="$(macos_release_app_process_args "$pid")"
  if [[ "$current_args" != "$expected_args" ]]; then
    macos_release_app_reap_if_terminated "$pid" && return 0
    echo "refusing to KILL an app process no longer owned by this gate" >&2
    return 1
  fi
  if ! kill -KILL "$pid" >/dev/null 2>&1; then
    macos_release_app_poll_pid_gone "$pid" && return 0
    echo "failed to send KILL to the gate-owned app process" >&2
    return 1
  fi
  macos_release_app_poll_pid_gone "$pid" && return 0
  echo "gate-owned app process survived TERM and KILL" >&2
  return 1
}

macos_release_app_acquire() {
  local marker="$MACOS_RELEASE_APP_STATE_DIR/acquired"
  local prior="$MACOS_RELEASE_APP_STATE_DIR/prior-state"
  [[ ! -e "$MACOS_RELEASE_APP_STATE_DIR" || -f "$marker" ]] || {
    echo "incomplete imported app ownership state exists" >&2
    return 1
  }
  [[ ! -f "$marker" ]] || return 0

  local pid args state pids
  pids="$(pgrep -x "$MACOS_RELEASE_APP_PROCESS_NAME" 2>/dev/null || true)"
  [[ "$(wc -w <<<"$pids" | tr -d ' ')" -le 1 ]] || {
    echo "refusing to displace multiple preexisting app processes" >&2
    return 1
  }
  state=absent
  if [[ -n "$pids" ]]; then
    pid="$pids"
    args="$(macos_release_app_process_args "$pid")"
    case "$args" in
      "$MACOS_RELEASE_APP_INSTALLED_EXE --hidden") state=hidden ;;
      "$MACOS_RELEASE_APP_INSTALLED_EXE"|"$MACOS_RELEASE_APP_INSTALLED_EXE -psn_"*)
        state=visible
        ;;
      *)
        echo "refusing to displace an unknown app process: $args" >&2
        return 1
        ;;
    esac
  fi
  mkdir -p "$MACOS_RELEASE_APP_STATE_DIR"
  printf '%s\n' "$state" >"$prior.tmp"
  mv "$prior.tmp" "$prior"
  : >"$marker"
  [[ -z "$pids" ]] || macos_release_app_stop_pid "$pid" "$args"
}

macos_release_app_launch_installed() {
  local state="$1"
  if [[ "$state" == hidden ]]; then
    set -- --hidden
  else
    set --
  fi
  /usr/bin/nohup /usr/bin/env -i \
    HOME="$HOME" \
    USER="${USER:-dev}" \
    LOGNAME="${LOGNAME:-${USER:-dev}}" \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    TMPDIR="${TMPDIR:-/tmp}" \
    LANG="${LANG:-en_US.UTF-8}" \
    "$MACOS_RELEASE_APP_INSTALLED_EXE" "$@" \
    </dev/null >/dev/null 2>&1 &
}

macos_release_app_restore() {
  local marker="$MACOS_RELEASE_APP_STATE_DIR/acquired"
  local prior="$MACOS_RELEASE_APP_STATE_DIR/prior-state"
  local owned="$MACOS_RELEASE_APP_STATE_DIR/imported.pid"
  [[ -f "$marker" ]] || return 0
  [[ -f "$prior" ]]
  local state pid pids expected
  state="$(<"$prior")"
  [[ "$state" == absent || "$state" == hidden || "$state" == visible ]]
  if [[ -f "$owned" ]]; then
    pid="$(<"$owned")"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]]
    macos_release_app_stop_pid "$pid" "$MACOS_RELEASE_APP_GATE_EXE"
    rm -f "$owned"
  fi

  pids="$(pgrep -x "$MACOS_RELEASE_APP_PROCESS_NAME" 2>/dev/null || true)"
  [[ "$(wc -w <<<"$pids" | tr -d ' ')" -le 1 ]]
  if [[ "$state" == absent ]]; then
    [[ -z "$pids" ]]
  else
    expected="$MACOS_RELEASE_APP_INSTALLED_EXE"
    [[ "$state" == visible ]] || expected="$expected --hidden"
    if [[ -z "$pids" ]]; then
      [[ -x "$MACOS_RELEASE_APP_INSTALLED_EXE" ]]
      macos_release_app_launch_installed "$state"
      for _ in {1..100}; do
        sleep 0.1
        pids="$(
          pgrep -x "$MACOS_RELEASE_APP_PROCESS_NAME" 2>/dev/null || true
        )"
        [[ "$(wc -w <<<"$pids" | tr -d ' ')" -le 1 ]]
        [[ -n "$pids" \
          && "$(macos_release_app_process_args "$pids")" == "$expected" ]] \
          && break
      done
    fi
    [[ -n "$pids" \
      && "$(macos_release_app_process_args "$pids")" == "$expected" ]]
  fi
  rm -rf "$MACOS_RELEASE_APP_STATE_DIR"
}
