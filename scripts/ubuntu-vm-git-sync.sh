#!/usr/bin/env bash
# Push the exact working tree to an isolated private checkout on the Linux VM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_REPO="${NVPN_UBUNTU_LOCAL_REPO_PATH:-$ROOT}"
SSH_HOST="${NVPN_UBUNTU_SSH_HOST:-${1:-}}"
SSH_JUMP="${NVPN_UBUNTU_SSH_JUMP:-}"
SSH_PROXY_COMMAND="${NVPN_UBUNTU_SSH_PROXY_COMMAND:-}"
GUEST_SRC_ROOT="${NVPN_UBUNTU_GUEST_SRC_ROOT:-src}"
GUEST_REPO_NAME="${NVPN_UBUNTU_GUEST_REPO_NAME:-nostr-vpn-release-gate}"
SYNC_LABEL="${NVPN_UBUNTU_REPO_LABEL:-nostr-vpn}"
GUEST_REPO="$GUEST_SRC_ROOT/$GUEST_REPO_NAME"
GUEST_BARE="$GUEST_SRC_ROOT/$GUEST_REPO_NAME.git"
REMOTE_REF="${NVPN_UBUNTU_GIT_REF:-refs/heads/codex/ubuntu-vm-sync}"
EXACT_COMMIT="${NVPN_UBUNTU_GIT_SYNC_EXACT_COMMIT:-}"
[[ -n "$SSH_HOST" ]] || {
  echo "set NVPN_UBUNTU_SSH_HOST or pass the Linux VM SSH target" >&2
  exit 2
}
sync_commit=""
SSH_ISOLATION_OPTIONS=(
  -o BatchMode=yes
  -o ControlMaster=no
  -o ControlPersist=no
  -o ControlPath=none
)
if [[ -n "$EXACT_COMMIT" ]]; then
  [[ "$EXACT_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
    echo "NVPN_UBUNTU_GIT_SYNC_EXACT_COMMIT must be an exact lowercase Git commit" >&2
    exit 2
  }
  resolved_commit="$(
    git -C "$LOCAL_REPO" rev-parse "$EXACT_COMMIT^{commit}" 2>/dev/null
  )" || {
    echo "NVPN_UBUNTU_GIT_SYNC_EXACT_COMMIT is unavailable in the local checkout" >&2
    exit 2
  }
  [[ "$resolved_commit" == "$EXACT_COMMIT" ]] || {
    echo "NVPN_UBUNTU_GIT_SYNC_EXACT_COMMIT is unavailable in the local checkout" >&2
    exit 2
  }
  sync_commit="$resolved_commit"
fi

ssh_command() {
  SSH_CMD=(ssh "${SSH_ISOLATION_OPTIONS[@]}")
  if [[ -n "$SSH_PROXY_COMMAND" ]]; then
    SSH_CMD+=(-o "ProxyCommand=$SSH_PROXY_COMMAND")
  elif [[ -n "$SSH_JUMP" ]]; then
    SSH_CMD+=(
      -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=no -o ControlPersist=no -o ControlPath=none -W %h:%p $SSH_JUMP"
    )
  fi
  SSH_CMD+=("$SSH_HOST")
}

git_ssh_command() {
  local -a command
  command=(ssh "${SSH_ISOLATION_OPTIONS[@]}")
  if [[ -n "$SSH_PROXY_COMMAND" ]]; then
    command+=(-o "ProxyCommand=$SSH_PROXY_COMMAND")
  elif [[ -n "$SSH_JUMP" ]]; then
    command+=(
      -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=no -o ControlPersist=no -o ControlPath=none -W %h:%p $SSH_JUMP"
    )
  fi
  printf '%q ' "${command[@]}"
}

if [[ "$GUEST_SRC_ROOT" != /* ]]; then
  ssh_command
  remote_home="$("${SSH_CMD[@]}" 'printf %s "$HOME"')"
  GUEST_SRC_ROOT="$remote_home/$GUEST_SRC_ROOT"
  GUEST_REPO="$GUEST_SRC_ROOT/$GUEST_REPO_NAME"
  GUEST_BARE="$GUEST_SRC_ROOT/$GUEST_REPO_NAME.git"
fi

make_sync_commit() {
  local git_dir tmp_index tree source_epoch
  git_dir="$(git -C "$LOCAL_REPO" rev-parse --path-format=absolute --git-dir)"
  tmp_index="$(mktemp "$git_dir/ubuntu-vm-index.XXXXXX")"
  (
    export GIT_INDEX_FILE="$tmp_index"
    source_epoch="$(git -C "$LOCAL_REPO" log -1 --format=%ct HEAD)"
    export GIT_AUTHOR_DATE="@$source_epoch"
    export GIT_COMMITTER_DATE="@$source_epoch"
    git -C "$LOCAL_REPO" read-tree HEAD
    git -C "$LOCAL_REPO" add -A
    tree="$(git -C "$LOCAL_REPO" write-tree)"
    printf 'Temporary Ubuntu VM sync\n' | git -C "$LOCAL_REPO" commit-tree "$tree"
  )
  rm -f "$tmp_index"
}

if [[ -z "$sync_commit" ]]; then
  if [[ -z "$(git -C "$LOCAL_REPO" status --porcelain)" ]]; then
    sync_commit="$(git -C "$LOCAL_REPO" rev-parse HEAD)"
  else
    sync_commit="$(make_sync_commit)"
  fi
fi
ssh_command
"${SSH_CMD[@]}" \
  "mkdir -p '$GUEST_SRC_ROOT'; test -d '$GUEST_BARE' || git init --bare '$GUEST_BARE'"
git_ssh="$(git_ssh_command)"
GIT_SSH_COMMAND="$git_ssh" \
  git -C "$LOCAL_REPO" push --force "$SSH_HOST:$GUEST_BARE" "$sync_commit:$REMOTE_REF"
"${SSH_CMD[@]}" "
  set -e
  if [ ! -d '$GUEST_REPO/.git' ]; then
    rm -rf '$GUEST_REPO'
    git clone '$GUEST_BARE' '$GUEST_REPO'
  fi
  # This checkout is release-gate scratch space. A prior interrupted build can
  # update generated lockfiles, so clear tracked scratch changes before moving
  # to the exact candidate ref.
  if git -C '$GUEST_REPO' rev-parse --verify HEAD >/dev/null 2>&1; then
    git -C '$GUEST_REPO' reset --hard HEAD
  fi
  git -C '$GUEST_REPO' remote set-url origin '$GUEST_BARE'
  git -C '$GUEST_REPO' fetch origin '$REMOTE_REF'
  git -C '$GUEST_REPO' checkout -B '${REMOTE_REF#refs/heads/}' FETCH_HEAD
  git -C '$GUEST_REPO' reset --hard FETCH_HEAD
  git -C '$GUEST_REPO' clean -ffd -e target/ -e linux/target/ -e artifacts/
"
echo "UBUNTU_VM_GIT_SYNC_OK $SYNC_LABEL"
