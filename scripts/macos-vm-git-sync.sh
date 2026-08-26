#!/usr/bin/env bash
# Push the exact working tree to private bare repositories on a macOS VM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_ROOT="$(cd "$ROOT/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-macos-vm-identity.sh"
SSH_HOST="${NVPN_MACOS_SSH_HOST:-${1:-}}"
GUEST_SRC_ROOT="${NVPN_MACOS_GUEST_SRC_ROOT:-src}"
REMOTE_REF="${NVPN_MACOS_GIT_REF:-refs/heads/codex/macos-vm-sync}"
[[ -n "$SSH_HOST" ]] || {
  echo "set NVPN_MACOS_SSH_HOST or pass the macOS VM SSH target" >&2
  exit 2
}
macos_vm_require_isolated_target "$SSH_HOST"
if [[ "$GUEST_SRC_ROOT" != /* ]]; then
  remote_home="$(ssh -o BatchMode=yes "$SSH_HOST" 'printf %s "$HOME"')"
  GUEST_SRC_ROOT="$remote_home/$GUEST_SRC_ROOT"
fi

make_sync_commit() {
  local repo_dir="$1"
  local git_dir tmp_index tree
  git_dir="$(git -C "$repo_dir" rev-parse --path-format=absolute --git-dir)"
  tmp_index="$(mktemp "$git_dir/macos-vm-index.XXXXXX")"
  (
    export GIT_INDEX_FILE="$tmp_index"
    git -C "$repo_dir" read-tree HEAD
    git -C "$repo_dir" add -A
    tree="$(git -C "$repo_dir" write-tree)"
    printf 'Temporary macOS VM sync\n' | git -C "$repo_dir" commit-tree "$tree"
  )
  rm -f "$tmp_index"
}

sync_repo() {
  local label="$1"
  local local_repo="$2"
  local guest_repo="$3"
  local guest_bare="${guest_repo}.git"
  local sync_commit
  if ! git -C "$local_repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Skipping macOS VM git sync for $label; $local_repo is not a checkout."
    return 0
  fi
  ssh -o BatchMode=yes "$SSH_HOST" \
    "mkdir -p '$(dirname "$guest_bare")'; test -d '$guest_bare' || /usr/bin/git init --bare '$guest_bare'"
  if [[ -z "$(git -C "$local_repo" status --porcelain)" ]]; then
    sync_commit="$(git -C "$local_repo" rev-parse HEAD)"
  else
    sync_commit="$(make_sync_commit "$local_repo")"
  fi
  GIT_SSH_COMMAND="ssh -o BatchMode=yes" \
    git -C "$local_repo" push --force \
      --receive-pack=/usr/bin/git-receive-pack \
      "$SSH_HOST:$guest_bare" "$sync_commit:$REMOTE_REF"
  ssh -o BatchMode=yes "$SSH_HOST" "
    set -e
    if [ ! -d '$guest_repo/.git' ]; then
      rm -rf '$guest_repo'
      /usr/bin/git clone '$guest_bare' '$guest_repo'
    fi
    # The VM checkout is disposable release-gate scratch space. Interrupted
    # builds and UI gates can leave tracked files modified, so discard those
    # before switching it to the exact candidate tree.
    /usr/bin/git -C '$guest_repo' reset --hard HEAD
    /usr/bin/git -C '$guest_repo' remote set-url origin '$guest_bare'
    /usr/bin/git -C '$guest_repo' fetch origin '$REMOTE_REF'
    /usr/bin/git -C '$guest_repo' checkout -B '${REMOTE_REF#refs/heads/}' FETCH_HEAD
    /usr/bin/git -C '$guest_repo' reset --hard FETCH_HEAD
    /usr/bin/git -C '$guest_repo' clean -ffd -e target/ -e dist/ -e artifacts/ -e macos/.build/
  "
  echo "MACOS_VM_GIT_SYNC_OK $label"
}

sync_repo nostr-vpn "$ROOT" "$GUEST_SRC_ROOT/nostr-vpn"

sync_path_deps="${NVPN_MACOS_SYNC_PATH_DEPS:-0}"
if [[ -n "${NVPN_FIPS_REPO_PATH:-}" ]]; then
  sync_path_deps=1
fi
case "$sync_path_deps" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On)
    sync_repo fips "${NVPN_FIPS_REPO_PATH:-$SRC_ROOT/fips}" "$GUEST_SRC_ROOT/fips"
    sync_repo cashu-service "$SRC_ROOT/cashu-service" "$GUEST_SRC_ROOT/cashu-service"
    ;;
esac
