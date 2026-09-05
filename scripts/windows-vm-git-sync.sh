#!/usr/bin/env bash
# Push the current workspace to a git remote on an SSH-reachable Windows VM and
# fast-forward the VM checkout. This intentionally avoids tar/rsync code syncs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_ROOT="$(cd "$ROOT/.." && pwd)"
SSH_HOST="${NVPN_WINDOWS_SSH_HOST:-${1:-win11-dev}}"
SSH_JUMP="${NVPN_WINDOWS_SSH_JUMP:-}"
SSH_PROXY_COMMAND="${NVPN_WINDOWS_SSH_PROXY_COMMAND:-}"
GUEST_REPO="${NVPN_WINDOWS_GUEST_REPO_PATH:-C:\\src\\nostr-vpn}"
GUEST_BARE_REPO="${NVPN_WINDOWS_GIT_BARE_PATH:-${GUEST_REPO}.git}"
REMOTE_REF="${NVPN_WINDOWS_GIT_REF:-refs/heads/codex/windows-vm-sync}"
EXACT_APP_COMMIT="${NVPN_WINDOWS_GIT_SYNC_EXACT_APP_COMMIT:-}"
REMOTE_URL="${NVPN_WINDOWS_GIT_REMOTE_URL:-${SSH_HOST}:${GUEST_BARE_REPO//\\//}}"
FIPS_REPO="${NVPN_WINDOWS_FIPS_REPO_PATH:-${NVPN_FIPS_REPO_PATH:-$SRC_ROOT/fips}}"
GUEST_FIPS_REPO="${NVPN_WINDOWS_GUEST_FIPS_REPO_PATH:-C:\\src\\fips}"
GUEST_FIPS_BARE_REPO="${NVPN_WINDOWS_FIPS_GIT_BARE_PATH:-${GUEST_FIPS_REPO}.git}"
CDK_SPILMAN_REPO="${NVPN_WINDOWS_CDK_SPILMAN_REPO_PATH:-$SRC_ROOT/cashu_spilman_channels}"
SSH_ISOLATION_OPTIONS=(
  -o BatchMode=yes
  -o ControlMaster=no
  -o ControlPersist=no
  -o ControlPath=none
)

run_ps() {
  local script="$1"
  local encoded
  local -a ssh_cmd
  encoded="$(printf '%s' "$script" | iconv -t UTF-16LE | base64 | tr -d '\n')"
  ssh_cmd=(ssh "${SSH_ISOLATION_OPTIONS[@]}")
  if [[ -n "$SSH_PROXY_COMMAND" ]]; then
    ssh_cmd+=(-o "ProxyCommand=$SSH_PROXY_COMMAND")
  elif [[ -n "$SSH_JUMP" ]]; then
    ssh_cmd+=(
      -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=no -o ControlPersist=no -o ControlPath=none -W %h:%p $SSH_JUMP"
    )
  fi
  ssh_cmd+=("$SSH_HOST")
  "${ssh_cmd[@]}" powershell.exe -NoProfile -EncodedCommand "$encoded"
}

git_ssh_command() {
  local -a ssh_cmd
  ssh_cmd=(ssh "${SSH_ISOLATION_OPTIONS[@]}")
  if [[ -n "$SSH_PROXY_COMMAND" ]]; then
    ssh_cmd+=(-o "ProxyCommand=$SSH_PROXY_COMMAND")
  elif [[ -n "$SSH_JUMP" ]]; then
    ssh_cmd+=(
      -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=no -o ControlPersist=no -o ControlPath=none -W %h:%p $SSH_JUMP"
    )
  fi
  printf '%q ' "${ssh_cmd[@]}"
}

ps_quote() {
  local value="${1//\'/\'\'}"
  printf "'%s'" "$value"
}

make_sync_commit() {
  local repo_dir="$1"
  local git_dir
  local tmp_index
  local tree
  local parent
  local source_epoch
  git_dir="$(git -C "$repo_dir" rev-parse --path-format=absolute --git-dir)"
  tmp_index="$(mktemp "$git_dir/windows-vm-index.XXXXXX")"
  (
    export GIT_INDEX_FILE="$tmp_index"
    source_epoch="$(git -C "$repo_dir" log -1 --format=%ct HEAD)"
    export GIT_AUTHOR_DATE="@$source_epoch"
    export GIT_COMMITTER_DATE="@$source_epoch"
    git -C "$repo_dir" read-tree HEAD
    git -C "$repo_dir" add -A
    tree="$(git -C "$repo_dir" write-tree)"
    if [[ "${NVPN_WINDOWS_GIT_SYNC_WITH_HISTORY:-0}" =~ ^(1|true|TRUE|True|yes|YES|Yes|on|ON|On)$ ]]; then
      parent="$(git -C "$repo_dir" rev-parse HEAD)"
      printf 'Temporary Windows VM sync\n' | git -C "$repo_dir" commit-tree "$tree" -p "$parent"
    else
      printf 'Temporary Windows VM sync\n' | git -C "$repo_dir" commit-tree "$tree"
    fi
  )
  rm -f "$tmp_index"
}

ensure_remote_bare_repo() {
  local bare_repo="$1"
  run_ps "\$ErrorActionPreference = 'Stop'
\$BareRepo = $(ps_quote "$bare_repo")
\$BareParent = Split-Path -Parent \$BareRepo
New-Item -ItemType Directory -Force -Path \$BareParent | Out-Null
if (!(Test-Path \$BareRepo)) {
  git init --bare \$BareRepo
} else {
  \$isBare = git -C \$BareRepo rev-parse --is-bare-repository
  if (\$LASTEXITCODE -ne 0 -or \$isBare.Trim() -ne 'true') {
    throw \"Windows git remote is not a bare repository: \$BareRepo\"
  }
}"
}

checkout_remote_ref() {
  local worktree="$1"
  local bare_repo="$2"
  local remote_ref="$3"
  local branch_name="${remote_ref#refs/heads/}"
  run_ps "\$ErrorActionPreference = 'Stop'
\$BareRepo = $(ps_quote "$bare_repo")
\$Worktree = $(ps_quote "$worktree")
\$RemoteRef = $(ps_quote "$remote_ref")
\$BranchName = $(ps_quote "$branch_name")
if (!(Test-Path (Join-Path \$Worktree '.git'))) {
  Remove-Item -Recurse -Force -Path \$Worktree -ErrorAction SilentlyContinue
  git clone \$BareRepo \$Worktree
}
Set-Location \$Worktree
git remote set-url origin \$BareRepo
git fetch origin \$RemoteRef
git checkout -B \$BranchName FETCH_HEAD
git reset --hard FETCH_HEAD
git clean -ffd -e target/ -e dist/ -e artifacts/ -e windows/NostrVpn.Windows/bin/ -e windows/NostrVpn.Windows/obj/
git status --short --branch"
}

sync_repo() {
  local label="$1"
  local local_repo="$2"
  local worktree="$3"
  local bare_repo="$4"
  local remote_ref="$5"
  local exact_commit="${6:-}"
  local remote_url="${SSH_HOST}:${bare_repo//\\//}"
  local sync_commit
  local resolved_commit
  local local_tree
  local local_clean
  local remote_commit
  local remote_tree
  local git_ssh

  if ! git -C "$local_repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if [[ -n "$exact_commit" ]]; then
      echo "exact Windows sync checkout for $label is unavailable: $local_repo" >&2
      return 2
    fi
    echo "Skipping Windows VM git sync for $label; local checkout not found at $local_repo"
    return
  fi

  if [[ -n "$exact_commit" ]]; then
    [[ "$exact_commit" =~ ^[0-9a-f]{40}$ ]] || {
      echo "exact Windows sync commit for $label must be a lowercase Git commit" >&2
      return 2
    }
    resolved_commit="$(
      git -C "$local_repo" rev-parse "$exact_commit^{commit}" 2>/dev/null
    )" || {
      echo "exact Windows sync commit for $label is unavailable locally" >&2
      return 2
    }
    [[ "$resolved_commit" == "$exact_commit" ]] || {
      echo "exact Windows sync commit for $label is unavailable locally" >&2
      return 2
    }
    local_clean=1
    sync_commit="$resolved_commit"
  fi

  ensure_remote_bare_repo "$bare_repo"
  if [[ -z "$exact_commit" ]]; then
    if [[ -z "$(git -C "$local_repo" status --porcelain)" ]]; then
      local_clean=1
      sync_commit="$(git -C "$local_repo" rev-parse HEAD)"
    else
      local_clean=0
      sync_commit="$(make_sync_commit "$local_repo")"
    fi
  fi
  local_tree="$(git -C "$local_repo" rev-parse "$sync_commit^{tree}")"
  git_ssh="$(git_ssh_command)"
  if GIT_SSH_COMMAND="$git_ssh" git -C "$local_repo" fetch --quiet "$remote_url" "$remote_ref" 2>/dev/null; then
    remote_commit="$(git -C "$local_repo" rev-parse FETCH_HEAD)"
    remote_tree="$(git -C "$local_repo" rev-parse "FETCH_HEAD^{tree}")"
    if [[ "$remote_tree" == "$local_tree" && ( "$local_clean" != "1" || "$remote_commit" == "$sync_commit" ) ]]; then
      echo "WINDOWS_VM_GIT_SYNC_UNCHANGED $label"
      checkout_remote_ref "$worktree" "$bare_repo" "$remote_ref"
      return
    fi
  fi

  GIT_SSH_COMMAND="$git_ssh" git -C "$local_repo" push --force "$remote_url" "$sync_commit:$remote_ref"
  checkout_remote_ref "$worktree" "$bare_repo" "$remote_ref"
  echo "WINDOWS_VM_GIT_SYNC_OK $label"
}

sync_repo \
  "nostr-vpn" "$ROOT" "$GUEST_REPO" "$GUEST_BARE_REPO" "$REMOTE_REF" \
  "$EXACT_APP_COMMIT"

case "${NVPN_WINDOWS_SYNC_PATH_DEPS:-1}" in
  0|false|FALSE|False|no|NO|No|off|OFF|Off)
    ;;
  *)
    sync_repo "cashu-service" "$SRC_ROOT/cashu-service" "C:\\src\\cashu-service" "C:\\src\\cashu-service.git" "refs/heads/codex/windows-vm-sync-cashu-service"
    sync_repo "cashu_spilman_channels" "$CDK_SPILMAN_REPO" "C:\\src\\cashu_spilman_channels" "C:\\src\\cashu_spilman_channels.git" "refs/heads/codex/windows-vm-sync-cashu-spilman-channels"
    sync_repo "fips" "$FIPS_REPO" "$GUEST_FIPS_REPO" "$GUEST_FIPS_BARE_REPO" "refs/heads/codex/windows-vm-sync-fips"
    sync_repo "hashtree" "$SRC_ROOT/hashtree" "C:\\src\\hashtree" "C:\\src\\hashtree.git" "refs/heads/codex/windows-vm-sync-hashtree"
    ;;
esac
