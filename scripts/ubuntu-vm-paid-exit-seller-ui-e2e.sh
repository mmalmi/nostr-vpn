#!/usr/bin/env bash
# Drive paid-exit seller settings through the exact host-built GTK app on the
# isolated Ubuntu VM and prove public-UI persistence across a relaunch.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_HOST="${NVPN_UBUNTU_SSH_HOST:-${1:-}}"
GUEST_SRC_ROOT="${NVPN_UBUNTU_GUEST_SRC_ROOT:-src}"
GUEST_REPO="$GUEST_SRC_ROOT/nostr-vpn-release-gate"
LOCAL_ARTIFACT_DIR="${NVPN_PAID_EXIT_SELLER_UI_ARTIFACT_DIR:-$ROOT/artifacts/paid-exit-seller-ui/linux}"
REMOTE_ARTIFACT="$GUEST_REPO/artifacts/linux-paid-exit-seller-ui"
[[ -n "$SSH_HOST" ]] || {
  echo "set NVPN_UBUNTU_SSH_HOST or pass the Linux VM SSH target" >&2
  exit 2
}

# shellcheck disable=SC1091
source "$ROOT/scripts/lib-ubuntu-vm-imported-release.sh"
export NVPN_UBUNTU_IMPORT_EVIDENCE_DIR="$LOCAL_ARTIFACT_DIR/import"

cleanup_remote_state() {
  ubuntu_vm_import_ssh_command
  "${NVPN_UBUNTU_IMPORT_SSH[@]}" bash -s -- "$GUEST_REPO" <<'GUEST'
set -euo pipefail
repo="$1"
case_root="/tmp/nvpn-linux-paid-exit-seller-ui"
if [[ -d "$repo" ]]; then
  repo="$(cd "$repo" && pwd -P)"
  artifact="$repo/artifacts/linux-paid-exit-seller-ui"
  [[ "$artifact" == */nostr-vpn-release-gate/artifacts/linux-paid-exit-seller-ui ]]
  rm -rf "$artifact"
fi
[[ "$case_root" == "/tmp/nvpn-linux-paid-exit-seller-ui" ]]
rm -rf "$case_root"
GUEST
}

cleanup() {
  local status="$?"
  trap - EXIT
  cleanup_remote_state || status=1
  ubuntu_vm_cleanup_imported_release_bundle || status=1
  exit "$status"
}
trap cleanup EXIT

case "${NVPN_UBUNTU_SKIP_GIT_SYNC:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
  *) "$ROOT/scripts/ubuntu-vm-git-sync.sh" "$SSH_HOST" ;;
esac
ubuntu_vm_import_release_bundle
ubuntu_vm_import_ssh_command

"${NVPN_UBUNTU_IMPORT_SSH[@]}" bash -s -- \
  "$GUEST_REPO" \
  "$NVPN_UBUNTU_IMPORTED_APP" \
  "$NVPN_UBUNTU_IMPORTED_CLI" \
  "$NVPN_UBUNTU_IMPORTED_RECEIPT" \
  "$REMOTE_ARTIFACT" <<'GUEST'
set -euo pipefail
repo="$1"
app="$2"
cli="$3"
bundle_receipt="$4"
artifact="$5"
case_root="/tmp/nvpn-linux-paid-exit-seller-ui"
xdg="$case_root/xdg"
data="$xdg/nostr-vpn"
rm -rf "$case_root" "$artifact"
mkdir -p "$data" "$artifact/screens"
artifact="$(cd "$artifact" && pwd -P)"
[[ "$artifact" == /* ]]
receipt="$artifact/receipt.json"

# shellcheck disable=SC1091
source "$repo/scripts/lib-linux-owned-test-app.sh"
"$repo/scripts/test-linux-owned-test-app-harness.sh"
cleanup() {
  local status="$?"
  trap - EXIT
  linux_stop_exact_test_app "$app" || status=1
  rm -rf "$case_root"
  exit "$status"
}
trap cleanup EXIT

app_sha="$(jq -er '.appGitSha' "$bundle_receipt")"
app_tree="$(jq -er '.appGitTree' "$bundle_receipt")"
app_hash="$(jq -er '.artifacts.app.sha256' "$bundle_receipt")"
cli_hash="$(jq -er '.artifacts.cli.sha256' "$bundle_receipt")"
[[ "$(sha256sum "$app" | awk '{print $1}')" == "$app_hash" ]]
[[ "$(sha256sum "$cli" | awk '{print $1}')" == "$cli_hash" ]]

"$cli" init --config "$data/config.toml" --force >/dev/null
"$cli" set --config "$data/config.toml" --autoconnect false >/dev/null

cd "$repo"
repo="$(pwd -P)"
[[ "$repo" == /* ]]
export GDK_BACKEND=x11
export GTK_A11Y=atspi
export NO_AT_BRIDGE=0
xvfb-run -a dbus-run-session -- env XDG_DATA_HOME="$xdg" \
  python3 "$repo/scripts/desktop-mobile-manual-join-atspi.py" \
    PaidExitSeller \
    --app "$app" \
    --cli "$cli" \
    --marker "$receipt" \
    --artifact-root "$artifact/screens" \
    --seller-price 1000000 \
    --seller-country FI \
    --seller-mint http://cashu-mint:3338 \
    --app-git-sha "$app_sha" \
    --app-git-tree "$app_tree"

jq -e \
  --arg app_sha "$app_sha" \
  --arg app_tree "$app_tree" \
  --arg app_hash "$app_hash" \
  --arg cli_hash "$cli_hash" '
    .receiptSchema == 1 and
    .platform == "linux" and
    .case == "paid-exit-seller" and
    .savedViaShippedUi == true and
    .enabledViaShippedUi == true and
    .uiRestartReadback == true and
    .privateStateRead == false and
    .paidExitEnabled == true and
    .paidExitPriceMsatPerGb == 1000000 and
    .paidExitCountryCode == "FI" and
    .paidExitAcceptedMints == ["http://cashu-mint:3338"] and
    .appGitSha == $app_sha and
    .appGitTree == $app_tree and
    .appExecutableSha256 == $app_hash and
    .cliExecutableSha256 == $cli_hash
  ' "$receipt" >/dev/null
GUEST

rm -rf "$LOCAL_ARTIFACT_DIR"
mkdir -p "$LOCAL_ARTIFACT_DIR"
ubuntu_vm_import_scp_command
"${NVPN_UBUNTU_IMPORT_SCP[@]}" -r \
  "$SSH_HOST:$REMOTE_ARTIFACT/." "$LOCAL_ARTIFACT_DIR/"
[[ -f "$LOCAL_ARTIFACT_DIR/receipt.json" ]] || {
  echo "Ubuntu VM paid-exit seller UI receipt was not copied to the host" >&2
  exit 1
}

echo "UBUNTU_VM_PAID_EXIT_SELLER_UI_E2E_OK"
