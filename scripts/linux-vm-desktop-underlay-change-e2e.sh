#!/usr/bin/env bash
# Real Linux VM network-change gate. The virtualization host creates a
# transient second NAT/NIC and physically cuts/restores the original link.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_APP_ROOT="${NVPN_RELEASE_APP_REPO_PATH:-$ROOT}"
HYPERVISOR_SSH="${NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH:?set NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH}"
VM_NAME="${NVPN_LINUX_UNDERLAY_VM_NAME:-${NVPN_UBUNTU_VM_NAME:-}}"
[[ -n "$VM_NAME" ]] || {
  echo "set NVPN_LINUX_UNDERLAY_VM_NAME" >&2
  exit 2
}
LINUX_SSH="${NVPN_UBUNTU_SSH_HOST:?set NVPN_UBUNTU_SSH_HOST}"
PRIMARY_PROXY="${NVPN_UBUNTU_SSH_PROXY_COMMAND:-}"
LINUX_JUMP="${NVPN_UBUNTU_SSH_JUMP:-}"
GUEST_SRC_ROOT="${NVPN_LINUX_UNDERLAY_GUEST_SRC_ROOT:-src/nvpn-desktop-underlay/linux-target}"
GUEST_REPO="$GUEST_SRC_ROOT/nostr-vpn-release-gate"
RUN_TOKEN="linux-$$-$RANDOM"
GUEST_IMPORT_DIR="/tmp/nvpn-linux-underlay-release-$RUN_TOKEN"
GUEST_BINARY="$GUEST_IMPORT_DIR/nvpn"
GUEST_RUNNER="$GUEST_IMPORT_DIR/desktop-linux-underlay-change-e2e.sh"
GUEST_CLEANUP_FAULT_RUNNER="$GUEST_IMPORT_DIR/desktop-linux-cleanup-fault-e2e.sh"
LOCAL_FIPS_REPO="${NVPN_FIPS_REPO_PATH:-}"
EXPECTED_FIPS_REV="${NVPN_EXPECTED_FIPS_REV:-}"
FIPS_SOURCE_REVISION=""
HYPERVISOR_BINARY=""
RECOVERY_DEADLINE_MS="${NVPN_DESKTOP_UNDERLAY_RECOVERY_DEADLINE_MS:-4000}"
NETWORK_ID="${NVPN_LINUX_UNDERLAY_NETWORK_ID:-desktop-underlay-linux-release-gate}"
SECONDARY_GATEWAY="${NVPN_LINUX_UNDERLAY_SECONDARY_GATEWAY:-172.31.254.1}"
SECONDARY_ADDRESS="${NVPN_LINUX_UNDERLAY_SECONDARY_ADDRESS:-172.31.254.10}"
SECONDARY_NETMASK="${NVPN_LINUX_UNDERLAY_SECONDARY_NETMASK:-255.255.255.0}"
SECONDARY_PREFIX="${NVPN_LINUX_UNDERLAY_SECONDARY_PREFIX:-24}"
FIXTURE_DNS_NAME="${NVPN_DESKTOP_UNDERLAY_FIXTURE_DNS_NAME:-underlay-gate.nvpn.test}"
PROBE_URL="${NVPN_DESKTOP_UNDERLAY_PROBE_URL:-https://example.com/}"
NETWORK_NAME="nvpn-underlay-$RUN_TOKEN"
PEER_STATE_DIR="/tmp/nvpn-underlay-peer-$RUN_TOKEN"
GUEST_STATE_DIR="/tmp/nvpn-underlay-target-$RUN_TOKEN"
PEER_TUN_IFACE="nvup${RANDOM}"
TARGET_TUN_IFACE="nvut${RANDOM}"
PEER_LISTEN_PORT="$((48000 + RANDOM % 1000))"
TARGET_LISTEN_PORT="$((49000 + RANDOM % 1000))"
WG_LISTEN_PORT="$((50000 + RANDOM % 1000))"
WG_PEER_IFACE="nvwg${RANDOM}"
WG_CLIENT_ADDRESS="${NVPN_LINUX_UNDERLAY_WG_CLIENT_ADDRESS:-10.232.0.2/32}"
WG_SERVER_ADDRESS="${NVPN_LINUX_UNDERLAY_WG_SERVER_ADDRESS:-10.232.0.1/24}"
WG_SERVER_IP="${WG_SERVER_ADDRESS%/*}"
COUNTER_CHAIN="nvu-$((RANDOM % 100000))"
PEER_NETNS="nvl$((RANDOM % 100000))"
PEER_HOST_VETH="nvlh$((RANDOM % 100000))"
PEER_NS_VETH="nvln0"
PEER_NAMESPACE_HOST_ADDRESS="${NVPN_LINUX_UNDERLAY_PEER_NAMESPACE_HOST_ADDRESS:-10.231.254.1}"
PEER_ENDPOINT_HOST="${NVPN_LINUX_UNDERLAY_PEER_NAMESPACE_ADDRESS:-10.231.254.2}"
PEER_NAMESPACE_PREFIX="${NVPN_LINUX_UNDERLAY_PEER_NAMESPACE_PREFIX:-30}"
PEER_FORWARD_CHAIN="nvf$((RANDOM % 100000))"
PEER_NAT_CHAIN="nvn$((RANDOM % 100000))"
ARTIFACT_DIR="${NVPN_LINUX_UNDERLAY_ARTIFACT_DIR:-$ROOT/artifacts/desktop-underlay/linux-$RUN_TOKEN}"
TARGET_RELEASE_BUNDLE="${NVPN_HOST_LINUX_VM_BUNDLE_DIR:-}"
TARGET_RELEASE_BINARY=""
TARGET_RELEASE_RECEIPT=""
TARGET_RELEASE_SHA256=""
TARGET_RELEASE_SIZE=""
SECONDARY_MAC=""
PRIMARY_MAC=""
PRIMARY_IFACE=""
PRIMARY_SOURCE=""
PRIMARY_ADDRESS=""
HYPERVISOR_UPLINK=""
SECONDARY_PROXY=""
LINUX_RUN_UNIT=""
GUEST_BINARY_COPY_TMP=""
NETWORK_CREATED=0
NIC_ATTACHED=0
PEER_INITIALIZED=0
GUEST_INITIALIZED=0
PEER_NAMESPACE_ATTEMPTED=0
TARGET_NPUB=""
TARGET_TUNNEL_IP=""
TARGET_PRIMARY_IFACE=""
TARGET_SECONDARY_IFACE=""
TARGET_PRIMARY_GATEWAY=""
TARGET_PRIMARY_ADDRESS=""
TARGET_WG_PUBLIC_KEY=""
WG_SERVER_PUBLIC_KEY=""
WG_ENDPOINT=""

mkdir -p "$ARTIFACT_DIR"

source "$ROOT/scripts/linux-vm-desktop-underlay-change-e2e.lib.sh"
source "$ROOT/scripts/lib-desktop-underlay-host-peer.sh"

resolve_expected_fips_revision() {
  local local_revision
  if [[ -n "$LOCAL_FIPS_REPO" ]]; then
    [[ -z "$(git -C "$LOCAL_FIPS_REPO" status --porcelain --untracked-files=all)" ]] \
      || fail "the exact FIPS release-gate checkout must be committed and clean"
    local_revision="$(git -C "$LOCAL_FIPS_REPO" rev-parse HEAD)"
    if [[ -n "$EXPECTED_FIPS_REV" \
      && "$local_revision" != "$EXPECTED_FIPS_REV"* \
      && "$EXPECTED_FIPS_REV" != "$local_revision"* ]]
    then
      fail "NVPN_EXPECTED_FIPS_REV differs from the local FIPS candidate"
    fi
    FIPS_SOURCE_REVISION="$local_revision"
    EXPECTED_FIPS_REV="${local_revision:0:10}"
  else
    EXPECTED_FIPS_REV="${EXPECTED_FIPS_REV:0:10}"
  fi
  [[ "$EXPECTED_FIPS_REV" =~ ^[0-9a-f]{10}$ ]] \
    || fail "set NVPN_EXPECTED_FIPS_REV to the intended FIPS Git revision"
}

sync_and_import_candidates() {
  local app_sha expected_tree harness_sha harness_tree target_head target_tree
  local guest_runner_sha cleanup_fault_runner_sha
  local host_peer_import_status=0
  RELEASE_APP_ROOT="$(cd "$RELEASE_APP_ROOT" && pwd -P)"
  export NVPN_RELEASE_APP_REPO_PATH="$RELEASE_APP_ROOT"
  app_sha="$(git -C "$RELEASE_APP_ROOT" rev-parse HEAD)"
  expected_tree="$(git -C "$RELEASE_APP_ROOT" rev-parse 'HEAD^{tree}')"
  harness_sha="$(git -C "$ROOT" rev-parse HEAD)"
  harness_tree="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
  [[ "$app_sha" == "${NVPN_EXPECTED_APP_GIT_SHA:-}" ]] \
    || fail "Linux underlay app revision differs from the release candidate"
  desktop_underlay_assert_app_candidate \
    "$app_sha" "$expected_tree" "$RELEASE_APP_ROOT" \
    || fail "Linux underlay app checkout is not the exact release candidate"
  {
    printf 'nvpn_base_commit=%s\n' "$app_sha"
    printf 'nvpn_tree=%s\n' "$expected_tree"
    printf 'harness_commit=%s\n' "$harness_sha"
    printf 'harness_tree=%s\n' "$harness_tree"
    printf 'fips_commit=%s\n' "$FIPS_SOURCE_REVISION"
    if [[ -n "$LOCAL_FIPS_REPO" ]]; then
      printf 'fips_tree=%s\n' \
        "$(git -C "$LOCAL_FIPS_REPO" rev-parse 'HEAD^{tree}')"
    fi
  } >"$ARTIFACT_DIR/source-provenance.txt"
  env \
    NVPN_UBUNTU_LOCAL_REPO_PATH="$RELEASE_APP_ROOT" \
    NVPN_UBUNTU_GUEST_SRC_ROOT="$GUEST_SRC_ROOT" \
    NVPN_UBUNTU_GIT_SYNC_EXACT_COMMIT="$app_sha" \
    "$ROOT/scripts/ubuntu-vm-git-sync.sh" "$LINUX_SSH"
  GUEST_REPO="$(run_primary "realpath '$GUEST_REPO'")"
  target_head="$(run_primary "git -C '$GUEST_REPO' rev-parse HEAD")"
  target_tree="$(run_primary "git -C '$GUEST_REPO' rev-parse 'HEAD^{tree}'")"
  [[ "$target_head" == "$app_sha" && "$target_tree" == "$expected_tree" ]] \
    || fail "Linux target revision/tree differs from the release candidate"
  desktop_underlay_import_host_peer \
    >"$ARTIFACT_DIR/host-peer-import.log" 2>&1 \
    || host_peer_import_status="$?"
  if [[ "$host_peer_import_status" != "0" ]]; then
    echo "Host peer import status: $host_peer_import_status" >&2
    tail -n 120 "$ARTIFACT_DIR/host-peer-import.log" >&2 || true
    fail "exact Linux candidate import failed"
  fi

  [[ -n "$TARGET_RELEASE_BUNDLE" \
    && "$TARGET_RELEASE_BUNDLE" == /* \
    && -d "$TARGET_RELEASE_BUNDLE" ]] \
    || fail "Linux underlay gate requires the exact release bundle"
  TARGET_RELEASE_BINARY="$TARGET_RELEASE_BUNDLE/nvpn"
  TARGET_RELEASE_RECEIPT="$TARGET_RELEASE_BUNDLE/receipt.json"
  [[ -x "$TARGET_RELEASE_BINARY" && -f "$TARGET_RELEASE_RECEIPT" ]] \
    || fail "exact Linux release bundle is incomplete"
  python3 - \
    "$TARGET_RELEASE_RECEIPT" \
    "$TARGET_RELEASE_BINARY" \
    "$app_sha" \
    "$expected_tree" \
    "$FIPS_SOURCE_REVISION" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

receipt_path, binary_path, app_sha, app_tree, fips_sha = sys.argv[1:]
receipt_file = pathlib.Path(receipt_path)
binary = pathlib.Path(binary_path)
receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
digest = hashlib.sha256(binary.read_bytes()).hexdigest()
cli = receipt.get("artifacts", {}).get("cli", {})
mode = receipt.get("builderMode")
builder_valid = (
    mode == "local-docker"
    and receipt.get("builtOnHostMac") is True
    and receipt.get("builtOnRemoteVm") is False
    and receipt.get("builderHostOs") == "Darwin"
    and receipt.get("builderHostArchitecture") in {"arm64", "x86_64"}
) or (
    mode == "remote-native"
    and receipt.get("builtOnHostMac") is False
    and receipt.get("builtOnRemoteVm") is True
    and receipt.get("builderHostOs") == "Linux"
    and receipt.get("builderHostArchitecture") == "x86_64"
)
if (
    receipt.get("schema") != 2
    or not builder_valid
    or re.fullmatch(
        r"sha256:[0-9a-f]{64}", receipt.get("containerImageId", "")
    )
    is None
    or re.fullmatch(r"[0-9a-f]{64}", receipt.get("dockerfileSha256", ""))
    is None
    or re.fullmatch(
        r"[0-9a-f]{64}", receipt.get("containerPayloadSha256", "")
    )
    is None
    or receipt.get("appGitSha") != app_sha
    or receipt.get("appGitTree") != app_tree
    or receipt.get("fipsGitSha") != fips_sha
    or cli.get("sha256") != digest
    or cli.get("size") != binary.stat().st_size
):
    raise SystemExit("exact Linux release bundle receipt differs")
PY
  TARGET_RELEASE_SHA256="$(
    shasum -a 256 "$TARGET_RELEASE_BINARY" | awk '{ print $1 }'
  )"
  TARGET_RELEASE_SIZE="$(stat -f '%z' "$TARGET_RELEASE_BINARY")"
  cp "$TARGET_RELEASE_RECEIPT" \
    "$ARTIFACT_DIR/tested-artifact-receipt.json"

  GUEST_BINARY_COPY_TMP="$GUEST_IMPORT_DIR/nvpn.copy"
  local -a primary_scp
  primary_scp=(scp -q "${SSH_LIVENESS_OPTIONS[@]}")
  if [[ -n "$PRIMARY_PROXY" ]]; then
    primary_scp+=(-o "ProxyCommand=$PRIMARY_PROXY")
  elif [[ -n "$LINUX_JUMP" ]]; then
    primary_scp+=(
      -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=no -o ControlPersist=no -o ControlPath=none -W %h:%p $LINUX_JUMP"
    )
  fi
  run_primary \
    "test ! -e '$GUEST_IMPORT_DIR' && install -d -m 0700 '$GUEST_IMPORT_DIR'"
  "${primary_scp[@]}" "$TARGET_RELEASE_BINARY" \
    "$LINUX_SSH:$GUEST_BINARY_COPY_TMP"
  guest_runner_sha="$(
    shasum -a 256 "$ROOT/scripts/desktop-linux-underlay-change-e2e.sh" \
      | awk '{ print $1 }'
  )"
  cleanup_fault_runner_sha="$(
    shasum -a 256 "$ROOT/scripts/desktop-linux-cleanup-fault-e2e.sh" \
      | awk '{ print $1 }'
  )"
  "${primary_scp[@]}" \
    "$ROOT/scripts/desktop-linux-underlay-change-e2e.sh" \
    "$LINUX_SSH:$GUEST_RUNNER.copy"
  "${primary_scp[@]}" \
    "$ROOT/scripts/desktop-linux-cleanup-fault-e2e.sh" \
    "$LINUX_SSH:$GUEST_CLEANUP_FAULT_RUNNER.copy"
  run_primary bash -s -- \
    "$GUEST_IMPORT_DIR" \
    "$TARGET_RELEASE_SHA256" \
    "$TARGET_RELEASE_SIZE" \
    "$EXPECTED_FIPS_REV" \
    "$guest_runner_sha" \
    "$cleanup_fault_runner_sha" <<'GUEST'
set -euo pipefail
import_dir="$1"
expected_sha="$2"
expected_size="$3"
expected_fips_rev="$4"
expected_runner_sha="$5"
expected_cleanup_fault_runner_sha="$6"
case "$import_dir" in
  /tmp/nvpn-linux-underlay-release-linux-*) ;;
  *) exit 2 ;;
esac
[[ -d "$import_dir" && -O "$import_dir" && ! -L "$import_dir" ]]
[[ -f "$import_dir/nvpn.copy" && ! -L "$import_dir/nvpn.copy" ]]
[[ -f "$import_dir/desktop-linux-underlay-change-e2e.sh.copy" \
  && ! -L "$import_dir/desktop-linux-underlay-change-e2e.sh.copy" ]]
[[ -f "$import_dir/desktop-linux-cleanup-fault-e2e.sh.copy" \
  && ! -L "$import_dir/desktop-linux-cleanup-fault-e2e.sh.copy" ]]
chmod 0500 "$import_dir/nvpn.copy"
[[ "$(sha256sum "$import_dir/nvpn.copy" | awk '{ print $1 }')" == "$expected_sha" ]]
[[ "$(stat -c '%s' "$import_dir/nvpn.copy")" == "$expected_size" ]]
file "$import_dir/nvpn.copy" | grep -Eq 'ELF 64-bit.*x86-64'
"$import_dir/nvpn.copy" version --verbose \
  | grep -Fq "(rev $expected_fips_rev)"
mv "$import_dir/nvpn.copy" "$import_dir/nvpn"
[[ "$(sha256sum "$import_dir/desktop-linux-underlay-change-e2e.sh.copy" \
  | awk '{ print $1 }')" == "$expected_runner_sha" ]]
[[ "$(sha256sum "$import_dir/desktop-linux-cleanup-fault-e2e.sh.copy" \
  | awk '{ print $1 }')" == "$expected_cleanup_fault_runner_sha" ]]
chmod 0500 \
  "$import_dir/desktop-linux-underlay-change-e2e.sh.copy" \
  "$import_dir/desktop-linux-cleanup-fault-e2e.sh.copy"
mv "$import_dir/desktop-linux-underlay-change-e2e.sh.copy" \
  "$import_dir/desktop-linux-underlay-change-e2e.sh"
mv "$import_dir/desktop-linux-cleanup-fault-e2e.sh.copy" \
  "$import_dir/desktop-linux-cleanup-fault-e2e.sh"
GUEST
  GUEST_BINARY_COPY_TMP=""

  local source_sha target_sha peer_sha
  source_sha="$TARGET_RELEASE_SHA256"
  target_sha="$(run_primary "sha256sum '$GUEST_BINARY' | cut -d ' ' -f1")"
  peer_sha="$(run_hypervisor \
    "sha256sum '$HYPERVISOR_BINARY' | cut -d ' ' -f1")"
  [[ "$source_sha" == "$target_sha" ]] \
    || fail "Linux target differs from the exact release CLI"
  [[ "$peer_sha" == "$DESKTOP_UNDERLAY_HOST_PEER_SHA256" ]] \
    || fail "Linux fixture peer differs from its exact release receipt"
  {
    printf 'source=%s\n' "$source_sha"
    printf 'target=%s\n' "$target_sha"
    printf 'peer=%s\n' "$peer_sha"
    printf 'builderMode=%s\n' \
      "$(jq -er '.builderMode' "$TARGET_RELEASE_RECEIPT")"
    printf 'builtOnHostMac=%s\n' \
      "$(jq -er '.builtOnHostMac' "$TARGET_RELEASE_RECEIPT")"
    printf 'builtOnRemoteVm=%s\n' \
      "$(jq -er '.builtOnRemoteVm' "$TARGET_RELEASE_RECEIPT")"
    printf 'targetImportSize=%s\n' "$TARGET_RELEASE_SIZE"
    printf 'targetImportDirectoryUnique=true\n'
    printf 'harnessRunnerSha256=%s\n' "$guest_runner_sha"
    printf 'cleanupFaultRunnerSha256=%s\n' "$cleanup_fault_runner_sha"
  } >"$ARTIFACT_DIR/linux-binary-sha256.txt"
  python3 - \
    "$ARTIFACT_DIR/tested-artifact.json" \
    "$ARTIFACT_DIR/tested-artifact-receipt.json" \
    "$TARGET_RELEASE_SHA256" \
    "$TARGET_RELEASE_SIZE" <<'PY'
import hashlib
import json
import pathlib
import sys

output, receipt_arg, cli_sha, cli_size = sys.argv[1:]
receipt = pathlib.Path(receipt_arg)
pathlib.Path(output).write_text(
    json.dumps(
        {
            "cliSha256": cli_sha,
            "cliSize": int(cli_size),
            "artifactReceiptSha256": hashlib.sha256(
                receipt.read_bytes()
            ).hexdigest(),
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY
}

capture_version_receipts() {
  local target_version peer_version expected
  expected="(rev $EXPECTED_FIPS_REV)"
  target_version="$(run_primary "$GUEST_BINARY version --verbose")"
  peer_version="$(run_hypervisor \
    "$HYPERVISOR_BINARY version --verbose")"
  grep -Fq "$expected" <<<"$target_version" \
    || fail "Linux target binary does not contain the expected FIPS revision"
  grep -Fq "$expected" <<<"$peer_version" \
    || fail "Linux peer binary does not contain the expected FIPS revision"
  printf '%s\n' "$target_version" >"$ARTIFACT_DIR/target-version.txt"
  printf '%s\n' "$peer_version" >"$ARTIFACT_DIR/peer-version.txt"
}

random_mac() {
  local octets
  octets="$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
  printf '52:54:00:%s:%s:%s\n' \
    "${octets:0:2}" "${octets:2:2}" "${octets:4:2}"
}

discover_primary_interface() {
  local row_count rows
  rows="$(run_hypervisor \
    "virsh domiflist '$VM_NAME' | awk '\$2 == \"network\" { print \$1 \"|\" \$3 \"|\" \$5 }'")"
  row_count="$(grep -c . <<<"$rows" || true)"
  [[ "$row_count" == "1" ]] \
    || fail "Linux VM must begin with exactly one libvirt network interface"
  IFS='|' read -r PRIMARY_IFACE PRIMARY_SOURCE PRIMARY_MAC <<<"$rows"
  [[ -n "$PRIMARY_IFACE" && -n "$PRIMARY_SOURCE" && -n "$PRIMARY_MAC" ]]

  PRIMARY_ADDRESS="$(run_hypervisor \
    "virsh domifaddr '$VM_NAME' --source lease | awk '\$2 == \"$PRIMARY_MAC\" && \$3 == \"ipv4\" { sub(/\\/.*/, \"\", \$4); print \$4; exit }'")"
  [[ -n "$PRIMARY_ADDRESS" ]] \
    || fail "could not resolve the Linux VM primary address from libvirt"
  HYPERVISOR_UPLINK="$(run_hypervisor \
    "ip -4 route get 1.1.1.1 | awk '{ for (i = 1; i <= NF; i++) if (\$i == \"dev\") { print \$(i + 1); exit } }'")"
  [[ -n "$HYPERVISOR_UPLINK" ]] \
    || fail "could not resolve the hypervisor physical uplink"
}

attach_secondary_network() {
  SECONDARY_MAC="$(random_mac)"
  run_hypervisor bash -s -- \
    "$VM_NAME" "$NETWORK_NAME" "$SECONDARY_GATEWAY" "$SECONDARY_NETMASK" "$SECONDARY_MAC" <<'SH'
set -euo pipefail
vm="$1"
network="$2"
gateway="$3"
netmask="$4"
mac="$5"
xml="$(mktemp)"
created=0
cleanup_remote() {
  status="$?"
  rm -f "$xml"
  if [[ "$status" -ne 0 && "$created" == "1" ]]; then
    virsh net-destroy "$network" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup_remote EXIT
! virsh net-info "$network" >/dev/null 2>&1
! ip -4 route | grep -Fq "$gateway"
cat >"$xml" <<EOF
<network>
  <name>$network</name>
  <forward mode='nat'/>
  <ip address='$gateway' netmask='$netmask'/>
</network>
EOF
virsh net-create "$xml" >/dev/null
created=1
virsh attach-interface \
  --domain "$vm" \
  --type network \
  --source "$network" \
  --model virtio \
  --mac "$mac" \
  --live >/dev/null
SH
  NETWORK_CREATED=1
  NIC_ATTACHED=1
  SECONDARY_PROXY="ssh -o BatchMode=yes -o ConnectionAttempts=1 \
-o ConnectTimeout=10 -o ControlMaster=no -o ControlPersist=no -o ControlPath=none \
-o ServerAliveInterval=2 -o ServerAliveCountMax=2 \
$HYPERVISOR_SSH -W $SECONDARY_ADDRESS:22"
}

wait_for_secondary_adapter() {
  local started="$SECONDS"
  while ((SECONDS - started < 30)); do
    if run_primary \
      "test \"\$(cat /sys/class/net/*/address | grep -Fxc '$SECONDARY_MAC')\" = 1" \
      >/dev/null 2>&1
    then
      return 0
    fi
    sleep 0.25
  done
  fail "Linux did not enumerate the transient second NIC"
}

wait_for_primary_guest() {
  local started="$SECONDS"
  while ((SECONDS - started < 30)); do
    if run_primary true >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

parse_key_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { value = substr($0, length(key) + 2) } END { print value }'
}

guest_initialize() {
  local output json
  output="$(run_guest_primary initialize \
    "NVPN_UNDERLAY_SECONDARY_ADDRESS=$SECONDARY_ADDRESS" \
    "NVPN_UNDERLAY_SECONDARY_PREFIX=$SECONDARY_PREFIX" \
    "NVPN_UNDERLAY_SECONDARY_GATEWAY=$SECONDARY_GATEWAY")"
  json="$(awk '/^\{.*\}$/ { value = $0 } END { print value }' <<<"$output")"
  [[ -n "$json" ]] || {
    printf '%s\n' "$output" >&2
    fail "Linux initialization did not return its identity receipt"
  }
  jq -e . <<<"$json" >/dev/null \
    || fail "Linux initialization returned invalid JSON"
  TARGET_NPUB="$(jq -r '.npub // empty' <<<"$json")"
  TARGET_TUNNEL_IP="$(jq -r '.tunnel_ip // empty' <<<"$json")"
  TARGET_PRIMARY_IFACE="$(jq -r '.primary_interface // empty' <<<"$json")"
  TARGET_SECONDARY_IFACE="$(jq -r '.secondary_interface // empty' <<<"$json")"
  TARGET_PRIMARY_GATEWAY="$(jq -r '.primary_gateway // empty' <<<"$json")"
  TARGET_PRIMARY_ADDRESS="$(jq -r '.primary_address // empty' <<<"$json")"
  TARGET_WG_PUBLIC_KEY="$(jq -r '.wireguard_public_key // empty' <<<"$json")"
  [[ -n "$TARGET_NPUB" \
    && -n "$TARGET_TUNNEL_IP" \
    && -n "$TARGET_PRIMARY_GATEWAY" \
    && -n "$TARGET_PRIMARY_ADDRESS" \
    && -n "$TARGET_WG_PUBLIC_KEY" ]]
  GUEST_INITIALIZED=1
  run_primary sudo -n cat "$GUEST_STATE_DIR/platform-network-monitor-probe.log" \
    >"$ARTIFACT_DIR/platform-network-monitor-probe.log"
  grep -Fq 'daemon: platform network change event; sampling physical route' \
    "$ARTIFACT_DIR/platform-network-monitor-probe.log" \
    || fail "production Linux netlink monitor probe receipt is missing"

  for _ in $(seq 1 40); do
    if secondary_ssh_command \
      && "${LINUX_SECONDARY_SSH[@]}" hostname >/dev/null 2>&1
    then
      return 0
    fi
    sleep 0.25
  done
  fail "Linux second NIC is configured but SSH cannot reach it out of band"
}

initialize_and_start_peer() {
  local output wg_output
  PEER_NAMESPACE_ATTEMPTED=1
  peer_command namespace-setup
  PEER_INITIALIZED=1
  output="$(peer_command initialize)"
  PEER_NPUB="$(parse_key_value npub <<<"$output")"
  PEER_TUNNEL_IP="$(parse_key_value tunnel_ip <<<"$output")"
  [[ -n "$PEER_NPUB" && -n "$PEER_TUNNEL_IP" ]]
  PEER_ENDPOINT="$PEER_ENDPOINT_HOST:$PEER_LISTEN_PORT"
  peer_command start \
    "NVPN_UNDERLAY_PEER_PUBLIC_ENDPOINT=$PEER_ENDPOINT" \
    "NVPN_UNDERLAY_TARGET_NPUB=$TARGET_NPUB"
  wg_output="$(peer_command wireguard-setup \
    "NVPN_UNDERLAY_WG_TARGET_PUBLIC_KEY=$TARGET_WG_PUBLIC_KEY")"
  WG_SERVER_PUBLIC_KEY="$(parse_key_value wireguard_public_key <<<"$wg_output")"
  WG_ENDPOINT="$(parse_key_value wireguard_endpoint <<<"$wg_output")"
  [[ -n "$WG_SERVER_PUBLIC_KEY" && -n "$WG_ENDPOINT" ]]
  peer_command listener-audit >"$ARTIFACT_DIR/peer-listener.txt"
  peer_command services \
    "NVPN_UNDERLAY_TARGET_TUNNEL_IP=$TARGET_TUNNEL_IP"
}

start_linux_runner() {
  LINUX_RUN_UNIT="nvpn-underlay-$RUN_TOKEN.service"
  start_guest_secondary_unit run \
    "NVPN_UNDERLAY_PEER_NPUB=$PEER_NPUB" \
    "NVPN_UNDERLAY_PEER_ENDPOINT=$PEER_ENDPOINT" \
    "NVPN_UNDERLAY_PEER_TUNNEL_IP=$PEER_TUNNEL_IP" \
    "NVPN_UNDERLAY_LISTEN_PORT=$TARGET_LISTEN_PORT" \
    "NVPN_UNDERLAY_WG_PEER_PUBLIC_KEY=$WG_SERVER_PUBLIC_KEY" \
    "NVPN_UNDERLAY_WG_ENDPOINT=$WG_ENDPOINT" \
    "NVPN_UNDERLAY_WG_CLIENT_ADDRESS=$WG_CLIENT_ADDRESS" \
    "NVPN_UNDERLAY_WG_SERVER_IP=$WG_SERVER_IP" \
    >"$ARTIFACT_DIR/linux-run.log" 2>&1
  wait_for_guest_marker ready 35
  guest_receipt secondary-underlay-ready.json \
    >"$ARTIFACT_DIR/secondary-underlay-ready.json"
  jq -e '
    .carrier == true
    and .active_profile == true
    and .default_route == false
    and .durable_default_route == true
    and .strict_exit_physical_defaults_absent == true
  ' "$ARTIFACT_DIR/secondary-underlay-ready.json" >/dev/null
  peer_command wait-ready >"$ARTIFACT_DIR/peer-ready.json"
  jq -e . "$ARTIFACT_DIR/peer-ready.json" >/dev/null
}

set_primary_link() {
  local state="$1"
  run_hypervisor \
    "date +%s.%N; virsh domif-setlink '$VM_NAME' '$PRIMARY_IFACE' '$state' >/dev/null"
}

assert_peer_recovered_from_source() {
  local cut_timestamp="$1"
  local expected_source="$2"
  local label="$3"
  local observer="$ROOT/scripts/desktop-underlay-peer-recovery-observer.sh"
  [[ -r "$observer" ]] || fail "peer recovery observer is missing"
  run_hypervisor sudo -n bash -s -- \
    "$PEER_STATE_DIR" "$cut_timestamp" "$expected_source" \
    "$RECOVERY_DEADLINE_MS" "$label" <"$observer"
}

guest_receipt() {
  run_secondary sudo -n cat "$GUEST_STATE_DIR/$1"
}

run_underlay_switches() {
  local cut receipt
  peer_command initial-source-audit \
    >"$ARTIFACT_DIR/initial-source-audit.txt"
  signal_guest arm-secondary
  wait_for_guest_marker armed-secondary 30
  cut="$(set_primary_link down)"
  printf '%s\n' "$cut" >"$ARTIFACT_DIR/secondary-link-cut-unix-seconds.txt"
  wait_for_guest_marker secondary.receipt.json 25
  receipt="$(guest_receipt secondary.receipt.json)"
  receipt="$(jq --argjson link_changed "$cut" \
    '. + {host_link_change_unix_seconds: $link_changed}' <<<"$receipt")"
  jq -e \
    --argjson deadline "$RECOVERY_DEADLINE_MS" \
    --arg interface "$TARGET_SECONDARY_IFACE" \
    --arg gateway "$SECONDARY_GATEWAY" \
    --arg source "$SECONDARY_ADDRESS" \
    '.recovery_milliseconds <= $deadline
      and .route_usable_monotonic_milliseconds > 0
      and .recovered_monotonic_milliseconds
        >= .route_usable_monotonic_milliseconds
      and .payload_successes_after > .payload_successes_before
      and .wireguard_payload_successes_after
        > .wireguard_payload_successes_before
      and (.wireguard_endpoint_route | length) == 1
      and .wireguard_endpoint_route[0].dev == $interface
      and .wireguard_endpoint_route[0].gateway == $gateway
      and .wireguard_endpoint_route[0].prefsrc == $source
      and .rebind_receipts_after == (.rebind_receipts_before + 1)' \
    <<<"$receipt" >/dev/null
  printf '%s\n' "$receipt" >"$ARTIFACT_DIR/secondary-receipt.json"
  jq -e . "$ARTIFACT_DIR/secondary-receipt.json" >/dev/null
  assert_peer_recovered_from_source "$cut" "$SECONDARY_ADDRESS" secondary \
    | tee "$ARTIFACT_DIR/secondary-peer-recovery.txt"

  signal_guest arm-primary
  wait_for_guest_marker armed-primary 30
  cut="$(set_primary_link up)"
  printf '%s\n' "$cut" >"$ARTIFACT_DIR/primary-link-cut-unix-seconds.txt"
  wait_for_guest_marker primary.receipt.json 25
  receipt="$(guest_receipt primary.receipt.json)"
  receipt="$(jq --argjson link_changed "$cut" \
    '. + {host_link_change_unix_seconds: $link_changed}' <<<"$receipt")"
  jq -e \
    --argjson deadline "$RECOVERY_DEADLINE_MS" \
    --arg interface "$TARGET_PRIMARY_IFACE" \
    --arg gateway "$TARGET_PRIMARY_GATEWAY" \
    --arg source "$TARGET_PRIMARY_ADDRESS" \
    '.recovery_milliseconds <= $deadline
      and .route_usable_monotonic_milliseconds > 0
      and .recovered_monotonic_milliseconds
        >= .route_usable_monotonic_milliseconds
      and .payload_successes_after > .payload_successes_before
      and .wireguard_payload_successes_after
        > .wireguard_payload_successes_before
      and (.wireguard_endpoint_route | length) == 1
      and .wireguard_endpoint_route[0].dev == $interface
      and .wireguard_endpoint_route[0].gateway == $gateway
      and .wireguard_endpoint_route[0].prefsrc == $source
      and .rebind_receipts_after == (.rebind_receipts_before + 1)' \
    <<<"$receipt" >/dev/null
  printf '%s\n' "$receipt" >"$ARTIFACT_DIR/primary-receipt.json"
  jq -e . "$ARTIFACT_DIR/primary-receipt.json" >/dev/null
  assert_peer_recovered_from_source "$cut" "$PRIMARY_ADDRESS" primary \
    | tee "$ARTIFACT_DIR/primary-peer-recovery.txt"
  peer_command wireguard-audit >"$ARTIFACT_DIR/wireguard-responder-audit.txt"
}

counter_value() {
  local key="$1"
  parse_key_value "$key"
}

stable_dns_counters() {
  local previous current started="$SECONDS" quiet_since
  previous="$(peer_command counters)" || return 1
  quiet_since="$SECONDS"
  while ((SECONDS - started < 20)); do
    sleep 0.2
    current="$(peer_command counters)" || return 1
    if [[ "$current" != "$previous" ]]; then
      quiet_since="$SECONDS"
    # Five clock ticks guarantee at least four quiet seconds despite SECONDS'
    # one-second precision, exceeding the old resolver's three-second timeout.
    elif ((SECONDS - quiet_since >= 5)); then
      printf '%s\n' "$current"
      return 0
    fi
    previous="$current"
  done
  fail "resolver path counters did not settle"
}

run_dns_case() {
  local name="$1"
  local counter="$2"
  local before after key before_value after_value
  local -a counters=(profile_dns cloudflare quad9 google fixture_dns)
  signal_guest "dns-$name.go"
  wait_for_guest_marker "dns-$name.configured" 30
  before="$(stable_dns_counters)"
  signal_guest "dns-$name.query"
  wait_for_guest_marker "dns-$name.receipt" 30
  after="$(stable_dns_counters)"
  signal_guest "dns-$name.snapshotted"
  wait_for_guest_marker "dns-$name.resumed" 30
  for key in "${counters[@]}"; do
    before_value="$(counter_value "$key" <<<"$before")"
    after_value="$(counter_value "$key" <<<"$after")"
    [[ "$before_value" =~ ^[0-9]+$ && "$after_value" =~ ^[0-9]+$ ]] \
      || fail "$name returned an invalid $key resolver counter"
    if [[ "$key" == "$counter" ]]; then
      ((after_value > before_value)) \
        || fail "$name did not create a real $counter resolver flow through the exit"
    else
      [[ "$after_value" == "$before_value" ]] \
        || fail "$name also used the forbidden $key resolver path"
    fi
  done
  {
    printf 'case=%s\n' "$name"
    for key in "${counters[@]}"; do
      printf 'before_%s=%s\n' "$key" "$(counter_value "$key" <<<"$before")"
      printf 'after_%s=%s\n' "$key" "$(counter_value "$key" <<<"$after")"
    done
  } >>"$ARTIFACT_DIR/dns-matrix.txt"
}

run_dns_matrix_and_direct_restore() {
  run_dns_case automatic profile_dns
  run_dns_case cloudflare cloudflare
  run_dns_case quad9 quad9
  run_dns_case custom google
  run_dns_case through-exit fixture_dns

  signal_guest select-direct
  wait_for_guest_runner_success \
    >"$ARTIFACT_DIR/linux-run-unit-receipt.txt"
  run_primary sudo -n cat "$GUEST_STATE_DIR/direct.receipt.json" \
    >"$ARTIFACT_DIR/direct-receipt.json"
  jq -e . "$ARTIFACT_DIR/direct-receipt.json" >/dev/null
  jq -e '
    .wireguard_interface_removed == true
    and .wireguard_endpoint_route_removed == true
    and .wireguard_policy_rule_removed == true
    and .wireguard_policy_table_empty == true
    and .verified_https == true
  ' "$ARTIFACT_DIR/direct-receipt.json" >/dev/null
  stop_guest_runner_unit
}

run_sigkill_restart_recovery() {
  run_guest_primary crash-repair \
    "NVPN_UNDERLAY_PEER_NPUB=$PEER_NPUB" \
    "NVPN_UNDERLAY_PEER_ENDPOINT=$PEER_ENDPOINT" \
    "NVPN_UNDERLAY_PEER_TUNNEL_IP=$PEER_TUNNEL_IP" \
    "NVPN_UNDERLAY_LISTEN_PORT=$TARGET_LISTEN_PORT" \
    "NVPN_UNDERLAY_WG_PEER_PUBLIC_KEY=$WG_SERVER_PUBLIC_KEY" \
    "NVPN_UNDERLAY_WG_ENDPOINT=$WG_ENDPOINT" \
    "NVPN_UNDERLAY_WG_CLIENT_ADDRESS=$WG_CLIENT_ADDRESS" \
    "NVPN_UNDERLAY_WG_SERVER_IP=$WG_SERVER_IP" \
    >"$ARTIFACT_DIR/crash-repair.log"
  run_primary sudo -n cat "$GUEST_STATE_DIR/crash-repair.receipt.json" \
    >"$ARTIFACT_DIR/crash-repair-receipt.json"
  jq -e . "$ARTIFACT_DIR/crash-repair-receipt.json" >/dev/null
  jq -e \
    --arg binary_sha256 "$TARGET_RELEASE_SHA256" \
    --argjson deadline "$RECOVERY_DEADLINE_MS" '
      .binary_sha256 == $binary_sha256
      and .sigkill_exit_code == 137
      and .fresh_wireguard_handshake == true
      and .through_exit_dns_before_crash == true
      and .verified_https_before_crash == true
      and .cleanup_journal_survived_sigkill == true
      and .wireguard_interface_survived_sigkill == true
      and .wireguard_endpoint_route_survived_sigkill == true
      and .wireguard_policy_rule_survived_sigkill == true
      and .wireguard_policy_table_survived_sigkill == true
      and .secure_dns_cleanup_ownership_survived_sigkill == true
      and .startup_repair_without_explicit_command == true
      and .cleanup_journal_removed == true
      and .wireguard_interface_removed == true
      and .wireguard_endpoint_route_removed == true
      and .wireguard_policy_rule_removed == true
      and .wireguard_policy_table_empty == true
      and .secure_dns_cleanup_ownership_removed == true
      and .physical_default_restored == true
      and .public_dns_restored == true
      and .verified_https_after_restart == true
      and .restart_daemon_paused == true
      and .restart_daemon_count == 1
      and .restart_daemon_pid > 0
      and .restart_repair_milliseconds <= $deadline
    ' "$ARTIFACT_DIR/crash-repair-receipt.json" >/dev/null
  run_primary sudo -n cat "$GUEST_STATE_DIR/crash-journal-ownership.json" \
    >"$ARTIFACT_DIR/crash-journal-ownership.json"
  jq -e \
    --arg iface "$TARGET_TUN_IFACE" '
      .iface == $iface
      and .wireguard.interface == "nvpn-wg-exit"
      and .wireguard.table == 51888
      and .wireguard.priority == 10888
      and .secure_dns.interface == $iface
    ' "$ARTIFACT_DIR/crash-journal-ownership.json" >/dev/null
}

run_cleanup_fault_regression() {
  local command_status=0
  if run_guest_primary cleanup-fault \
    "NVPN_UNDERLAY_PEER_NPUB=$PEER_NPUB" \
    "NVPN_UNDERLAY_PEER_ENDPOINT=$PEER_ENDPOINT" \
    "NVPN_UNDERLAY_PEER_TUNNEL_IP=$PEER_TUNNEL_IP" \
    "NVPN_UNDERLAY_LISTEN_PORT=$TARGET_LISTEN_PORT" \
    "NVPN_UNDERLAY_WG_PEER_PUBLIC_KEY=$WG_SERVER_PUBLIC_KEY" \
    "NVPN_UNDERLAY_WG_ENDPOINT=$WG_ENDPOINT" \
    "NVPN_UNDERLAY_WG_CLIENT_ADDRESS=$WG_CLIENT_ADDRESS" \
    "NVPN_UNDERLAY_WG_SERVER_IP=$WG_SERVER_IP" \
    >"$ARTIFACT_DIR/cleanup-fault.log" 2>&1
  then
    :
  else
    command_status=$?
  fi
  printf 'exitStatus=%s\n' "$command_status" \
    >"$ARTIFACT_DIR/cleanup-fault-command-status.txt"
  capture_cleanup_fault_diagnostics
  ((command_status == 0)) || return "$command_status"
  jq -e '
      .xtables_retries_exhausted == true
      and .normal_stop_failed == true
      and .physical_network_restored_before_repair == true
      and .repair_transitioned_to_disconnected == true
    ' "$ARTIFACT_DIR/cleanup-fault-receipt.json" >/dev/null
}

run_optional_cleanup_fault_regression() {
  case "${NVPN_LINUX_UNDERLAY_CLEANUP_FAULT_DIAGNOSTIC:-0}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On)
      run_cleanup_fault_regression
      ;;
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping optional Linux xtables cleanup-fault diagnostic."
      ;;
    *)
      fail "unsupported NVPN_LINUX_UNDERLAY_CLEANUP_FAULT_DIAGNOSTIC value"
      ;;
  esac
}

capture_cleanup_fault_diagnostics() {
  local name destination
  local diagnostics_dir="$ARTIFACT_DIR/cleanup-fault-diagnostics"
  local -a diagnostics=(
    cleanup-fault.receipt.json
    xtables-stop.log
    fault-daemon.stdout.log
    fault-daemon.stderr.log
    xtables-lock-held
    xtables-lock-release
  )
  mkdir -p "$diagnostics_dir"
  : >"$ARTIFACT_DIR/cleanup-fault-diagnostics.txt"
  for name in "${diagnostics[@]}"; do
    destination="$diagnostics_dir/$name"
    if run_primary sudo -n test -f "$GUEST_STATE_DIR/$name"; then
      run_primary sudo -n cat "$GUEST_STATE_DIR/$name" >"$destination"
      printf '%s=present\n' "$name" \
        >>"$ARTIFACT_DIR/cleanup-fault-diagnostics.txt"
    else
      printf '%s=missing\n' "$name" \
        >>"$ARTIFACT_DIR/cleanup-fault-diagnostics.txt"
    fi
  done
  if [[ -f "$diagnostics_dir/cleanup-fault.receipt.json" ]]; then
    cp "$diagnostics_dir/cleanup-fault.receipt.json" \
      "$ARTIFACT_DIR/cleanup-fault-receipt.json"
  fi
}

capture_guest_state() {
  local transport="$1"
  local remote_command
  remote_command="sudo -n tar --ignore-failed-read -C '$GUEST_STATE_DIR' -cf - \
identity.json daemon.state.json daemon.stderr.log daemon.stdout.log \
payload.log platform-network-monitor-probe.log signed-rosters.json \
runner.stdout.log runner.stderr.log \
secondary-underlay-ready.json secondary.nm-uuid \
secondary.receipt.json primary.receipt.json direct.receipt.json \
crash-repair.receipt.json crash-journal-ownership.json \
crash-connect.stderr.log crash-restart-daemon.stderr.log \
cleanup-fault.receipt.json xtables-stop.log \
fault-daemon.stdout.log fault-daemon.stderr.log \
xtables-lock-held xtables-lock-release"
  case "$transport" in
    secondary)
      run_secondary_bounded 30 "$remote_command" \
        | tar -C "$ARTIFACT_DIR/guest-state" -xf -
      ;;
    primary)
      primary_ssh_command
      "${LINUX_PRIMARY_SSH[@]}" "$remote_command" \
        | tar -C "$ARTIFACT_DIR/guest-state" -xf -
      ;;
    *)
      fail "unsupported guest evidence transport: $transport"
      ;;
  esac
}

capture_peer_state() {
  run_hypervisor_bounded 30 \
    "sudo -n tar --ignore-failed-read -C '$PEER_STATE_DIR' -cf - \
      daemon.state.json daemon.stderr.log daemon.stdout.log signed-rosters.json \
      dns.log dnsmasq.log fips-underlay.pcap.txt wireguard-underlay.pcap.txt \
      peer-payload.log tcpdump.log wg-tcpdump.log" \
    | tar -C "$ARTIFACT_DIR/peer-state" -xf -
}

capture_remote_state() {
  local guest_capture_required="$GUEST_INITIALIZED"
  local peer_capture_required="$PEER_INITIALIZED"
  local guest_capture_succeeded=0
  local peer_capture_succeeded=0
  local capture_failed=0
  mkdir -p "$ARTIFACT_DIR/guest-state" "$ARTIFACT_DIR/peer-state"
  if [[ -n "$SECONDARY_PROXY" ]] \
    && run_secondary_bounded 8 \
      sudo -n test -d "$GUEST_STATE_DIR" >/dev/null 2>&1
  then
    capture_guest_state secondary && guest_capture_succeeded=1
  fi
  if [[ "$guest_capture_succeeded" == "0" ]] \
    && run_primary sudo -n test -d "$GUEST_STATE_DIR" >/dev/null 2>&1
  then
    capture_guest_state primary && guest_capture_succeeded=1
  fi
  if [[ "$PEER_INITIALIZED" == "1" ]] \
    && run_hypervisor_bounded 8 \
      "sudo -n test -d '$PEER_STATE_DIR'" >/dev/null 2>&1
  then
    capture_peer_state && peer_capture_succeeded=1
  fi
  find "$ARTIFACT_DIR/guest-state" "$ARTIFACT_DIR/peer-state" \
    -type f \( -iname '*secret*' -o -name 'config.toml' \) -delete
  if [[ "$guest_capture_required" == "1" && "$guest_capture_succeeded" != "1" ]]; then
    capture_failed=1
  fi
  if [[ "$peer_capture_required" == "1" && "$peer_capture_succeeded" != "1" ]]; then
    capture_failed=1
  fi
  if [[ "$guest_capture_required" == "0" \
    && "$peer_capture_required" == "0" \
    && "$guest_capture_succeeded" == "0" \
    && "$peer_capture_succeeded" == "0" ]]
  then
    return 0
  fi
  {
    printf 'guest_capture_required=%s\n' "$guest_capture_required"
    printf 'guest_capture_succeeded=%s\n' "$guest_capture_succeeded"
    printf 'peer_capture_required=%s\n' "$peer_capture_required"
    printf 'peer_capture_succeeded=%s\n' "$peer_capture_succeeded"
    printf 'capture_failed=%s\n' "$capture_failed"
  } >"$ARTIFACT_DIR/runtime-evidence-capture.txt"
  if [[ "$capture_failed" == "0" ]]; then
    echo "REMOTE_RUNTIME_EVIDENCE_CAPTURED" \
      >>"$ARTIFACT_DIR/runtime-evidence-capture.txt"
  fi
  [[ "$capture_failed" == "0" ]]
}

audit_guest_cleanup() {
  run_primary sudo -n bash -s -- \
    "$GUEST_BINARY" "$GUEST_STATE_DIR" "$TARGET_TUN_IFACE" \
    "$PRIMARY_MAC" "$SECONDARY_MAC" "$PROBE_URL" <<'SH'
set -euo pipefail
binary="$1"
state="$2"
tun="$3"
primary_mac="${4,,}"
secondary_mac="${5,,}"
url="$6"
interface_for_mac() {
  local wanted="$1"
  local path
  for path in /sys/class/net/*/address; do
    [[ "$(<"$path")" == "$wanted" ]] && basename "$(dirname "$path")"
  done
  return 0
}
primary="$(interface_for_mac "$primary_mac")"
secondary="$(interface_for_mac "$secondary_mac")"
profile_uuid="$(cat "$state/secondary.nm-uuid" 2>/dev/null || true)"
profile_name="$(cat "$state/secondary.nm-name" 2>/dev/null || true)"
cleanup_state() {
  rm -rf "$state"
}
trap cleanup_state EXIT
[[ -n "$primary" ]] || {
  echo "Linux guest cleanup audit failed: original physical interface is missing" >&2
  exit 1
}
[[ -z "$secondary" ]] || {
  echo "Linux guest cleanup audit failed: transient physical interface remains" >&2
  exit 1
}
"$binary" stop --config "$state/config.toml" --timeout-secs 5 --force >/dev/null
! pgrep -a -x nvpn 2>/dev/null | grep -Fq -- "--config $state/config.toml" \
  || { echo "Linux guest cleanup audit failed: nvpn process remains" >&2; exit 1; }
! ip link show dev "$tun" >/dev/null 2>&1 \
  || { echo "Linux guest cleanup audit failed: nvpn tunnel remains" >&2; exit 1; }
! resolvectl dns "$tun" 2>/dev/null | grep -Fq 127.0.0.1 \
  || { echo "Linux guest cleanup audit failed: nvpn DNS remains" >&2; exit 1; }
if [[ -n "$profile_uuid" ]]; then
  ! nmcli -t -f UUID connection show | grep -Fxq "$profile_uuid" \
    || {
      echo "Linux guest cleanup audit failed: transient NetworkManager profile remains" >&2
      exit 1
    }
fi
if [[ -n "$profile_name" ]]; then
  ! nmcli -t -f NAME connection show | grep -Fxq "$profile_name" \
    || {
      echo "Linux guest cleanup audit failed: transient NetworkManager profile name remains" >&2
      exit 1
    }
fi
deadline=$((SECONDS + 15))
while ((SECONDS < deadline)); do
  [[ "$(ip -j -4 route get 1.1.1.1 | jq -r '.[0].dev')" == "$primary" ]] && break
  sleep 0.1
done
[[ "$(ip -j -4 route get 1.1.1.1 | jq -r '.[0].dev')" == "$primary" ]] \
  || { echo "Linux guest cleanup audit failed: native default route was not restored" >&2; exit 1; }
host="${url#*://}"
host="${host%%/*}"
getent ahostsv4 "${host%%:*}" >/dev/null \
  || { echo "Linux guest cleanup audit failed: native DNS was not restored" >&2; exit 1; }
curl -4 --fail --silent --show-error --max-time 8 --output /dev/null "$url" \
  || { echo "Linux guest cleanup audit failed: native HTTPS was not restored" >&2; exit 1; }
[[ ! -e "$state/emergency-repair-invoked" ]] \
  || { echo "Linux guest cleanup audit failed: emergency repair was invoked" >&2; exit 1; }
rm -rf "$state"
[[ ! -e "$state" ]]
trap - EXIT
echo "LINUX_GUEST_CLEANUP_AUDIT_OK"
SH
}

audit_hypervisor_cleanup() {
  run_hypervisor_bounded 30 bash -s -- \
    "$VM_NAME" "$NETWORK_NAME" "$PRIMARY_IFACE" "$PRIMARY_MAC" \
    "$PEER_TUN_IFACE" "$PEER_STATE_DIR" "$COUNTER_CHAIN" \
    "$PEER_NETNS" "$PEER_HOST_VETH" "$PEER_ENDPOINT_HOST" \
    "$PEER_NAMESPACE_PREFIX" "$PEER_FORWARD_CHAIN" "$PEER_NAT_CHAIN" <<'SH'
set -euo pipefail
vm="$1"
network="$2"
primary_iface="$3"
primary_mac="$4"
peer_tun="$5"
peer_state="$6"
counter_chain="$7"
peer_netns="$8"
peer_host_veth="$9"
peer_address="${10}"
peer_prefix="${11}"
forward_chain="${12}"
nat_chain="${13}"
fail() {
  echo "Linux hypervisor cleanup audit failed: $*" >&2
  exit 1
}
rows="$(virsh domiflist "$vm" | awk '$2 == "network" { print $1 "|" $5 }')"
[[ "$(grep -c . <<<"$rows" || true)" == "1" ]] \
  || fail "VM does not have exactly its original NIC"
[[ "$rows" == "$primary_iface|$primary_mac" ]] \
  || fail "VM NIC identity differs from the original"
[[ "$(virsh domif-getlink "$vm" "$primary_iface" | awk '{ print $NF }')" == "up" ]] \
  || fail "VM primary link was not restored"
! virsh net-info "$network" >/dev/null 2>&1 \
  || fail "transient libvirt network remains"
! ip link show dev "$peer_tun" >/dev/null 2>&1 \
  || fail "peer tunnel remains"
! sudo -n test -e "$peer_state" \
  || fail "peer state directory remains"
! sudo -n iptables -t mangle -S "$counter_chain" >/dev/null 2>&1 \
  || fail "peer DNS counter chain remains"
! sudo -n ip netns list | awk '{ print $1 }' | grep -Fxq "$peer_netns" \
  || fail "peer namespace remains"
! sudo -n test -e "/run/nvpn-$peer_netns" \
  || fail "peer daemon singleton runtime remains"
! ip link show dev "$peer_host_veth" >/dev/null 2>&1 \
  || fail "peer namespace veth remains"
! ip -4 route show exact "$peer_address/$peer_prefix" | grep -q . \
  || fail "peer namespace route remains"
! sudo -n iptables -S "$forward_chain" >/dev/null 2>&1 \
  || fail "peer forwarding chain remains"
! sudo -n iptables -t nat -S "$nat_chain" >/dev/null 2>&1 \
  || fail "peer NAT chain remains"
! pgrep -a -x nvpn 2>/dev/null | grep -Fq -- "--config $peer_state/config.toml" \
  || fail "peer process remains"
echo "LINUX_HYPERVISOR_CLEANUP_AUDIT_OK"
SH
}

cleanup_guest_import() {
  run_primary bash -s -- "$GUEST_IMPORT_DIR" <<'GUEST'
set -euo pipefail
import_dir="$1"
case "$import_dir" in
  /tmp/nvpn-linux-underlay-release-linux-*) ;;
  *) exit 2 ;;
esac
if [[ -e "$import_dir" ]]; then
  [[ -d "$import_dir" && ! -L "$import_dir" ]]
  find "$import_dir" -xdev -depth -mindepth 1 -delete
  rmdir "$import_dir"
fi
test ! -e "$import_dir"
GUEST
  printf 'remoteArtifactRemoved=true\n' \
    >"$ARTIFACT_DIR/target-import-cleanup-audit.txt"
}

cleanup() {
  local status="$?"
  local cleanup_failed=0
  trap - EXIT INT TERM
  set +e
  set +u
  if [[ -n "$PRIMARY_IFACE" ]]; then
    run_hypervisor_bounded 30 \
      "virsh domif-setlink '$VM_NAME' '$PRIMARY_IFACE' up" >/dev/null 2>&1 \
      || cleanup_failed=1
  fi
  if [[ "$NIC_ATTACHED" == "1" ]]; then
    wait_for_primary_guest || cleanup_failed=1
  fi
  if [[ -n "$GUEST_BINARY_COPY_TMP" ]]; then
    run_primary "rm -f '$GUEST_BINARY_COPY_TMP'" >/dev/null 2>&1 || cleanup_failed=1
  fi
  capture_remote_state || cleanup_failed=1
  if [[ -n "$LINUX_RUN_UNIT" ]]; then
    run_primary sudo -n systemctl status --no-pager "$LINUX_RUN_UNIT" \
      >"$ARTIFACT_DIR/linux-run-unit-cleanup-state.txt" 2>&1 || true
    stop_guest_runner_unit >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "$NIC_ATTACHED" == "1" ]]; then
    run_guest_primary cleanup >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "$PEER_INITIALIZED" == "1" ]]; then
    peer_command cleanup >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "$PEER_NAMESPACE_ATTEMPTED" == "1" ]]; then
    peer_command namespace-cleanup >/dev/null 2>&1 || cleanup_failed=1
    peer_command namespace-audit >"$ARTIFACT_DIR/peer-namespace-cleanup-audit.txt" 2>&1 \
      || cleanup_failed=1
  fi
  desktop_underlay_cleanup_host_peer >/dev/null 2>&1 \
    || cleanup_failed=1
  if [[ "$NIC_ATTACHED" == "1" && -n "$SECONDARY_MAC" ]]; then
    run_hypervisor_bounded 30 \
      "virsh detach-interface --domain '$VM_NAME' --type network --mac '$SECONDARY_MAC' --live" \
      >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "$NETWORK_CREATED" == "1" ]]; then
    run_hypervisor_bounded 30 \
      "virsh net-destroy '$NETWORK_NAME'" >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "$NIC_ATTACHED" == "1" ]]; then
    wait_for_primary_guest || cleanup_failed=1
    audit_guest_cleanup >"$ARTIFACT_DIR/guest-cleanup-audit.txt" 2>&1 \
      || cleanup_failed=1
    audit_hypervisor_cleanup >"$ARTIFACT_DIR/hypervisor-cleanup-audit.txt" 2>&1 \
      || cleanup_failed=1
  fi
  cleanup_guest_import >/dev/null 2>&1 || cleanup_failed=1
  if [[ "$cleanup_failed" == "1" ]]; then
    echo "Linux underlay cleanup audit failed; inspect $ARTIFACT_DIR" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

resolve_expected_fips_revision
sync_and_import_candidates
capture_version_receipts
discover_primary_interface
attach_secondary_network
wait_for_secondary_adapter
guest_initialize
initialize_and_start_peer
start_linux_runner
run_underlay_switches
run_dns_matrix_and_direct_restore
run_sigkill_restart_recovery
run_optional_cleanup_fault_regression

echo "LINUX_UNDERLAY_NETWORK_CHANGE_E2E_OK"
echo "artifacts=$ARTIFACT_DIR"
