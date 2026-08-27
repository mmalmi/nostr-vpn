#!/usr/bin/env bash
# Real Windows VM network-change gate.
#
# The virtualization host creates a transient second NAT network, attaches one
# second NIC to the running guest, and then physically cuts/restores the
# original virtual link. A production nvpn/FIPS peer on the host provides a
# selected exit, resolver, and continuous reverse-direction payload. The guest
# simultaneously sends continuous payload through its shipped Wintun/FIPS
# daemon and requires in-place carrier recovery within four seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HYPERVISOR_SSH="${NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH:?set NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH}"
VM_NAME="${NVPN_WINDOWS_UNDERLAY_VM_NAME:-${NVPN_WINDOWS_VM_NAME:-}}"
[[ -n "$VM_NAME" ]] || {
  echo "set NVPN_WINDOWS_UNDERLAY_VM_NAME" >&2
  exit 2
}
WINDOWS_SSH="${NVPN_WINDOWS_SSH_HOST:?set NVPN_WINDOWS_SSH_HOST}"
PRIMARY_PROXY="${NVPN_WINDOWS_SSH_PROXY_COMMAND:-}"
WINDOWS_JUMP="${NVPN_WINDOWS_SSH_JUMP:-}"
GUEST_REPO="${NVPN_WINDOWS_GUEST_REPO_PATH:-C:\\src\\nvpn-desktop-underlay\\windows-target\\nostr-vpn-release-gate}"
GUEST_FIPS_REPO="${NVPN_WINDOWS_GUEST_FIPS_REPO_PATH:-C:\\src\\nvpn-desktop-underlay\\windows-target\\fips-release-gate}"
GUEST_BINARY="${NVPN_WINDOWS_EXACT_CLI_PATH:?set NVPN_WINDOWS_EXACT_CLI_PATH to the packaged Windows CLI}"
GUEST_INSTALLER_RECEIPT="${NVPN_WINDOWS_INSTALLER_RECEIPT_PATH:?set NVPN_WINDOWS_INSTALLER_RECEIPT_PATH to its installer receipt}"
HOST_INSTALLER_RECEIPT="${NVPN_WINDOWS_HOST_INSTALLER_RECEIPT_PATH:?set NVPN_WINDOWS_HOST_INSTALLER_RECEIPT_PATH to the host-copied installer receipt}"
HOST_SOURCE_FIPS_RECEIPT="${NVPN_WINDOWS_HOST_SOURCE_FIPS_RECEIPT_PATH:?set NVPN_WINDOWS_HOST_SOURCE_FIPS_RECEIPT_PATH to the host-copied crates.io source receipt}"
ARTIFACT_APP_SHA="${NVPN_WINDOWS_ARTIFACT_APP_GIT_SHA:-${NVPN_EXPECTED_APP_GIT_SHA:-}}"
ARTIFACT_APP_TREE="${NVPN_WINDOWS_ARTIFACT_APP_GIT_TREE:-${NVPN_EXPECTED_APP_GIT_TREE:-}}"
LOCAL_FIPS_REPO="${NVPN_FIPS_REPO_PATH:-}"
EXPECTED_FIPS_SHA="${NVPN_EXPECTED_FIPS_GIT_SHA:?set NVPN_EXPECTED_FIPS_GIT_SHA}"
EXPECTED_FIPS_TREE="${NVPN_EXPECTED_FIPS_GIT_TREE:?set NVPN_EXPECTED_FIPS_GIT_TREE}"
EXPECTED_FIPS_VERSION="${NVPN_EXPECTED_FIPS_VERSION:?set NVPN_EXPECTED_FIPS_VERSION}"
EXPECTED_FIPS_REV=""
FIPS_SOURCE_REVISION=""
HYPERVISOR_BINARY=""
RECOVERY_DEADLINE_MS="${NVPN_DESKTOP_UNDERLAY_RECOVERY_DEADLINE_MS:-4000}"
NETWORK_ID="${NVPN_WINDOWS_UNDERLAY_NETWORK_ID:-desktop-underlay-windows-release-gate}"
SECONDARY_GATEWAY="${NVPN_WINDOWS_UNDERLAY_SECONDARY_GATEWAY:-172.31.253.1}"
SECONDARY_ADDRESS="${NVPN_WINDOWS_UNDERLAY_SECONDARY_ADDRESS:-172.31.253.10}"
SECONDARY_NETMASK="${NVPN_WINDOWS_UNDERLAY_SECONDARY_NETMASK:-255.255.255.0}"
SECONDARY_PREFIX="${NVPN_WINDOWS_UNDERLAY_SECONDARY_PREFIX:-24}"
FIXTURE_DNS_NAME="${NVPN_DESKTOP_UNDERLAY_FIXTURE_DNS_NAME:-underlay-gate.nvpn.test}"
PROBE_URL="${NVPN_DESKTOP_UNDERLAY_PROBE_URL:-https://example.com/}"
RUN_TOKEN="windows-$$-$RANDOM"
NETWORK_NAME="nvpn-underlay-$RUN_TOKEN"
PEER_STATE_DIR="/tmp/nvpn-underlay-peer-$RUN_TOKEN"
GUEST_STATE_DIR="C:\\nvpn-underlay-$RUN_TOKEN"
GUEST_CONFIG="$GUEST_STATE_DIR\\config.toml"
PEER_TUN_IFACE="nvup${RANDOM}"
PEER_LISTEN_PORT="$((46000 + RANDOM % 1000))"
TARGET_LISTEN_PORT="$((47000 + RANDOM % 1000))"
WG_LISTEN_PORT="$((51000 + RANDOM % 1000))"
WG_PEER_IFACE="nvwg${RANDOM}"
WG_CLIENT_ADDRESS="${NVPN_WINDOWS_UNDERLAY_WG_CLIENT_ADDRESS:-10.232.1.2/32}"
WG_SERVER_ADDRESS="${NVPN_WINDOWS_UNDERLAY_WG_SERVER_ADDRESS:-10.232.1.1/24}"
WG_SERVER_IP="${WG_SERVER_ADDRESS%/*}"
WG_TARGET_INTERFACE="nvpn-wg-exit"
COUNTER_CHAIN="nvu-$((RANDOM % 100000))"
PEER_NETNS="nvw$((RANDOM % 100000))"
PEER_HOST_VETH="nvwh$((RANDOM % 100000))"
PEER_NS_VETH="nvwn0"
PEER_NAMESPACE_HOST_ADDRESS="${NVPN_WINDOWS_UNDERLAY_PEER_NAMESPACE_HOST_ADDRESS:-10.231.253.1}"
PEER_ENDPOINT_HOST="${NVPN_WINDOWS_UNDERLAY_PEER_NAMESPACE_ADDRESS:-10.231.253.2}"
PEER_NAMESPACE_PREFIX="${NVPN_WINDOWS_UNDERLAY_PEER_NAMESPACE_PREFIX:-30}"
PEER_FORWARD_CHAIN="nvf$((RANDOM % 100000))"
PEER_NAT_CHAIN="nvn$((RANDOM % 100000))"
ARTIFACT_DIR="${NVPN_DESKTOP_UNDERLAY_ARTIFACT_DIR:-$ROOT/artifacts/desktop-underlay/windows-$RUN_TOKEN}"
SECONDARY_MAC=""
PRIMARY_MAC=""
PRIMARY_IFACE=""
PRIMARY_SOURCE=""
PRIMARY_ADDRESS=""
HYPERVISOR_UPLINK=""
SECONDARY_PROXY=""
WINDOWS_RUN_PID=""
GUEST_INITIALIZED=0
QUARANTINE_GUEST_NETWORK=0
NETWORK_CREATED=0
NIC_ATTACHED=0
PEER_INITIALIZED=0
PEER_NAMESPACE_ATTEMPTED=0
TARGET_WG_PUBLIC_KEY=""
TARGET_PRIMARY_GATEWAY=""
TARGET_PRIMARY_ADDRESS=""
WG_SERVER_PUBLIC_KEY=""
WG_ENDPOINT=""
CANDIDATE_NATIVE_CONFIG_PATH=""
CANDIDATE_NATIVE_MARKER_PATH=""
CANDIDATE_NATIVE_OWNER_DIR=""

mkdir -p "$ARTIFACT_DIR"

source "$ROOT/scripts/windows-vm-desktop-underlay-change-e2e.lib.sh"
source "$ROOT/scripts/lib-desktop-underlay-host-peer.sh"

[[ -f "$HOST_INSTALLER_RECEIPT" && -r "$HOST_INSTALLER_RECEIPT" ]] \
  || fail "host-copied Windows installer receipt is unreadable: $HOST_INSTALLER_RECEIPT"
[[ -f "$HOST_SOURCE_FIPS_RECEIPT" && -r "$HOST_SOURCE_FIPS_RECEIPT" ]] \
  || fail "host-copied Windows crates.io source receipt is unreadable: $HOST_SOURCE_FIPS_RECEIPT"
EXPECTED_INSTALLER_RECEIPT_SHA256="$(shasum -a 256 "$HOST_INSTALLER_RECEIPT" | awk '{ print $1 }')"
[[ "$EXPECTED_INSTALLER_RECEIPT_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || fail "host-copied Windows installer receipt has no SHA-256"

resolve_expected_fips_revision() {
  [[ -n "$LOCAL_FIPS_REPO" ]] \
    || fail "set NVPN_FIPS_REPO_PATH to the exact FIPS release checkout"
  [[ -z "$(git -C "$LOCAL_FIPS_REPO" status --porcelain --untracked-files=all)" ]] \
    || fail "the exact FIPS release-gate checkout must be committed and clean"
  FIPS_SOURCE_REVISION="$(git -C "$LOCAL_FIPS_REPO" rev-parse HEAD)"
  [[ "$FIPS_SOURCE_REVISION" == "$EXPECTED_FIPS_SHA" \
    && "$(git -C "$LOCAL_FIPS_REPO" rev-parse 'HEAD^{tree}')" == "$EXPECTED_FIPS_TREE" ]] \
    || fail "local FIPS checkout differs from the exact crates.io release"
  EXPECTED_FIPS_REV="${EXPECTED_FIPS_SHA:0:10}"
}

sync_and_import_candidates() {
  local harness_sha harness_tree windows_head windows_tree
  local expected_fips_tree="" windows_fips_tree=""
  [[ "$ARTIFACT_APP_SHA" =~ ^[0-9a-f]{40}$ \
    && "$ARTIFACT_APP_TREE" =~ ^[0-9a-f]{40}$ ]] \
    || fail "Windows underlay requires an exact packaged app revision and tree"
  [[ "$(git -C "$ROOT" rev-parse "$ARTIFACT_APP_SHA^{tree}")" == "$ARTIFACT_APP_TREE" ]] \
    || fail "Windows packaged app revision/tree is unavailable or inconsistent"
  harness_sha="$(git -C "$ROOT" rev-parse HEAD)"
  harness_tree="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
  desktop_underlay_assert_app_candidate "$harness_sha" "$harness_tree" \
    || fail "Windows underlay harness checkout is not committed and clean"
  node "$ROOT/scripts/release-source-verification.mjs" \
    windows-cratesio-provenance \
    "$HOST_SOURCE_FIPS_RECEIPT" \
    "$HOST_INSTALLER_RECEIPT" \
    "$ARTIFACT_APP_SHA" \
    "$ARTIFACT_APP_TREE" \
    "$LOCAL_FIPS_REPO" \
    "$EXPECTED_FIPS_SHA" \
    "$EXPECTED_FIPS_TREE" \
    "$EXPECTED_FIPS_VERSION" \
    >"$ARTIFACT_DIR/cratesio-provenance-validation.json"
  {
    printf 'nvpn_base_commit=%s\n' "$ARTIFACT_APP_SHA"
    printf 'nvpn_tree=%s\n' "$ARTIFACT_APP_TREE"
    printf 'harness_commit=%s\n' "$harness_sha"
    printf 'harness_tree=%s\n' "$harness_tree"
    printf 'fips_commit=%s\n' "$FIPS_SOURCE_REVISION"
    if [[ -n "$LOCAL_FIPS_REPO" ]]; then
      printf 'fips_tree=%s\n' \
        "$(git -C "$LOCAL_FIPS_REPO" rev-parse 'HEAD^{tree}')"
    fi
  } >"$ARTIFACT_DIR/source-provenance.txt"

  env \
    NVPN_WINDOWS_SSH_HOST="$WINDOWS_SSH" \
    NVPN_WINDOWS_SSH_PROXY_COMMAND="$PRIMARY_PROXY" \
    NVPN_WINDOWS_SSH_JUMP="$WINDOWS_JUMP" \
    NVPN_WINDOWS_GUEST_REPO_PATH="$GUEST_REPO" \
    NVPN_WINDOWS_GUEST_FIPS_REPO_PATH="$GUEST_FIPS_REPO" \
    NVPN_WINDOWS_FIPS_REPO_PATH="${LOCAL_FIPS_REPO:-$ROOT/../fips}" \
    NVPN_WINDOWS_SYNC_PATH_DEPS="$([[ -n "$LOCAL_FIPS_REPO" ]] && echo 1 || echo 0)" \
    NVPN_WINDOWS_GIT_SYNC_EXACT_APP_COMMIT="$harness_sha" \
    "$ROOT/scripts/windows-vm-git-sync.sh" "$WINDOWS_SSH"

  if [[ -n "$LOCAL_FIPS_REPO" ]]; then
    for crate in fips-core fips-endpoint fips-identity; do
      [[ -f "$LOCAL_FIPS_REPO/crates/$crate/Cargo.toml" ]] \
        || fail "NVPN_FIPS_REPO_PATH is missing crates/$crate/Cargo.toml"
    done
    expected_fips_tree="$(
      git -C "$LOCAL_FIPS_REPO" rev-parse 'HEAD^{tree}'
    )"
    run_ps_primary \
      "git -C $(ps_quote "$GUEST_FIPS_REPO") checkout --detach $(ps_quote "$FIPS_SOURCE_REVISION") | Out-Null"
  fi

  windows_head="$(run_ps_primary \
    "Set-Location $(ps_quote "$GUEST_REPO"); git rev-parse HEAD" \
    | tr -d '\r' \
    | awk '/^[0-9a-f]{40}$/ { value = $0 } END { print value }')"
  windows_tree="$(run_ps_primary \
    "Set-Location $(ps_quote "$GUEST_REPO"); git rev-parse 'HEAD^{tree}'" \
    | tr -d '\r' \
    | awk '/^[0-9a-f]{40}$/ { value = $0 } END { print value }')"
  [[ "$windows_head" == "$harness_sha" \
    && "$windows_tree" == "$harness_tree" ]] \
    || fail "Windows checkout differs from the exact harness revision/tree"
  if [[ -n "$LOCAL_FIPS_REPO" ]]; then
    windows_fips_tree="$(run_ps_primary \
      "git -C $(ps_quote "$GUEST_FIPS_REPO") rev-parse 'HEAD^{tree}'" \
      | tr -d '\r' \
      | awk '/^[0-9a-f]{40}$/ { value = $0 } END { print value }')"
    [[ "$windows_fips_tree" == "$expected_fips_tree" ]] \
      || fail "Windows FIPS tree differs from the local release-gate tree"
  fi
  run_ps_primary \
    "& $(ps_quote "$GUEST_REPO\\scripts\\test-desktop-windows-wireguard-ownership.ps1")" \
    >"$ARTIFACT_DIR/windows-wireguard-ownership-harness.log"
  grep -Fq 'WINDOWS_NATIVE_WIREGUARD_OWNERSHIP_HARNESS_OK' \
    "$ARTIFACT_DIR/windows-wireguard-ownership-harness.log" \
    || fail "Windows native WireGuard ownership regression harness failed"

  run_ps_primary "\$ErrorActionPreference = 'Stop'
\$Bin = $(ps_quote "$GUEST_BINARY")
\$ReceiptPath = $(ps_quote "$GUEST_INSTALLER_RECEIPT")
if (!(Test-Path -LiteralPath \$ReceiptPath -PathType Leaf)) {
  throw \"exact Windows installer receipt is missing: \$ReceiptPath\"
}
if (!(Test-Path -LiteralPath \$Bin -PathType Leaf)) {
  throw \"exact packaged nvpn.exe is missing: \$Bin\"
}
\$Receipt = Get-Content -Raw -LiteralPath \$ReceiptPath | ConvertFrom-Json
\$ReceiptHash = (Get-FileHash -Algorithm SHA256 -LiteralPath \$ReceiptPath).Hash.ToLowerInvariant()
\$CliHash = (Get-FileHash -Algorithm SHA256 -LiteralPath \$Bin).Hash.ToLowerInvariant()
\$CliSize = (Get-Item -LiteralPath \$Bin).Length
if (
  \$ReceiptHash -ne $(ps_quote "$EXPECTED_INSTALLER_RECEIPT_SHA256") -or
  \$Receipt.artifactType -ne 'exact installed Windows Release setup' -or
  \$Receipt.appGitSha -ne $(ps_quote "$ARTIFACT_APP_SHA") -or
  \$Receipt.appGitTree -ne $(ps_quote "$ARTIFACT_APP_TREE") -or
  \$Receipt.fipsGitSha -ne $(ps_quote "$EXPECTED_FIPS_SHA") -or
  \$Receipt.fipsGitTree -ne $(ps_quote "$EXPECTED_FIPS_TREE") -or
  \$Receipt.fipsVersion -ne $(ps_quote "$EXPECTED_FIPS_VERSION") -or
  \$Receipt.installerInstalledAndLaunched -ne \$true -or
  \$Receipt.installedAppStayedAlive -ne \$true -or
  \$Receipt.payloads.cli.sha256 -ne \$CliHash -or
  [int64]\$Receipt.payloads.cli.size -ne \$CliSize
) {
  throw 'Windows underlay CLI differs from the exact installed-and-launched installer payload'
}
Get-Content -Raw -LiteralPath \$ReceiptPath
Write-Host \"WINDOWS_EXACT_INSTALLER_RECEIPT_SHA256=\$ReceiptHash\"
Write-Host \"WINDOWS_EXACT_INSTALLER_CLI_SHA256=\$CliHash\"" \
    >"$ARTIFACT_DIR/exact-artifact-validation.log"

  NVPN_EXPECTED_APP_GIT_SHA="$ARTIFACT_APP_SHA" \
    desktop_underlay_import_host_peer \
      >"$ARTIFACT_DIR/host-peer-import.log" 2>&1 \
    || {
      tail -n 120 "$ARTIFACT_DIR/host-peer-import.log" >&2 || true
      fail "Windows underlay host-peer import failed"
    }
}

capture_version_receipts() {
  local expected="fips_core_version: $EXPECTED_FIPS_VERSION (rev $EXPECTED_FIPS_REV)"
  local target_sha target_size
  run_ps_primary \
    "& $(ps_quote "$GUEST_BINARY") version --verbose" \
    | tr -d '\r' >"$ARTIFACT_DIR/target-version.txt"
  ssh -o BatchMode=yes "$HYPERVISOR_SSH" \
    "'$HYPERVISOR_BINARY' version --verbose" \
    >"$ARTIFACT_DIR/peer-version.txt"
  grep -Fxq "$expected" "$ARTIFACT_DIR/target-version.txt" \
    || fail "Windows target binary does not report exact FIPS version/revision $EXPECTED_FIPS_VERSION/$EXPECTED_FIPS_REV"
  grep -Fxq "$expected" "$ARTIFACT_DIR/peer-version.txt" \
    || fail "Windows peer binary does not report exact FIPS version/revision $EXPECTED_FIPS_VERSION/$EXPECTED_FIPS_REV"
  target_sha="$(
    run_ps_primary \
      "(Get-FileHash -Algorithm SHA256 -LiteralPath $(ps_quote "$GUEST_BINARY")).Hash.ToLowerInvariant()" \
      | tr -d '\r' \
      | awk '/^[0-9a-f]{64}$/ { value = $0 } END { print value }'
  )"
  target_size="$(
    run_ps_primary \
      "(Get-Item -LiteralPath $(ps_quote "$GUEST_BINARY")).Length" \
      | tr -d '\r' \
      | awk '/^[1-9][0-9]*$/ { value = $0 } END { print value }'
  )"
  [[ "$target_sha" =~ ^[0-9a-f]{64}$ \
    && "$target_size" =~ ^[1-9][0-9]*$ ]] \
    || fail "Windows target binary has no exact byte receipt"
  python3 - \
    "$ARTIFACT_DIR/tested-artifact.json" \
    "$target_sha" \
    "$target_size" <<'PY'
import json
import pathlib
import sys

output, cli_sha, cli_size = sys.argv[1:]
pathlib.Path(output).write_text(
    json.dumps(
        {
            "cliSha256": cli_sha,
            "cliSize": int(cli_size),
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY
}

random_mac() {
  local octets
  octets="$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
  printf '52:54:00:%s:%s:%s\n' \
    "${octets:0:2}" "${octets:2:2}" "${octets:4:2}"
}

discover_primary_interface() {
  local row_count rows
  rows="$(ssh -o BatchMode=yes "$HYPERVISOR_SSH" \
    "virsh domiflist '$VM_NAME' | awk '\$2 == \"network\" { print \$1 \"|\" \$3 \"|\" \$5 }'")"
  row_count="$(grep -c . <<<"$rows" || true)"
  [[ "$row_count" == "1" ]] \
    || fail "Windows VM must begin with exactly one libvirt network interface"
  IFS='|' read -r PRIMARY_IFACE PRIMARY_SOURCE PRIMARY_MAC <<<"$rows"
  [[ -n "$PRIMARY_IFACE" && -n "$PRIMARY_SOURCE" && -n "$PRIMARY_MAC" ]]

  PRIMARY_ADDRESS="$(ssh -o BatchMode=yes "$HYPERVISOR_SSH" \
    "virsh domifaddr '$VM_NAME' --source lease | awk '\$2 == \"$PRIMARY_MAC\" && \$3 == \"ipv4\" { sub(/\\/.*/, \"\", \$4); print \$4; exit }'")"
  [[ -n "$PRIMARY_ADDRESS" ]] \
    || fail "could not resolve the Windows VM primary address from libvirt"
  HYPERVISOR_UPLINK="$(ssh -o BatchMode=yes "$HYPERVISOR_SSH" \
    "ip -j -4 route get 1.1.1.1 | jq -r '.[0].dev'")"
  [[ -n "$HYPERVISOR_UPLINK" ]] \
    || fail "could not resolve the hypervisor uplink for the isolated peer"
}

attach_secondary_network() {
  SECONDARY_MAC="$(random_mac)"
  ssh -o BatchMode=yes "$HYPERVISOR_SSH" bash -s -- \
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
if virsh net-info "$network" >/dev/null 2>&1; then
  echo "transient network already exists: $network" >&2
  exit 1
fi
if ip -4 route | grep -Fq "$gateway"; then
  echo "secondary gateway conflicts with an existing hypervisor route" >&2
  exit 1
fi
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
  --model e1000e \
  --mac "$mac" \
  --live >/dev/null
SH
  NETWORK_CREATED=1
  NIC_ATTACHED=1
  SECONDARY_PROXY="ssh -o BatchMode=yes $HYPERVISOR_SSH -W $SECONDARY_ADDRESS:22"
}

wait_for_secondary_adapter() {
  local started="$SECONDS"
  while ((SECONDS - started < 30)); do
    if run_ps_primary \
      "\$m = ($(ps_quote "$SECONDARY_MAC") -replace '[^0-9A-Fa-f]', '').ToUpperInvariant(); if (Get-NetAdapter -IncludeHidden | Where-Object { (([string]\$_.MacAddress) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq \$m }) { exit 0 } else { exit 1 }" \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  fail "Windows did not enumerate the transient second NIC"
}

parse_key_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { value = substr($0, length(key) + 2) } END { print value }'
}

guest_initialize() {
  local script output json
  script="& $(ps_quote "$GUEST_REPO\\scripts\\desktop-windows-underlay-change-e2e.ps1") \
-Action Initialize \
-Binary $(ps_quote "$GUEST_BINARY") \
-Config $(ps_quote "$GUEST_CONFIG") \
-StateDir $(ps_quote "$GUEST_STATE_DIR") \
-PrimaryMac $(ps_quote "$PRIMARY_MAC") \
-SecondaryMac $(ps_quote "$SECONDARY_MAC") \
-SecondaryAddress $(ps_quote "$SECONDARY_ADDRESS") \
-SecondaryGateway $(ps_quote "$SECONDARY_GATEWAY") \
-SecondaryPrefixLength $SECONDARY_PREFIX \
-NetworkId $(ps_quote "$NETWORK_ID")"
  output="$(run_ps_primary "$script" | tr -d '\r')"
  json="$(awk '/^\{.*\}$/ { value = $0 } END { print value }' <<<"$output")"
  [[ -n "$json" ]] || {
    printf '%s\n' "$output" >&2
    fail "Windows initialization did not return its identity receipt"
  }
  TARGET_NPUB="$(jq -r '.npub // empty' <<<"$json")"
  TARGET_TUNNEL_IP="$(jq -r '.tunnel_ip // empty' <<<"$json")"
  PRIMARY_INDEX="$(jq -r '.primary_interface_index // empty' <<<"$json")"
  SECONDARY_INDEX="$(jq -r '.secondary_interface_index // empty' <<<"$json")"
  TARGET_PRIMARY_ADDRESS="$(jq -r '.primary_address // empty' <<<"$json")"
  TARGET_PRIMARY_GATEWAY="$(jq -r '.primary_gateway // empty' <<<"$json")"
  TARGET_WG_PUBLIC_KEY="$(jq -r '.wireguard_public_key // empty' <<<"$json")"
  [[ -n "$TARGET_NPUB" \
    && -n "$TARGET_TUNNEL_IP" \
    && -n "$TARGET_PRIMARY_ADDRESS" \
    && -n "$TARGET_PRIMARY_GATEWAY" \
    && -n "$TARGET_WG_PUBLIC_KEY" ]]

  for _ in $(seq 1 40); do
    if secondary_ssh_command \
      && "${WINDOWS_SECONDARY_SSH[@]}" hostname >/dev/null 2>&1; then
      GUEST_INITIALIZED=1
      return 0
    fi
    sleep 0.25
  done
  fail "Windows second NIC is configured but SSH cannot reach it out of band"
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

start_windows_runner() {
  local script
  script="& $(ps_quote "$GUEST_REPO\\scripts\\desktop-windows-underlay-change-e2e.ps1") \
-Action Run \
-Binary $(ps_quote "$GUEST_BINARY") \
-Config $(ps_quote "$GUEST_CONFIG") \
-StateDir $(ps_quote "$GUEST_STATE_DIR") \
-PrimaryMac $(ps_quote "$PRIMARY_MAC") \
-SecondaryMac $(ps_quote "$SECONDARY_MAC") \
-NetworkId $(ps_quote "$NETWORK_ID") \
-PeerNpub $(ps_quote "$PEER_NPUB") \
-PeerEndpoint $(ps_quote "$PEER_ENDPOINT") \
-PeerTunnelIp $(ps_quote "$PEER_TUNNEL_IP") \
-WireGuardPeerPublicKey $(ps_quote "$WG_SERVER_PUBLIC_KEY") \
-WireGuardEndpoint $(ps_quote "$WG_ENDPOINT") \
-WireGuardClientAddress $(ps_quote "$WG_CLIENT_ADDRESS") \
-WireGuardServerIp $(ps_quote "$WG_SERVER_IP") \
-WireGuardInterface $(ps_quote "$WG_TARGET_INTERFACE") \
-FixtureDnsName $(ps_quote "$FIXTURE_DNS_NAME") \
-ProbeUrl $(ps_quote "$PROBE_URL") \
-ExpectedFipsVersion $(ps_quote "$EXPECTED_FIPS_VERSION") \
-ExpectedFipsRevision $(ps_quote "$EXPECTED_FIPS_REV") \
-ListenPort $TARGET_LISTEN_PORT \
-RecoveryDeadlineMilliseconds $RECOVERY_DEADLINE_MS"
  (
    run_ps_secondary "$script"
  ) >"$ARTIFACT_DIR/windows-run.log" 2>&1 &
  WINDOWS_RUN_PID="$!"
  wait_for_guest_marker ready 35
  peer_command wait-ready >"$ARTIFACT_DIR/peer-ready.json"
  jq -e . "$ARTIFACT_DIR/peer-ready.json" >/dev/null
}

set_primary_link() {
  local state="$1"
  ssh -o BatchMode=yes "$HYPERVISOR_SSH" \
    "date +%s.%N; virsh domif-setlink '$VM_NAME' '$PRIMARY_IFACE' '$state' >/dev/null"
}

assert_peer_recovered_from_source() {
  local cut_timestamp="$1"
  local expected_source="$2"
  local label="$3"
  local observer="$ROOT/scripts/desktop-underlay-peer-recovery-observer.sh"
  [[ -r "$observer" ]] || fail "peer recovery observer is missing"
  ssh -o BatchMode=yes "$HYPERVISOR_SSH" sudo -n bash -s -- \
    "$PEER_STATE_DIR" "$cut_timestamp" "$expected_source" \
    "$RECOVERY_DEADLINE_MS" "$label" <"$observer"
}

guest_receipt() {
  local name="$1"
  run_ps_secondary \
    "Get-Content -Raw -LiteralPath $(ps_quote "$GUEST_STATE_DIR\\$name")" \
    | tr -d '\r' \
    | awk '/^\{.*\}$/ { value = $0 } END { print value }'
}

validate_guest_recovery_receipt() {
  local receipt="$1" interface_index="$2" gateway="$3" source="$4"
  jq -e \
    --argjson deadline "$RECOVERY_DEADLINE_MS" \
    --argjson interface_index "$interface_index" \
    --arg gateway "$gateway" \
    --arg source "$source" \
    '.recovery_milliseconds <= $deadline
      and .observation_started_unix_milliseconds > 0
      and .rebind_unix_milliseconds
        >= .observation_started_unix_milliseconds
      and .payload_success_unix_milliseconds
        >= .route_usable_unix_milliseconds
      and .wireguard_payload_success_unix_milliseconds
        >= .route_usable_unix_milliseconds
      and .recovered_unix_milliseconds
        == ([
          .rebind_unix_milliseconds,
          .payload_success_unix_milliseconds,
          .wireguard_payload_success_unix_milliseconds
        ] | max)
      and .recovery_milliseconds
        == (.recovered_unix_milliseconds - .route_usable_unix_milliseconds)
      and .payload_successes_after > .payload_successes_before
      and .wireguard_payload_successes_after
        > .wireguard_payload_successes_before
      and .wireguard_endpoint_route.destination_prefix != null
      and .wireguard_endpoint_route.interface_index == $interface_index
      and .wireguard_endpoint_route.next_hop == $gateway
      and .wireguard_endpoint_route.source_address == $source
      and .rebind_receipts_after == (.rebind_receipts_before + 1)' \
    <<<"$receipt" >/dev/null
}

run_underlay_switches() {
  local cut receipt
  signal_guest arm-secondary
  wait_for_guest_marker armed-secondary 30
  cut="$(set_primary_link down | tr -d '\r')"
  printf '%s\n' "$cut" >"$ARTIFACT_DIR/secondary-link-cut-unix-seconds.txt"
  wait_for_guest_marker secondary.receipt.json 15
  receipt="$(guest_receipt secondary.receipt.json)"
  receipt="$(jq --argjson link_changed "$cut" \
    '. + {host_link_change_unix_seconds: $link_changed}' <<<"$receipt")"
  validate_guest_recovery_receipt \
    "$receipt" "$SECONDARY_INDEX" "$SECONDARY_GATEWAY" "$SECONDARY_ADDRESS"
  printf '%s\n' "$receipt" >"$ARTIFACT_DIR/secondary-receipt.json"
  jq -e . "$ARTIFACT_DIR/secondary-receipt.json" >/dev/null
  assert_peer_recovered_from_source "$cut" "$SECONDARY_ADDRESS" secondary \
    | tee "$ARTIFACT_DIR/secondary-peer-recovery.txt"

  signal_guest arm-primary
  wait_for_guest_marker armed-primary 30
  cut="$(set_primary_link up | tr -d '\r')"
  printf '%s\n' "$cut" >"$ARTIFACT_DIR/primary-link-cut-unix-seconds.txt"
  wait_for_guest_marker primary.receipt.json 15
  receipt="$(guest_receipt primary.receipt.json)"
  receipt="$(jq --argjson link_changed "$cut" \
    '. + {host_link_change_unix_seconds: $link_changed}' <<<"$receipt")"
  validate_guest_recovery_receipt \
    "$receipt" "$PRIMARY_INDEX" "$TARGET_PRIMARY_GATEWAY" "$TARGET_PRIMARY_ADDRESS"
  printf '%s\n' "$receipt" >"$ARTIFACT_DIR/primary-receipt.json"
  jq -e . "$ARTIFACT_DIR/primary-receipt.json" >/dev/null
  assert_peer_recovered_from_source "$cut" "$PRIMARY_ADDRESS" primary \
    | tee "$ARTIFACT_DIR/primary-peer-recovery.txt"
  peer_command wireguard-audit >"$ARTIFACT_DIR/wireguard-responder-audit.txt"
}

peer_counters() {
  peer_command counters
}

counter_value() {
  local key="$1"
  parse_key_value "$key"
}

stable_dns_counters() {
  local previous current attempt
  previous="$(peer_counters)"
  for attempt in $(seq 1 20); do
    sleep 0.2
    current="$(peer_counters)"
    if [[ "$current" == "$previous" ]]; then
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
  wait_for_guest_marker "dns-$name.configured" 35
  before="$(stable_dns_counters)"
  signal_guest "dns-$name.query"
  wait_for_guest_marker "dns-$name.receipt" 35
  after="$(stable_dns_counters)"
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

run_dns_matrix_and_crash_restore() {
  run_dns_case automatic profile_dns
  run_dns_case cloudflare cloudflare
  run_dns_case quad9 quad9
  run_dns_case custom google
  run_dns_case through-exit fixture_dns

  signal_guest select-direct
  wait_for_guest_marker crash-recovery.receipt.json 45
  wait_for_guest_marker direct.receipt.json 45
  wait_for_guest_marker done 10
  wait "$WINDOWS_RUN_PID"
  WINDOWS_RUN_PID=""
  guest_receipt crash-recovery.receipt.json \
    >"$ARTIFACT_DIR/crash-recovery-receipt.json"
  guest_receipt direct.receipt.json >"$ARTIFACT_DIR/direct-receipt.json"
  jq -e '
    .crashed_daemon_pid > 0
    and .replacement_daemon_pid > 0
    and .replacement_daemon_pid != .crashed_daemon_pid
    and .daemon_process_count == 1
    and .exact_candidate_binary_restarted == true
    and .cleanup_journal_present_before_crash == true
    and .cleanup_journal_survived_forced_termination == true
    and .paid_exit_cleanup_ownership_removed_after_restart == true
    and .crash_cleanup_journal_replaced_after_restart == true
    and (.active_direct_cleanup_journal_present | type) == "boolean"
    and (.active_direct_cleanup_route_count | type) == "number"
    and .active_direct_cleanup_route_count >= 0
    and (.native_wireguard_config_path | type == "string" and length > 0)
    and (.native_wireguard_owner_marker_path | type == "string" and length > 0)
    and (.native_wireguard_owner_directory_path | type == "string" and length > 0)
    and .native_wireguard_owner_directory_layout == true
    and .native_wireguard_owned_files_survived_forced_termination == true
    and .native_wireguard_owned_files_removed_after_restart == true
    and .selected_direct_while_daemon_stopped == true
    and .startup_recovery_milliseconds <= 30000
    and .wireguard_exit_state_remained_installed_after_crash == true
    and .dns_policy_remained_installed_after_crash == true
    and .public_dns == true
    and .verified_https == true
  ' "$ARTIFACT_DIR/crash-recovery-receipt.json" >/dev/null
  CANDIDATE_NATIVE_CONFIG_PATH="$(
    jq -er '.native_wireguard_config_path' \
      "$ARTIFACT_DIR/crash-recovery-receipt.json"
  )"
  CANDIDATE_NATIVE_MARKER_PATH="$(
    jq -er '.native_wireguard_owner_marker_path' \
      "$ARTIFACT_DIR/crash-recovery-receipt.json"
  )"
  CANDIDATE_NATIVE_OWNER_DIR="$(
    jq -er '.native_wireguard_owner_directory_path' \
      "$ARTIFACT_DIR/crash-recovery-receipt.json"
  )"
  jq -e '
    .wireguard_interface_removed == true
    and .wireguard_endpoint_route_removed == true
    and .wireguard_service_removed == true
    and .wireguard_source_secrets_removed == true
    and .verified_https == true
  ' "$ARTIFACT_DIR/direct-receipt.json" >/dev/null

  local post_stop
  post_stop="\$ErrorActionPreference = 'Stop'
\$primary = Get-NetAdapter -IncludeHidden | Where-Object { (([string]\$_.MacAddress) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq (($(ps_quote "$PRIMARY_MAC") -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()) }
\$route = Find-NetRoute -RemoteIPAddress '1.1.1.1' | Select-Object -First 1
if ([int]\$route.InterfaceIndex -ne [int]\$primary.ifIndex) { throw 'native Direct route was not restored after daemon stop' }
if (Get-Process nvpn -ErrorAction SilentlyContinue) { throw 'candidate nvpn daemon still runs after cleanup' }
if (Get-Service -Name $(ps_quote "WireGuardTunnel\$$WG_TARGET_INTERFACE") -ErrorAction SilentlyContinue) { throw 'WireGuard exit service remains after cleanup' }
if (Get-NetAdapter -Name $(ps_quote "$WG_TARGET_INTERFACE") -IncludeHidden -ErrorAction SilentlyContinue) { throw 'WireGuard exit adapter remains after cleanup' }
\$endpointHost = ([Uri]('udp://' + $(ps_quote "$WG_ENDPOINT"))).Host
if (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix \"\$endpointHost/32\" -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -ne 0) { throw 'WireGuard endpoint bypass remains after cleanup' }
foreach (\$ownedPath in @($(ps_quote "$CANDIDATE_NATIVE_CONFIG_PATH"), $(ps_quote "$CANDIDATE_NATIVE_MARKER_PATH"), $(ps_quote "$CANDIDATE_NATIVE_OWNER_DIR"))) {
  if (Test-Path -LiteralPath \$ownedPath) { throw ('candidate-owned native WireGuard artifact remains after daemon stop: ' + \$ownedPath) }
}
\$rules = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { \$_.DisplayName -eq 'nostr-vpn secure DNS' -or \$_.Comment -eq 'nostr-vpn authenticated DNS-over-HTTPS stub' })
if (\$rules.Count -ne 0) { throw 'nvpn secure DNS policy remains after daemon stop' }
[Net.Dns]::GetHostAddresses(([Uri]$(ps_quote "$PROBE_URL")).DnsSafeHost) | Out-Null
& curl.exe -4 --ssl-revoke-best-effort --fail --silent --max-time 8 --output NUL $(ps_quote "$PROBE_URL")
if (\$LASTEXITCODE -ne 0) { throw 'verified HTTPS failed after native Direct restoration' }
Write-Output 'WINDOWS_NATIVE_DIRECT_RESTORED'"
  run_ps_secondary "$post_stop" | tee "$ARTIFACT_DIR/post-stop.txt"
}

audit_guest_cleanup() {
  local script
  script="\$ErrorActionPreference = 'Stop'
\$statePath = $(ps_quote "$GUEST_STATE_DIR\\adapter-state.json")
if (Test-Path -LiteralPath \$statePath) {
  \$saved = Get-Content -Raw -LiteralPath \$statePath | ConvertFrom-Json
  \$primaryIp = Get-NetIPInterface -InterfaceIndex ([int]\$saved.primary_interface_index) -AddressFamily IPv4
  if ([string]\$saved.primary_automatic_metric -eq 'Enabled') {
    if ([string]\$primaryIp.AutomaticMetric -ne 'Enabled') { throw 'primary automatic metric was not restored' }
  } elseif ([int]\$primaryIp.InterfaceMetric -ne [int]\$saved.primary_metric) {
    throw 'primary interface metric was not restored'
  }
}
if (Get-Process nvpn -ErrorAction SilentlyContinue) { throw 'candidate nvpn process remains after cleanup' }
if (Get-Service -Name $(ps_quote "WireGuardTunnel\$$WG_TARGET_INTERFACE") -ErrorAction SilentlyContinue) {
  throw 'WireGuard exit service remains after cleanup'
}
if (Get-NetAdapter -Name $(ps_quote "$WG_TARGET_INTERFACE") -IncludeHidden -ErrorAction SilentlyContinue) {
  throw 'WireGuard exit adapter remains after cleanup'
}
\$endpointHost = ([Uri]('udp://' + $(ps_quote "$WG_ENDPOINT"))).Host
if (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix \"\$endpointHost/32\" -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -ne 0) {
  throw 'WireGuard endpoint bypass remains after cleanup'
}
foreach (\$ownedPath in @($(ps_quote "$CANDIDATE_NATIVE_CONFIG_PATH"), $(ps_quote "$CANDIDATE_NATIVE_MARKER_PATH"), $(ps_quote "$CANDIDATE_NATIVE_OWNER_DIR"))) {
  if (
    ![string]::IsNullOrWhiteSpace(\$ownedPath) -and
    (Test-Path -LiteralPath \$ownedPath)
  ) {
    throw ('candidate-owned native WireGuard artifact remains after cleanup: ' + \$ownedPath)
  }
}
\$processMarkers = @('probe.pid', 'wireguard-probe.pid', 'watchdog.pid')
foreach (\$marker in \$processMarkers) {
  \$processPath = Join-Path $(ps_quote "$GUEST_STATE_DIR") \$marker
  if (Test-Path -LiteralPath \$processPath) {
    \$processId = [int](Get-Content -Raw -LiteralPath \$processPath)
    if (Get-Process -Id \$processId -ErrorAction SilentlyContinue) {
      throw (\"recorded cleanup process remains after cleanup: \$marker\")
    }
  }
}
if (Get-NetAdapter -Name $(ps_quote "nvpn-underlay-gate") -ErrorAction SilentlyContinue) {
  throw 'candidate Wintun interface remains after cleanup'
}
\$cleanupJournal = $(ps_quote "$GUEST_STATE_DIR\\daemon.cleanup.json")
if (Test-Path -LiteralPath \$cleanupJournal) {
  throw 'durable cleanup journal remains after recovered daemon stop'
}
\$rules = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {
  \$_.DisplayName -eq 'nostr-vpn secure DNS' -or
  \$_.Comment -eq 'nostr-vpn authenticated DNS-over-HTTPS stub'
})
if (\$rules.Count -ne 0) { throw 'nvpn secure DNS policy remains after cleanup' }
\$primary = Get-NetAdapter -IncludeHidden | Where-Object {
  (([string]\$_.MacAddress) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq
    (($(ps_quote "$PRIMARY_MAC") -replace '[^0-9A-Fa-f]', '').ToUpperInvariant())
}
\$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {
  \$route = Find-NetRoute -RemoteIPAddress '1.1.1.1' | Select-Object -First 1
  if ([int]\$route.InterfaceIndex -eq [int]\$primary.ifIndex) { break }
  Start-Sleep -Milliseconds 100
} while ([DateTime]::UtcNow -lt \$deadline)
if ([int]\$route.InterfaceIndex -ne [int]\$primary.ifIndex) {
  throw 'native primary route was not restored during cleanup'
}
[Net.Dns]::GetHostAddresses(([Uri]$(ps_quote "$PROBE_URL")).DnsSafeHost) | Out-Null
& curl.exe -4 --ssl-revoke-best-effort --fail --silent --max-time 8 --output NUL $(ps_quote "$PROBE_URL")
if (\$LASTEXITCODE -ne 0) { throw 'native HTTPS failed after cleanup' }
\$emergencyRepair = $(ps_quote "$GUEST_STATE_DIR\\emergency-repair-invoked")
if (Test-Path -LiteralPath \$emergencyRepair) {
  throw 'normal Windows cleanup invoked emergency repair-network'
}
Remove-Item -Recurse -Force -LiteralPath $(ps_quote "$GUEST_STATE_DIR") -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $(ps_quote "$GUEST_STATE_DIR")) { throw 'guest gate state remains after cleanup' }
Write-Output 'WINDOWS_GUEST_CLEANUP_AUDIT_OK'"
  run_ps_cleanup_management "$script" 120
}

audit_hypervisor_cleanup() {
  ssh -o BatchMode=yes "$HYPERVISOR_SSH" bash -s -- \
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
rows="$(virsh domiflist "$vm" | awk '$2 == "network" { print $1 "|" $5 }')"
[[ "$(grep -c . <<<"$rows" || true)" == "1" ]]
[[ "$rows" == "$primary_iface|$primary_mac" ]]
[[ "$(virsh domif-getlink "$vm" "$primary_iface" | awk '{ print $NF }')" == "up" ]]
! virsh net-info "$network" >/dev/null 2>&1
! ip link show dev "$peer_tun" >/dev/null 2>&1
! sudo -n test -e "$peer_state"
! sudo -n iptables -t mangle -S "$counter_chain" >/dev/null 2>&1
! sudo -n ip netns list | awk '{ print $1 }' | grep -Fxq "$peer_netns"
! ip link show dev "$peer_host_veth" >/dev/null 2>&1
! ip -4 route show exact "$peer_address/$peer_prefix" | grep -q .
! sudo -n iptables -S "$forward_chain" >/dev/null 2>&1
! sudo -n iptables -t nat -S "$nat_chain" >/dev/null 2>&1
! pgrep -a -x nvpn 2>/dev/null | grep -Fq -- "--config $peer_state/config.toml"
echo "WINDOWS_HYPERVISOR_CLEANUP_AUDIT_OK"
SH
}

collect_failure_artifacts() {
  if [[ -n "$SECONDARY_PROXY" ]]; then
    local guest_log="$ARTIFACT_DIR/guest-failure-diagnostics.txt"
    : >"$guest_log"
    for name in \
      last-condition-error.txt \
      last-crash-recovery-error.txt \
      daemon.stderr.log \
      daemon.stdout.log \
      daemon.restart.stderr.log \
      daemon.restart.stdout.log \
      payload.log \
      wireguard-payload.log
    do
      {
        printf '### %s\n' "$name"
        run_ps_cleanup_management \
          "if (Test-Path -LiteralPath $(ps_quote "$GUEST_STATE_DIR\\$name")) { Get-Content -LiteralPath $(ps_quote "$GUEST_STATE_DIR\\$name") -Tail 500 } else { Write-Output '<missing>' }" \
          10
      } >>"$guest_log" 2>&1 || true
    done
    {
      printf '### nvpn-status\n'
      run_ps_cleanup_management \
        "\$raw = & $(ps_quote "$GUEST_BINARY") status --config $(ps_quote "$GUEST_CONFIG") --json --discover-secs 0
\$status = \$raw | ConvertFrom-Json
[pscustomobject]@{
  status_source = \$status.status_source
  daemon = [pscustomobject]@{
    running = \$status.daemon.running
    pid = \$status.daemon.pid
    state = [pscustomobject]@{
      binary_version = \$status.daemon.state.binary_version
      fips_core_version = \$status.daemon.state.fips_core_version
      mesh_ready = \$status.daemon.state.mesh_ready
      connected_peer_count = \$status.daemon.state.connected_peer_count
      vpn_status = \$status.daemon.state.vpn_status
      network = \$status.daemon.state.network
    }
  }
} | ConvertTo-Json -Depth 6" 10
      printf '### adapters-and-routes\n'
      run_ps_cleanup_management \
        "Get-NetAdapter -IncludeHidden | Format-Table -AutoSize; Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric,InterfaceMetric | Format-Table -AutoSize" \
        10
    } >>"$guest_log" 2>&1 || true
  fi

  if [[ "$PEER_INITIALIZED" == "1" ]]; then
    ssh -o BatchMode=yes "$HYPERVISOR_SSH" \
      sudo -n bash -s -- "$PEER_STATE_DIR" "$HYPERVISOR_BINARY" \
      >"$ARTIFACT_DIR/peer-failure-diagnostics.txt" 2>&1 <<'SH' || true
set -u
state="$1"
binary="$2"
for name in daemon.stderr.log daemon.stdout.log peer-payload.log dnsmasq.log dns.log fips-underlay.pcap.txt wireguard-underlay.pcap.txt; do
  printf '### %s\n' "$name"
  if [[ -f "$state/$name" ]]; then
    tail -n 500 "$state/$name"
  else
    printf '<missing>\n'
  fi
done
printf '### nvpn-status\n'
"$binary" status --config "$state/config.toml" --json --discover-secs 0 \
  | jq '{
      status_source,
      daemon: {
        running: .daemon.running,
        pid: .daemon.pid,
        state: (.daemon.state | {
          binary_version,
          fips_core_version,
          mesh_ready,
          connected_peer_count,
          vpn_status,
          network
        })
      }
    }' || true
SH
  fi
}

run_ps_cleanup_management() {
  local script="$1" channel_timeout="${2:-5}"
  if [[ "$GUEST_INITIALIZED" == "1" ]]; then
    run_ps_with secondary "$script" "$channel_timeout"
  else
    run_ps_with primary "$script" "$channel_timeout"
  fi
}

guest_cleanup_ownership_state() {
  local output
  if ! output="$(run_ps_cleanup_management \
    "if (Test-Path -LiteralPath $(ps_quote "$GUEST_STATE_DIR\\cleanup-owned")) { Write-Output 'owned' } else { Write-Output 'unowned' }" \
    5 2>/dev/null)"
  then
    echo "unknown"
    return
  fi
  output="$(tr -d '\r' <<<"$output" | awk 'NF { value = $0 } END { print value }')"
  case "$output" in
    owned|unowned) echo "$output" ;;
    *) echo "unknown" ;;
  esac
}

cleanup() {
  local status="$?"
  local cleanup_failed=0
  trap - EXIT INT TERM
  set +e
  set +u

  if [[ -n "$PRIMARY_IFACE" ]]; then
    ssh -o BatchMode=yes "$HYPERVISOR_SSH" \
      "virsh domif-setlink '$VM_NAME' '$PRIMARY_IFACE' up" >/dev/null 2>&1 || true
  fi

  if [[ -n "$SECONDARY_PROXY" && -n "$WINDOWS_RUN_PID" ]]; then
    run_ps_cleanup_management \
      "[IO.File]::WriteAllText($(ps_quote "$GUEST_STATE_DIR\\cancel"), 'cancel', [Text.UTF8Encoding]::new(\$false))" \
      5 >/dev/null 2>&1 || true
  fi
  if [[ "$status" -ne 0 ]]; then
    collect_failure_artifacts
  fi
  if [[ -n "$SECONDARY_PROXY" ]]; then
    local ownership_state
    ownership_state="$(guest_cleanup_ownership_state)"
    printf '%s\n' "$ownership_state" >"$ARTIFACT_DIR/guest-cleanup-ownership.txt"
    case "$ownership_state" in
      owned)
        if run_ps_cleanup_management \
          "\$runnerPid = 0
\$runnerPath = $(ps_quote "$GUEST_STATE_DIR\\runner.pid")
if (Test-Path -LiteralPath \$runnerPath) {
  \$runnerPid = [int](Get-Content -Raw -LiteralPath \$runnerPath)
}
& $(ps_quote "$GUEST_REPO\\scripts\\desktop-windows-underlay-change-e2e.ps1") -Action Cleanup -Binary $(ps_quote "$GUEST_BINARY") -Config $(ps_quote "$GUEST_CONFIG") -StateDir $(ps_quote "$GUEST_STATE_DIR") -RunnerPid \$runnerPid" \
          180 >"$ARTIFACT_DIR/guest-cleanup-command.txt" 2>&1
        then
          audit_guest_cleanup >"$ARTIFACT_DIR/guest-cleanup-audit.txt" 2>&1 \
            || {
              cleanup_failed=1
              QUARANTINE_GUEST_NETWORK=1
            }
        else
          cleanup_failed=1
          QUARANTINE_GUEST_NETWORK=1
        fi
        ;;
      unowned) ;;
      *)
        cleanup_failed=1
        QUARANTINE_GUEST_NETWORK=1
        ;;
    esac
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
  if [[ "$QUARANTINE_GUEST_NETWORK" == "0" ]]; then
    if [[ "$NIC_ATTACHED" == "1" && -n "$SECONDARY_MAC" ]]; then
      ssh -o BatchMode=yes "$HYPERVISOR_SSH" \
        "virsh detach-interface --domain '$VM_NAME' --type network --mac '$SECONDARY_MAC' --live" \
        >/dev/null 2>&1 || true
    fi
    if [[ "$NETWORK_CREATED" == "1" ]]; then
      ssh -o BatchMode=yes "$HYPERVISOR_SSH" \
        "virsh net-destroy '$NETWORK_NAME'" >/dev/null 2>&1 || cleanup_failed=1
    fi
    if [[ "$NIC_ATTACHED" == "1" ]]; then
      audit_hypervisor_cleanup >"$ARTIFACT_DIR/hypervisor-cleanup-audit.txt" 2>&1 \
        || cleanup_failed=1
    fi
  else
    echo "Windows guest cleanup is unproven; secondary network retained for quarantine" \
      >"$ARTIFACT_DIR/guest-network-quarantine.txt"
  fi
  if [[ "$cleanup_failed" == "1" ]]; then
    echo "Windows underlay cleanup audit failed; inspect $ARTIFACT_DIR" >&2
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
start_windows_runner
run_underlay_switches
run_dns_matrix_and_crash_restore

echo "WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E_OK"
echo "artifacts=$ARTIFACT_DIR"
