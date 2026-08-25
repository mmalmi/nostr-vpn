#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/workspace/nostr-vpn"
LINUX_DIR="$ROOT_DIR/linux"
ARTIFACT_DIR="$ROOT_DIR/artifacts/linux-gui-e2e"
E2E_ROOT="/tmp/nostr-vpn-linux-gui-e2e-$$"
DATA_HOME="$E2E_ROOT/data"
CONFIG_HOME="$E2E_ROOT/config"
CONFIG_PATH="$DATA_HOME/nostr-vpn/config.toml"
BOB_CONFIG="$E2E_ROOT/bob.toml"
FAKE_NVPN="$E2E_ROOT/nvpn"
SCREENSHOT="$ARTIFACT_DIR/nostr-vpn-linux-gui-e2e.png"
IDLE_CPU_RESULT="$ARTIFACT_DIR/linux-gui-idle-cpu.json"
IDLE_CPU_GATE="${NVPN_LINUX_GUI_IDLE_CPU_GATE:-${NVPN_IDLE_CPU_GATE:-1}}"
IDLE_CPU_MAX_PERCENT="${NVPN_LINUX_GUI_IDLE_CPU_MAX_PERCENT:-${NVPN_IDLE_CPU_MAX_PERCENT:-5}}"
IDLE_CPU_SAMPLE_SECONDS="${NVPN_LINUX_GUI_IDLE_CPU_SAMPLE_SECONDS:-${NVPN_IDLE_CPU_SAMPLE_SECONDS:-10}}"
IDLE_CPU_SETTLE_SECONDS="${NVPN_LINUX_GUI_IDLE_CPU_SETTLE_SECONDS:-${NVPN_IDLE_CPU_SETTLE_SECONDS:-3}}"
cargo_config_args=()
cargo_lock_args=(--locked)

if [[ -n "${NVPN_FIPS_REPO_PATH:-}" ]]; then
  if [[ "${NVPN_LINUX_LOCKFILE_OVERLAY_ACTIVE:-0}" != "1" ]]; then
    echo "Local-FIPS Linux GUI smoke requires isolated Cargo.lock overlays." >&2
    exit 2
  fi
  cargo_config_args+=(
    --config "patch.crates-io.nvpn-fips-core.path=\"$NVPN_FIPS_REPO_PATH/crates/fips-core\""
    --config "patch.crates-io.nvpn-fips-endpoint.path=\"$NVPN_FIPS_REPO_PATH/crates/fips-endpoint\""
    --config "patch.crates-io.nvpn-fips-identity.path=\"$NVPN_FIPS_REPO_PATH/crates/fips-identity\""
  )
  cargo_lock_args=()
fi

cargo_run() {
  if ((${#cargo_config_args[@]})); then
    cargo "${cargo_config_args[@]}" "$@"
  else
    cargo "$@"
  fi
}

rm -rf "$E2E_ROOT"
mkdir -p "$ARTIFACT_DIR" "$(dirname "$CONFIG_PATH")" "$CONFIG_HOME"
rm -f "$SCREENSHOT"

cd "$ROOT_DIR"
cargo_run build "${cargo_lock_args[@]}" -p nvpn >/dev/null
"$ROOT_DIR/target/debug/nvpn" init --config "$CONFIG_PATH" --force >/dev/null
"$ROOT_DIR/target/debug/nvpn" init --config "$BOB_CONFIG" --force >/dev/null

npub_to_hex() {
  python3 - "$1" <<'PY'
import sys

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def polymod(values):
    generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                chk ^= generator
    return chk

def hrp_expand(hrp):
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]

def convertbits(data, frombits, tobits, pad=False):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("invalid data range")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding")
    return bytes(ret)

value = sys.argv[1].strip()
pos = value.rfind("1")
if pos < 1:
    raise SystemExit("invalid bech32 value")
hrp = value[:pos]
data = [CHARSET.index(char) for char in value[pos + 1:]]
if hrp != "npub" or len(data) < 6 or polymod(hrp_expand(hrp) + data) != 1:
    raise SystemExit("invalid npub")
payload = convertbits(data[:-6], 5, 8)
if len(payload) != 32:
    raise SystemExit("invalid npub payload length")
print(payload.hex())
PY
}

own_npub="$(awk '
  /^\[nostr\]$/ { in_nostr = 1; next }
  /^\[/ { in_nostr = 0 }
  in_nostr && /^public_key[[:space:]]*=/ { print $3; exit }
' "$CONFIG_PATH" | tr -d '"')"
bob_npub="$(awk '
  /^\[nostr\]$/ { in_nostr = 1; next }
  /^\[/ { in_nostr = 0 }
  in_nostr && /^public_key[[:space:]]*=/ { print $3; exit }
' "$BOB_CONFIG" | tr -d '"')"
own_hex="$(npub_to_hex "$own_npub")"
bob_hex="$(npub_to_hex "$bob_npub")"
now="$(date +%s)"

"$ROOT_DIR/target/debug/nvpn" set \
  --config "$CONFIG_PATH" \
  --participant "$own_npub" \
  --participant "$bob_npub" >/dev/null

"$ROOT_DIR/target/debug/nvpn" set \
  --config "$CONFIG_PATH" \
  --network-id "linux-gui-fips-e2e" \
  --node-name "alice" \
  --endpoint "10.203.0.10:51820" \
  --listen-port 51820 \
  --fips-advertise-endpoint true \
  --fips-peer-endpoint "$bob_npub=10.203.0.11:51820" >/dev/null

tmp_config="$(mktemp)"
awk '
  /^\[peer_aliases\]$/ { skip = 1; next }
  /^\[/ { skip = 0 }
  !skip { print }
' "$CONFIG_PATH" > "$tmp_config"
{
  cat "$tmp_config"
  printf '\n[peer_aliases]\n'
  printf '"%s" = "bob"\n' "$bob_npub"
} > "$CONFIG_PATH"
rm -f "$tmp_config"

cat > "$FAKE_NVPN" <<SH
#!/usr/bin/env bash
set -euo pipefail

case "\${1:-}" in
  status)
    cat <<JSON
{
  "status_source": "daemon",
  "daemon": {
    "running": true,
    "state": {
      "updated_at": $now,
      "binary_version": "4.0.0",
      "local_endpoint": "10.203.0.10:51820",
      "advertised_endpoint": "10.203.0.10:51820",
      "listen_port": 51820,
      "vpn_enabled": true,
      "vpn_active": true,
      "vpn_status": "FIPS private mesh ready",
      "expected_peer_count": 1,
      "connected_peer_count": 1,
      "mesh_ready": true,
      "port_mapping": {
        "upnp": { "state": "unknown" },
        "natPmp": { "state": "unknown" },
        "pcp": { "state": "unknown" }
      },
      "peers": [{
        "participant_pubkey": "$bob_hex",
        "node_id": "",
        "tunnel_ip": "10.44.219.172/32",
        "endpoint": "fips",
        "runtime_endpoint": "fips",
        "tx_bytes": 4096,
        "rx_bytes": 8192,
        "public_key": "",
        "advertised_routes": [],
        "last_mesh_seen_at": $now,
        "last_fips_seen_at": $now,
        "reachable": true,
        "last_handshake_at": $now,
        "error": null
      }]
    }
  }
}
JSON
    ;;
  service)
    if [[ "\${2:-}" == "status" ]]; then
      cat <<JSON
{
  "supported": true,
  "installed": true,
  "disabled": false,
  "loaded": true,
  "running": true,
  "pid": 4242,
  "label": "to.nostrvpn.nvpn",
  "plist_path": "",
  "binary_version": "4.0.0"
}
JSON
    else
      exit 0
    fi
    ;;
  start|pause|reload|down)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
SH
chmod +x "$FAKE_NVPN"

cd "$LINUX_DIR"
cargo_run build "${cargo_lock_args[@]}" >/dev/null

export XDG_DATA_HOME="$DATA_HOME"
export XDG_CONFIG_HOME="$CONFIG_HOME"
export NVPN_CLI_PATH="$FAKE_NVPN"
export GDK_BACKEND="${GDK_BACKEND:-x11}"
export DISPLAY="${DISPLAY:-:99}"

"$LINUX_DIR/target/debug/nostr-vpn" > "$ARTIFACT_DIR/app.log" 2>&1 &
app_pid=$!

cleanup_app() {
  if kill -0 "$app_pid" >/dev/null 2>&1; then
    kill "$app_pid" >/dev/null 2>&1 || true
    wait "$app_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup_app EXIT

window_id=""
for _ in $(seq 1 80); do
  if ! kill -0 "$app_pid" >/dev/null 2>&1; then
    echo "linux gui e2e failed: app exited before creating a window" >&2
    cat "$ARTIFACT_DIR/app.log" >&2 || true
    exit 1
  fi
  window_id="$(xdotool search --onlyvisible --name "Nostr VPN" 2>/dev/null | head -n1 || true)"
  if [[ -n "$window_id" ]]; then
    break
  fi
  sleep 0.25
done

if [[ -z "$window_id" ]]; then
  echo "linux gui e2e failed: Nostr VPN window was not visible" >&2
  cat "$ARTIFACT_DIR/app.log" >&2 || true
  exit 1
fi

xdotool windowactivate "$window_id" >/dev/null 2>&1 || true
sleep 1
import -window "$window_id" "$SCREENSHOT"

dimensions="$(identify -format '%w %h' "$SCREENSHOT")"
mean="$(identify -format '%[fx:mean]' "$SCREENSHOT")"
width="${dimensions%% *}"
height="${dimensions##* }"
if ! awk -v width="$width" -v height="$height" 'BEGIN { exit !(width >= 900 && height >= 600) }'; then
  echo "linux gui e2e failed: screenshot is too small: $dimensions" >&2
  exit 1
fi

awk -v mean="$mean" 'BEGIN { exit !(mean > 0.01 && mean < 0.99) }'

case "$IDLE_CPU_GATE" in
  0|false|FALSE|False|no|NO|No|off|OFF|Off)
    echo "Skipping Linux GUI idle CPU gate because NVPN_LINUX_GUI_IDLE_CPU_GATE=$IDLE_CPU_GATE"
    ;;
  *)
    "$ROOT_DIR/scripts/idle-cpu-gate.py" host-pid \
      --pid "$app_pid" \
      --label "Linux GTK app" \
      --artifact "$IDLE_CPU_RESULT" \
      --max-percent "$IDLE_CPU_MAX_PERCENT" \
      --sample-seconds "$IDLE_CPU_SAMPLE_SECONDS" \
      --settle-seconds "$IDLE_CPU_SETTLE_SECONDS"
    ;;
esac

echo "--- Linux GUI app log ---"
tail -n 80 "$ARTIFACT_DIR/app.log" || true
echo "--- Linux GUI screenshot ---"
echo "$SCREENSHOT"
echo "linux gui e2e passed: GTK app opened under Xvfb and rendered a FIPS daemon-backed network state"
