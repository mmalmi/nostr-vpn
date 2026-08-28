#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_PROXY_IMAGE='getumbrel/app-proxy:1.7.0@sha256:ec0de0b944a2e63d52fdd82b3760d90a35f8b442d17a8407afdee3af3e842d5a'
AUTH_IMAGE='getumbrel/auth-server:1.7.0@sha256:7fc9d52d4176639e84044b63aa07efcac78a508a05bb4480436be9db977a7191'
IMAGE="${NOSTR_VPN_IMAGE:-nostr-vpn-umbrel-auth-join-e2e:local}"
PROJECT="${NVPN_UMBREL_AUTH_JOIN_PROJECT:-nostr-vpn-umbrel-auth-join-e2e}"
PROXY_PORT="${NVPN_UMBREL_AUTH_JOIN_PROXY_PORT:-38380}"
AUTH_PORT="${NVPN_UMBREL_AUTH_JOIN_AUTH_PORT:-38300}"
RPC_PORT="${NVPN_UMBREL_AUTH_JOIN_RPC_PORT:-38301}"
SCANNER_PORT="${NVPN_UMBREL_AUTH_JOIN_SCANNER_PORT:-38382}"
NETWORK_OCTET="${NVPN_UMBREL_AUTH_JOIN_NETWORK_OCTET:-$((100 + ($$ % 100)))}"
SUBNET="${NVPN_UMBREL_AUTH_JOIN_SUBNET:-10.253.${NETWORK_OCTET}.0/24}"
REQUESTER_IP="${NVPN_UMBREL_AUTH_JOIN_REQUESTER_IP:-10.253.${NETWORK_OCTET}.10}"
SCANNER_IP="${NVPN_UMBREL_AUTH_JOIN_SCANNER_IP:-10.253.${NETWORK_OCTET}.11}"
JWT_SECRET=nvpn-umbrel-auth-join-e2e-jwt-secret
AUTH_SECRET=nvpn-umbrel-auth-join-e2e-hmac-secret
PASSWORD=nvpn-umbrel-auth-join-e2e-password
TMP="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-umbrel-auth-join-e2e.XXXXXX")"
COMPOSE="$TMP/compose.yml"
FIXTURE_RESULT="$TMP/fixture-result.json"
STUB_PID=''

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if ((status != 0)) && [[ -f "$COMPOSE" ]]; then
    echo "Umbrel auth/join e2e failed; collecting bounded container diagnostics." >&2
    docker compose -p "$PROJECT" -f "$COMPOSE" ps >&2 || true
    docker compose -p "$PROJECT" -f "$COMPOSE" logs --no-color --tail 120 \
      auth app_proxy web scanner_web scanner_daemon >&2 || true
  fi
  docker compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans \
    >/dev/null 2>&1 || true
  if [[ "$STUB_PID" =~ ^[0-9]+$ ]]; then
    kill "$STUB_PID" >/dev/null 2>&1 || true
    wait "$STUB_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

docker info >/dev/null

case "${NVPN_UMBREL_AUTH_JOIN_SKIP_BUILD:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On)
    docker image inspect "$IMAGE" >/dev/null
    ;;
  *)
    [[ -z "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=all)" ]] || {
      echo "Umbrel auth/join image builds require a clean candidate checkout." >&2
      exit 2
    }
    docker build -f "$ROOT_DIR/umbrel/Dockerfile" -t "$IMAGE" "$ROOT_DIR"
    ;;
esac

mkdir -p "$TMP/app-data/nostr-vpn" "$TMP/data" "$TMP/nvpn-data" "$TMP/scanner-data"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}" \
  cargo build --quiet --manifest-path "$ROOT_DIR/Cargo.toml" \
    -p nostr-vpn-core --example desktop_manual_join_e2e_fixture
TARGET_DIR="$(
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}" \
    cargo metadata --manifest-path "$ROOT_DIR/Cargo.toml" --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])'
)"
FIXTURE="$TARGET_DIR/debug/examples/desktop_manual_join_e2e_fixture"
"$FIXTURE" prepare \
  --admin-data-dir "$TMP/scanner-data/config/nvpn" \
  --joiner-data-dir "$TMP/nvpn-data/config/nvpn" \
  --result "$FIXTURE_RESULT" \
  --admin-endpoint "$SCANNER_IP:25111" \
  --joiner-endpoint "$REQUESTER_IP:25110" \
  --direction umbrel-auth-requester
python3 - "$ROOT_DIR/umbrel/umbrel-app.yml" "$TMP/umbrel-app.yml" "$PROXY_PORT" <<'PY'
import re
import sys
from pathlib import Path

source, destination, port = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
manifest = source.read_text()
updated, count = re.subn(r"(?m)^port: [0-9]+$", f"port: {port}", manifest)
if count != 1:
    raise SystemExit(f"expected one Umbrel manifest port, found {count}")
destination.write_text(updated)
PY
cp "$TMP/umbrel-app.yml" "$TMP/app-data/nostr-vpn/umbrel-app.yml"
printf 'user:\n  wallpaper: "18"\n' >"$TMP/data/umbrel.yaml"

python3 - "$RPC_PORT" "$JWT_SECRET" "$PASSWORD" <<'PY' &
import base64
import hashlib
import hmac
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port, secret, password = int(sys.argv[1]), sys.argv[2].encode(), sys.argv[3]

def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
payload = b64(json.dumps({"proxyToken": True}, separators=(",", ":")).encode())
body = f"{header}.{payload}"
token = f"{body}.{b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())}"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        try:
            data = json.loads(self.rfile.read(length))
        except Exception:
            data = {}
        if self.path != "/trpc/user.login" or data.get("password") != password:
            self.send_response(401)
            self.end_headers()
            return
        encoded = json.dumps({"result": {"data": {"ok": True}}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header(
            "set-cookie",
            f"UMBREL_PROXY_TOKEN={token}; Path=/; HttpOnly; SameSite=Lax",
        )
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
PY
STUB_PID=$!

python3 - "$RPC_PORT" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
for _ in range(100):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.1)
raise SystemExit("Umbrel login RPC fixture did not start")
PY

cat >"$COMPOSE" <<YAML
services:
  daemon:
    image: $IMAGE
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun:/dev/net/tun]
    entrypoint: [/usr/local/bin/nvpn]
    command: [daemon, --paused, --config, /data/config/nvpn/config.toml]
    environment:
      HOME: /data/home
      XDG_CONFIG_HOME: /data/config
    volumes: [$TMP/nvpn-data:/data]
    networks:
      default:
        ipv4_address: $REQUESTER_IP
  web:
    image: $IMAGE
    depends_on: [daemon]
    command: [--listen, 0.0.0.0:38080, --behind-trusted-proxy, --config, /data/config/nvpn/config.toml]
    environment:
      HOME: /data/home
      XDG_CONFIG_HOME: /data/config
      NVPN_CLI_PATH: /usr/local/bin/nvpn
      NVPN_DAEMON_STATUS_MODE: state-file
      NVPN_EXTERNAL_DAEMON: "true"
    volumes: [$TMP/nvpn-data:/data]
  scanner_daemon:
    image: $IMAGE
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun:/dev/net/tun]
    entrypoint: [/usr/local/bin/nvpn]
    command: [daemon, --paused, --config, /scanner/config/nvpn/config.toml]
    environment:
      HOME: /scanner/home
      XDG_CONFIG_HOME: /scanner/config
    volumes: [$TMP/scanner-data:/scanner]
    networks:
      default:
        ipv4_address: $SCANNER_IP
  scanner_web:
    image: $IMAGE
    depends_on: [scanner_daemon]
    command: [--listen, 0.0.0.0:38081, --behind-trusted-proxy, --config, /scanner/config/nvpn/config.toml]
    environment:
      HOME: /scanner/home
      XDG_CONFIG_HOME: /scanner/config
      NVPN_CLI_PATH: /usr/local/bin/nvpn
      NVPN_DAEMON_STATUS_MODE: state-file
      NVPN_EXTERNAL_DAEMON: "true"
    ports: [127.0.0.1:$SCANNER_PORT:38081]
    volumes: [$TMP/scanner-data:/scanner]
  auth:
    image: $AUTH_IMAGE
    environment:
      PORT: 2000
      UMBREL_AUTH_SECRET: $AUTH_SECRET
      MANAGER_IP: 127.0.0.1
      MANAGER_PORT: 3006
      DASHBOARD_IP: 127.0.0.1
      DASHBOARD_PORT: 3004
      JWT_SECRET: $JWT_SECRET
      UMBRELD_RPC_HOST: host.docker.internal:$RPC_PORT
    extra_hosts: [host.docker.internal:host-gateway]
    ports: [127.0.0.1:$AUTH_PORT:2000]
    volumes:
      - $TMP/app-data:/app-data:ro
      - $TMP/data:/data:ro
  app_proxy:
    image: $APP_PROXY_IMAGE
    depends_on: [web, auth]
    environment:
      PROXY_PORT: $PROXY_PORT
      PROXY_AUTH_ADD: "true"
      PROXY_AUTH_WHITELIST: ""
      PROXY_AUTH_BLACKLIST: ""
      APP_HOST: web
      APP_PORT: 38080
      APP_MANIFEST_FILE: /extra/umbrel-app.yml
      UMBREL_AUTH_PORT: $AUTH_PORT
      UMBREL_AUTH_SECRET: $AUTH_SECRET
      MANAGER_IP: 127.0.0.1
      MANAGER_PORT: 3006
      JWT_SECRET: $JWT_SECRET
    ports: [127.0.0.1:$PROXY_PORT:$PROXY_PORT]
    volumes: [$TMP/umbrel-app.yml:/extra/umbrel-app.yml:ro]
networks:
  default:
    driver: bridge
    ipam:
      config:
        - subnet: $SUBNET
YAML

docker compose -p "$PROJECT" -f "$COMPOSE" up -d

code=''
for _ in $(seq 1 120); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$PROXY_PORT/api/health" || true)"
  [[ "$code" == 302 ]] && break
  sleep 1
done
[[ "$code" == 302 ]] || {
  echo "Umbrel app proxy did not protect the nVPN health endpoint." >&2
  exit 1
}
location="$(curl -sSI "http://127.0.0.1:$PROXY_PORT/api/health" \
  | awk 'BEGIN{IGNORECASE=1} /^location:/ {sub(/\r$/, "", $2); print $2; exit}')"
[[ "$location" == "http://127.0.0.1:$AUTH_PORT/"* ]]
[[ "$location" == *'app=nostr-vpn'* ]]
[[ "$location" == *'path=%2Fapi%2Fhealth'* ]]

PROXY_BASE="http://127.0.0.1:$PROXY_PORT" \
SCANNER_BASE="http://127.0.0.1:$SCANNER_PORT" \
AUTH_PORT="$AUTH_PORT" TEST_PASSWORD="$PASSWORD" \
  pnpm --dir "$ROOT_DIR/web/control-panel" exec node --input-type=module - <<'JS'
import { chromium } from '@playwright/test'

const proxy = process.env.PROXY_BASE
const scanner = process.env.SCANNER_BASE
const authPort = process.env.AUTH_PORT
const browser = await chromium.launch({ headless: true })
let context
try {
  context = await browser.newContext()
  const page = await context.newPage()
  await page.goto(`${proxy}/`, { waitUntil: 'domcontentloaded' })
  if (new URL(page.url()).port !== authPort) {
    throw new Error(`expected Umbrel auth redirect, got ${page.url()}`)
  }
  const password = page.locator('input[type=password]')
  await password.waitFor({ state: 'visible' })
  await password.fill(process.env.TEST_PASSWORD)
  await page.locator('button[type=submit]').click()
  await page.waitForURL(`${proxy}/`, { waitUntil: 'domcontentloaded', timeout: 30_000 })
  await page.getByRole('heading', { name: 'Nostr VPN' }).waitFor({ state: 'visible' })

  const health = await context.request.get(`${proxy}/api/health`)
  if (health.status() !== 200) {
    throw new Error(`authenticated health returned ${health.status()}`)
  }
  const cookies = await context.cookies(proxy)
  const token = cookies.filter((cookie) => cookie.name === 'UMBREL_PROXY_TOKEN')
  if (token.length !== 1 || !token[0].httpOnly || token[0].sameSite !== 'Lax') {
    throw new Error('Umbrel proxy cookie was not exact')
  }

  const tick = async () => {
    const response = await context.request.post(`${proxy}/api/tick`)
    if (!response.ok()) throw new Error(`tick returned ${response.status()}`)
    return response.json()
  }
  let state = await tick()
  if (state.networks.length !== 0) {
    throw new Error('unjoined Umbrel fixture unexpectedly has a network')
  }

  const deadline = Date.now() + 15_000
  do {
    state = await tick()
    if (String(state.joinRequestQrCodeOrLink ?? '').startsWith('nvpn://join-request/')) break
    await new Promise((resolve) => setTimeout(resolve, 200))
  } while (Date.now() < deadline)
  const request = String(state.joinRequestQrCodeOrLink ?? '')
  const requesterNpub = String(state.ownNpub ?? '')
  if (!request.startsWith('nvpn://join-request/')) {
    throw new Error('unjoined Umbrel did not expose a signed join request')
  }
  if (!requesterNpub.startsWith('npub1')) {
    throw new Error('unjoined Umbrel did not expose its requester identity')
  }

  await page.goto(`${proxy}/`, { waitUntil: 'domcontentloaded' })
  await page.getByRole('button', { name: 'Add Network' }).click()
  await page.getByRole('button', { name: 'Join Network', exact: true }).click()
  await page.getByRole('img', { name: 'QR code' }).waitFor({ state: 'visible' })
  const copy = page.getByRole('button', { name: 'Copy Join request' })
  await copy.waitFor({ state: 'visible' })
  if (await copy.isDisabled()) throw new Error('join request copy action is disabled')

  const qrResponse = await context.request.post(`${proxy}/api/qr_matrix`, {
    data: { text: request },
  })
  if (!qrResponse.ok()) throw new Error(`QR matrix returned ${qrResponse.status()}`)
  const qr = await qrResponse.json()
  if (!(qr.width > 0) || qr.cells.length !== qr.width * qr.width || !qr.cells.some(Boolean)) {
    throw new Error('join request QR matrix is invalid')
  }

  const scannerPage = await context.newPage()
  await scannerPage.goto(`${scanner}/`, { waitUntil: 'domcontentloaded' })
  await scannerPage.getByRole('heading', { name: 'Nostr VPN' }).waitFor({ state: 'visible' })
  await scannerPage.getByRole('button', { name: 'Add Device' }).click()
  await scannerPage.getByPlaceholder('Paste a join request to continue').fill(request)
  const confirm = scannerPage.getByRole('dialog', { name: 'Add Device?' })
  await confirm.waitFor({ state: 'visible' })
  await confirm.getByRole('button', { name: 'Add', exact: true }).click()
  await scannerPage.getByText('Device added', { exact: true }).waitFor({ state: 'visible' })

  const scannerResponse = await context.request.post(`${scanner}/api/tick`)
  if (!scannerResponse.ok()) throw new Error(`scanner tick returned ${scannerResponse.status()}`)
  const scannerState = await scannerResponse.json()
  const scannerNetwork = scannerState.networks.find((network) => network.enabled)
  const scannerNpub = String(scannerState.ownNpub ?? '')
  if (!scannerNpub.startsWith('npub1')) {
    throw new Error('scanner did not expose its admin identity')
  }
  const requesterAdded = scannerNetwork?.participants?.some(
    (participant) => participant.npub === requesterNpub,
  )
  if (!requesterAdded) throw new Error('requester was not added to the scanner roster')
  await scannerPage.close()

  const requesterDeadline = Date.now() + 15_000
  let requesterNetwork
  do {
    state = await tick()
    requesterNetwork = state.networks.find(
      (network) => network.enabled && network.participants?.some(
        (participant) => participant.npub === scannerNpub && participant.isAdmin,
      ),
    )
    if (requesterNetwork) break
    await new Promise((resolve) => setTimeout(resolve, 200))
  } while (Date.now() < requesterDeadline)
  if (!requesterNetwork) throw new Error('requester did not activate the scanned network')
  // A joined device deliberately retains a reusable request link so it can
  // ask to join another network later. The completion contract is instead
  // the active admin-signed network above plus leaving the QR modal below.
  await page.getByRole('dialog', { name: 'Add Network' }).waitFor({ state: 'hidden', timeout: 15_000 })
  await page.getByRole('button', { name: 'Add Network' }).waitFor({ state: 'visible' })

  const unauthenticated = await browser.newContext()
  try {
    const response = await unauthenticated.request.get(`${proxy}/api/health`, { maxRedirects: 0 })
    if (response.status() !== 302) {
      throw new Error(`fresh unauthenticated health returned ${response.status()}`)
    }
  } finally {
    await unauthenticated.close()
  }
} finally {
  if (context) await context.close()
  await browser.close()
}
JS

[[ "$(curl -sS -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:$PROXY_PORT/api/health")" == 302 ]]
echo "Umbrel authenticated requester-join e2e passed"
