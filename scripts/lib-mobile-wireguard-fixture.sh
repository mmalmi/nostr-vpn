#!/usr/bin/env bash

MOBILE_WG_FIXTURE_REMOTE=0
MOBILE_WG_FIXTURE_REMOTE_MODE=""
MOBILE_WG_FIXTURE_REMOTE_DIR=""
MOBILE_WG_FIXTURE_REMOTE_IMAGE_BUILT=0
MOBILE_WG_FIXTURE_VOLUME_DIR=""
MOBILE_WG_FIXTURE_ENDPOINT_FAMILY=""
MOBILE_WG_FIXTURE_REMOTE_INTERFACE=""
MOBILE_WG_FIXTURE_REMOTE_NFT_TABLE=""
MOBILE_WG_FIXTURE_STARTED=0
MOBILE_WG_FIXTURE_REMOTE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MOBILE_WG_FIXTURE_SSH_CONTROL_PATH="/tmp/nvpn-wg-fixture-$PPID-$$"

mobile_wg_fixture_begin_cleanup() {
  trap - EXIT
  trap '' HUP INT TERM
}

mobile_wg_endpoint_fields() {
  local raw_host="${1:-}" raw_port="${2:-}"
  python3 - "$raw_host" "$raw_port" <<'PY'
import ipaddress
import re
import sys

host, raw_port = sys.argv[1:]
if (
    not host
    or host != host.strip()
    or any(character.isspace() for character in host)
):
    raise SystemExit(1)
if not re.fullmatch(r"[1-9][0-9]*", raw_port):
    raise SystemExit(1)
port = int(raw_port)
if port > 65535:
    raise SystemExit(1)

try:
    address = ipaddress.ip_address(host)
except ValueError:
    name = host[:-1] if host.endswith(".") else host
    if (
        not name
        or len(host) > 253
        or re.fullmatch(r"[0-9.]+", name)
    ):
        raise SystemExit(1)
    label_pattern = re.compile(
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    )
    if any(not label_pattern.fullmatch(label) for label in name.split(".")):
        raise SystemExit(1)
    family = "dns"
    authority = f"{host}:{port}"
else:
    family = "ipv4" if address.version == 4 else "ipv6"
    authority = f"{host}:{port}" if address.version == 4 else f"[{host}]:{port}"

print(f"{family}\t{host}\t{authority}")
PY
}

mobile_wg_endpoint_family() {
  local fields
  fields="$(mobile_wg_endpoint_fields "${1:-}" 1)" || return 1
  printf '%s\n' "${fields%%$'\t'*}"
}

mobile_wg_dns_case_fields() {
  local label="$1" dns_name="$2" profile_dns_ip="$3" through_dns_ip="$4"
  case "$label" in
    automatic-profile)
      printf 'automatic|cloudflare||||%s|%s|dns-profile\n' \
        "$dns_name" "$profile_dns_ip"
      ;;
    cloudflare-doh)
      printf 'encrypted|cloudflare||||cloudflare.192-0-43-8.sslip.io|192.0.43.8|doh-cloudflare\n'
      ;;
    quad9-doh)
      printf 'encrypted|quad9||||quad9.192-0-43-8.sslip.io|192.0.43.8|doh-quad9\n'
      ;;
    custom-doh)
      printf 'encrypted|custom|https://dns.google/dns-query|8.8.8.8||custom.192-0-43-8.sslip.io|192.0.43.8|doh-google\n'
      ;;
    through-exit)
      printf 'through_exit|cloudflare|||%s|through-exit.%s|%s|dns-through\n' \
        "$through_dns_ip" "$dns_name" "$profile_dns_ip"
      ;;
    *)
      echo "unknown WireGuard exit DNS case: $label" >&2
      return 2
      ;;
  esac
}

mobile_wg_dns_cases_are_complete() {
  [[ "$#" -eq 5 \
    && "$1" == automatic-profile \
    && "$2" == cloudflare-doh \
    && "$3" == quad9-doh \
    && "$4" == custom-doh \
    && "$5" == through-exit ]]
}

mobile_wg_fixture_validate_ssh_host() {
  local host="$1"
  if [[ -z "$host" || "$host" == -* || "$host" =~ [[:space:]] ]]; then
    echo "remote mobile WireGuard fixture SSH host is invalid" >&2
    return 1
  fi
}

mobile_wg_remote_exec() {
  local host="${NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST:-}"
  local command="" quoted argument
  local -a control_options=(-o ControlMaster=auto -o ControlPersist=60 \
    -o "ControlPath=$MOBILE_WG_FIXTURE_SSH_CONTROL_PATH")
  if [[ "${1:-}" == "--fresh" ]]; then
    shift
    control_options=(-o ControlMaster=no -o ControlPath=none)
  fi
  mobile_wg_fixture_validate_ssh_host "$host" || return 1
  for argument in "$@"; do
    printf -v quoted '%q' "$argument"
    command+="$quoted "
  done
  ssh \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o ConnectionAttempts=1 \
    -o ServerAliveInterval=3 \
    -o ServerAliveCountMax=2 \
    "${control_options[@]}" \
    "$host" "$command"
}

mobile_wg_fixture_recover_inactive_remote_dir() {
  local first_entry="" marker="$MOBILE_WG_FIXTURE_REMOTE_DIR/.nvpn-fixture-owner"
  mobile_wg_fixture_validate_remote_dir || return 1
  mobile_wg_remote_exec test ! -e "$MOBILE_WG_FIXTURE_REMOTE_DIR" && return 0
  mobile_wg_remote_exec test -d "$MOBILE_WG_FIXTURE_REMOTE_DIR" \
    && mobile_wg_remote_exec test ! -L "$MOBILE_WG_FIXTURE_REMOTE_DIR" \
    && mobile_wg_remote_exec test -O "$MOBILE_WG_FIXTURE_REMOTE_DIR" \
    || return 1
  first_entry="$(mobile_wg_remote_exec find "$MOBILE_WG_FIXTURE_REMOTE_DIR" \
    -mindepth 1 -maxdepth 1 -print -quit)" || return 1
  if [[ -n "$first_entry" ]] \
    && ! mobile_wg_remote_native clean >/dev/null 2>&1
  then
    mobile_wg_remote_exec test -f "$marker" \
      && mobile_wg_remote_exec test ! -L "$marker" \
      && mobile_wg_remote_exec test -O "$marker" \
      && mobile_wg_remote_exec test ! -e \
        "$MOBILE_WG_FIXTURE_REMOTE_DIR/mobile-wireguard-exit-remote-native.sh" \
      || return 1
  fi
  mobile_wg_remote_exec sudo -n rm -f \
    "$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/server.key" \
    "$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/client.key" \
    && mobile_wg_remote_exec sudo -n find "$MOBILE_WG_FIXTURE_REMOTE_DIR" \
      -xdev -depth -mindepth 1 -delete \
    && mobile_wg_remote_exec sudo -n rmdir "$MOBILE_WG_FIXTURE_REMOTE_DIR" \
    && mobile_wg_remote_exec --fresh test ! -e "$MOBILE_WG_FIXTURE_REMOTE_DIR"
}

mobile_wg_fixture_validate_remote_dir() {
  [[ "$MOBILE_WG_FIXTURE_REMOTE_DIR" =~ ^(/var)?/tmp/nvpn-mobile-wg-exit\.[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] || return 1
  mobile_wg_remote_exec sh -c '
    root=${1%/*}
    [ -d "$root" ] && [ ! -L "$root" ] &&
      { [ "$root" != /var/tmp ] || [ ! -L /var ]; } &&
      [ ! -L "$1" ] && [ ! -L "$1/fixture" ]
  ' sh "$MOBILE_WG_FIXTURE_REMOTE_DIR"
}

mobile_wg_remote_close_control() {
  local host="${NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST:-}"
  [[ -n "$host" ]] || return 0
  ssh \
    -o "ControlPath=$MOBILE_WG_FIXTURE_SSH_CONTROL_PATH" \
    -O exit "$host" >/dev/null 2>&1 || true
}

mobile_wg_remote_has_command() {
  mobile_wg_remote_exec \
    env "PATH=$MOBILE_WG_FIXTURE_REMOTE_PATH" \
    sh -c 'command -v "$1" >/dev/null 2>&1' sh "$1"
}

mobile_wg_remote_docker() {
  if bool_is_true "${NVPN_MOBILE_WG_EXIT_REMOTE_DOCKER_SUDO:-0}"; then
    mobile_wg_remote_exec sudo -n docker "$@"
  else
    mobile_wg_remote_exec docker "$@"
  fi
}

mobile_wg_fixture_docker() {
  if [[ "$MOBILE_WG_FIXTURE_REMOTE" -eq 1 ]]; then
    if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" != "docker" ]]; then
      echo "remote native fixture cannot execute an arbitrary Docker command" >&2
      return 2
    fi
    mobile_wg_remote_docker "$@"
  else
    docker "$@"
  fi
}

mobile_wg_fixture_validate_docker_context() {
  local root="$1" ignore expected
  ignore="$root/Dockerfile.mobile-wireguard-exit-e2e.dockerignore"
  expected=$'**\n\n!scripts\nscripts/**\n!scripts/mobile-wireguard-exit-server.sh\n!scripts/mobile-wireguard-http-probe.py\n!scripts/mobile-wireguard-tls-sni-count.py'
  [[ -f "$ignore" && ! -L "$ignore" && "$(<"$ignore")" == "$expected" ]] || {
    echo "mobile WireGuard Docker context is not strictly fixture-scoped" >&2
    return 1
  }
}

mobile_wg_fixture_stage_remote_docker_context() {
  local root="$1" remote_host="$2" source
  local -a root_sources=(
    "$root/Dockerfile.mobile-wireguard-exit-e2e"
    "$root/Dockerfile.mobile-wireguard-exit-e2e.dockerignore"
  )
  local -a script_sources=(
    "$root/scripts/mobile-wireguard-exit-server.sh"
    "$root/scripts/mobile-wireguard-http-probe.py"
    "$root/scripts/mobile-wireguard-tls-sni-count.py"
  )
  mobile_wg_fixture_validate_docker_context "$root" || return 1
  for source in "${root_sources[@]}" "${script_sources[@]}"; do
    [[ -f "$source" && ! -L "$source" ]] || {
      echo "mobile WireGuard remote Docker source is missing or unsafe: $source" >&2
      return 1
    }
  done
  mobile_wg_remote_exec mkdir -p "$MOBILE_WG_FIXTURE_REMOTE_DIR/scripts" \
    && scp -q \
      "${root_sources[@]}" \
      "$remote_host:$MOBILE_WG_FIXTURE_REMOTE_DIR/" \
    && scp -q \
      "${script_sources[@]}" \
      "$remote_host:$MOBILE_WG_FIXTURE_REMOTE_DIR/scripts/"
}

mobile_wg_fixture_initialize() {
  local root="$1" local_fixture_dir="$2"
  local remote_host="${NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST:-}"
  local remote_temp_root="${NVPN_MOBILE_WG_EXIT_REMOTE_TEMP_ROOT:-/tmp}"
  if [[ -z "$remote_host" ]]; then
    command -v docker >/dev/null 2>&1 || {
      echo "local mobile WireGuard fixture requires docker" >&2
      return 1
    }
    MOBILE_WG_FIXTURE_VOLUME_DIR="$local_fixture_dir"
    return 0
  fi

  case "$remote_temp_root" in
    /tmp|/var/tmp) ;;
    *) echo "remote fixture temp root must be /tmp or /var/tmp" >&2; return 2 ;;
  esac

  MOBILE_WG_FIXTURE_REMOTE=1
  MOBILE_WG_FIXTURE_REMOTE_MODE="${NVPN_MOBILE_WG_EXIT_REMOTE_MODE:-native}"
  MOBILE_WG_FIXTURE_ENDPOINT_FAMILY="$(
    mobile_wg_endpoint_family "${NVPN_MOBILE_WG_EXIT_HOST_IP:-}"
  )" || {
    echo "remote mobile WireGuard fixture host is malformed" >&2
    return 1
  }
  mobile_wg_fixture_validate_ssh_host "$remote_host" || return 1
  : "${NVPN_MOBILE_WG_EXIT_HOST_IP:?remote fixture requires its reachable public address}"
  command -v ssh >/dev/null 2>&1 \
    && command -v scp >/dev/null 2>&1 \
    || {
      echo "remote mobile WireGuard fixture requires ssh and scp" >&2
      return 1
    }
  case "$MOBILE_WG_FIXTURE_REMOTE_MODE" in
    native)
      if [[ "$(mobile_wg_remote_exec uname -s)" != "Linux" ]]; then
        echo "remote native mobile WireGuard fixture requires Linux" >&2
        return 1
      fi
      if ! mobile_wg_remote_exec sudo -n true >/dev/null; then
        echo "remote native mobile WireGuard fixture requires passwordless sudo" >&2
        return 1
      fi
      local missing_packages=()
      mobile_wg_remote_has_command wg \
        || missing_packages+=(wireguard-tools)
      mobile_wg_remote_has_command dnsmasq \
        || missing_packages+=(dnsmasq-base)
      mobile_wg_remote_has_command nft \
        || missing_packages+=(nftables)
      mobile_wg_remote_has_command flock \
        || missing_packages+=(util-linux)
      mobile_wg_remote_has_command tcpdump \
        || missing_packages+=(tcpdump)
      if ((${#missing_packages[@]} > 0)); then
        if ! bool_is_true "${NVPN_MOBILE_WG_EXIT_REMOTE_INSTALL_PACKAGES:-1}"; then
          echo "remote native fixture is missing required packages: ${missing_packages[*]}" >&2
          return 1
        fi
        mobile_wg_remote_exec \
          sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update -qq
        mobile_wg_remote_exec \
          sudo -n env DEBIAN_FRONTEND=noninteractive \
          apt-get install -y -qq "${missing_packages[@]}"
      fi
      ;;
    docker)
      mobile_wg_remote_exec command -v docker >/dev/null \
        || {
          echo "remote mobile WireGuard fixture host has no docker" >&2
          return 1
        }
      mobile_wg_remote_docker info >/dev/null \
        || {
          echo "remote mobile WireGuard fixture cannot access Docker" >&2
          return 1
        }
      ;;
    *)
      echo "NVPN_MOBILE_WG_EXIT_REMOTE_MODE must be native or docker" >&2
      return 2
      ;;
  esac
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    MOBILE_WG_FIXTURE_REMOTE_INTERFACE="nwg$HOST_PORT"
    MOBILE_WG_FIXTURE_REMOTE_NFT_TABLE="nvpnwg$HOST_PORT"
    MOBILE_WG_FIXTURE_REMOTE_DIR="$remote_temp_root/nvpn-mobile-wg-exit.port-$HOST_PORT"
    mobile_wg_fixture_recover_inactive_remote_dir || {
      echo "remote mobile WireGuard fixture found active or foreign same-port state" >&2
      return 1
    }
    mobile_wg_remote_exec mkdir -m 700 "$MOBILE_WG_FIXTURE_REMOTE_DIR" \
      || return 1
    mobile_wg_remote_exec install -m 600 /dev/null \
      "$MOBILE_WG_FIXTURE_REMOTE_DIR/.nvpn-fixture-owner" || return 1
  else
    MOBILE_WG_FIXTURE_REMOTE_DIR="$(
      mobile_wg_remote_exec mktemp -d "$remote_temp_root/nvpn-mobile-wg-exit.XXXXXX"
    )"
  fi
  mobile_wg_fixture_validate_remote_dir || {
    echo "remote mobile WireGuard fixture returned an unsafe temp path" >&2
    MOBILE_WG_FIXTURE_REMOTE_DIR=""
    return 1
  }
  mobile_wg_remote_exec mkdir -p "$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    scp -q \
      "$root/scripts/mobile-wireguard-exit-remote-native.sh" \
      "$root/scripts/mobile-wireguard-udp-echo.py" \
      "$root/scripts/mobile-wireguard-http-probe.py" \
      "$root/scripts/mobile-wireguard-tls-sni-count.py" \
      "$remote_host:$MOBILE_WG_FIXTURE_REMOTE_DIR/" \
      || return 1
    mobile_wg_remote_exec \
      chmod 700 \
      "$MOBILE_WG_FIXTURE_REMOTE_DIR/mobile-wireguard-exit-remote-native.sh"
  else
    mobile_wg_fixture_stage_remote_docker_context "$root" "$remote_host" \
      || return 1
  fi
  scp -q \
    "$local_fixture_dir/server.key" \
    "$local_fixture_dir/server.pub" \
    "$local_fixture_dir/client.key" \
    "$local_fixture_dir/client.pub" \
    "$remote_host:$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/" \
    || return 1
  mobile_wg_remote_exec chmod 700 "$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture"
  mobile_wg_remote_exec \
    chmod 600 \
    "$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/server.key" \
    "$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/client.key"
  MOBILE_WG_FIXTURE_VOLUME_DIR="$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture"
}

mobile_wg_listener_port_in_use() {
  local port="$1" listeners="$2"
  python3 - "$port" "$listeners" <<'PY'
import re
import sys

port, listeners = sys.argv[1:]
for line in listeners.splitlines():
    if any(
        re.search(rf"[\].:]{re.escape(port)}$", field)
        for field in line.split()
    ):
        raise SystemExit(0)
raise SystemExit(1)
PY
}

mobile_wg_fixture_assert_available() {
  local container="$1" host_port="$2"
  [[ "$host_port" =~ ^[1-9][0-9]{0,4}$ \
    && "$HTTP_PROBE_PORT" =~ ^[1-9][0-9]{0,4}$ ]] \
    && ((host_port <= 65535 && HTTP_PROBE_PORT <= 65535)) || {
    echo "mobile WireGuard fixture ports must be in 1-65535" >&2
    return 1
  }
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" != "native" ]] \
    && mobile_wg_fixture_docker container inspect "$container" >/dev/null 2>&1
  then
    echo "mobile WireGuard fixture container name is already in use: $container" >&2
    return 1
  fi
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    if mobile_wg_remote_exec \
        sudo -n ip link show "$MOBILE_WG_FIXTURE_REMOTE_INTERFACE" \
        >/dev/null 2>&1 \
      || mobile_wg_remote_exec \
        sudo -n nft list table inet "$MOBILE_WG_FIXTURE_REMOTE_NFT_TABLE" \
        >/dev/null 2>&1
    then
      echo "remote fixture interface or nft table is already in use" >&2
      return 1
    fi
  fi
  local listeners tcp_listeners
  if [[ "$MOBILE_WG_FIXTURE_REMOTE" -eq 1 ]]; then
    listeners="$(mobile_wg_remote_exec ss -H -lun 2>/dev/null)" || {
      echo "remote fixture could not inspect UDP listeners before mutation" >&2
      return 1
    }
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iUDP:"$host_port" 2>/dev/null | grep -q .; then
      echo "mobile WireGuard fixture UDP port is already occupied: $host_port" >&2
      return 1
    fi
    return 0
  else
    listeners="$(netstat -an -p udp 2>/dev/null || true)"
  fi
  if mobile_wg_listener_port_in_use "$host_port" "$listeners"; then
    echo "mobile WireGuard fixture UDP port is already occupied: $host_port" >&2
    return 1
  fi
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    tcp_listeners="$(mobile_wg_remote_exec ss -H -ltn 2>/dev/null)" || {
      echo "remote fixture could not inspect TCP listeners before mutation" >&2
      return 1
    }
    if mobile_wg_listener_port_in_use "$HTTP_PROBE_PORT" "$tcp_listeners"; then
      echo "remote fixture HTTP probe TCP port is already occupied: $HTTP_PROBE_PORT" >&2
      return 1
    fi
  fi
}

mobile_wg_fixture_build() {
  local root="$1" image="$2" image_ready="$3"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    return 0
  elif [[ "$MOBILE_WG_FIXTURE_REMOTE" -eq 1 ]]; then
    mobile_wg_fixture_validate_docker_context "$root" || return 1
    if mobile_wg_fixture_docker image inspect "$image" >/dev/null 2>&1; then
      echo "remote fixture image tag is already in use: $image" >&2
      return 1
    fi
    mobile_wg_fixture_docker build -q \
      -f "$MOBILE_WG_FIXTURE_REMOTE_DIR/Dockerfile.mobile-wireguard-exit-e2e" \
      -t "$image" \
      "$MOBILE_WG_FIXTURE_REMOTE_DIR" >/dev/null
    MOBILE_WG_FIXTURE_REMOTE_IMAGE_BUILT=1
  elif ! bool_is_true "$image_ready"; then
    mobile_wg_fixture_validate_docker_context "$root" || return 1
    docker build -q \
      -f "$root/Dockerfile.mobile-wireguard-exit-e2e" \
      -t "$image" \
      "$root" >/dev/null
  fi
}

mobile_wg_remote_native() {
  mobile_wg_remote_exec \
    sudo -n env \
    "PATH=$MOBILE_WG_FIXTURE_REMOTE_PATH" \
    "NVPN_MOBILE_WG_REMOTE_STATE_DIR=$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture" \
    "NVPN_MOBILE_WG_REMOTE_INTERFACE=$MOBILE_WG_FIXTURE_REMOTE_INTERFACE" \
    "NVPN_MOBILE_WG_REMOTE_NFT_TABLE=$MOBILE_WG_FIXTURE_REMOTE_NFT_TABLE" \
    "NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=$MOBILE_WG_FIXTURE_ENDPOINT_FAMILY" \
    "NVPN_MOBILE_WG_SERVER_PRIVATE_KEY_FILE=$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/server.key" \
    "NVPN_MOBILE_WG_CLIENT_PUBLIC_KEY_FILE=$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/client.pub" \
    "NVPN_MOBILE_WG_TUNNEL_CIDR=$TUNNEL_SERVER_IP/24" \
    "NVPN_MOBILE_WG_CLIENT_IP=$TUNNEL_CLIENT_IP" \
    "NVPN_MOBILE_WG_THROUGH_DNS_IP=$THROUGH_DNS_IP" \
    "NVPN_MOBILE_WG_LISTEN_PORT=$HOST_PORT" \
    "NVPN_MOBILE_WG_DNS_NAME=$DNS_NAME" \
    "NVPN_MOBILE_WG_HTTP_PROBE_PORT=$HTTP_PROBE_PORT" \
    "NVPN_MOBILE_WG_HTTP_TOKEN=$HTTP_PROBE_TOKEN" \
    "$MOBILE_WG_FIXTURE_REMOTE_DIR/mobile-wireguard-exit-remote-native.sh" \
    "$@"
}

mobile_wg_fixture_run() {
  local image="$1" container="$2" volume_dir="$3"
  MOBILE_WG_FIXTURE_STARTED=1
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native start
    return
  fi
  mobile_wg_fixture_docker run -d \
    --name "$container" \
    --cap-add NET_ADMIN \
    --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 \
    -p "$HOST_PORT:51820/udp" \
    -v "$volume_dir:/fixture" \
    -e "NVPN_MOBILE_WG_TUNNEL_CIDR=$TUNNEL_SERVER_IP/24" \
    -e "NVPN_MOBILE_WG_CLIENT_IP=$TUNNEL_CLIENT_IP" \
    -e "NVPN_MOBILE_WG_THROUGH_DNS_IP=$THROUGH_DNS_IP" \
    -e "NVPN_MOBILE_WG_DNS_NAME=$DNS_NAME" \
    -e "NVPN_MOBILE_WG_HTTP_PROBE_PORT=$HTTP_PROBE_PORT" \
    -e "NVPN_MOBILE_WG_HTTP_TOKEN=$HTTP_PROBE_TOKEN" \
    "$image" >/dev/null
}

mobile_wg_fixture_ready() {
  local container="$1"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native ready
  else
    mobile_wg_fixture_docker exec "$container" test -f /fixture/ready
  fi
}

mobile_wg_fixture_running() {
  local container="$1"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native ready
  else
    [[ "$(mobile_wg_fixture_docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" == "true" ]]
  fi
}

mobile_wg_fixture_logs() {
  local container="$1"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_exec \
      tail -n 100 \
      "$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/dns.log" \
      "$MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/udp-echo.log" \
      2>/dev/null || true
  else
    mobile_wg_fixture_docker logs "$container"
  fi
}

mobile_wg_fixture_wg_bytes() {
  local container="$1"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native wg-bytes
  else
    mobile_wg_fixture_docker exec "$container" wg show wg0 transfer \
      | awk '{ rx += $2; tx += $3 } END { printf "%d\t%d\n", rx, tx }'
  fi
}

mobile_wg_fixture_forward_packets() {
  local container="$1"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native forward-packets
  else
    mobile_wg_fixture_docker exec "$container" \
      iptables -L nvpn-mobile-wg-forward -v -n -x \
      | awk '$3 == "ACCEPT" && ($7 == "wg0" || $8 == "wg0") { packets += $1 } END { print packets + 0 }'
  fi
}

mobile_wg_fixture_dns_count() {
  local container="$1" name="$2"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native dns-count "$name"
  else
    mobile_wg_fixture_docker exec "$container" \
      sh -c 'grep -Fci "$1" /fixture/dns.log 2>/dev/null || true' sh "$name"
  fi
}

mobile_wg_fixture_through_dns_count() {
  local container="$1"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native through-dns-count
    return
  fi
  mobile_wg_fixture_docker exec "$container" \
    iptables -L nvpn-wg-dns-through -v -n -x \
    | awk '$3 == "ACCEPT" { packets += $1 } END { print packets + 0 }'
}

mobile_wg_fixture_profile_dns_count() {
  local container="$1"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native profile-dns-count
    return
  fi
  mobile_wg_fixture_docker exec "$container" \
    iptables -L nvpn-wg-dns-profile -v -n -x \
    | awk '$3 == "ACCEPT" { packets += $1 } END { print packets + 0 }'
}

mobile_wg_fixture_forward_dns_count() {
  local container="$1"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native forward-dns-count
    return
  fi
  mobile_wg_fixture_docker exec "$container" \
    iptables -L nvpn-wg-dns-forward -v -n -x \
    | awk '$3 == "ACCEPT" { packets += $1 } END { print packets + 0 }'
}

mobile_wg_fixture_dns_evidence_snapshot() {
  local container="$1" probe_host="$2"
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_remote_native dns-evidence-snapshot "$probe_host"
    return
  fi
  mobile_wg_fixture_docker exec -i "$container" \
    sh -s -- "$probe_host" <<'SH'
set -eu
probe_host="$1"
chain_packets() {
  iptables -L "$1" -v -n -x \
    | awk '$3 == "ACCEPT" { packets += $1 } END { print packets + 0 }'
}
query_count="$(grep -Fci "$probe_host" /fixture/dns.log 2>/dev/null || true)"
sni_counts="$(
  python3 /usr/local/bin/mobile-wireguard-tls-sni-count.py \
    /fixture/resolver-clienthello.pcap \
    cloudflare-dns.com dns.quad9.net dns.google
)"
printf '%s\t%s\t%s\t%s\t%s\n' \
  "$query_count" \
  "$(chain_packets nvpn-wg-dns-profile)" \
  "$sni_counts" \
  "$(chain_packets nvpn-wg-dns-through)" \
  "$(chain_packets nvpn-wg-dns-forward)"
SH
}

mobile_wg_fixture_timed_dns_evidence_snapshot() {
  local container="$1" probe_host="$2" observed_at
  observed_at="$(date -u +%s)"
  printf '%s\t%s\n' \
    "$observed_at" \
    "$(mobile_wg_fixture_dns_evidence_snapshot "$container" "$probe_host")"
}

mobile_wg_fixture_wait_for_dns_case_evidence() {
  local platform="$1" label="$2" evidence="$3" before="$4"
  local container="$5" probe_host="$6" timeout_seconds="$7"
  local after deadline snapshot_file
  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
    echo "$platform $label has an invalid DNS evidence timeout" >&2
    return 2
  }
  deadline=$((SECONDS + timeout_seconds))
  snapshot_file="$(mktemp "${TMPDIR:-/tmp}/nvpn-dns-evidence.XXXXXX")"
  while true; do
    if mobile_wg_fixture_dns_evidence_snapshot \
        "$container" "$probe_host" >"$snapshot_file"
    then
      after="$(<"$snapshot_file")"
      if mobile_wg_fixture_assert_dns_case_evidence \
          "$platform" "$label" "$evidence" "$before" "$after" \
          >/dev/null 2>&1
      then
        rm -f "$snapshot_file"
        printf '%s\n' "$after"
        return 0
      fi
    fi
    if (( SECONDS >= deadline )); then
      rm -f "$snapshot_file"
      mobile_wg_fixture_assert_dns_case_evidence \
        "$platform" "$label" "$evidence" "$before" "$after"
      return 1
    fi
    sleep 1
  done
}

mobile_wg_fixture_assert_dns_case_evidence() {
  local platform="$1" label="$2" evidence="$3" before="$4" after="$5"
  local b_query b_profile b_cf_sni b_q9_sni b_google_sni b_through b_forward_dns
  local a_query a_profile a_cf_sni a_q9_sni a_google_sni a_through a_forward_dns
  IFS=$'\t' read -r \
    b_query b_profile b_cf_sni b_q9_sni b_google_sni b_through b_forward_dns \
    <<<"$before"
  IFS=$'\t' read -r \
    a_query a_profile a_cf_sni a_q9_sni a_google_sni a_through a_forward_dns \
    <<<"$after"
  local value
  for value in \
    "$b_query" "$b_profile" "$b_cf_sni" "$b_q9_sni" "$b_google_sni" \
    "$b_through" "$b_forward_dns" \
    "$a_query" "$a_profile" "$a_cf_sni" "$a_q9_sni" "$a_google_sni" \
    "$a_through" "$a_forward_dns"
  do
    [[ "$value" =~ ^[0-9]+$ ]] || {
      echo "$platform $label returned a non-numeric DNS evidence counter" >&2
      return 1
    }
  done

  local -a increased=() unchanged=()
  case "$evidence" in
    dns-profile)
      increased=(query profile)
      unchanged=(through forward_dns)
      [[ "$platform" == iOS ]] \
        || unchanged+=(cf_sni q9_sni google_sni)
      ;;
    doh-cloudflare)
      unchanged=(query profile through forward_dns)
      if [[ "$platform" != iOS ]]; then
        increased=(cf_sni)
        [[ "$platform" == macOS ]] || unchanged+=(q9_sni google_sni)
      fi
      ;;
    doh-quad9)
      unchanged=(query profile through forward_dns)
      if [[ "$platform" != iOS ]]; then
        increased=(q9_sni)
        [[ "$platform" == macOS ]] || unchanged+=(cf_sni google_sni)
      fi
      ;;
    doh-google)
      unchanged=(query profile through forward_dns)
      if [[ "$platform" != iOS ]]; then
        increased=(google_sni)
        [[ "$platform" == macOS ]] || unchanged+=(cf_sni q9_sni)
      fi
      ;;
    dns-through)
      increased=(query through)
      unchanged=(profile forward_dns)
      [[ "$platform" == iOS ]] \
        || unchanged+=(cf_sni q9_sni google_sni)
      ;;
    *)
      echo "$platform $label has unknown DNS evidence kind: $evidence" >&2
      return 2
      ;;
  esac

  local counter before_value after_value
  if ((${#increased[@]})); then
    for counter in "${increased[@]}"; do
      case "$counter" in
        query) before_value="$b_query"; after_value="$a_query" ;;
        profile) before_value="$b_profile"; after_value="$a_profile" ;;
        cf_sni) before_value="$b_cf_sni"; after_value="$a_cf_sni" ;;
        q9_sni) before_value="$b_q9_sni"; after_value="$a_q9_sni" ;;
        google_sni) before_value="$b_google_sni"; after_value="$a_google_sni" ;;
        through) before_value="$b_through"; after_value="$a_through" ;;
        forward_dns) before_value="$b_forward_dns"; after_value="$a_forward_dns" ;;
      esac
      if (( after_value <= before_value )); then
        echo "$platform $label did not use required DNS path $counter ($before_value->$after_value)" >&2
        return 1
      fi
    done
  fi
  for counter in "${unchanged[@]}"; do
    case "$counter" in
      query) before_value="$b_query"; after_value="$a_query" ;;
      profile) before_value="$b_profile"; after_value="$a_profile" ;;
      cf_sni) before_value="$b_cf_sni"; after_value="$a_cf_sni" ;;
      q9_sni) before_value="$b_q9_sni"; after_value="$a_q9_sni" ;;
      google_sni) before_value="$b_google_sni"; after_value="$a_google_sni" ;;
      through) before_value="$b_through"; after_value="$a_through" ;;
      forward_dns) before_value="$b_forward_dns"; after_value="$a_forward_dns" ;;
    esac
    if (( after_value != before_value )); then
      echo "$platform $label leaked or fell back through forbidden DNS path $counter ($before_value->$after_value)" >&2
      return 1
    fi
  done
  echo "$platform $label DNS path passed: $before -> $after"
}

mobile_wg_fixture_assert_timed_dns_case_evidence() {
  local platform="$1" label="$2" evidence="$3" before="$4" after="$5"
  local before_at after_at before_counters after_counters
  before_at="${before%%$'\t'*}"
  after_at="${after%%$'\t'*}"
  before_counters="${before#*$'\t'}"
  after_counters="${after#*$'\t'}"
  [[ "$before_at" =~ ^[0-9]+$ && "$after_at" =~ ^[0-9]+$ \
    && "$after_at" -gt "$before_at" ]] || {
    echo "$platform $label DNS evidence is not bounded by an increasing timestamp" >&2
    return 1
  }
  mobile_wg_fixture_assert_dns_case_evidence \
    "$platform" "$label" "$evidence" "$before_counters" "$after_counters"
}

mobile_wg_fixture_cleanup() {
  local container="$1" image="$2"
  local cleanup_failed=0 inspect_status=0 remote_dir=""
  local native_stop_failed=0 native_clean_failed=0
  if [[ -n "$MOBILE_WG_FIXTURE_REMOTE_DIR" ]]; then
    mobile_wg_fixture_validate_remote_dir || {
      echo "remote fixture cleanup refuses an unsafe path" >&2
      mobile_wg_remote_close_control
      return 1
    }
    remote_dir="$MOBILE_WG_FIXTURE_REMOTE_DIR"
    if ! mobile_wg_remote_exec sudo -n rm -f \
      "$remote_dir/fixture/server.key" \
      "$remote_dir/fixture/client.key" >/dev/null 2>&1
    then
      cleanup_failed=1
    fi
  fi
  if [[ "$MOBILE_WG_FIXTURE_STARTED" -eq 1 ]]; then
    if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
      mobile_wg_remote_native stop >/dev/null 2>&1 \
        || native_stop_failed=1
      mobile_wg_remote_native clean >/dev/null 2>&1 \
        || native_clean_failed=1
      if [[ "$native_stop_failed" -ne 0 || "$native_clean_failed" -ne 0 ]]; then
        echo "remote native WireGuard fixture did not prove complete cleanup" >&2
        cleanup_failed=1
      else
        MOBILE_WG_FIXTURE_STARTED=0
      fi
    else
      mobile_wg_fixture_docker rm -f "$container" >/dev/null 2>&1 || true
      if mobile_wg_fixture_docker container inspect "$container" \
        >/dev/null 2>&1
      then
        inspect_status=0
      else
        inspect_status=$?
      fi
      if [[ "$inspect_status" -eq 1 ]]; then
        MOBILE_WG_FIXTURE_STARTED=0
      else
        echo "WireGuard fixture container survived cleanup or could not be verified" >&2
        cleanup_failed=1
      fi
    fi
  fi
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_IMAGE_BUILT" -eq 1 ]]; then
    mobile_wg_fixture_docker image rm "$image" >/dev/null 2>&1 || true
    if mobile_wg_fixture_docker image inspect "$image" >/dev/null 2>&1; then
      inspect_status=0
    else
      inspect_status=$?
    fi
    if [[ "$inspect_status" -eq 1 ]]; then
      MOBILE_WG_FIXTURE_REMOTE_IMAGE_BUILT=0
    else
      echo "remote WireGuard fixture image survived cleanup or could not be verified" >&2
      cleanup_failed=1
    fi
  fi
  if [[ -n "$remote_dir" ]]; then
    if ! mobile_wg_remote_exec test ! -e \
      "$remote_dir/fixture/server.key" >/dev/null 2>&1
    then
      echo "remote WireGuard fixture private keys survived cleanup" >&2
      cleanup_failed=1
    fi
    if ! mobile_wg_remote_exec test ! -e \
      "$remote_dir/fixture/client.key" >/dev/null 2>&1
    then
      echo "remote WireGuard fixture private keys survived cleanup" >&2
      cleanup_failed=1
    fi
    if [[ "$MOBILE_WG_FIXTURE_STARTED" -eq 0 ]]; then
      if ! mobile_wg_remote_exec \
        sudo -n find "$remote_dir" \
        -xdev -depth -mindepth 1 -delete \
        >/dev/null 2>&1 \
        || ! mobile_wg_remote_exec sudo -n rmdir "$remote_dir" \
          >/dev/null 2>&1
      then
        cleanup_failed=1
      fi
    else
      cleanup_failed=1
    fi
  fi
  mobile_wg_remote_close_control
  if [[ -n "$remote_dir" ]]; then
    if mobile_wg_remote_exec --fresh test ! -e "$remote_dir" >/dev/null 2>&1
    then
      MOBILE_WG_FIXTURE_REMOTE_DIR=""
    else
      echo "remote WireGuard fixture directory survived fresh-session cleanup verification" >&2
      cleanup_failed=1
    fi
  fi
  return "$cleanup_failed"
}
