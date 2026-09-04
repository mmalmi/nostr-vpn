#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/release_common.sh"
enable_deterministic_build_env "$ROOT"

OUTPUT_DIR="${1:?Linux ARM64 CLI gate output directory is required}"
TARGET=aarch64-unknown-linux-musl
ARCHIVE="$OUTPUT_DIR/nvpn-$TARGET.tar.gz"
RECEIPT="$OUTPUT_DIR/receipt.json"
BUILDER_IMAGE="${NVPN_LINUX_MUSL_IMAGE:-messense/rust-musl-cross:aarch64-musl}"
SMOKE_IMAGE="${NVPN_LINUX_ARM64_SMOKE_IMAGE:-nostr-vpn-linux-dev:latest}"
TEMP_DIR=""

cleanup() {
  [[ -z "$TEMP_DIR" ]] || rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

case "$(uname -m)" in
  arm64|aarch64) ;;
  *)
    echo "Linux ARM64 CLI native smoke requires an ARM64 release host" >&2
    exit 1
    ;;
esac
case "$(docker info --format '{{.Architecture}}')" in
  arm64|aarch64) ;;
  *)
    echo "Linux ARM64 CLI native smoke requires an ARM64 Docker engine" >&2
    exit 1
    ;;
esac
smoke_image_platform="$(
  docker image inspect --format '{{.Os}}/{{.Architecture}}' "$SMOKE_IMAGE" \
    2>/dev/null
)" || {
  echo "Linux ARM64 CLI smoke image is not present locally: $SMOKE_IMAGE" >&2
  exit 1
}
case "$smoke_image_platform" in
  linux/arm64|linux/aarch64) ;;
  *)
    echo "Linux ARM64 CLI smoke image has the wrong platform: $smoke_image_platform" >&2
    exit 1
    ;;
esac

app_head="$(git -C "$ROOT" rev-parse HEAD)"
app_tree="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo "Linux ARM64 CLI gate requires a clean application checkout" >&2
  exit 1
}
[[ -z "${NVPN_EXPECTED_APP_GIT_SHA:-}" \
  || "$app_head" == "$NVPN_EXPECTED_APP_GIT_SHA" ]] || {
  echo "Linux ARM64 CLI gate application revision differs from the sealed candidate" >&2
  exit 1
}
[[ -z "${NVPN_EXPECTED_APP_GIT_TREE:-}" \
  || "$app_tree" == "$NVPN_EXPECTED_APP_GIT_TREE" ]] || {
  echo "Linux ARM64 CLI gate application tree differs from the sealed candidate" >&2
  exit 1
}

: "${NVPN_FIPS_REPO_PATH:?Linux ARM64 CLI gate requires NVPN_FIPS_REPO_PATH}"
fips_head="$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse HEAD)"
fips_tree="$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse 'HEAD^{tree}')"
[[ -z "$(git -C "$NVPN_FIPS_REPO_PATH" status --porcelain --untracked-files=all)" ]] || {
  echo "Linux ARM64 CLI gate requires a clean FIPS checkout" >&2
  exit 1
}
[[ -z "${NVPN_EXPECTED_FIPS_GIT_SHA:-}" \
  || "$fips_head" == "$NVPN_EXPECTED_FIPS_GIT_SHA" ]] || {
  echo "Linux ARM64 CLI gate FIPS revision differs from the sealed candidate" >&2
  exit 1
}
[[ -z "${NVPN_EXPECTED_FIPS_GIT_TREE:-}" \
  || "$fips_tree" == "$NVPN_EXPECTED_FIPS_GIT_TREE" ]] || {
  echo "Linux ARM64 CLI gate FIPS tree differs from the sealed candidate" >&2
  exit 1
}

[[ ! -L "$OUTPUT_DIR" ]] || {
  echo "Linux ARM64 CLI gate output directory is unsafe" >&2
  exit 1
}
mkdir -p "$OUTPUT_DIR"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-linux-arm64-cli-gate.XXXXXX")"
target_dir="$TEMP_DIR/target"
binary="$target_dir/$TARGET/release/nvpn"

build_log="$OUTPUT_DIR/build.log"
if ! NVPN_LINUX_MUSL_TARGET_DIR="$target_dir" \
  "$ROOT/scripts/build-nvpn-linux-musl" "$TARGET" \
    >"$build_log" 2>&1
then
  tail -n 200 "$build_log" >&2
  exit 1
fi
[[ -x "$binary" ]] || {
  echo "Linux ARM64 CLI cross-build produced no executable" >&2
  exit 1
}
file "$binary" | grep -Eq 'ELF 64-bit.*(ARM aarch64|ARM64)' || {
  echo "Linux ARM64 CLI cross-build produced the wrong architecture" >&2
  exit 1
}
file "$binary" | grep -Eq 'statically linked|static-pie linked' || {
  echo "Linux ARM64 CLI cross-build did not produce a static executable" >&2
  exit 1
}

archive_root="$TEMP_DIR/archive"
mkdir -p "$archive_root/nvpn"
install -m 0755 "$binary" "$archive_root/nvpn/nvpn"
printf '%s\n' \
  '#!/bin/bash' \
  'set -e' \
  '' \
  'path_contains() {' \
  '  case ":${PATH}:" in' \
  '    *":$1:"*) return 0 ;;' \
  '    *) return 1 ;;' \
  '  esac' \
  '}' \
  '' \
  'default_install_dir() {' \
  '  if [ "$(uname -s)" = "Darwin" ] && { [ -d /opt/homebrew/bin ] || path_contains /opt/homebrew/bin; }; then' \
  "    printf '%s\\n' /opt/homebrew/bin" \
  '  else' \
  "    printf '%s\\n' /usr/local/bin" \
  '  fi' \
  '}' \
  '' \
  'INSTALL_DIR="${1:-$(default_install_dir)}"' \
  'install -d "${INSTALL_DIR}"' \
  'install -m 755 nvpn "${INSTALL_DIR}/"' \
  >"$archive_root/nvpn/install.sh"
chmod 0755 "$archive_root/nvpn/install.sh"
printf '%s\n' \
  'nvpn - FIPS private mesh CLI' \
  '============================' \
  '' \
  'Binary included:' \
  '  nvpn  - CLI control plane' \
  '' \
  'Quick install:' \
  '  ./install.sh' \
  '  ./install.sh ~/.local/bin' \
  >"$archive_root/nvpn/README.txt"
python3 - "$archive_root" "$SOURCE_DATE_EPOCH" <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
epoch = int(sys.argv[2])
for path in sorted(root.rglob("*"), reverse=True):
    os.utime(path, (epoch, epoch), follow_symlinks=False)
os.utime(root, (epoch, epoch), follow_symlinks=False)
PY
rm -f "$ARCHIVE" "$RECEIPT"
COPYFILE_DISABLE=1 tar --no-xattrs -cf "$TEMP_DIR/nvpn-$TARGET.tar" \
  -C "$archive_root" nvpn/README.txt nvpn/install.sh nvpn/nvpn
gzip -n "$TEMP_DIR/nvpn-$TARGET.tar"
mv "$TEMP_DIR/nvpn-$TARGET.tar.gz" "$ARCHIVE"

smoke_dir="$TEMP_DIR/smoke"
mkdir -p "$smoke_dir"
docker run --rm -i --pull never --platform linux/arm64 \
  --user "$(id -u):$(id -g)" \
  --entrypoint sh \
  -v "$OUTPUT_DIR:/gate:ro" \
  -v "$smoke_dir:/result" \
  "$SMOKE_IMAGE" -se -- "$TARGET" <<'SH'
target="$1"
case "$(uname -m)" in arm64|aarch64) ;; *) exit 20 ;; esac
mkdir -p /tmp/nvpn-arm64-smoke
tar -xzf "/gate/nvpn-$target.tar.gz" -C /tmp/nvpn-arm64-smoke
binary=/tmp/nvpn-arm64-smoke/nvpn/nvpn
"$binary" --version > /result/short-version.txt
"$binary" version --verbose > /result/verbose-version.txt
"$binary" service status --json --skip-binary-version \
  --config /tmp/nvpn-arm64-smoke/config.toml > /result/status.json
uname -m > /result/architecture.txt
sha256sum "/gate/nvpn-$target.tar.gz" | awk '{print $1}' \
  > /result/archive-sha256.txt
sha256sum "$binary" | awk '{print $1}' > /result/cli-sha256.txt
SH

short_version="$(<"$smoke_dir/short-version.txt")"
verbose_version="$(<"$smoke_dir/verbose-version.txt")"
native_arch="$(<"$smoke_dir/architecture.txt")"
native_archive_sha="$(<"$smoke_dir/archive-sha256.txt")"
native_cli_sha="$(<"$smoke_dir/cli-sha256.txt")"
archive_sha="$(shasum -a 256 "$ARCHIVE" | awk '{print tolower($1)}')"
cli_sha="$(shasum -a 256 "$binary" | awk '{print tolower($1)}')"
app_version="$(package_version "$ROOT")"
[[ "$short_version" == "nvpn $app_version" \
  && "$verbose_version" == "$app_version"$'\n'fips_core_version:* \
  && "$native_archive_sha" == "$archive_sha" \
  && "$native_cli_sha" == "$cli_sha" ]] || {
  echo "Linux ARM64 CLI native smoke differs from the exact archive" >&2
  exit 1
}
fips_version_line="${verbose_version##*fips_core_version: }"
fips_version="${fips_version_line%% *}"
[[ "$fips_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || {
  echo "Linux ARM64 CLI did not report its FIPS component version" >&2
  exit 1
}
[[ "$fips_version" == "${NVPN_EXPECTED_FIPS_VERSION:-$fips_version}"* ]] || {
  echo "Linux ARM64 CLI embedded the wrong FIPS component version" >&2
  exit 1
}

[[ "$app_head" == "$(git -C "$ROOT" rev-parse HEAD)" \
  && "$app_tree" == "$(git -C "$ROOT" rev-parse 'HEAD^{tree}')" \
  && -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" \
  && "$fips_head" == "$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse HEAD)" \
  && "$fips_tree" == "$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse 'HEAD^{tree}')" \
  && -z "$(git -C "$NVPN_FIPS_REPO_PATH" status --porcelain --untracked-files=all)" ]] || {
  echo "Linux ARM64 CLI source changed during build or native smoke" >&2
  exit 1
}

build_image_id="$(docker image inspect --format '{{.Id}}' "$BUILDER_IMAGE")"
python3 - \
  "$RECEIPT" "$app_head" "$app_tree" "$archive_sha" "$cli_sha" \
  "$(wc -c <"$ARCHIVE" | tr -d '[:space:]')" \
  "$(wc -c <"$binary" | tr -d '[:space:]')" \
  "$short_version" "$verbose_version" "$fips_version" "$native_arch" \
  "$(uname -s)" "$(uname -m)" "$build_image_id" <<'PY'
import json
import pathlib
import sys

(
    receipt, app_head, app_tree, archive_sha, cli_sha, archive_size,
    cli_size, short_version, verbose_version, fips_version, native_arch,
    build_host_os, build_host_arch, build_image_id,
) = sys.argv[1:]
payload = {
    "receiptSchema": 1,
    "artifactType": "exact native-smoked Linux ARM64 static CLI",
    "platform": "linux",
    "architecture": "aarch64",
    "target": "aarch64-unknown-linux-musl",
    "appGitSha": app_head,
    "appGitTree": app_tree,
    "sourceClean": True,
    "buildMethod": "repository Docker cross-build",
    "buildHostOs": build_host_os,
    "buildHostArchitecture": build_host_arch,
    "buildImageId": build_image_id,
    "archiveSha256": archive_sha,
    "archiveSize": int(archive_size),
    "cliSha256": cli_sha,
    "cliSize": int(cli_size),
    "shortVersion": short_version,
    "verboseVersion": verbose_version,
    "fipsVersion": fips_version,
    "nativeSmokeHostOs": "Linux",
    "nativeSmokeHostArchitecture": native_arch,
    "nativeArchitectureVerified": True,
    "nativeCliSmokePassed": True,
    "nativeStatusSmokePassed": True,
    "nativeSmokeArchiveSha256": archive_sha,
    "nativeSmokeCliSha256": cli_sha,
    "nativeNetworkSmokeSkipped": "CAP_NET_ADMIN unavailable",
    "smokePassed": True,
    "armv6Build": False,
}
pathlib.Path(receipt).write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

echo "Linux ARM64 CLI cross-build and native smoke passed: $RECEIPT"
