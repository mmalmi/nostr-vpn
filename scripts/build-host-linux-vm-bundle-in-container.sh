#!/usr/bin/env bash
# Canonical payload executed by both host-Docker and remote-native Linux
# release builders. The caller supplies only exact source/output mounts and
# the source-bound environment validated by prepare-host-linux-vm-bundle.sh.
set -euo pipefail

[[ "$#" == 1 && ( "$1" == "realize" || "$1" == "build" ) ]] || {
  echo "usage: $0 realize|build" >&2
  exit 2
}
PHASE="$1"
cd /workspace/app
fips_config=(
  --config 'patch.crates-io.nvpn-fips-core.path="/workspace/fips/crates/fips-core"'
  --config 'patch.crates-io.nvpn-fips-endpoint.path="/workspace/fips/crates/fips-endpoint"'
  --config 'patch.crates-io.nvpn-fips-identity.path="/workspace/fips/crates/fips-identity"'
)
lock_verifier=/workspace/app/scripts/verify-cargo-path-patch-lock.py
cargo_cache_verifier=/workspace/app/scripts/host_linux_cargo_archive_cache.py
fips_packages=()
while IFS= read -r package; do
  fips_packages+=("$package")
done < <(python3 "$lock_verifier" --manifest-specs /workspace/fips)
[[ "${#fips_packages[@]}" == 3 ]]

export CARGO_TARGET_DIR=/target-root
[[ "$CARGO_HOME" == /cargo-home && "$HOME" == /cargo-home ]]
for variable in \
  CARGO_BUILD_RUSTC_WRAPPER \
  CARGO_ENCODED_RUSTFLAGS \
  RUSTC_WRAPPER \
  RUSTC_WORKSPACE_WRAPPER \
  RUSTFLAGS
do
  [[ -z "${!variable:-}" ]] || {
    echo "Linux release builder refuses an injected compiler environment" >&2
    exit 2
  }
done
if find /workspace/app /workspace/fips \
  \( -path '*/.cargo/config' -o -path '*/.cargo/config.toml' \) \
  -print -quit | grep -q .
then
  echo "Linux release builder refuses source-local Cargo configuration" >&2
  exit 2
fi

if [[ "$PHASE" == "realize" ]]; then
  cp Cargo.lock /output/root-Cargo.lock.committed
  cargo "${fips_config[@]}" metadata --format-version 1 >/dev/null
  python3 "$lock_verifier" \
    --validate /output/root-Cargo.lock.committed Cargo.lock \
    "${fips_packages[@]}" \
    > /output/root-realized-cargo-lock-sha256.txt
  grep -Fx "$EXPECTED_ROOT_REALIZED_CARGO_LOCK_SHA256" \
    /output/root-realized-cargo-lock-sha256.txt
  cargo "${fips_config[@]}" fetch --locked

  cd /workspace/app/linux
  cp Cargo.lock /output/linux-Cargo.lock.committed
  cargo "${fips_config[@]}" metadata --format-version 1 >/dev/null
  python3 "$lock_verifier" \
    --validate /output/linux-Cargo.lock.committed Cargo.lock \
    "${fips_packages[@]}" \
    > /output/linux-realized-cargo-lock-sha256.txt
  grep -Fx "$EXPECTED_LINUX_REALIZED_CARGO_LOCK_SHA256" \
    /output/linux-realized-cargo-lock-sha256.txt
  cargo "${fips_config[@]}" fetch --locked
  python3 "$cargo_cache_verifier" audit \
    /cargo-download-cache /cargo-home \
    /workspace/app/Cargo.lock /workspace/app/linux/Cargo.lock
  exit 0
fi

[[ "$(sha256sum /workspace/app/Cargo.lock | awk '{print $1}')" \
  == "$EXPECTED_ROOT_REALIZED_CARGO_LOCK_SHA256" ]]
[[ "$(sha256sum /workspace/app/linux/Cargo.lock | awk '{print $1}')" \
  == "$EXPECTED_LINUX_REALIZED_CARGO_LOCK_SHA256" ]]
python3 "$cargo_cache_verifier" audit \
  /cargo-download-cache /cargo-home \
  /workspace/app/Cargo.lock /workspace/app/linux/Cargo.lock
export CARGO_NET_OFFLINE=true

cd /workspace/app
cargo "${fips_config[@]}" build --frozen --release -p nvpn
cargo "${fips_config[@]}" build --frozen --release \
  --target x86_64-unknown-linux-musl \
  -p nvpn
cargo "${fips_config[@]}" build --frozen --release \
  -p nostr-vpn-core --example desktop_manual_join_e2e_fixture

cd /workspace/app/linux
cargo "${fips_config[@]}" build --frozen --release

install -m 0555 /target-root/release/nvpn /output/nvpn
install -m 0555 \
  /target-root/release/examples/desktop_manual_join_e2e_fixture \
  /output/desktop_manual_join_e2e_fixture
install -m 0555 /target-root/release/nostr-vpn /output/nostr-vpn
install -m 0555 \
  /target-root/x86_64-unknown-linux-musl/release/nvpn \
  /output/nvpn-x86_64-unknown-linux-musl
file \
  /output/nvpn \
  /output/desktop_manual_join_e2e_fixture \
  /output/nostr-vpn \
  /output/nvpn-x86_64-unknown-linux-musl \
  > /output/file.txt
for artifact in \
  nvpn \
  desktop_manual_join_e2e_fixture \
  nostr-vpn \
  nvpn-x86_64-unknown-linux-musl
do
  grep -F "$artifact" /output/file.txt | grep -Eq 'ELF 64-bit.*x86-64'
done
grep -F 'nvpn-x86_64-unknown-linux-musl' /output/file.txt \
  | grep -Eq 'statically linked|static-pie linked'
/output/nvpn --version > /output/cli-short-version.txt
/output/nvpn version --verbose > /output/cli-verbose-version.txt
/output/nvpn-x86_64-unknown-linux-musl --version \
  > /output/musl-cli-short-version.txt
/output/nvpn-x86_64-unknown-linux-musl version --verbose \
  > /output/musl-cli-verbose-version.txt

# Package the already-built, exact glibc binaries. cargo-deb's default strip
# step would create different payload bytes, so it is explicitly disabled.
mkdir -p /workspace/app/target/release /workspace/app/linux/target/release
install -m 0555 /output/nvpn /workspace/app/target/release/nvpn
install -m 0555 /output/nostr-vpn \
  /workspace/app/linux/target/release/nostr-vpn
cd /workspace/app/linux
unset CARGO_TARGET_DIR
rm -rf target/debian
# cargo-deb invokes Cargo metadata internally and cannot receive Cargo's
# command-line --config values. Create its one exact, fresh packaging-only
# config after compilation, with no persistent or executable config surface.
python3 - /cargo-home/config.toml <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
content = (
    '[patch.crates-io]\n'
    'nvpn-fips-core = { path = "/workspace/fips/crates/fips-core" }\n'
    'nvpn-fips-endpoint = { path = "/workspace/fips/crates/fips-endpoint" }\n'
    'nvpn-fips-identity = { path = "/workspace/fips/crates/fips-identity" }\n'
).encode()
descriptor = os.open(
    path,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
    0o400,
)
with os.fdopen(descriptor, "wb") as output:
    output.write(content)
    output.flush()
    os.fsync(output.fileno())
PY
cargo deb --frozen --offline --no-build --no-strip
python3 - /cargo-home/config.toml <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.is_file() or path.is_symlink():
    raise SystemExit("packaging-only Cargo config changed")
path.unlink()
PY
python3 "$cargo_cache_verifier" audit \
  /cargo-download-cache /cargo-home \
  /workspace/app/Cargo.lock /workspace/app/linux/Cargo.lock
deb="$(find target/debian -maxdepth 1 -type f -name '*.deb' -print)"
[[ "$(printf '%s\n' "$deb" | sed '/^$/d' | wc -l)" == "1" ]]
install -m 0444 "$deb" /output/nostr-vpn.deb
rm -rf /output/deb-root
mkdir -p /output/deb-root
dpkg-deb -x /output/nostr-vpn.deb /output/deb-root
cmp -s /output/deb-root/usr/bin/nostr-vpn /output/nostr-vpn
cmp -s /output/deb-root/usr/bin/nvpn /output/nvpn
[[ "$(dpkg-deb -f /output/nostr-vpn.deb Package)" == "nostr-vpn" ]]
[[ "$(dpkg-deb -f /output/nostr-vpn.deb Architecture)" == "amd64" ]]
dpkg-deb -f /output/nostr-vpn.deb Version > /output/deb-version.txt

archive_root=/output/archive-root
rm -rf "$archive_root"
mkdir -p "$archive_root/nvpn"
install -m 0555 /output/nvpn-x86_64-unknown-linux-musl \
  "$archive_root/nvpn/nvpn"
printf '%s\n' \
  '#!/bin/bash' \
  'set -e' \
  'install -d "${1:-/usr/local/bin}"' \
  'install -m 755 nvpn "${1:-/usr/local/bin}/"' \
  >"$archive_root/nvpn/install.sh"
chmod 0555 "$archive_root/nvpn/install.sh"
printf '%s\n' 'nvpn - FIPS private mesh CLI' \
  >"$archive_root/nvpn/README.txt"
find "$archive_root" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
tar \
  --sort=name \
  --format=ustar \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --mtime="@${SOURCE_DATE_EPOCH}" \
  -cf /output/nvpn-x86_64-unknown-linux-musl.tar \
  -C "$archive_root" \
  nvpn/README.txt nvpn/install.sh nvpn/nvpn
gzip -n -f /output/nvpn-x86_64-unknown-linux-musl.tar
tar -xOf /output/nvpn-x86_64-unknown-linux-musl.tar.gz nvpn/nvpn \
  | cmp -s - /output/nvpn-x86_64-unknown-linux-musl
rm -rf "$archive_root" /output/deb-root
rustc --version > /output/rustc-version.txt
cargo --version > /output/cargo-version.txt
