#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_DIR="$(cd "${NVPN_RELEASE_APP_REPO_PATH:-$ROOT_DIR}" && pwd)"
cd "$ROOT_DIR"

ensure_cargo_audit() {
  if cargo audit --version >/dev/null 2>&1; then
    return
  fi

  local version="${CARGO_AUDIT_VERSION:-0.22.1}"
  cargo install cargo-audit --version "$version" --locked
}

ensure_cargo_audit

# Temporary accepted upstream warnings:
# - RUSTSEC-2024-0384: `instant` is pulled by nostr 0.44.x; remove once fips/nostr
#   can move to the stable nostr line that replaces it.
# - RUSTSEC-2024-0436: `paste` is pulled by netlink-packet-core 0.8.1 via
#   netdev/rtnetlink; remove once rust-netlink ships a replacement.
# - RUSTSEC-2026-0002: `lru` 0.12 is pulled by hashtree-resolver/updater via
#   nostr-database 0.35; remove once hashtree can move to lru >= 0.16.3.
# - RUSTSEC-2026-0194 / RUSTSEC-2026-0195: `quick-xml` 0.39 is pulled by
#   plist 1.9 via netdev on Apple targets; remove once plist releases a
#   quick-xml >= 0.41 update or netdev removes that dependency path.
# - RUSTSEC-2026-0243: `nostr-relay-pool` 0.44 is now maintained inside
#   nostr-sdk; remove when the exact FIPS/nostr dependency line moves to 0.45.
# - RUSTSEC-2026-0253: `lru` 0.16 is required by the exact FIPS/nostr and QR
#   dependency lines. The reported unwind requires a panicking key Drop plus
#   catch_unwind; these paths use ordinary owned keys and do not recover across
#   their drop panics. Remove when both lines accept patched lru >= 0.18.2.
# - RUSTSEC-2026-0374: `basic-toml` 0.1.10 is an unmaintained build-time
#   dependency of Askama's derive macro through UniFFI 0.29.5. The hosted
#   release checks already accept this informational advisory; it is not the
#   VPN runtime TOML parser. Remove when UniFFI/Askama drops basic-toml.
audit_args=(
  --deny warnings
  --ignore RUSTSEC-2024-0384
  --ignore RUSTSEC-2024-0436
  --ignore RUSTSEC-2026-0002
  --ignore RUSTSEC-2026-0194
  --ignore RUSTSEC-2026-0195
  --ignore RUSTSEC-2026-0243
  --ignore RUSTSEC-2026-0253
  --ignore RUSTSEC-2026-0374
)

# This candidate was frozen before these advisories were published. Its runtime
# was reviewed against their prerequisites, not declared dependency-free:
# - RUSTSEC-2026-0459: bundled SQLite is affected when opening a less-trusted
#   database plus a crafted sibling WAL. NVPN opens application-owned stores.
#   wallet/database_backup.rs imports one database, not a WAL; persistence.rs
#   rejects a pre-existing wallet or any sidecar before a new restore. Generic
#   library callers must assess their own database-file trust boundary.
# - RUSTSEC-2026-0486: the affected rustix xattr getters/list functions are not
#   called by core, procfs or tempfile. The only xattr consumer is tar through
#   hashtree-updater, which reads/unpacks Archive, never builds an archive;
#   extraction defaults to no xattrs and its optional path only sets them.
# - RUSTSEC-2026-0441: pin-utils through nix 0.26.4 is unmaintained; this is an
#   informational advisory without a reported vulnerability.
# Do not carry these exceptions into another product revision. Upgrade SQLite
# and rustix and retire the pin-utils dependency before qualifying a successor.
frozen_candidate=52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4
if [[ "$(git rev-parse HEAD)" == "$frozen_candidate" ]] \
  && git diff --quiet "$frozen_candidate" -- .; then
  audit_args+=(
    --ignore RUSTSEC-2026-0459
    --ignore RUSTSEC-2026-0486
    --ignore RUSTSEC-2026-0441
  )
fi

cargo audit "${audit_args[@]}"
(cd linux && cargo audit "${audit_args[@]}")
