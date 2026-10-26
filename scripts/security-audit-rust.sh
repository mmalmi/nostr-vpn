#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

ensure_cargo_audit() {
  if cargo audit --version >/dev/null 2>&1; then
    return
  fi

  local version="${CARGO_AUDIT_VERSION:-0.22.1}"
  cargo install cargo-audit --version "$version" --locked
}

ensure_cargo_audit

# Temporary 4.1.19 native-only Zstd applicability review. The guard pins both
# lockfiles, registry sources, features and consumers; changed scope fails closed.
# HTTP decompression is reachable, but these specific vulnerable paths are not:
# - 0391: compression-codecs owns a fresh decoder, never borrowed with_context.
# - 0395/0399/0402/0404: experimental APIs disabled.
# - 0396/0398/0405: seekable disabled; 0401: zdict_builder disabled.
# - 0397: around_pos receives exactly the initialized written_len, never capacity.
# - 0400: decoder streams and resets between members; no mixed bulk operations.
# - 0403: bundled C library built without legacy support; no system-library override.
# - 0406: no zstdmt and tower exposes only decompression; 0410: native, not wasm32.
# Review: https://github.com/RustSec/advisory-db/tree/main/crates/zstd-safe
# Retained release artifacts additionally require bundled-library provenance.
# Remove this exception when the dependency chain accepts the patched versions.
mkdir -p artifacts/security-audit
python3 scripts/release-gate-zstd-audit-scope.py > artifacts/security-audit/zstd-scope.json

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
  --ignore RUSTSEC-2026-0391
  --ignore RUSTSEC-2026-0395
  --ignore RUSTSEC-2026-0396
  --ignore RUSTSEC-2026-0397
  --ignore RUSTSEC-2026-0398
  --ignore RUSTSEC-2026-0399
  --ignore RUSTSEC-2026-0400
  --ignore RUSTSEC-2026-0401
  --ignore RUSTSEC-2026-0402
  --ignore RUSTSEC-2026-0403
  --ignore RUSTSEC-2026-0404
  --ignore RUSTSEC-2026-0405
  --ignore RUSTSEC-2026-0406
  --ignore RUSTSEC-2026-0410
)

cargo audit "${audit_args[@]}"
(cd linux && cargo audit "${audit_args[@]}")
