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

cargo audit "${audit_args[@]}"
(cd linux && cargo audit "${audit_args[@]}")
