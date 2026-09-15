#!/bin/bash
# Publish Nostr VPN crates to crates.io in dependency order.
#
# Usage:
#   ./scripts/publish.sh           # Publish all publishable crates
#   ./scripts/publish.sh --dry-run # Build every distributable package without publishing
#   ./scripts/publish.sh --plan    # Print publish order

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/release_common.sh"

# Package verification needs neither debug symbols nor incremental build caches.
export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

DRY_RUN=""
PLAN_ONLY=0
PREFLIGHT_ONLY=0
WAIT_TIME="${CARGO_PUBLISH_WAIT_SECS:-30}"
FAILED_CRATES=()

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN="--dry-run"
            ;;
        --plan)
            PLAN_ONLY=1
            ;;
        --preflight)
            PREFLIGHT_ONLY=1
            ;;
        --no-allow-dirty)
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

DEPENDENCY_CRATES=("nvpn-cdk-spilman" "nvpn-cashu-service")

TIER_1_CRATES=(
    "nostr-vpn-core"
    "nostr-vpn-wintun"
)

TIER_2_CRATES=(
    "nvpn"
)

ALL_CRATES=(
    "${DEPENDENCY_CRATES[@]}"
    "${TIER_1_CRATES[@]}"
    "${TIER_2_CRATES[@]}"
)

exact_stage_value() {
    local field="$1"
    python3 - "$NVPN_RELEASE_STAGE_DIR/release.json" "$field" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
if not isinstance(value, str) or not value:
    raise SystemExit(f"invalid staged source field: {sys.argv[2]}")
print(value)
PY
}

verify_exact_release_source() {
    local actual_head actual_tree actual_tag
    [[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || {
        echo "Crates publication refuses a dirty release checkout." >&2
        return 1
    }
    actual_head="$(git rev-parse HEAD)"
    actual_tree="$(git rev-parse 'HEAD^{tree}')"
    actual_tag="$(git rev-parse -q --verify "${EXPECTED_TAG}^{commit}")"
    [[ "$actual_head" == "$EXPECTED_COMMIT" \
        && "$actual_tree" == "$EXPECTED_TREE" \
        && "$actual_tag" == "$EXPECTED_COMMIT" ]] || {
        echo "Crates publication source/tag differs from exact staging." >&2
        return 1
    }
}

bind_package_digest() {
    local crate="$1"
    local package_path receipt_path
    verify_exact_release_source
    package_path="$(
        cargo metadata --locked --no-deps --format-version 1 \
            | NVPN_CARGO_RECEIPT_CRATE="$crate" python3 -c '
import json
import os
import sys

crate = os.environ["NVPN_CARGO_RECEIPT_CRATE"]
metadata = json.load(sys.stdin)
package = next(value for value in metadata["packages"] if value["name"] == crate)
print(os.path.join(
    metadata["target_directory"],
    "package",
    "{}-{}.crate".format(crate, package["version"]),
))
'
    )"
    [[ -f "$package_path" && ! -L "$package_path" ]] || {
        echo "Cargo package output is missing for ${crate}: ${package_path}" >&2
        return 1
    }
    mkdir -p "$PACKAGE_RECEIPT_DIR"
    chmod 700 "$PACKAGE_RECEIPT_DIR"
    receipt_path="$PACKAGE_RECEIPT_DIR/${crate}.json"
    python3 - \
        "$NVPN_RELEASE_STAGE_DIR/release.json" \
        "$crate" \
        "$package_path" \
        "$receipt_path" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
import time

release = json.load(open(sys.argv[1], encoding="utf-8"))
crate = sys.argv[2]
package = pathlib.Path(sys.argv[3]).resolve(strict=True)
output = pathlib.Path(sys.argv[4])
payload = package.read_bytes()
receipt = {
    "schema": 1,
    "kind": "nvpn-cargo-package-publication-v1",
    "createdAt": int(time.time()),
    "crate": crate,
    "appGitSha": release["commit"],
    "appGitTree": release["release_gate_attestation"]["app_git_tree"],
    "releaseTag": release["tag"],
    "packageSha256": hashlib.sha256(payload).hexdigest(),
    "packageSize": len(payload),
}
if output.is_file():
    previous = json.loads(output.read_text())
    same_source = all(
        previous.get(field) == receipt[field]
        for field in ("crate", "appGitSha", "appGitTree", "releaseTag")
    )
    if same_source and previous.get("packageSha256") != receipt["packageSha256"]:
        raise SystemExit(
            f"crate package bytes changed after exact preflight: {crate}"
        )
output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
output.chmod(0o600)
PY
}

verify_published_crate() {
    local crate="$1"
    local version expected downloaded actual
    version="$(
        cargo metadata --locked --no-deps --format-version 1 \
            | NVPN_CARGO_RECEIPT_CRATE="$crate" python3 -c '
import json
import os
import sys

crate = os.environ["NVPN_CARGO_RECEIPT_CRATE"]
metadata = json.load(sys.stdin)
print(next(value["version"] for value in metadata["packages"] if value["name"] == crate))
'
    )"
    expected="$(
        python3 -c '
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))["packageSha256"])
' "$PACKAGE_RECEIPT_DIR/${crate}.json"
    )"
    downloaded="$(mktemp "${TMPDIR:-/tmp}/nvpn-crate.XXXXXX")"
    for _ in {1..20}; do
        if curl -fsSL \
            "https://static.crates.io/crates/${crate}/${crate}-${version}.crate" \
            -o "$downloaded"
        then
            actual="$(shasum -a 256 "$downloaded" | awk '{print tolower($1)}')"
            if [[ "$actual" == "$expected" ]]; then
                rm -f "$downloaded"
                echo "[ok] ${crate} ${version} registry package matches exact staged bytes"
                return 0
            fi
            rm -f "$downloaded"
            echo "Published ${crate} ${version} differs from the exact package digest." >&2
            return 1
        fi
        sleep 3
    done
    rm -f "$downloaded"
    echo "Could not verify published ${crate} ${version} package bytes." >&2
    return 1
}

preflight_crates_io_credentials() {
    local crate

    # crates.io no longer exposes an API-token identity lookup. Cargo's
    # read-only owner query is the supported way to resolve the configured
    # credential provider without uploading. The owners response is public, so
    # the first cargo publish remains the server-side permission check. Query
    # every crate in the plan before packaging.
    for crate in "${ALL_CRATES[@]}"; do
        if ! cargo owner --list --registry crates-io "$crate" >/dev/null; then
            echo "Cargo could not resolve crates.io credentials for ${crate}." >&2
            return 1
        fi
        echo "[ok] Cargo credential provider is ready for ${crate}"
    done
}

publish_crate() {
    local crate="$1"
    local output

    echo ""
    echo "=========================================="
    echo "Publishing: ${crate}"
    echo "=========================================="

    if [[ -z "$DRY_RUN" ]]; then
        verify_exact_release_source
    fi
    if output=$(cargo publish --locked -p "$crate" $DRY_RUN 2>&1); then
        echo "$output"
        echo "[ok] ${crate} published successfully"
    elif echo "$output" | grep -q "already exists"; then
        echo "[ok] ${crate} already published at this version (skipping)"
    else
        echo "$output"
        echo "[fail] Failed to publish ${crate} (continuing...)"
        return 1
    fi
    if [[ -z "$DRY_RUN" ]]; then
        verify_published_crate "$crate"
    fi

    return 0
}

prepare_payment_dependencies() {
    local crate version manifest package_dir archive code files pending=()
    for crate in ${DEPENDENCY_CRATES[@]+"${DEPENDENCY_CRATES[@]}"}; do
        # Keep unchanged dependency versions on crates.io. Repackaging them at
        # every app commit changes Cargo's VCS metadata and archive checksum.
        read -r version manifest < <(
            cargo metadata --locked --no-deps --format-version 1 | python3 -c '
import json,sys
p = next(p for p in json.load(sys.stdin)["packages"] if p["name"] == sys.argv[1])
print(p["version"], p["manifest_path"])
' "$crate"
        )
        package_dir="$(dirname "$manifest")"
        archive="$(mktemp "${TMPDIR:-/tmp}/nvpn-dependency.XXXXXX")"
        if ! code="$(curl -sSL --connect-timeout 15 --max-time 60 -w '%{http_code}' \
            "https://static.crates.io/crates/${crate}/${crate}-${version}.crate" -o "$archive")"; then
            rm -f "$archive"
            return 1
        fi
        case "$code" in
            200)
                if ! files="$(cargo package --locked -p "$crate" --list)" \
                    || ! python3 "$SCRIPT_DIR/verify-cargo-registry-dependency.py" \
                        "$crate" "$version" "$package_dir" "$archive" <<<"$files"; then
                    rm -f "$archive"
                    return 1
                fi
                ;;
            403|404) pending+=("$crate") ;;
            *)
                rm -f "$archive"
                echo "Cannot check registry dependency ${crate}: HTTP ${code}" >&2
                return 1
                ;;
        esac
        rm -f "$archive"
    done
    DEPENDENCY_CRATES=(${pending[@]+"${pending[@]}"})
    # Selected new workspace packages are verified together. Unchanged
    # dependencies resolve from their actual registry archives and checksums.
    ALL_CRATES=(${DEPENDENCY_CRATES[@]+"${DEPENDENCY_CRATES[@]}"} "${TIER_1_CRATES[@]}" "${TIER_2_CRATES[@]}")
}

verify_cargo_packages() {
    local package_args=() crate
    for crate in "${ALL_CRATES[@]}"; do
        package_args+=(--package "$crate")
    done
    # Cargo packages the selected workspace dependencies into a temporary
    # registry and builds their actual archives in dependency order. Unlike a
    # local cargo check, this catches patches missing from the registry before
    # publishing any dependency or starting native/device release checks.
    cargo package --locked "${package_args[@]}"
}

publish_tier() {
    local tier_name="$1"
    shift

    local crates=("$@")
    local log_dir
    log_dir="$(mktemp -d "${TMPDIR:-/tmp}/nostr-vpn-publish.XXXXXX")"
    local pids=()
    local crate

    echo ""
    echo "=== ${tier_name}: ${crates[*]} ==="

    for crate in "${crates[@]}"; do
        publish_crate "$crate" >"${log_dir}/${crate}.log" 2>&1 &
        pids+=("$!")
    done

    local published=0
    local status=0
    local i
    for i in "${!pids[@]}"; do
        crate="${crates[$i]}"
        if ! wait "${pids[$i]}"; then
            FAILED_CRATES+=("$crate")
            status=1
        fi

        cat "${log_dir}/${crate}.log"
        if grep -q "published successfully" "${log_dir}/${crate}.log"; then
            published=1
        fi
    done

    rm -rf "$log_dir"

    if [[ "$status" -eq 0 && "$published" -eq 1 && -z "$DRY_RUN" ]]; then
        echo ""
        echo "Waiting ${WAIT_TIME}s for crates.io to index this tier..."
        sleep "$WAIT_TIME"
    fi

    return 0
}

if [[ "$PLAN_ONLY" -eq 1 ]]; then
    printf '%s\n' "${ALL_CRATES[@]}"
    exit 0
fi

if [[ -n "$DRY_RUN" ]]; then
    echo "=== DRY RUN MODE ==="
fi

echo "Publishing Nostr VPN crates to crates.io"
cd "$REPO_DIR"
if [[ -z "$DRY_RUN" ]]; then
    require_release_mutation_gate "$REPO_DIR"
    EXPECTED_COMMIT="$(exact_stage_value commit)"
    EXPECTED_TREE="$(exact_stage_value release_gate_attestation.app_git_tree)"
    EXPECTED_TAG="$(exact_stage_value tag)"
    PACKAGE_RECEIPT_DIR="${NVPN_CARGO_PACKAGE_RECEIPT_DIR:-$REPO_DIR/artifacts/release-publication/cargo}"
    export EXPECTED_COMMIT EXPECTED_TREE EXPECTED_TAG PACKAGE_RECEIPT_DIR
    verify_exact_release_source
fi

prepare_payment_dependencies

if [[ "$PREFLIGHT_ONLY" -eq 1 ]]; then
    [[ -z "$DRY_RUN" ]] || {
        echo "--preflight and --dry-run cannot be combined." >&2
        exit 1
    }
    preflight_crates_io_credentials
fi

verify_cargo_packages
if [[ -z "$DRY_RUN" ]]; then
    verify_exact_release_source
    for crate in "${ALL_CRATES[@]}"; do
        bind_package_digest "$crate"
    done
fi
if [[ "$PREFLIGHT_ONLY" -eq 1 || -n "$DRY_RUN" ]]; then
    echo "[ok] Every distributable Cargo package built successfully."
    exit 0
fi

# The maintained payment dependencies must exist before the application crates.
for crate in ${DEPENDENCY_CRATES[@]+"${DEPENDENCY_CRATES[@]}"}; do
    publish_tier "Dependency" "$crate"
    [[ ${#FAILED_CRATES[@]} -eq 0 ]] || exit 1
done
publish_tier "Tier 1" "${TIER_1_CRATES[@]}"
[[ ${#FAILED_CRATES[@]} -eq 0 ]] || exit 1
publish_tier "Tier 2" "${TIER_2_CRATES[@]}"

if [[ ${#FAILED_CRATES[@]} -eq 0 ]]; then
    echo "[ok] All crates published successfully!"
else
    echo "[fail] Failed to publish: ${FAILED_CRATES[*]}"
    exit 1
fi
