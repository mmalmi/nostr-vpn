set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

info:
    @echo "Nostr VPN commands"
    @echo
    @echo "Run"
    @echo "  just run"
    @echo "  just run-macos"
    @echo "  just run-linux"
    @echo "  just run-windows"
    @echo "  just run-android"
    @echo "  just run-ios"
    @echo
    @echo "Build"
    @echo "  just build"
    @echo "  just release"
    @echo "  just release-startos"
    @echo
    @echo "macOS"
    @echo "  just macos-gen-swift"
    @echo "  just macos-rust"
    @echo "  just macos-xcframework"
    @echo "  just macos-xcodeproj"
    @echo "  just macos-build"
    @echo
    @echo "Linux"
    @echo "  just linux-build"
    @echo
    @echo "Windows"
    @echo "  just windows-build"
    @echo
    @echo "Android"
    @echo "  just android-build"
    @echo "  just android-install"
    @echo "  just android-smoke"
    @echo "  just android-smoke-vpn"
    @echo
    @echo "iOS"
    @echo "  just ios-build"
    @echo "  just ios-run"
    @echo "  just ios-smoke"
    @echo "  just ios-screenshots"
    @echo "  just ios-smoke-device"
    @echo
    @echo "Checks"
    @echo "  just icons"
    @echo "  just test"
    @echo "  just mobile-test-kit"
    @echo "  just mobile-test-kit-rust"
    @echo "  just mobile-test-kit-sim"
    @echo "  just mobile-test-kit-device"
    @echo "  just mobile-test-kit-exit"
    @echo "  just check-source-file-lines"
    @echo "  just dataplane-safety-fast [suites...]"
    @echo "  just dataplane-host-pair-comparison-dry-run"
    @echo "  just dataplane-host-pair-comparison"
    @echo "  just release-gate"
    @echo "  just verify-fast"
    @echo "  just verify-health"
    @echo "  just verify-full"
    @echo "  just security-regressions"
    @echo "  just e2e"
    @echo "  just e2e-connect"
    @echo "  just e2e-active-network"
    @echo "  just e2e-umbrel-web"
    @echo "  just e2e-exit-node"
    @echo "  just e2e-paid-exit"
    @echo "  just e2e-paid-exit-automatic"
    @echo "  just e2e-paid-exit-token"
    @echo "  just e2e-fips-routed-udp"
    @echo "  just e2e-join-request"
    @echo "  just e2e-roster-admin"
    @echo "  just e2e-desktop-roster-join"
    @echo "  just e2e-device-roster"
    @echo "  just e2e-wireguard-exit"
    @echo "  just e2e-wireguard-exit-userspace"
    @echo "  just e2e-wireguard-exit-host"
    @echo "  just e2e-wireguard-exit-windows-vm"
    @echo "  just e2e-wireguard-direct-windows-vm"

run:
    @case "$(uname -s)" in \
        Darwin) just run-macos ;; \
        Linux) just run-linux ;; \
        MINGW*|MSYS*|CYGWIN*) just run-windows ;; \
        *) echo "No local run target for $(uname -s). Use just --list for available commands." >&2; exit 1 ;; \
    esac

run-macos:
    ./tools/run-macos

run-linux:
    ./tools/run-linux

run-windows:
    ./tools/run-windows

run-android:
    ./tools/run-android install

run-ios:
    ./tools/run-ios run

build:
    @case "$(uname -s)" in \
        Darwin) just macos-build ;; \
        Linux) just linux-build ;; \
        MINGW*|MSYS*|CYGWIN*) just windows-build ;; \
        *) cargo build -p nvpn -p nostr-vpn-reflector ;; \
    esac
    @./scripts/build-output-path

linux-build:
    ./tools/run-linux cargo build

linux-e2e-gui:
    ./tools/run-linux ./scripts/e2e-smoke.sh

e2e-desktop-roster-join:
    @case "$(uname -s)" in \
        Darwin) ./scripts/e2e-desktop-roster-join.sh ;; \
        Linux) ./tools/run-linux /workspace/nostr-vpn/scripts/e2e-desktop-roster-join.sh ;; \
        MINGW*|MSYS*|CYGWIN*) powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/e2e-desktop-roster-join.ps1 ;; \
        *) echo "No desktop roster e2e target for $(uname -s)." >&2; exit 1 ;; \
    esac

e2e-device-roster:
    ./scripts/e2e-device-roster.sh

windows-build:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/windows-build.ps1

android-build:
    ./tools/run-android build

android-install:
    ./tools/run-android install

android-smoke:
    ./scripts/mobile-android-smoke.sh

android-smoke-vpn:
    ./scripts/mobile-android-smoke.sh --vpn-cycle

ios-build:
    ./tools/run-ios build

ios-run:
    ./tools/run-ios run

ios-smoke:
    ./scripts/mobile-ios-smoke.sh simulator

ios-screenshots:
    ./scripts/ios-screenshots

ios-smoke-device:
    ./scripts/mobile-ios-smoke.sh device --vpn-cycle

mobile-test-kit:
    ./scripts/mobile-test-kit.sh fast

mobile-test-kit-rust:
    ./scripts/mobile-test-kit.sh rust

mobile-test-kit-sim:
    ./scripts/mobile-test-kit.sh simulator

mobile-test-kit-device:
    ./scripts/mobile-test-kit.sh device

mobile-test-kit-exit:
    ./scripts/mobile-test-kit.sh exit

macos-gen-swift:
    ./scripts/macos-build macos-gen-swift

macos-rust:
    ./scripts/macos-build macos-rust

macos-xcframework:
    ./scripts/macos-build macos-xcframework

macos-xcodeproj:
    ./scripts/macos-build macos-xcodeproj

macos-build:
    ./scripts/macos-build macos-build

icons:
    ./scripts/regen-app-icons

release:
    node scripts/local-release.mjs

release-startos:
    node scripts/startos-release.mjs

test:
    cargo test

check-source-file-lines:
    ./scripts/check-source-file-lines.sh

dataplane-safety-fast *suites:
    ./scripts/test-dataplane-safety-fast.sh {{suites}}

dataplane-host-pair-comparison-dry-run:
    NVPN_HOST_PAIR_COMPARISON_DRY_RUN=1 \
    NVPN_HOST_PAIR_COMPARISON_RUN_OUTPUT_DIR="${TMPDIR:-/tmp}/nvpn-host-pair-comparison-dry-run" \
    NVPN_HOST_PAIR_COMPARISON_SSH="${NVPN_HOST_PAIR_COMPARISON_SSH:-bench-host}" \
    NVPN_HOST_PAIR_COMPARISON_LOCAL_UNDERLAY_IP="${NVPN_HOST_PAIR_COMPARISON_LOCAL_UNDERLAY_IP:-192.0.2.10}" \
    NVPN_HOST_PAIR_COMPARISON_REMOTE_UNDERLAY_IP="${NVPN_HOST_PAIR_COMPARISON_REMOTE_UNDERLAY_IP:-192.0.2.20}" \
    NVPN_HOST_PAIR_COMPARISON_BACKENDS="${NVPN_HOST_PAIR_COMPARISON_BACKENDS:-boringtun,wireguard-go}" \
    NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES="${NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES:-clean,stress}" \
    NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_SIDES="${NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_SIDES:-both}" \
    NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_WORKERS="${NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_WORKERS:-auto}" \
    ./scripts/run-host-pair-comparison.sh

dataplane-host-pair-comparison:
    NVPN_HOST_PAIR_COMPARISON_BACKENDS="${NVPN_HOST_PAIR_COMPARISON_BACKENDS:-boringtun,wireguard-go}" \
    NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES="${NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES:-clean,stress}" \
    NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_SIDES="${NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_SIDES:-both}" \
    NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_WORKERS="${NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_WORKERS:-auto}" \
    ./scripts/run-host-pair-comparison.sh

release-gate:
    ./scripts/release-gate.sh

release-tooling-contracts:
    ./scripts/test-release-tooling-contracts.sh

verify-fast:
    ./scripts/verify.sh fast

verify-health:
    ./scripts/verify.sh health

verify-full:
    ./scripts/verify.sh full

security-regressions:
    cargo test -p nvpn platform_routing
    cargo test -p nostr-vpn-app-core mobile_config
    ./scripts/e2e-wireguard-exit-docker.sh

e2e:
    ./scripts/e2e-docker.sh

e2e-connect:
    ./scripts/e2e-connect-docker.sh

e2e-active-network:
    ./scripts/e2e-active-network-docker.sh

e2e-umbrel-web:
    ./scripts/e2e-umbrel-web-docker.sh

e2e-divergent-roster:
    ./scripts/e2e-divergent-roster-docker.sh

e2e-exit-node:
    ./scripts/e2e-exit-node-docker.sh

e2e-paid-exit:
    ./scripts/e2e-paid-exit-docker.sh

e2e-paid-exit-automatic:
    ./scripts/e2e-paid-exit-automatic-docker.sh

e2e-paid-exit-token:
    ./scripts/e2e-paid-exit-token-docker.sh

e2e-fips-routed-udp:
    ./scripts/e2e-fips-routed-udp-docker.sh

e2e-join-request:
    cargo test -p nostr-vpn-app-core websocket_seed_router_routes_new_recipient_without_preconverged_roster_peer

e2e-roster-admin:
    ./scripts/e2e-roster-admin-docker.sh

e2e-wireguard-exit:
    ./scripts/e2e-wireguard-exit-docker.sh

e2e-wireguard-exit-userspace:
    ./scripts/e2e-wireguard-exit-userspace-docker.sh

e2e-wireguard-exit-host:
    ./scripts/e2e-wireguard-exit-host.sh

e2e-wireguard-exit-windows-vm:
    ./scripts/windows-vm-wireguard-exit-e2e.sh

# Requires NVPN_WINDOWS_WG_EXIT_CONFIG_FILE and a disposable elevated Windows VM.
e2e-wireguard-direct-windows-vm:
    NVPN_WINDOWS_REQUIRE_WG_DIRECT_E2E=1 ./scripts/windows-vm-wireguard-exit-e2e.sh
