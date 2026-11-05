#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Python 3.11+ supports descriptor-relative cleanup, as on the release-test VM.
IMAGE="${NVPN_LINUX_SERVICE_CLEANUP_TEST_IMAGE:-python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f}"

docker run --rm -i --cpus 1 --memory 256m --memory-swap 256m --pids-limit 64 \
  -v "$ROOT:/workspace:ro" \
  "$IMAGE" bash -s <<'SH'
set -euo pipefail

artifact_root=/tmp/nvpn-linux-vm-release.fixture/mobile-join
receipt=/tmp/nvpn-linux-vm-release.fixture/receipt.json
package_receipt=/tmp/nvpn-linux-vm-release.fixture/debian-package-install.json
service_binary=/usr/local/bin/nvpn
service_unit=/etc/systemd/system/nvpn.service
config=/root/.config/nvpn/config.toml
cashu_dir=/root/.config/nvpn/cashu
daemon_log=/root/.config/nvpn/daemon.log
mkdir -p "$artifact_root" "$(dirname "$config")" /usr/local/test-bin
printf '#!/usr/bin/env bash\nexit 0\n' >/usr/bin/nostr-vpn
printf '#!/usr/bin/env bash\nif [[ "$*" == *"service uninstall"* ]]; then\n  if [[ -e /tmp/nvpn-uninstall-fail-once ]]; then rm -f /tmp/nvpn-uninstall-fail-once; exit 1; fi\n  rm -f /etc/systemd/system/nvpn.service\nfi\n' >/usr/bin/nvpn
chmod +x /usr/bin/nostr-vpn /usr/bin/nvpn
cli_hash="$(sha256sum /usr/bin/nvpn | awk '{ print $1 }')"
printf '{"artifacts":{"cli":{"sha256":"%s"}}}\n' "$cli_hash" >"$receipt"
printf '{}\n' >"$package_receipt"
printf 'profile\n' >"$config"
printf '#!/usr/bin/env bash\nshift\nexec "$@"\n' >/usr/local/test-bin/sudo
printf '#!/usr/bin/env bash\n[[ "$1" == -er && "$2" == .artifacts.cli.sha256 ]] || exit 2\nsed -n '\''s/.*"sha256":"\\([0-9a-f]*\\)".*/\\1/p'\'' "$3"\n' \
  >/usr/local/test-bin/jq
printf '#!/usr/bin/env bash\nif [[ "${1:-}" == is-active ]]; then exit 3; fi\nexit 0\n' >/usr/local/test-bin/systemctl
chmod +x /usr/local/test-bin/jq /usr/local/test-bin/sudo /usr/local/test-bin/systemctl
export PATH="/usr/local/test-bin:$PATH"

write_candidate_unit() {
  printf '[Service]\nExecStart="%s" daemon --service --config "%s" --iface "nvpn0"\n' \
    "$service_binary" "$config" >"$service_unit"
}
run_cleanup() {
  /workspace/scripts/linux-release-mobile-join-remote.sh Cleanup \
    "$artifact_root" /usr/bin/nostr-vpn /usr/bin/nvpn \
    "$receipt" "$package_receipt" 1
}

mkdir -p "$(dirname "$daemon_log")"
printf 'preserved diagnostic\n' >"$daemon_log"
[[ "$(/workspace/scripts/linux-release-mobile-join-remote.sh ReadDaemonLog \
  "$artifact_root" /usr/bin/nostr-vpn /usr/bin/nvpn \
  "$receipt" "$package_receipt")" == "preserved diagnostic" ]]

# A unit written before the binary copy completed is still exactly attributable
# to this already-armed candidate attempt and must be removable.
if run_cleanup; then
  echo "candidate cleanup removed a profile without gate ownership" >&2
  exit 1
fi
grep -Fxq profile "$config"
rm -rf "${config%/config.toml}"
python3 /workspace/scripts/linux_release_profile.py reset \
  "${config%/config.toml}" "$artifact_root/canonical-profile.json"
write_candidate_unit
run_cleanup
[[ ! -e "$service_unit" && ! -e "$service_binary" ]]

# Cleanup is idempotent when an interrupted install left nothing behind.
run_cleanup

# The root daemon writes the release-test Cashu wallet below the dedicated
# desktop profile. Cleanup must remove that root-owned state so the next
# public-UI Reset starts from the same empty profile.
# The preceding cleanup removed the owned directory. Start the next independent
# fixture with fresh ownership, just as a new artifact directory would do.
rm -rf "${config%/config.toml}"
rm "$artifact_root/canonical-profile.json"
python3 /workspace/scripts/linux_release_profile.py reset \
  "${config%/config.toml}" "$artifact_root/canonical-profile.json"
mkdir -p "$cashu_dir"
printf 'wallet\n' >"$cashu_dir/wallet.sqlite"
run_cleanup
[[ ! -e "$cashu_dir" ]]

# A failed uninstall propagates, preserves exact bytes, and a later EXIT-trap
# retry can remove those same candidate-owned bytes.
cp /usr/bin/nvpn "$service_binary"
write_candidate_unit
touch /tmp/nvpn-uninstall-fail-once
if run_cleanup; then
  echo "candidate cleanup hid an uninstall failure" >&2
  exit 1
fi
[[ -f "$service_binary" && -f "$service_unit" ]]
run_cleanup
[[ ! -e "$service_unit" && ! -e "$service_binary" ]]

# Fail closed instead of deleting a foreign binary at the shared service path.
printf 'foreign\n' >"$service_binary"
write_candidate_unit
if run_cleanup; then
  echo "candidate cleanup removed a mismatched service binary" >&2
  exit 1
fi
grep -Fxq foreign "$service_binary"
SH

echo LINUX_RELEASE_MOBILE_JOIN_SERVICE_CLEANUP_HARNESS_OK
