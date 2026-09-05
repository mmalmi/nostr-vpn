#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  if ! rg -q --fixed-strings "$pattern" "$ROOT/$file"; then
    printf 'manual join platform contract missing %s in %s\n' "$description" "$file" >&2
    exit 1
  fi
}

# Each app must expose both halves of the explicit out-of-band workflow: the joiner trusts
# an admin Device ID + Network ID, and the admin adds the joiner's Device ID.
require android/app/src/main/java/org/nostrvpn/app/core/AppCoreClient.kt 'manual_add_network' 'Android joiner action'
require android/app/src/main/java/org/nostrvpn/app/AndroidDevices.kt 'Admin Device ID' 'Android joiner fields'
require android/app/src/main/java/org/nostrvpn/app/AndroidDevices.kt 'Add by Device ID' 'Android admin action'

require ios/Sources/NativeCoreClient.swift 'manual_add_network' 'iOS joiner action'
require ios/Sources/DevicesViews.swift 'Admin Device ID' 'iOS joiner fields'
require ios/Sources/SettingsViews.swift 'Add by Device ID' 'iOS admin action'
require ios/Sources/AppModel.swift 'await vpnController.hasPendingJoinReceipts()' 'iOS receiver receipt drain before config restart'
require ios/Sources/PacketTunnelController.swift 'providerMessage("joinReceiptsPending")' 'iOS live receipt query'
require ios/PacketTunnel/PacketTunnelProvider.swift 'nostr_vpn_mobile_tunnel_has_pending_join_receipts(handle)' 'iOS native receipt queue query'
require ios/Bindings/NostrVpnAppCoreC.h 'nostr_vpn_mobile_tunnel_has_pending_join_receipts' 'iOS receipt query binding'

require macos/Sources/AppManagerSettings.swift '.manualAddNetwork' 'macOS joiner action'
require macos/Sources/RootViewDevices.swift 'Admin Device ID' 'macOS joiner fields'
require macos/Sources/RootViewDevices.swift 'Add by Device ID' 'macOS admin action'

require windows/NostrVpn.Windows/Core/NativeActions.cs 'manual_add_network' 'Windows joiner action'
require windows/NostrVpn.Windows/MainWindow.xaml 'Admin Device ID' 'Windows joiner fields'
require windows/NostrVpn.Windows/MainWindow.xaml 'Add by Device ID' 'Windows admin action'

require linux/src/main/share_page.rs 'NativeAppAction::ManualAddNetwork' 'Linux joiner action'
require linux/src/main/share_page.rs 'Admin Device ID' 'Linux joiner fields'
require linux/src/main/share_page.rs "Joiner's Device ID" 'Linux admin action'

require crates/nostr-vpn-web/src/main.rs '/api/manual_add_network' 'web joiner API'
require web/control-panel/src/App.svelte 'Admin Device ID' 'web joiner fields'
require web/control-panel/src/App.svelte 'Add by Device ID' 'web admin action'

require crates/nostr-vpn-cli/src/main/cli_args.rs 'JoinManual(ManualJoinArgs)' 'CLI joiner command'
require crates/nostr-vpn-cli/src/main/cli_args.rs 'AddDevice(UpdateRosterArgs)' 'CLI admin command'
require crates/nostr-vpn-cli/src/main/command_dispatch.rs 'println!("device_id={}", app.nostr.public_key);' 'CLI admin share value'

printf 'Manual join platform contract passed for Android, iOS, macOS, Windows, Linux, web, and CLI.\n'
