import SwiftUI

struct DiagnosticsCard: View {
    let state: AppState

    var body: some View {
        AppCard {
            Text("Diagnostics")
                .font(.headline)
            Metric("Runtime", state.runtimeStatusDetail.isEmpty ? state.platform : state.runtimeStatusDetail)
            Metric("Peers", "\(state.connectedPeerCount)/\(state.expectedPeerCount)")
                .accessibilityIdentifier("diagnostics-peers")
                .accessibilityValue("\(state.connectedPeerCount)/\(state.expectedPeerCount)")
            Metric("Roster FIPS", "\(state.fipsConnectedPeerCount)/\(state.fipsRosterPeerCount) direct")
            Metric("Other FIPS", "\(state.nonFipsRosterPeerCount)")
                .accessibilityIdentifier("diagnostics-other-fips")
                .accessibilityValue("\(state.nonFipsRosterPeerCount)")
            Metric("MagicDNS", state.magicDnsStatus)
            Metric("Version", state.appVersion)
            Metric("Config", state.configPath)
            ForEach(state.health) { issue in
                VStack(alignment: .leading, spacing: 3) {
                    Text(issue.severity)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.orange)
                    Text(issue.summary)
                    if !issue.detail.isEmpty {
                        Text(issue.detail)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}
