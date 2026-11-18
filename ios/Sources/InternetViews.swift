import Foundation
import SwiftUI

struct InternetPage: View {
    @ObservedObject var model: AppModel
    let network: NetworkState?

    private var exitParticipants: [ParticipantState] {
        network?.participants.filter { participant in
            participant.offersExitNode && !isSelf(participant, state: model.state)
        } ?? []
    }

    private func selectSource(_ source: String) {
        model.dispatch(
            NativeActions.updateSettings(["internetSource": source]),
            status: "Saving internet"
        )
    }

    private func selectPeer(_ npub: String) {
        model.dispatch(
            NativeActions.updateSettings(["internetSource": "private_vpn", "exitNode": npub]),
            status: "Saving internet"
        )
    }

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 14) {
                if !model.state.error.isEmpty || !model.statusMessage.isEmpty {
                    NoticeCard(
                        text: model.state.error.isEmpty
                            ? model.statusMessage
                            : model.state.error
                    )
                    .accessibilityIdentifier("internet-settings-status")
                }
                AppCard {
                    Text("Internet source")
                        .font(.headline)
                    Picker("Internet source", selection: Binding(
                        get: { model.state.internetSource },
                        set: selectSource
                    )) {
                        Text("This device").tag("direct")
                            .accessibilityIdentifier("internet-source-direct")
                        Text("Private VPN device").tag("private_vpn")
                            .accessibilityIdentifier("internet-source-private-vpn")
                        Text("WireGuard VPN").tag("wireguard")
                            .accessibilityIdentifier("internet-source-wireguard")
                    }
                    .pickerStyle(.menu)
                    .accessibilityIdentifier("internet-source-picker")

                    Text(model.state.exitNodeStatusText)
                        .font(.footnote)
                        .foregroundStyle(
                            model.state.exitNodeBlocked ? Color.red : Color.secondary
                        )
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("internet-source-status")

                    if model.state.internetSource == "private_vpn" {
                        if exitParticipants.isEmpty {
                            Text("No trusted devices sharing internet")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        } else {
                            ForEach(exitParticipants) { participant in
                                ExitNodeRow(
                                    title: participant.displayName,
                                    subtitle: deviceSubtitle(participant, state: model.state),
                                    selected: model.state.exitNode == participant.npub,
                                    enabled: true,
                                    action: { selectPeer(participant.npub) }
                                )
                                .accessibilityIdentifier("private-exit-\(participant.npub)")
                                .accessibilityAddTraits(model.state.exitNode == participant.npub ? .isSelected : [])
                            }
                        }
                    }

                    Toggle("Block internet if selected source disconnects", isOn: Binding(
                        get: { model.state.exitNodeLeakProtection },
                        set: { value in
                            model.dispatch(
                                NativeActions.updateSettings(["exitNodeLeakProtection": value]),
                                status: "Saving internet"
                            )
                        }
                    ))
                }
                if model.state.internetSource == "wireguard" {
                    WireGuardSettingsCard(model: model)
                }
                if model.state.internetSource != "direct" {
                    ExitDnsSettingsCard(model: model)
                }
            }
            .padding()
        }
        .scrollIndicators(.hidden)
        .safeAreaPadding(.bottom, 92)
        .background(AppColors.background)
    }
}

struct ExitNodeRow: View {
    let title: String
    let subtitle: String
    let selected: Bool
    let enabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundColor(selected ? AppColors.accent : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.body)
                        .foregroundColor(.primary)
                    if !subtitle.isEmpty {
                        Text(subtitle)
                            .font(.footnote)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }
                Spacer()
            }
            .padding(.vertical, 6)
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .opacity(enabled ? 1.0 : 0.5)
    }
}
