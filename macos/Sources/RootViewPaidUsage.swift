import SwiftUI

extension RootView {
    @ViewBuilder
    var paidExitUsageSummary: some View {
        let market = state.paidRouteMarket
        let providers = PaidExitUsage.providers(
            channels: market.channels, sessions: market.sessions, offers: market.offers
        )
        if !providers.isEmpty {
            let total = providers.reduce(into: PaidExitUsage(id: "total", name: "All exits")) {
                $0.add(bytes: $1.bytes, paidMsat: $1.paidMsat)
            }
            let selected = ["paid_automatic", "paid_manual"].contains(state.internetSource)
                ? state.exitNode : ""
            surface {
                sectionHeader("Paid Internet Usage", systemImage: "chart.bar")
                Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 10) {
                    GridRow {
                        Text("Exit")
                        Text("Data transferred").gridColumnAlignment(.trailing)
                        Text("Payments sent").gridColumnAlignment(.trailing)
                            .help("Excludes money still reserved in payment channels.")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    ForEach(providers.sorted { left, right in
                        if (left.id == selected) != (right.id == selected) { return left.id == selected }
                        return left.name < right.name
                    }) { provider in
                        GridRow {
                            HStack(spacing: 6) {
                                Text(provider.name).textSelection(.enabled)
                                if provider.id == selected {
                                    Text("Selected").font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer(minLength: 0)
                            }
                            Text(formatDecimalBytes(provider.bytes)).monospacedDigit()
                            Text(provider.paymentText).monospacedDigit()
                        }
                    }
                    Divider().gridCellColumns(3)
                    GridRow {
                        Text(total.name)
                        Text(formatDecimalBytes(total.bytes)).monospacedDigit()
                        Text(total.paymentText).monospacedDigit()
                    }
                    .fontWeight(.medium)
                }
                Text("All recorded activity on this device · Uploads and downloads")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .accessibilityIdentifier("paid-exit-usage-summary")
        }
    }
}
