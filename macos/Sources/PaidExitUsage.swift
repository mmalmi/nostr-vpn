import Foundation

struct PaidExitUsage: Identifiable {
    let id: String
    var name: String
    var bytes: UInt64 = 0
    var paidMsat: UInt64 = 0

    var paymentText: String {
        let whole = paidMsat / 1_000
        let remainder = paidMsat % 1_000
        guard remainder != 0 else { return "\(whole) sat" }
        let fraction = String(format: "%03llu", remainder)
            .replacingOccurrences(of: "0+$", with: "", options: .regularExpression)
        return "\(whole).\(fraction) sat"
    }

    mutating func add(bytes: UInt64, paidMsat: UInt64) {
        let data = self.bytes.addingReportingOverflow(bytes)
        self.bytes = data.overflow ? .max : data.partialValue
        let payment = self.paidMsat.addingReportingOverflow(paidMsat)
        self.paidMsat = payment.overflow ? .max : payment.partialValue
    }

    static func providers(
        channels: [NativePaidRouteChannelState],
        sessions: [NativePaidRouteSessionState],
        offers: [NativePaidRouteOfferState]
    ) -> [PaidExitUsage] {
        let buyerChannels = Dictionary(
            channels.filter { $0.role == "buyer" }.map { ($0.channelId, $0) },
            uniquingKeysWith: { $0.paidMsat >= $1.paidMsat ? $0 : $1 }
        )
        let uniqueSessions = Dictionary(
            sessions.map { ($0.sessionId, $0) },
            uniquingKeysWith: { $0.updatedAtUnix >= $1.updatedAtUnix ? $0 : $1 }
        )
        let sessionsByChannel = Dictionary(grouping: uniqueSessions.values, by: \.channelId)
        var usageByProvider: [String: PaidExitUsage] = [:]
        for channel in buyerChannels.values {
            let provider = channel.counterpartyNpub
            let history = sessionsByChannel[channel.channelId] ?? []
            var usage = usageByProvider[provider] ?? PaidExitUsage(id: provider, name: "")
            for session in history {
                usage.add(bytes: session.bytes, paidMsat: 0)
            }
            // Payments are cumulative per channel. Reserved funding and the
            // session's copy of that same payment must not be added again.
            usage.add(bytes: 0, paidMsat: max(channel.paidMsat, history.map(\.paidMsat).max() ?? 0))
            usageByProvider[provider] = usage
        }
        return usageByProvider.values.sorted { $0.id < $1.id }.enumerated().map { index, value in
            var usage = value
            let history = uniqueSessions.values.filter {
                buyerChannels[$0.channelId]?.counterpartyNpub == usage.id
            }.sorted { $0.updatedAtUnix > $1.updatedAtUnix }
            let country = offers.filter { $0.sellerNpub == usage.id && !$0.countryCode.isEmpty }
                .max { $0.lastSeenUnix < $1.lastSeenUnix }?.countryCode
                ?? history.first { !$0.observedCountryCode.isEmpty }?.observedCountryCode
                ?? history.first { !$0.claimedCountryCode.isEmpty }?.claimedCountryCode
                ?? ""
            let address = history.first { !$0.realizedExitIp.isEmpty }?.realizedExitIp ?? ""
            let countryName = Locale.current.localizedString(forRegionCode: country) ?? country
            usage.name = [countryName, address].filter { !$0.isEmpty }.joined(separator: " · ")
            if usage.name.isEmpty { usage.name = "Provider \(index + 1)" }
            return usage
        }
    }
}
