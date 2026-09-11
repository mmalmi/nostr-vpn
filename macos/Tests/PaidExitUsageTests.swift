import Foundation

@main
struct PaidExitUsageTests {
    static func main() {
        let first = channel("first", provider: "provider-a", paid: 2_500)
        let renewed = channel("renewed", provider: "provider-a", paid: 4_000)
        let other = channel("other", provider: "provider-b", paid: 1_250)
        var seller = channel("seller", provider: "buyer", paid: 90_000)
        seller.role = "seller"
        let active = session("active", channel: "renewed", bytes: 3_000_000, paid: 4_000)
        var closed = session("closed", channel: "first", bytes: 2_000_000, paid: 2_000)
        closed.lifecycleStatus = "closed"
        closed.deliveredUnits = 2_000_000_000
        let result = PaidExitUsage.providers(
            channels: [first, first, renewed, other, seller],
            sessions: [closed, active, active,
                       session("other", channel: "other", bytes: 500_000, paid: 1_250),
                       session("seller", channel: "seller", bytes: 90_000_000, paid: 90_000)],
            offers: []
        )
        precondition(result.count == 2)
        precondition(result[0].bytes == 5_000_000, "use observed traffic, including closed channels, rather than billing units")
        precondition(result[0].paidMsat == 6_500, "count cumulative payments once per channel")
        precondition(result[0].paymentText == "6.5 sat")
        precondition(result[0].name.contains("198.51.100.42"), "retain a readable provider after its offer expires")
        precondition(result[1].paymentText == "1.25 sat")
        var total = result.reduce(into: PaidExitUsage(id: "all", name: "All exits")) {
            $0.add(bytes: $1.bytes, paidMsat: $1.paidMsat)
        }
        precondition(total.bytes == 5_500_000)
        precondition(total.paymentText == "7.75 sat", "exclude refundable channel funding and seller income")
        total.add(bytes: .max, paidMsat: .max)
        precondition(total.bytes == .max && total.paidMsat == .max)
        precondition(PaidExitUsage(id: "tiny", name: "", paidMsat: 1).paymentText == "0.001 sat")
        print("Paid exit usage: renewal, history, deduplication, payment totals and precision passed")
    }

    static func channel(_ id: String, provider: String, paid: UInt64) -> NativePaidRouteChannelState {
        NativePaidRouteChannelState(
            channelId: id, offerId: "internet-exit", role: "buyer", status: "active",
            mintUrl: "https://mint.example", counterpartyNpub: provider,
            capacitySat: 1_000, capacityText: "1000 sat", paidMsat: paid, paidText: "",
            updatedAtUnix: 100, expiresAtUnix: 200, error: ""
        )
    }

    static func session(_ id: String, channel: String, bytes: UInt64, paid: UInt64) -> NativePaidRouteSessionState {
        NativePaidRouteSessionState(
            sessionId: id, leaseId: id, channelId: channel, statusText: "", lifecycleStatus: "active",
            accessState: "paid", titleText: "", detailText: "", settlementText: "",
            collectActionText: "", collectActionHelpText: "", paymentChannelReady: true,
            allowRouting: true, deliveredUnits: bytes, usageText: "", amountDueMsat: paid,
            amountDueText: "", paidMsat: paid, paidText: "", channelBalanceMsat: 999_000,
            channelBalanceText: "", unpaidMsat: 0, unpaidText: "", activeMillis: 0, bytes: bytes,
            packets: 0, realizedExitIp: "198.51.100.42", claimedCountryCode: "FI",
            observedCountryCode: "", countryClaimStatus: "", locationText: "", observedAsn: 0,
            hasQuality: false, qualityText: "", bandwidthText: "", latencyMs: 0, jitterMs: 0,
            packetLossPpm: 0, downBps: 0, upBps: 0, updatedAtUnix: 100, expiresAtUnix: 200
        )
    }
}
