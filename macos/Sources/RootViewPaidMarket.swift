import AppKit
import CoreImage
import SwiftUI

extension RootView {
    var paidRouteMarketSettings: some View {
        let market = state.paidRouteMarket
        return VStack(alignment: .leading, spacing: 14) {
            if market.supported && !market.sessions.isEmpty {
                paidRouteActiveSessionSection(market)
                paidRouteOfferDiscoverySection(market)
            } else {
                paidRouteOfferDiscoverySection(market)
            }
        }
    }

    func paidRouteActiveSessionSection(_ market: NativePaidRouteMarketState) -> some View {
        surface {
            HStack(spacing: 12) {
                sectionHeader("Current Internet", systemImage: "bolt.horizontal.circle.fill")
                Spacer(minLength: 16)
                Button {
                    manager.streamPaidRoutePayments()
                } label: {
                    Label("Pay", systemImage: "arrow.up.right.circle.fill")
                }
                .controlSize(.small)
                .disabled(manager.actionInFlight || !paidRouteHasStreamablePayments(market.sessions))
                .help("Send due payments")
            }
            VStack(alignment: .leading, spacing: 8) {
                ForEach(market.sessions, id: \.sessionId) { session in
                    paidRouteSessionRow(session)
                }
            }
            paidRoutePaymentActionResult(market.lastPaymentAction)
        }
    }

    func paidRouteOfferDiscoverySection(_ market: NativePaidRouteMarketState) -> some View {
        let visibleOffers = paidRouteVisibleOffers(market)
        return surface {
            HStack(spacing: 12) {
                sectionHeader("Find Internet", systemImage: "cart.fill")
                Spacer(minLength: 16)
                Button {
                    manager.discoverPaidRouteOffers()
                } label: {
                    Label("Find", systemImage: "magnifyingglass")
                }
                .controlSize(.small)
                .disabled(manager.actionInFlight || !market.supported)
                .accessibilityIdentifier("paid-exit-discover")
            }

            if !market.statusText.isEmpty {
                Text(market.statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if !manager.actionError.isEmpty {
                Label(manager.actionError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            HStack(spacing: 8) {
                TextField("Provider npub or paid exit link", text: $manualPaidExitProvider)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("manual-paid-exit-provider")
                Button("Add") {
                    manager.setManualPaidExitProvider(manualPaidExitProvider)
                }
                .disabled(manager.actionInFlight || manualPaidExitProvider.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                if !market.manualProviderLink.isEmpty {
                    Button("Clear") { manager.clearManualPaidExitProvider() }
                        .disabled(manager.actionInFlight)
                }
            }
            if !market.manualProviderStatusText.isEmpty {
                Text(market.manualProviderStatusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if market.supported && !market.offers.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        label("Available")
                        Spacer(minLength: 8)
                        Picker("Country", selection: $paidRouteOfferCountryFilter) {
                            Text("Any country").tag("all")
                            ForEach(market.countryOptions, id: \.self) { country in
                                Text(country).tag(country)
                            }
                        }
                        .pickerStyle(.menu)
                        .controlSize(.small)
                        .help("Country")
                        Picker("Sort", selection: $paidRouteOfferSort) {
                            Text("Quality").tag("quality")
                            Text("Price").tag("price")
                            Text("Newest").tag("newest")
                        }
                        .pickerStyle(.segmented)
                        .controlSize(.small)
                        .frame(width: 210)
                    }
                    .onChange(of: paidRouteOfferCountryFilter) { _, _ in
                        applyPaidRouteMarketFilter()
                    }
                    .onChange(of: paidRouteOfferSort) { _, _ in
                        applyPaidRouteMarketFilter()
                    }
                    if visibleOffers.isEmpty {
                        Text("No matching offers")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(visibleOffers, id: \.key) { offer in
                            paidRouteOfferRow(offer)
                        }
                    }
                }
            }
        }
    }

    func paidRouteOfferRow(_ offer: NativePaidRouteOfferState) -> some View {
        let compatibleMint = offer.acceptedMints.contains { accepted in
            state.paidRouteMarket.wallet.mints.contains { $0.url == accepted }
        }
        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: "network")
                    .foregroundStyle(.secondary)
                Text(paidRouteOfferTitle(offer))
                    .fontWeight(.medium)
                    .lineLimit(1)
                Spacer(minLength: 12)
                Text(offer.priceText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                if state.internetSource == "paid_manual" && state.exitNode == offer.sellerNpub {
                    Label(
                        state.exitNodeActive ? "Active" : "Connecting",
                        systemImage: state.exitNodeActive ? "checkmark.circle.fill" : "clock.fill"
                    )
                        .font(.caption)
                        .foregroundStyle(state.exitNodeActive ? Color.green : Color.orange)
                } else if paidRouteOfferHasBuyerChannel(offer) {
                    Label("Ready", systemImage: "checkmark.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Button {
                        manager.buyPaidRouteOffer(offer)
                    } label: {
                        Label("Buy", systemImage: "cart.fill")
                    }
                    .controlSize(.small)
                    .disabled(manager.actionInFlight || !compatibleMint)
                }
            }
            HStack(spacing: 10) {
                Text(offer.statusText)
                let metricText = paidRouteMetricText(
                    fallbackText(
                        offer.qualityText,
                        paidRouteQualityText(
                            latencyMs: offer.latencyMs,
                            jitterMs: offer.jitterMs,
                            packetLossPpm: offer.packetLossPpm
                        )
                    ),
                    offer.bandwidthText
                )
                if !metricText.isEmpty {
                    Text(metricText)
                }
                Text(paidRouteIpText(ipv4: offer.ipv4, ipv6: offer.ipv6))
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            if !compatibleMint {
                Text("Add one of this seller’s accepted mints to buy")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
    }

    func paidRouteOfferHasBuyerChannel(_ offer: NativePaidRouteOfferState) -> Bool {
        state.paidRouteMarket.channels.contains { channel in
            channel.offerId == offer.offerId
                && channel.counterpartyNpub == offer.sellerNpub
                && channel.role == "buyer"
                && ["opening", "probing", "active", "paused"].contains(channel.status)
                && state.paidRouteMarket.sessions.contains { session in
                    session.channelId == channel.channelId && session.allowRouting
                }
        }
    }

    func paidRouteSessionIsSelected(_ session: NativePaidRouteSessionState) -> Bool {
        let seller = paidRouteSessionSellerNpub(session)
        guard !seller.isEmpty,
              ["paid_automatic", "paid_manual"].contains(state.internetSource),
              state.exitNode == seller
        else {
            return false
        }
        let nowUnix = UInt64(Date().timeIntervalSince1970)
        let current = state.paidRouteMarket.sessions.first { candidate in
            paidRouteSessionSellerNpub(candidate) == seller
                && ["opening", "probing", "active", "paused"].contains(candidate.lifecycleStatus)
                && (candidate.expiresAtUnix == 0 || candidate.expiresAtUnix > nowUnix)
        }
        return current?.sessionId == session.sessionId
    }

    func paidRouteSessionSellerNpub(_ session: NativePaidRouteSessionState) -> String {
        state.paidRouteMarket.channels.first { channel in
            channel.channelId == session.channelId && channel.role == "buyer"
        }?.counterpartyNpub ?? ""
    }

    func paidRouteMarketChannel(for session: NativePaidRouteSessionState) -> NativePaidRouteChannelState? {
        state.paidRouteMarket.channels.first { $0.channelId == session.channelId }
    }

    func paidRouteSessionLiveMetaText(
        _ session: NativePaidRouteSessionState,
        channel: NativePaidRouteChannelState?,
        counterpartyLabel: String
    ) -> String {
        var parts: [String] = []
        if let channel {
            if !channel.counterpartyNpub.isEmpty {
                parts.append("\(counterpartyLabel) \(paidRouteShortIdentifier(channel.counterpartyNpub))")
            }
            if !channel.status.isEmpty {
                parts.append("channel \(paidRoutePlainStatus(channel.status, fallback: channel.status).lowercased())")
            }
            if !channel.capacityText.isEmpty {
                parts.append("\(channel.capacityText) capacity")
            }
        } else if !session.channelId.isEmpty {
            parts.append("channel \(paidRouteShortIdentifier(session.channelId))")
        }
        if !session.accessState.isEmpty {
            parts.append(paidRouteAccessTitle(session.accessState, fallback: session.lifecycleStatus))
        }
        if session.updatedAtUnix > 0 {
            parts.append("updated \(paidRouteRelativePastText(session.updatedAtUnix))")
        }
        if session.expiresAtUnix > 0 {
            parts.append(paidRouteExpiryText(session.expiresAtUnix))
        }
        return parts.joined(separator: " · ")
    }

    func paidRouteSessionRow(_ session: NativePaidRouteSessionState) -> some View {
        let selected = paidRouteSessionIsSelected(session)
        let channel = paidRouteMarketChannel(for: session)
        let metricText = paidRouteMetricText(
            fallbackText(
                session.qualityText,
                paidRouteQualityText(
                    latencyMs: session.latencyMs,
                    jitterMs: session.jitterMs,
                    packetLossPpm: session.packetLossPpm
                )
            ),
            session.bandwidthText
        )
        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: session.allowRouting ? "bolt.horizontal.circle.fill" : "pause.circle.fill")
                    .foregroundStyle(session.allowRouting ? .green : .orange)
                Text(paidRouteBuyerSessionTitle(session, selected: selected))
                    .fontWeight(.medium)
                Spacer(minLength: 12)
                if selected {
                    Button {
                        manager.selectDirectExit()
                    } label: {
                        Label("Stop", systemImage: "stop.circle.fill")
                    }
                    .controlSize(.small)
                    .disabled(manager.actionInFlight)
                    .help("Stop using this seller")
                } else {
                    Button {
                        manager.usePaidRouteSession(session)
                    } label: {
                        Label("Connect", systemImage: "arrow.right.circle.fill")
                    }
                    .controlSize(.small)
                    .disabled(manager.actionInFlight || !session.allowRouting)
                    .help("Use this seller")
                }
                Button {
                    manager.probePaidRouteSession(session)
                } label: {
                    Image(systemName: "speedometer")
                }
                .buttonStyle(.borderless)
                .disabled(manager.actionInFlight)
                .help("Probe exit quality")
                if paidRouteSessionCanOpenChannel(session) {
                    Button {
                        manager.openPaidRouteChannelFromWallet(session)
                    } label: {
                        Image(systemName: "creditcard.fill")
                    }
                    .buttonStyle(.borderless)
                    .disabled(manager.actionInFlight || state.paidRouteMarket.wallet.defaultMint.isEmpty)
                    .help("Fund this exit")
                }
                if paidRouteSessionCanSignPayment(session) {
                    Button {
                        manager.signPaidRoutePaymentEnvelopeFromWallet(session)
                    } label: {
                        Image(systemName: "arrow.up.forward.circle.fill")
                    }
                    .buttonStyle(.borderless)
                    .disabled(manager.actionInFlight)
                    .help("Pay due usage")
                }
                if !selected && paidRouteSessionCanCloseChannel(session) {
                    Button {
                        manager.closePaidRouteChannelFromWallet(session)
                    } label: {
                        Label("Close", systemImage: "checkmark.seal.fill")
                    }
                    .controlSize(.small)
                    .disabled(manager.actionInFlight)
                    .help("Close and settle channel")
                }
                if paidRouteSessionHasSendableEnvelope(session) {
                    Button {
                        manager.sendPaidRoutePaymentEnvelope(state.paidRouteMarket.lastPaymentAction.envelopeJson)
                    } label: {
                        Image(systemName: "paperplane.fill")
                    }
                    .buttonStyle(.borderless)
                    .disabled(manager.actionInFlight)
                    .help("Send payment")
                }
                Text(fallbackText(session.paidText, "\(formatPaidRouteMsat(session.paidMsat)) paid"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 10) {
                Text(fallbackText(session.usageText, paidRouteUsageText(session)))
                Text(fallbackText(session.amountDueText, "\(formatPaidRouteMsat(session.amountDueMsat)) due"))
                if session.unpaidMsat > 0 {
                    Text(fallbackText(session.unpaidText, "\(formatPaidRouteMsat(session.unpaidMsat)) behind"))
                }
                if !session.locationText.isEmpty {
                    Text(session.locationText)
                        .foregroundStyle(session.countryClaimStatus == "mismatch" ? Color.orange : Color.secondary)
                } else {
                    if !session.realizedExitIp.isEmpty {
                        Text(session.realizedExitIp)
                    }
                    if !session.observedCountryCode.isEmpty {
                        Text(session.observedCountryCode)
                    }
                    if let countryClaimText = paidRouteCountryClaimText(session) {
                        Text(countryClaimText)
                            .foregroundStyle(session.countryClaimStatus == "mismatch" ? Color.orange : Color.green)
                    }
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            Text(paidRouteSessionLiveMetaText(session, channel: channel, counterpartyLabel: "seller"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            if !metricText.isEmpty {
                Text(metricText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            if !session.settlementText.isEmpty {
                Text(session.settlementText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }

    func paidRouteSessionCanOpenChannel(_ session: NativePaidRouteSessionState) -> Bool {
        !session.paymentChannelReady
            && ["free_probe", "grace", "suspended"].contains(session.accessState)
            && ["opening", "probing", "active", "paused"].contains(session.lifecycleStatus)
            && (session.expiresAtUnix == 0 || session.expiresAtUnix > UInt64(Date().timeIntervalSince1970))
    }

    func paidRouteSessionCanSignPayment(_ session: NativePaidRouteSessionState) -> Bool {
        session.paymentChannelReady
            && session.amountDueMsat > session.paidMsat
            && ["grace", "suspended"].contains(session.accessState)
            && ["probing", "active", "paused"].contains(session.lifecycleStatus)
    }

    func paidRouteSessionCanCloseChannel(_ session: NativePaidRouteSessionState) -> Bool {
        session.paymentChannelReady
            && !session.sessionId.isEmpty
            && ["closed", "expired"].contains(session.lifecycleStatus) == false
    }

    func paidRouteHasStreamablePayments(_ sessions: [NativePaidRouteSessionState]) -> Bool {
        sessions.contains { paidRouteSessionCanSignPayment($0) }
    }

    func paidRouteSessionHasSendableEnvelope(_ session: NativePaidRouteSessionState) -> Bool {
        let action = state.paidRouteMarket.lastPaymentAction
        return ["create", "open_channel", "sign", "close"].contains(action.kind)
            && action.sessionId == session.sessionId
            && !action.envelopeJson.isEmpty
    }

    func paidRouteCountryClaimText(_ session: NativePaidRouteSessionState) -> String? {
        switch session.countryClaimStatus {
        case "match":
            return session.claimedCountryCode.isEmpty ? nil : "verified"
        case "mismatch":
            return session.claimedCountryCode.isEmpty ? "country mismatch" : "claimed \(session.claimedCountryCode)"
        default:
            return nil
        }
    }

    func paidRouteBuyerSessionTitle(_ session: NativePaidRouteSessionState, selected: Bool) -> String {
        switch session.lifecycleStatus {
        case "expired":
            return "Ended"
        case "closed":
            return "Closed"
        case "failed":
            return "Connection failed"
        default:
            break
        }
        if selected {
            if state.exitNodeActive {
                return "Connected"
            }
            if state.exitNodeBlocked {
                return "Unavailable"
            }
            return "Connecting"
        }
        if !session.titleText.isEmpty {
            return session.titleText
        }
        if session.allowRouting {
            return "Ready"
        }
        if session.unpaidMsat > 0 {
            return "Payment needed"
        }
        if !session.paymentChannelReady {
            return "Needs funds"
        }
        return paidRoutePlainStatus(session.statusText, fallback: session.lifecycleStatus)
    }

    func paidPublicExitSubtitle(_ session: NativePaidRouteSessionState) -> String {
        if !session.observedCountryCode.isEmpty && !session.realizedExitIp.isEmpty {
            return "\(session.observedCountryCode), \(session.realizedExitIp)"
        }
        if !session.statusText.isEmpty {
            return session.statusText
        }
        return "Paid internet seller"
    }

    func paidRouteOfferTitle(_ offer: NativePaidRouteOfferState) -> String {
        offer.countryCode.isEmpty ? "Unknown country" : offer.countryCode
    }

    func paidRouteVisibleOffers(_ market: NativePaidRouteMarketState) -> [NativePaidRouteOfferState] {
        if market.hiddenOfferCount > 0 || !market.visibleOffers.isEmpty {
            return market.visibleOffers
        }
        return market.offers
    }

    func applyPaidRouteMarketFilter() {
        manager.setPaidRouteMarketFilter(
            countryCode: paidRouteOfferCountryFilter,
            sort: paidRouteOfferSort
        )
    }

    func paidRouteWalletActionTitle(_ kind: String) -> String {
        switch kind {
        case "topup": return "Top up"
        case "receive": return "Received"
        case "send": return "Token ready"
        case "withdraw": return "Withdrawn"
        case "refresh": return "Wallet refreshed"
        case "open_channel": return "Exit funded"
        case "close": return "Channel closed"
        default: return kind
        }
    }

    func paidRouteWalletActionIcon(_ kind: String) -> String {
        switch kind {
        case "topup": return "arrow.down.circle.fill"
        case "receive": return "tray.and.arrow.down.fill"
        case "send": return "paperplane.fill"
        case "withdraw": return "bolt.fill"
        case "open_channel": return "creditcard.fill"
        default: return "creditcard.fill"
        }
    }

    func paidRoutePaymentActionTitle(_ kind: String) -> String {
        switch kind {
        case "send": return "Payment sent"
        case "receive": return "Payment received"
        case "apply": return "Payment applied"
        case "create": return "Payment ready"
        case "open_channel": return "Exit funded"
        case "sign": return "Payment ready"
        case "close": return "Channel closed"
        case "collect": return "Collected"
        case "stream": return "Payments sent"
        case "probe": return "Quality checked"
        default:
            return kind.isEmpty ? "Payment" : kind.replacingOccurrences(of: "_", with: " ").capitalized
        }
    }

    func paidRoutePaymentActionIcon(_ kind: String) -> String {
        switch kind {
        case "send": return "paperplane.fill"
        case "receive": return "tray.and.arrow.down.fill"
        case "apply": return "checkmark.seal.fill"
        case "create": return "doc.badge.plus"
        case "open_channel": return "creditcard.fill"
        case "sign": return "arrow.up.forward.circle.fill"
        case "close": return "checkmark.seal.fill"
        case "collect": return "checkmark.seal.fill"
        case "stream": return "arrow.up.right.circle.fill"
        case "probe": return "speedometer"
        default: return "creditcard.fill"
        }
    }

    func paidRouteIpText(ipv4: Bool, ipv6: Bool) -> String {
        switch (ipv4, ipv6) {
        case (true, true): return "IPv4/IPv6"
        case (true, false): return "IPv4"
        case (false, true): return "IPv6"
        default: return "IP unknown"
        }
    }

    func paidRouteQualityText(latencyMs: UInt32, jitterMs: UInt32, packetLossPpm: UInt32) -> String {
        if latencyMs == 0, jitterMs == 0, packetLossPpm == 0 {
            return "Quality unmeasured"
        }
        let lossPercent = Double(packetLossPpm) / 10_000.0
        return "\(latencyMs) ms · \(jitterMs) ms jitter · \(String(format: "%.2f", lossPercent))% loss"
    }

    func paidRouteMetricText(_ qualityText: String, _ bandwidthText: String) -> String {
        [qualityText, bandwidthText]
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && $0 != "Quality unmeasured" }
            .joined(separator: " · ")
    }

    func paidRouteSessionDetail(_ session: NativePaidRouteSessionState) -> String {
        if !session.detailText.isEmpty {
            return session.detailText
        }
        let access = paidRouteAccessTitle(session.accessState, fallback: session.lifecycleStatus)
        let used = paidRouteUsageText(session)
        return "\(access), \(used), \(formatPaidRouteMsat(session.amountDueMsat)) due"
    }

    func paidRouteUsageText(_ session: NativePaidRouteSessionState) -> String {
        if !session.usageText.isEmpty {
            return session.usageText
        }
        if session.bytes > 0 {
            return "\(formatBytes(session.bytes)) used"
        }
        if session.packets > 0 {
            return "\(session.packets) packets"
        }
        return "\(session.deliveredUnits) units"
    }

    func paidRouteAccessTitle(_ value: String, fallback: String) -> String {
        switch value {
        case "paid": return "Paid"
        case "free_probe": return "Free test"
        case "grace": return "Grace"
        case "suspended": return "Paused"
        default:
            return paidRoutePlainStatus(value, fallback: fallback)
        }
    }

    func paidRoutePlainStatus(_ value: String, fallback: String) -> String {
        let raw = value.isEmpty ? fallback : value
        switch raw {
        case "opening": return "Opening"
        case "probing": return "Checking quality"
        case "active": return "Active"
        case "paused": return "Paused"
        case "closed": return "Closed"
        case "session": return "Session"
        default:
            return raw
                .replacingOccurrences(of: "_", with: " ")
                .capitalized
        }
    }

    func formatPaidRouteMsat(_ msat: UInt64) -> String {
        if msat >= 1_000 {
            let sats = Double(msat) / 1_000.0
            return "\(String(format: "%.3f", sats)) sat"
        }
        return "\(msat) msat"
    }

    func fallbackText(_ value: String, _ fallback: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? fallback : value
    }

}
