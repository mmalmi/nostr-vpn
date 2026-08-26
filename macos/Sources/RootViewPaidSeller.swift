import AppKit
import CoreImage
import SwiftUI

extension RootView {
    var paidExitSellerSettings: some View {
        VStack(alignment: .leading, spacing: 14) {
            paidExitSellerStatusSettings
            if state.paidExitSeller.supported {
                paidExitSellerListingSettings
                paidExitSellerPaymentSettings
                paidExitSellerActivitySettings
                paidExitSellerTermsSettings
            }
        }
    }

    var paidExitSellerStatusSettings: some View {
        surface {
            HStack(spacing: 12) {
                sectionHeader("Share My Internet", systemImage: "bitcoinsign.circle.fill")
                Spacer(minLength: 16)
                Toggle("", isOn: Binding(
                    get: { state.paidExitSeller.enabled },
                    set: { manager.setPaidExitEnabled($0) }
                ))
                .labelsHidden()
                .toggleStyle(.switch)
                .accessibilityIdentifier("paid-exit-seller-enabled")
                .disabled(manager.actionInFlight || !state.paidExitSeller.supported)
            }
            if !state.paidExitSeller.supported {
                Text("Selling internet is unavailable on this platform.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text(paidExitSellerSummaryText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if state.paidExitSeller.supported {
                paidExitSellerStatusBadges
                paidExitSellerInternetSummary
                if !state.paidExitSeller.providerLink.isEmpty {
                    HStack(spacing: 8) {
                        Text(state.paidExitSeller.providerLink)
                            .font(.caption.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button("Copy paid exit link") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(state.paidExitSeller.providerLink, forType: .string)
                        }
                        .controlSize(.small)
                    }
                }
            }
        }
    }

    var paidExitSellerStatusBadges: some View {
        HStack(spacing: 8) {
            badge(state.paidExitSeller.enabled ? "Selling" : "Off", style: state.paidExitSeller.enabled ? .ok : .muted)
            badge(fallbackText(state.paidExitSeller.internetText, paidExitCurrentInternetTitle), style: .muted)
            if !state.paidExitSeller.publicIpText.isEmpty {
                badge("Public IP \(state.paidExitSeller.publicIpText)", style: .muted)
            }
        }
    }

    var paidExitSellerInternetSummary: some View {
        VStack(alignment: .leading, spacing: 8) {
            paidExitSummaryRow(
                title: "Internet",
                value: fallbackText(state.paidExitSeller.internetText, paidExitCurrentInternetTitle),
                detail: paidExitCurrentInternetDetail,
                systemImage: "network"
            )
            if !state.paidExitSeller.priceText.isEmpty {
                paidExitSummaryRow(
                    title: "Price",
                    value: state.paidExitSeller.priceText,
                    detail: state.paidExitSeller.acceptedMints.first ?? "",
                    systemImage: "creditcard.fill"
                )
            }
            paidExitSummaryRow(
                title: fallbackText(state.paidExitSeller.channelCreditTitleText, "Pending buyer credit"),
                value: fallbackText(
                    state.paidExitSeller.channelCreditText,
                    formatPaidRouteMsat(state.paidExitSeller.channelCreditMsat)
                ),
                detail: fallbackText(
                    state.paidExitSeller.channelCreditHelpText,
                    state.paidExitSeller.channelCreditMsat > 0 ? "Collect to move it into wallet" : ""
                ),
                systemImage: "person.crop.circle.badge.checkmark"
            )
        }
    }

    func paidExitSummaryRow(
        title: String,
        value: String,
        detail: String,
        systemImage: String
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: systemImage)
                .foregroundStyle(.secondary)
                .frame(width: 16)
            Text(title)
                .font(.caption.weight(.semibold))
                .frame(width: 104, alignment: .leading)
            Text(value)
                .font(.caption)
                .lineLimit(1)
                .truncationMode(.middle)
            if !detail.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
    }

    var paidExitSellerListingSettings: some View {
        surface {
            HStack(spacing: 12) {
                sectionHeader("What Buyers See", systemImage: "mappin.and.ellipse")
                Spacer(minLength: 16)
                paidExitSellerSaveButton
            }
            VStack(alignment: .leading, spacing: 10) {
                paidExitFormRow("Country") {
                    TextField("FI", text: $paidExitCountryCode)
                        .frame(width: 70)
                        .accessibilityIdentifier("paid-exit-country-code")
                        .onChange(of: paidExitCountryCode) { _, value in
                            paidExitCountryCode = String(
                                value.uppercased().filter { $0.isASCII && $0.isLetter }.prefix(2)
                            )
                        }
                }
                paidExitFormRow("Works with") {
                    Text("IPv4")
                }
            }
            disclosureSection(
                title: "More Details",
                systemImage: "slider.horizontal.3",
                isExpanded: $paidExitListingAdvancedExpanded,
                font: .subheadline.weight(.semibold)
            ) {
                VStack(alignment: .leading, spacing: 10) {
                    paidExitFormRow("ASN") {
                        TextField("12345", text: $paidExitAsn)
                            .frame(width: 120)
                    }
                }
                .padding(.top, 8)
            }
        }
    }

    var paidExitSellerPaymentSettings: some View {
        surface {
            sectionHeader("Price", systemImage: "creditcard.fill")
            VStack(alignment: .leading, spacing: 10) {
                paidExitFormRow("Charge") {
                    HStack(spacing: 8) {
                        TextField("0", text: $paidExitPriceMsatPerGb)
                            .frame(width: 130)
                            .accessibilityIdentifier("paid-exit-price-msat-per-gb")
                        Text("msat/GB")
                            .foregroundStyle(.secondary)
                    }
                }
                if !paidExitPriceMsatPerGb.isEmpty && !paidExitPriceIsValid {
                    Text("Use a whole number of millisatoshis per GB.")
                        .font(.caption)
                        .foregroundStyle(Color.orange)
                }
                paidExitFormRow("Mint") {
                    TextField("https://mint.minibits.cash/Bitcoin", text: $paidExitAcceptedMints)
                        .accessibilityIdentifier("paid-exit-accepted-mints")
                }
            }
        }
    }

    var paidExitSellerTermsSettings: some View {
        surface {
            disclosureSection(
                title: "Trial and Limits",
                systemImage: "slider.horizontal.3",
                isExpanded: $paidExitAdvancedTermsExpanded,
                font: .headline
            ) {
                VStack(alignment: .leading, spacing: 10) {
                    paidExitFormRow("Per buyer") {
                        HStack(spacing: 8) {
                            paidExitTermInput("Max balance", "250 sat", text: $paidExitMaxChannelCapacitySat)
                            paidExitTermInput("Channel expires", "1 day", text: $paidExitChannelExpirySecs)
                        }
                    }
                    paidExitFormRow("Free test") {
                        HStack(spacing: 8) {
                            paidExitTermInput("Before payment", "1 MB", text: $paidExitFreeProbeUnits)
                            paidExitTermInput("After payment runs out", "256 KB", text: $paidExitGraceUnits)
                        }
                    }
                    if !state.paidExitSeller.settlementText.isEmpty {
                        Text(state.paidExitSeller.settlementText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.top, 8)
            }
        }
    }

    func paidExitTermInput(_ title: String, _ placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            TextField(placeholder, text: text)
                .frame(width: 132)
        }
    }

    func paidExitFormRow<Content: View>(
        _ title: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        HStack(alignment: .center, spacing: 12) {
            Text(title)
                .foregroundStyle(.secondary)
                .frame(width: 96, alignment: .leading)
            content()
        }
    }

    var paidExitSellerActivitySettings: some View {
        surface {
            HStack(spacing: 12) {
                sectionHeader("Customers", systemImage: "person.2.fill")
            }
            paidRoutePaymentActionResult(state.paidRouteMarket.lastPaymentAction)
            if !state.paidExitSeller.sessions.isEmpty || !state.paidExitSeller.channels.isEmpty {
                paidExitSellerCustomerSummary
            }
            if state.paidExitSeller.sessions.isEmpty {
                emptyRow("No customers connected", systemImage: "person.2")
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(state.paidExitSeller.sessions, id: \.sessionId) { session in
                        paidExitSellerSessionRow(session)
                    }
                }
            }
        }
    }

    var paidExitSellerCustomerSummary: some View {
        let sessions = state.paidExitSeller.sessions
        let connected = Int(state.paidExitSeller.currentConnectionCount)
        let behind = sessions.filter { $0.unpaidMsat > 0 }.count
        let collectable = sessions.filter(paidExitSellerSessionCanCollect).count
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                badge("\(connected) connected", style: connected > 0 ? .ok : .muted)
                badge("\(state.paidExitSeller.pastConnectionCount) past", style: .muted)
                badge("\(state.paidExitSeller.channels.count) open channels", style: .muted)
                if behind > 0 || state.paidExitSeller.totalUnpaidMsat > 0 {
                    badge("\(max(behind, 1)) behind", style: .warn)
                }
                if collectable > 0 {
                    badge("\(collectable) collectable", style: .muted)
                }
            }
            HStack(spacing: 12) {
                Text(fallbackText(state.paidExitSeller.totalTrafficText, "\(formatBytes(state.paidExitSeller.totalBillableBytes)) routed"))
                Text(fallbackText(state.paidExitSeller.totalPaidText, "\(formatPaidRouteMsat(state.paidExitSeller.totalPaidMsat)) paid"))
                Text(fallbackText(state.paidExitSeller.totalDueText, "\(formatPaidRouteMsat(state.paidExitSeller.totalDueMsat)) due"))
                if state.paidExitSeller.totalUnpaidMsat > 0 {
                    Text(fallbackText(state.paidExitSeller.totalUnpaidText, "\(formatPaidRouteMsat(state.paidExitSeller.totalUnpaidMsat)) behind"))
                        .foregroundStyle(Color.orange)
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
        }
    }

    var paidExitSellerActionButtons: some View {
        paidExitSellerSaveButton
    }

    var paidExitSellerSaveButton: some View {
        let upstream = paidExitCurrentUpstream
        let priceMsatPerGb = paidExitPriceMsatPerGb
        let acceptedMints = paidExitAcceptedMints
        let maxChannelCapacitySat = paidExitMaxChannelCapacitySat
        let channelExpirySecs = paidExitChannelExpirySecs
        let freeProbeUnits = paidExitFreeProbeUnits
        let graceUnits = paidExitGraceUnits
        let countryCode = paidExitCountryCode
        let asn = paidExitAsn

        return Button {
            manager.savePaidExitSellerSettings(
                upstream: upstream,
                priceMsatPerGb: priceMsatPerGb,
                acceptedMints: acceptedMints,
                maxChannelCapacitySat: maxChannelCapacitySat,
                channelExpirySecs: channelExpirySecs,
                freeProbeUnits: freeProbeUnits,
                graceUnits: graceUnits,
                countryCode: countryCode,
                asn: asn
            )
        } label: {
            Label("Save", systemImage: "checkmark")
        }
        .accessibilityIdentifier("paid-exit-seller-save")
        .disabled(manager.actionInFlight || !paidExitPriceIsValid)
    }

    var paidExitPriceIsValid: Bool {
        UInt64(paidExitPriceMsatPerGb.trimmingCharacters(in: .whitespacesAndNewlines)) != nil
    }

    func paidExitSellerSessionRow(_ session: NativePaidRouteSessionState) -> some View {
        let channel = paidExitSellerChannel(for: session)
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
                Text(paidExitSellerSessionTitle(session))
                    .fontWeight(.medium)
                Spacer(minLength: 12)
                if paidExitSellerSessionCanCollect(session) {
                    Button {
                        manager.collectPaidExitChannel(session)
                    } label: {
                        Label(paidExitSellerCollectButtonTitle(session), systemImage: paidExitSellerCollectButtonIcon(session))
                    }
                    .controlSize(.small)
                    .disabled(manager.actionInFlight)
                    .help(paidExitSellerCollectButtonHelp(session))
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
                if session.packets > 0 {
                    Text("\(session.packets) packets")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            Text(paidRouteSessionLiveMetaText(session, channel: channel, counterpartyLabel: "buyer"))
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

    func paidExitSellerChannel(for session: NativePaidRouteSessionState) -> NativePaidRouteChannelState? {
        state.paidExitSeller.channels.first { $0.channelId == session.channelId }
    }

    func paidRouteShortIdentifier(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count > 18 else {
            return trimmed
        }
        return "\(trimmed.prefix(10))…\(trimmed.suffix(6))"
    }

    func paidRouteRelativePastText(_ unix: UInt64) -> String {
        let now = UInt64(Date().timeIntervalSince1970)
        guard unix < now else {
            return "just now"
        }
        return "\(formatCompactDurationSeconds(now - unix)) ago"
    }

    func paidRouteExpiryText(_ unix: UInt64) -> String {
        let now = UInt64(Date().timeIntervalSince1970)
        if unix >= now {
            return "ends in \(formatCompactDurationSeconds(unix - now))"
        }
        return "ended \(formatCompactDurationSeconds(now - unix)) ago"
    }

    func paidExitSellerSessionCanCollect(_ session: NativePaidRouteSessionState) -> Bool {
        session.paymentChannelReady
            && session.paidMsat > 0
            && !session.channelId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func paidExitSellerCollectButtonTitle(_ session: NativePaidRouteSessionState) -> String {
        fallbackText(session.collectActionText, session.allowRouting ? "End & Collect" : "Collect")
    }

    func paidExitSellerCollectButtonIcon(_ session: NativePaidRouteSessionState) -> String {
        session.allowRouting ? "stop.circle.fill" : "checkmark.seal.fill"
    }

    func paidExitSellerCollectButtonHelp(_ session: NativePaidRouteSessionState) -> String {
        fallbackText(session.collectActionHelpText, session.allowRouting ? "Stop routing and move paid channel funds to wallet" : "Move paid channel funds to wallet")
    }

    func paidExitSellerSessionTitle(_ session: NativePaidRouteSessionState) -> String {
        if !session.titleText.isEmpty {
            return session.titleText
        }
        if session.allowRouting {
            return "Buyer online"
        }
        if session.unpaidMsat > 0 {
            return "Waiting for payment"
        }
        return session.statusText.isEmpty ? "Buyer session" : session.statusText
    }

    func paidExitPrivateAccessTitle(_ value: String) -> String {
        value == "denied" ? "Denied" : value
    }

    func paidExitTrafficUnitDraft(_ units: UInt64) -> String {
        formatBinaryBytesCompact(units)
    }

    func paidExitPricingUnitDraft(_ units: UInt64) -> String {
        formatDecimalBytes(units)
    }

    func paidExitDurationDraft(_ seconds: UInt64) -> String {
        if seconds == 0 {
            return "0 sec"
        }
        if seconds % 86_400 == 0 {
            let days = seconds / 86_400
            return days == 1 ? "1 day" : "\(days) days"
        }
        if seconds % 3_600 == 0 {
            let hours = seconds / 3_600
            return hours == 1 ? "1 hour" : "\(hours) hours"
        }
        if seconds % 60 == 0 {
            let minutes = seconds / 60
            return minutes == 1 ? "1 min" : "\(minutes) min"
        }
        return "\(seconds) sec"
    }

    func formatCompactDurationSeconds(_ seconds: UInt64) -> String {
        if seconds < 60 {
            return "\(seconds)s"
        }
        let minutes = seconds / 60
        if minutes < 60 {
            return "\(minutes)m"
        }
        let hours = minutes / 60
        if hours < 48 {
            return "\(hours)h"
        }
        let days = hours / 24
        return "\(days)d"
    }

    func formatDecimalBytes(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var index = 0
        while value >= 1_000, index < units.count - 1 {
            value /= 1_000
            index += 1
        }
        if index == 0 {
            return "\(bytes) B"
        }
        if value.rounded() == value {
            return String(format: "%.0f %@", value, units[index])
        }
        return String(format: "%.1f %@", value, units[index])
    }

    func formatBinaryBytesCompact(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var index = 0
        while value >= 1_024, index < units.count - 1 {
            value /= 1_024
            index += 1
        }
        if index == 0 {
            return "\(bytes) B"
        }
        if value.rounded() == value {
            return String(format: "%.0f %@", value, units[index])
        }
        return String(format: "%.1f %@", value, units[index])
    }

    func formatBytes(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var index = 0
        while value >= 1_024, index < units.count - 1 {
            value /= 1_024
            index += 1
        }
        if index == 0 {
            return "\(bytes) B"
        }
        if value.rounded() == value {
            return String(format: "%.0f %@", value, units[index])
        }
        return String(format: "%.1f %@", value, units[index])
    }

    func parsePositiveUInt64(_ value: String) -> UInt64? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let parsed = UInt64(trimmed), parsed > 0 else {
            return nil
        }
        return parsed
    }
}
