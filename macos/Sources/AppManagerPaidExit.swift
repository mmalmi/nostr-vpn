import AppKit
import Darwin
import Foundation
import SwiftUI

extension AppManager {
    func setAdvertiseExitNode(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(advertiseExitNode: enabled)), status: "Saving routing")
    }

    func setPaidExitEnabled(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(paidExitEnabled: enabled)), status: "Saving selling")
    }

    func savePaidExitSellerSettings(
        upstream: String,
        priceMsatPerGb: String,
        acceptedMints: String,
        maxChannelCapacitySat: String,
        channelExpirySecs: String,
        freeProbeUnits: String,
        graceUnits: String,
        countryCode: String,
        asn: String
    ) {
        guard let priceMsatPerGb = UInt64(priceMsatPerGb.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            actionError = "Enter an integer price in msat/GB."
            return
        }
        dispatch(.updateSettings(patch: settingsPatch(
            paidExitUpstream: upstream,
            paidExitPriceMsatPerGb: priceMsatPerGb,
            paidExitAcceptedMints: acceptedMints,
            paidExitMaxChannelCapacitySat: UInt64(maxChannelCapacitySat.trimmingCharacters(in: .whitespacesAndNewlines)),
            paidExitChannelExpirySecs: Self.parsePaidExitDurationSeconds(channelExpirySecs),
            paidExitFreeProbeUnits: Self.parsePaidExitTrafficUnits(freeProbeUnits),
            paidExitGraceUnits: Self.parsePaidExitTrafficUnits(graceUnits),
            paidExitCountryCode: countryCode,
            paidExitAsn: asn
        )), status: "Saving seller settings")
    }

    static func parsePaidExitTrafficUnits(_ value: String) -> UInt64? {
        parsePaidExitUnits(value, byteScale: 1_024)
    }

    static func parsePaidExitDurationSeconds(_ value: String) -> UInt64? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if let seconds = UInt64(trimmed) {
            return seconds
        }
        let lowercased = trimmed
            .replacingOccurrences(of: ",", with: "")
            .lowercased()
        var numberText = ""
        var unitText = ""
        for character in lowercased {
            if character.isNumber || character == "." {
                numberText.append(character)
            } else if !character.isWhitespace {
                unitText.append(character)
            }
        }
        guard let amount = Double(numberText), amount.isFinite, amount >= 0 else {
            return nil
        }
        let multiplier: Double
        switch unitText {
        case "", "s", "sec", "secs", "second", "seconds":
            multiplier = 1
        case "m", "min", "mins", "minute", "minutes":
            multiplier = 60
        case "h", "hr", "hrs", "hour", "hours":
            multiplier = 3_600
        case "d", "day", "days":
            multiplier = 86_400
        default:
            return nil
        }
        let seconds = (amount * multiplier).rounded()
        guard seconds >= 0, seconds <= Double(UInt64.max) else {
            return nil
        }
        return UInt64(seconds)
    }

    static func parsePaidExitUnits(_ value: String, byteScale: Double) -> UInt64? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if let rawUnits = UInt64(trimmed) {
            return rawUnits
        }
        return parseByteUnitCount(trimmed, scale: byteScale)
    }

    static func parseByteUnitCount(_ value: String, scale: Double) -> UInt64? {
        let lowercased = value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: ",", with: "")
            .lowercased()
        var numberText = ""
        var unitText = ""
        for character in lowercased {
            if character.isNumber || character == "." {
                numberText.append(character)
            } else if !character.isWhitespace {
                unitText.append(character)
            }
        }
        guard let amount = Double(numberText), amount.isFinite, amount >= 0 else {
            return nil
        }
        let multiplier: Double
        switch unitText {
        case "", "b", "byte", "bytes":
            multiplier = 1
        case "k", "kb", "kib":
            multiplier = scale
        case "m", "mb", "mib":
            multiplier = pow(scale, 2)
        case "g", "gb", "gib":
            multiplier = pow(scale, 3)
        case "t", "tb", "tib":
            multiplier = pow(scale, 4)
        default:
            return nil
        }
        let units = (amount * multiplier).rounded()
        guard units >= 0, units <= Double(UInt64.max) else {
            return nil
        }
        return UInt64(units)
    }

    func addPaidRouteWalletMint(url: String) {
        let trimmedUrl = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedUrl.isEmpty else { return }
        dispatch(
            .addPaidRouteWalletMint(url: trimmedUrl, label: nil),
            status: "Saving wallet"
        )
    }

    func removePaidRouteWalletMint(_ url: String) {
        dispatch(.removePaidRouteWalletMint(url: url), status: "Saving wallet")
    }

    func setPaidRouteDefaultMint(_ url: String) {
        dispatch(.setPaidRouteDefaultMint(url: url), status: "Saving wallet")
    }

    func refreshPaidRouteWallet() {
        dispatch(.refreshPaidRouteWallet(refresh: true), status: "Refreshing wallet")
    }

    func topUpPaidRouteWallet(mintUrl: String?, amountSat: String) {
        guard let amount = Self.parsePositiveUInt64(amountSat) else { return }
        dispatch(
            .topUpPaidRouteWallet(mintUrl: Self.optionalTrimmed(mintUrl), amountSat: amount),
            status: "Creating invoice"
        )
    }

    func receivePaidRouteWalletToken(_ token: String) {
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        dispatch(.receivePaidRouteWalletToken(token: trimmed), status: "Receiving token")
    }

    func previewPaidRouteWalletToken(_ token: String) {
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        dispatch(.previewPaidRouteWalletToken(token: trimmed), status: "Checking token")
    }

    func sendPaidRouteWalletToken(mintUrl: String?, amountSat: String) {
        guard let amount = Self.parsePositiveUInt64(amountSat) else { return }
        dispatch(
            .sendPaidRouteWalletToken(mintUrl: Self.optionalTrimmed(mintUrl), amountSat: amount),
            status: "Creating token"
        )
    }

    func withdrawPaidRouteWalletLightning(mintUrl: String?, invoice: String) {
        let trimmedInvoice = invoice.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedInvoice.isEmpty else { return }
        dispatch(
            .withdrawPaidRouteWalletLightning(
                mintUrl: Self.optionalTrimmed(mintUrl),
                invoice: trimmedInvoice
            ),
            status: "Paying invoice"
        )
    }

    func buyPaidRouteOffer(_ offer: NativePaidRouteOfferState) {
        dispatch(
            .buyPaidRouteOffer(
                offerKey: offer.key,
                mintUrl: nil,
                channelCapacitySat: nil
            ),
            status: "Buying"
        )
    }

    func setManualPaidExitProvider(_ provider: String) {
        let provider = provider.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !provider.isEmpty else { return }
        dispatch(.setManualPaidExitProvider(provider: provider), status: "Adding provider")
    }

    func clearManualPaidExitProvider() {
        dispatch(.clearManualPaidExitProvider, status: "Clearing provider")
    }

    func usePaidRouteSession(_ session: NativePaidRouteSessionState) {
        dispatch(
            .selectPaidRouteSession(sessionId: session.sessionId, connect: true),
            status: "Connecting"
        )
    }

    func probePaidRouteSession(_ session: NativePaidRouteSessionState) {
        dispatch(
            .probePaidRouteSession(
                sessionId: session.sessionId,
                timeoutSecs: 5
            ),
            status: "Checking connection"
        )
    }

    func openPaidRouteChannelFromWallet(_ session: NativePaidRouteSessionState) {
        dispatch(
            .openPaidRouteChannelFromWallet(
                sessionId: session.sessionId,
                mintUrl: nil,
                paidMsat: nil,
                maxAmountPerOutput: nil,
                keysetId: nil
            ),
            status: "Funding seller"
        )
    }

    func signPaidRoutePaymentEnvelopeFromWallet(_ session: NativePaidRouteSessionState) {
        dispatch(
            .signPaidRoutePaymentEnvelopeFromWallet(
                sessionId: session.sessionId,
                kind: "balance-update",
                deliveredUnits: nil,
                paidMsat: nil
            ),
            status: "Paying seller"
        )
    }

    func closePaidRouteChannelFromWallet(_ session: NativePaidRouteSessionState) {
        dispatch(
            .closePaidRouteChannelFromWallet(
                sessionId: session.sessionId,
                publish: true
            ),
            status: "Closing channel"
        )
    }

    func sendPaidRoutePaymentEnvelope(_ envelopeJson: String) {
        let trimmed = envelopeJson.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        dispatch(.sendPaidRoutePaymentEnvelope(envelopeJson: trimmed), status: "Sending payment")
    }

    func streamPaidRoutePayments() {
        dispatch(
            .streamPaidRoutePayments(publish: true, minIncrementMsat: 1, limit: 0),
            status: "Paying for usage"
        )
    }

    func clearPaidRouteActivity() {
        dispatch(.clearPaidRouteActivity, status: "Clearing activity")
    }

    func receivePaidRoutePayments() {
        dispatch(.receivePaidRoutePayments(durationSecs: 5), status: "Receiving payments")
    }

    func collectPaidExitChannel(_ session: NativePaidRouteSessionState) {
        let channelId = session.channelId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !channelId.isEmpty else { return }
        dispatch(.collectPaidExitChannel(channelId: channelId), status: "Collecting payment")
    }

    func collectDuePaidExitChannels() {
        dispatch(.collectDuePaidExitChannels, status: "Collecting payments")
    }

    static func optionalTrimmed(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? nil : trimmed
    }

    static func emptyAllFilter(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed == "all" ? "" : trimmed
    }

    static func parsePositiveUInt64(_ value: String) -> UInt64? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let amount = UInt64(trimmed), amount > 0 else {
            return nil
        }
        return amount
    }

    func setPaidRouteMarketFilter(countryCode: String, sort: String) {
        dispatch(
            .setPaidRouteMarketFilter(
                query: "",
                countryCode: Self.emptyAllFilter(countryCode),
                mintUrl: "",
                requireIpv4: false,
                requireIpv6: false,
                sort: sort.isEmpty ? "quality" : sort
            ),
            status: "Filtering sellers"
        )
    }

    func discoverPaidRouteOffers() {
        dispatch(.discoverPaidRouteOffers(durationSecs: 5), status: "Finding sellers")
    }
}
