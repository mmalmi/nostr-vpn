import AppKit
import CoreImage
import Foundation
import SwiftUI

enum PaidRouteWalletFlow: String, Identifiable {
    case receive
    case send

    var id: String { rawValue }
}

private func isLikelyCashuToken(_ value: String) -> Bool {
    let token = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return token.count > 12 && token.lowercased().hasPrefix("cashu")
}

private func validatedCashuMintURL(_ value: String) -> String? {
    let candidate = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard
        !candidate.isEmpty,
        let components = URLComponents(string: candidate),
        let scheme = components.scheme?.lowercased(),
        scheme == "http" || scheme == "https",
        components.host?.isEmpty == false,
        components.query == nil,
        components.fragment == nil
    else {
        return nil
    }
    return candidate
}

extension RootView {
    var paidRouteWalletSettings: some View {
        let market = state.paidRouteMarket
        return VStack(alignment: .leading, spacing: 14) {
            if market.supported {
                paidRouteWalletSection(market.wallet)
            } else {
                surface {
                    sectionHeader("Wallet", systemImage: "creditcard.fill")
                    if !market.statusText.isEmpty {
                        Text(market.statusText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    func paidRouteWalletSection(_ wallet: NativePaidRouteWalletState) -> some View {
        surface {
            Text("Pay for internet access and receive earnings when you sell bandwidth.")
                .font(.callout)
                .foregroundStyle(.secondary)

            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    sectionHeader("Wallet", systemImage: "creditcard.fill")
                    if wallet.balanceKnown {
                        Text(fallbackText(wallet.totalBalanceText, formatPaidRouteMsat(wallet.totalBalanceMsat)))
                            .font(.system(size: 30, weight: .bold, design: .rounded))
                        Text("Available")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if !wallet.channelBalanceText.isEmpty {
                        Text(wallet.channelBalanceText)
                            .font(.callout.weight(.medium))
                            .foregroundStyle(.secondary)
                    }
                    if !wallet.defaultMint.isEmpty {
                        Text(wallet.defaultMint)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                Spacer(minLength: 12)
                Button {
                    manager.refreshPaidRouteWallet()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh wallet")
                .disabled(manager.actionInFlight)
            }

            HStack(spacing: 10) {
                Button {
                    paidRouteWalletFlow = .receive
                } label: {
                    Label("Receive", systemImage: "arrow.down.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)

                Button {
                    paidRouteWalletFlow = .send
                } label: {
                    Label("Send", systemImage: "arrow.up.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            }
            .controlSize(.large)

            if state.walletFiatEnabled {
                if !wallet.fiatBalanceText.isEmpty {
                    Text(wallet.fiatBalanceText)
                        .font(.headline)
                }

                if !wallet.exchangeRateText.isEmpty {
                    Text([wallet.exchangeRateText, wallet.exchangeRateStatus]
                        .filter { !$0.isEmpty && $0 != "Updated" && $0 != "Refreshing" }
                        .joined(separator: " · "))
                        .font(.caption)
                        .foregroundStyle(wallet.exchangeRateStale ? Color.orange : Color.secondary)
                }
            }

            HStack(spacing: 8) {
                TextField("Mint URL", text: $paidRouteMintUrl)
                    .onSubmit(addPaidRouteMintFromInput)
                Button {
                    addPaidRouteMintFromInput()
                } label: {
                    Label("Add", systemImage: "plus.circle.fill")
                }
                .disabled(manager.actionInFlight || validatedCashuMintURL(paidRouteMintUrl) == nil)
            }

            if !paidRouteMintUrl.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
               validatedCashuMintURL(paidRouteMintUrl) == nil {
                Text("Enter an http(s) mint URL without a query or fragment.")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if wallet.mints.isEmpty {
                emptyRow("No wallet mints", systemImage: "creditcard")
            } else {
                VStack(spacing: 6) {
                    ForEach(wallet.mints, id: \.url) { mint in
                        paidRouteMintRow(mint)
                    }
                }
            }

            paidRouteWalletActionResult(wallet.lastAction)
        }
        .sheet(item: $paidRouteWalletFlow) { flow in
            paidRouteWalletFlowSheet(flow, wallet: wallet)
        }
    }

    func paidRouteWalletFlowSheet(
        _ flow: PaidRouteWalletFlow,
        wallet: NativePaidRouteWalletState
    ) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(flow == .receive ? "Receive" : "Send")
                        .font(.title2.weight(.semibold))
                    if wallet.balanceKnown {
                        Text(fallbackText(wallet.totalBalanceText, formatPaidRouteMsat(wallet.totalBalanceMsat)))
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Button("Done") { paidRouteWalletFlow = nil }
            }

            if flow == .receive {
                GroupBox("Lightning") {
                    VStack(alignment: .leading, spacing: 8) {
                        if wallet.defaultMint.isEmpty {
                            Text("Add a mint before using Lightning.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 8) {
                            TextField("Amount in sats", text: $paidRouteTopupAmount)
                            Button("Create Invoice") {
                                manager.topUpPaidRouteWallet(mintUrl: nil, amountSat: paidRouteTopupAmount)
                            }
                            .disabled(manager.actionInFlight || wallet.defaultMint.isEmpty || parsePositiveUInt64(paidRouteTopupAmount) == nil)
                        }
                    }
                    .padding(6)
                }
                GroupBox("Token") {
                    HStack(spacing: 8) {
                        TextField("Paste token", text: $paidRouteReceiveToken)
                            .onChange(of: paidRouteReceiveToken) { _, value in
                                autoReceivePaidRouteWalletToken(value)
                            }
                        Button {
                            showingWalletTokenScanner = true
                        } label: {
                            Label("Scan QR", systemImage: "camera.viewfinder")
                        }
                        .disabled(manager.actionInFlight)
                    }
                    .padding(6)
                }
            } else {
                GroupBox("Lightning") {
                    VStack(alignment: .leading, spacing: 8) {
                        if wallet.defaultMint.isEmpty {
                            Text("Add a mint before using Lightning.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 8) {
                            TextField("Invoice", text: $paidRouteWithdrawInvoice)
                            Button("Pay") {
                                manager.withdrawPaidRouteWalletLightning(mintUrl: nil, invoice: paidRouteWithdrawInvoice)
                            }
                            .disabled(manager.actionInFlight || wallet.defaultMint.isEmpty || paidRouteWithdrawInvoice.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        }
                    }
                    .padding(6)
                }
                GroupBox("Token") {
                    HStack(spacing: 8) {
                        TextField("Amount in sats", text: $paidRouteSendAmount)
                        Button("Export") {
                            manager.sendPaidRouteWalletToken(mintUrl: nil, amountSat: paidRouteSendAmount)
                        }
                        .disabled(manager.actionInFlight || wallet.defaultMint.isEmpty || parsePositiveUInt64(paidRouteSendAmount) == nil)
                    }
                    .padding(6)
                }
            }

            paidRouteWalletActionResult(wallet.lastAction, showInvoiceQRCode: flow == .receive)
        }
        .padding(22)
        .frame(width: 520)
        .sheet(isPresented: $showingWalletTokenScanner) {
            QRCodeScannerSheet { value in
                previewPaidRouteWalletToken(value)
            }
        }
        .sheet(isPresented: $showingWalletTokenReview) {
            paidRouteWalletTokenReview(wallet: state.paidRouteMarket.wallet)
        }
    }

    func autoReceivePaidRouteWalletToken(_ value: String) {
        guard isLikelyCashuToken(value) else { return }
        previewPaidRouteWalletToken(value)
    }

    func previewPaidRouteWalletToken(_ value: String) {
        let token = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else { return }
        paidRouteReceiveToken = ""
        showingWalletTokenScanner = false
        pendingWalletToken = token
        redeemingWalletToken = false
        showingWalletTokenReview = true
        manager.previewPaidRouteWalletToken(token)
    }

    func paidRouteWalletTokenReview(wallet: NativePaidRouteWalletState) -> some View {
        let preview = wallet.lastAction
        let checked = preview.kind == "preview"
        let ready = checked && preview.tokenRedeemable && !manager.actionInFlight
        let reviewStatus = !state.error.isEmpty
            ? "Could not redeem token: \(state.error)"
            : (redeemingWalletToken ? "Redeeming…" : (checked ? preview.statusText : "Checking…"))
        return VStack(alignment: .leading, spacing: 16) {
            Text("Redeem token?")
                .font(.title2.weight(.semibold))
            LabeledContent("Amount", value: checked ? preview.amountText : "Checking…")
            if checked {
                LabeledContent("Mint", value: preview.mintUrl)
                if !preview.tokenMemo.isEmpty {
                    LabeledContent("Memo", value: preview.tokenMemo)
                }
            }
            LabeledContent("Status", value: reviewStatus)
            HStack {
                Spacer()
                Button("Cancel") {
                    showingWalletTokenReview = false
                    pendingWalletToken = ""
                    redeemingWalletToken = false
                }
                .disabled(manager.actionInFlight)
                Button("Redeem") {
                    let token = pendingWalletToken
                    redeemingWalletToken = true
                    manager.receivePaidRouteWalletToken(token)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(manager.actionInFlight || !ready)
            }
        }
        .padding(22)
        .frame(width: 480)
        .onChange(of: manager.actionInFlight) { _, inFlight in
            guard !inFlight, redeemingWalletToken else { return }
            if state.error.isEmpty && state.paidRouteMarket.wallet.lastAction.kind == "receive" {
                showingWalletTokenReview = false
                pendingWalletToken = ""
            }
            redeemingWalletToken = false
        }
    }

    @ViewBuilder
    func paidRouteWalletActionResult(
        _ action: NativePaidRouteWalletActionState,
        showInvoiceQRCode: Bool = false
    ) -> some View {
        if !action.kind.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Image(systemName: paidRouteWalletActionIcon(action.kind))
                        .foregroundStyle(.secondary)
                    Text(action.statusText.isEmpty ? paidRouteWalletActionTitle(action.kind) : action.statusText)
                        .font(.caption.weight(.medium))
                    if action.amountSat > 0 {
                        Text(fallbackText(action.amountText, "\(action.amountSat) sat"))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if action.feeSat > 0 {
                        Text(fallbackText(action.feeText, "\(action.feeSat) sat fee"))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if !action.paymentRequest.isEmpty {
                    if showInvoiceQRCode && action.kind == "topup" {
                        VStack(spacing: 10) {
                            QrCodeView(text: action.paymentRequest)
                                .frame(width: 220, height: 220)
                            if action.expiresAtUnix > 0 {
                                Text(paidRouteExpiryText(action.expiresAtUnix))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Button {
                                manager.copy(action.paymentRequest, as: .paymentRequest)
                            } label: {
                                Label(
                                    manager.copiedValue == .paymentRequest ? "Copied" : "Copy Invoice",
                                    systemImage: manager.copiedValue == .paymentRequest ? "checkmark" : "doc.on.doc"
                                )
                            }
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        paidRouteWalletOutputRow("Invoice", value: action.paymentRequest, copied: .paymentRequest)
                    }
                }
                if !action.token.isEmpty {
                    paidRouteWalletOutputRow("Token", value: action.token, copied: .cashuToken)
                }
                if !action.preimage.isEmpty {
                    paidRouteWalletOutputRow("Preimage", value: action.preimage, copied: .lightningPreimage)
                }
            }
        }
    }

    func paidRouteWalletOutputRow(_ title: String, value: String, copied: CopyValue) -> some View {
        HStack(spacing: 8) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 56, alignment: .leading)
            Text(value)
                .font(.caption)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
            Spacer(minLength: 8)
            copyButton(value: value, copied: copied, systemImage: "doc.on.doc")
        }
    }

    @ViewBuilder
    func paidRoutePaymentActionResult(_ action: NativePaidRoutePaymentActionState) -> some View {
        if !action.kind.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Image(systemName: paidRoutePaymentActionIcon(action.kind))
                        .foregroundStyle(.secondary)
                    Text(action.statusText.isEmpty ? paidRoutePaymentActionTitle(action.kind) : action.statusText)
                        .font(.caption.weight(.medium))
                    if action.paidMsat > 0 {
                        Text(fallbackText(action.paidText, "\(formatPaidRouteMsat(action.paidMsat)) paid"))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if action.unpaidMsat > 0 {
                        Text(fallbackText(action.unpaidText, "\(formatPaidRouteMsat(action.unpaidMsat)) behind"))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if !action.envelopeJson.isEmpty {
                    paidRouteWalletOutputRow("Payment", value: action.envelopeJson, copied: .paymentEnvelope)
                }
            }
        }
    }

    func paidRouteMintRow(_ mint: NativePaidRouteWalletMintState) -> some View {
        HStack(spacing: 10) {
            Button {
                manager.setPaidRouteDefaultMint(mint.url)
            } label: {
                Image(systemName: mint.isDefault ? "star.fill" : "star")
                    .foregroundStyle(mint.isDefault ? .yellow : .secondary)
            }
            .buttonStyle(.plain)
            .disabled(manager.actionInFlight || mint.isDefault)

            Text(mint.url)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 12)
            if mint.balanceKnown {
                Text(fallbackText(mint.balanceText, formatPaidRouteMsat(mint.balanceMsat)))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Button {
                manager.removePaidRouteWalletMint(mint.url)
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.plain)
            .disabled(manager.actionInFlight)
        }
    }

    func addPaidRouteMintFromInput() {
        guard !manager.actionInFlight else { return }
        guard let url = validatedCashuMintURL(paidRouteMintUrl) else { return }
        manager.addPaidRouteWalletMint(url: url)
        paidRouteMintUrl = ""
    }
}
