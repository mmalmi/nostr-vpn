import SwiftUI

extension RootView {
    func paidRouteWalletFlowSheet(
        _ flow: PaidRouteWalletFlow,
        wallet: NativePaidRouteWalletState
    ) -> some View {
        let selectedMint = wallet.mints.first { $0.url == paidRouteWalletSelectedMint }
        let action = wallet.lastAction
        let actionMatchesFlow = flow == .receive
            ? action.kind.hasPrefix("topup")
            : ["send", "withdraw"].contains(action.kind)
        return VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text(flow == .receive ? "Receive" : "Send")
                    .font(.title2.weight(.semibold))
                Spacer()
                Button("Done") { paidRouteWalletFlow = nil }
            }

            VStack(alignment: .leading, spacing: 6) {
                Picker(flow == .receive ? "Receive at" : "Send from", selection: $paidRouteWalletSelectedMint) {
                    if selectedMint == nil {
                        Text("Choose a mint").tag("")
                    }
                    ForEach(wallet.mints, id: \.url) { mint in
                        Text(mint.url).tag(mint.url)
                    }
                }
                .accessibilityIdentifier("wallet-flow-mint")
                .disabled(manager.actionInFlight)
                if let selectedMint, selectedMint.balanceKnown {
                    Text("Available: \(fallbackText(selectedMint.balanceText, formatPaidRouteMsat(selectedMint.balanceMsat)))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if flow == .receive {
                GroupBox("Lightning") {
                    VStack(alignment: .leading, spacing: 8) {
                        if selectedMint == nil {
                            Text("Add a mint before using Lightning.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 8) {
                            TextField("Amount in sats", text: $paidRouteTopupAmount)
                            Button("Create Invoice") {
                                if let amount = parsePositiveUInt64(paidRouteTopupAmount) {
                                    runPaidRouteWalletAction(
                                        .topUpPaidRouteWallet(mintUrl: paidRouteWalletSelectedMint, amountSat: amount),
                                        status: "Creating invoice"
                                    )
                                }
                            }
                            .disabled(manager.actionInFlight || selectedMint == nil || parsePositiveUInt64(paidRouteTopupAmount) == nil)
                        }
                    }
                    .padding(6)
                }
                GroupBox("Token") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Tokens are received at the mint that issued them.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
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
                    }
                    .padding(6)
                }
            } else {
                GroupBox("Lightning") {
                    VStack(alignment: .leading, spacing: 8) {
                        if selectedMint == nil {
                            Text("Add a mint before using Lightning.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 8) {
                            TextField("Invoice", text: $paidRouteWithdrawInvoice)
                            Button("Pay") {
                                runPaidRouteWalletAction(
                                    .withdrawPaidRouteWalletLightning(mintUrl: paidRouteWalletSelectedMint, invoice: paidRouteWithdrawInvoice.trimmingCharacters(in: .whitespacesAndNewlines)),
                                    status: "Paying invoice"
                                )
                            }
                            .disabled(manager.actionInFlight || selectedMint == nil || paidRouteWithdrawInvoice.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        }
                    }
                    .padding(6)
                }
                GroupBox("Token") {
                    HStack(spacing: 8) {
                        TextField("Amount in sats", text: $paidRouteSendAmount)
                        Button("Export") {
                            if let amount = parsePositiveUInt64(paidRouteSendAmount) {
                                runPaidRouteWalletAction(
                                    .sendPaidRouteWalletToken(mintUrl: paidRouteWalletSelectedMint, amountSat: amount),
                                    status: "Creating token"
                                )
                            }
                        }
                        .disabled(manager.actionInFlight || selectedMint == nil || parsePositiveUInt64(paidRouteSendAmount) == nil)
                    }
                    .padding(6)
                }
            }

            if !paidRouteWalletFlowError.isEmpty {
                Text(paidRouteWalletFlowError)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
            if paidRouteWalletShowsResult && !manager.actionInFlight
                && actionMatchesFlow && action.mintUrl == paidRouteWalletSelectedMint {
                paidRouteWalletActionResult(action, showInvoiceQRCode: flow == .receive)
            }
        }
        .padding(22)
        .frame(width: 520)
        .onChange(of: paidRouteWalletSelectedMint) { _, _ in
            paidRouteWalletShowsResult = true
            paidRouteWalletFlowError = ""
        }
        .sheet(isPresented: $showingWalletTokenScanner) {
            QRCodeScannerSheet { value in
                previewPaidRouteWalletToken(value)
            }
        }
        .sheet(isPresented: $showingWalletTokenReview) {
            paidRouteWalletTokenReview(wallet: state.paidRouteMarket.wallet)
        }
    }

    func openPaidRouteWalletFlow(_ flow: PaidRouteWalletFlow, wallet: NativePaidRouteWalletState) {
        paidRouteWalletSelectedMint = wallet.defaultMint
        paidRouteWalletShowsResult = true
        paidRouteWalletFlowError = ""
        paidRouteWalletFlow = flow
    }

    func runPaidRouteWalletAction(_ action: NativeAppAction, status: String) {
        paidRouteWalletShowsResult = false
        paidRouteWalletFlowError = ""
        manager.dispatch(action, status: status) { success in
            paidRouteWalletShowsResult = success
            paidRouteWalletFlowError = success ? "" : manager.actionError
        }
    }
}
