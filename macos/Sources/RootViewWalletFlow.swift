import SwiftUI

extension RootView {
    func paidRouteWalletFlowSheet(
        _ flow: PaidRouteWalletFlow,
        wallet: NativePaidRouteWalletState,
        selectedMintUrl: String,
        showsResult: Bool,
        flowError: String
    ) -> some View {
        let selectedMint = wallet.mints.first { $0.url == selectedMintUrl }
        let sendingCredit = flow == .send && selectedMintUrl == "earned-credit"
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
                    if flow == .send, let balance = earnedCreditBalance {
                        Text("Earned credit (\(balance) sat)").tag("earned-credit")
                    }
                    if selectedMint == nil && !sendingCredit {
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
            } else if sendingCredit {
                WalletCreditPaymentView(configPath: state.configPath, invoice: $paidRouteWithdrawInvoice)
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

            if !flowError.isEmpty {
                Text(flowError)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
            if showsResult && !manager.actionInFlight
                && actionMatchesFlow && action.mintUrl == selectedMintUrl {
                paidRouteWalletActionResult(action, showInvoiceQRCode: flow == .receive)
            }
        }
        .task(id: state.configPath) {
            guard flow == .send else { return }
            let path = state.configPath
            let result = try? await walletCreditCommand(configPath: path, arguments: ["credit-balance"])
            guard !Task.isCancelled else { return }
            earnedCreditBalance = result?.earnedCreditSat
            if wallet.mints.isEmpty && earnedCreditBalance != nil { paidRouteWalletSelectedMint = "earned-credit" }
        }
        .padding(22)
        .frame(width: 520)
        .onChange(of: paidRouteWalletSelectedMint) { _, _ in
            paidRouteWalletShowsResult = flow == .receive && canResumePaidRouteInvoice(wallet.lastAction)
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
        earnedCreditBalance = nil
        paidRouteWalletSelectedMint = wallet.defaultMint
        paidRouteWalletShowsResult = flow == .receive && canResumePaidRouteInvoice(wallet.lastAction)
        paidRouteWalletFlowError = ""
        paidRouteWalletFlow = flow
    }

    func canResumePaidRouteInvoice(_ action: NativePaidRouteWalletActionState) -> Bool {
        action.kind == "topup"
            && action.mintUrl == paidRouteWalletSelectedMint
            && !action.paymentRequest.isEmpty
            && (action.expiresAtUnix == 0 || Double(action.expiresAtUnix) > Date().timeIntervalSince1970)
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

private struct EarnedCreditQuote: Codable, Equatable, Sendable {
    let agreement_id: String
    let debtor: String
    let payment_hash: String
    let amount_sat: UInt64
    let fee_sat: UInt64
    let expires_at: UInt64
}

private struct WalletCreditResult: Decodable, Sendable {
    let earnedCreditSat: UInt64?
    let costCreditSat: UInt64?
    let network: String?
    let autoCashout: CreditSchedule?
    let configured: Bool?
    let forwardingFeeSat: UInt64?
    let terminalFeeSat: UInt64?
    let networkFeeMsat: UInt64?
    let quote: EarnedCreditQuote?
    let state: String?
    enum CodingKeys: String, CodingKey {
        case earnedCreditSat = "earned_credit_sat", costCreditSat = "cost_credit_sat", quote, state, network, configured
        case autoCashout = "auto_cashout", forwardingFeeSat = "forwarding_fee_sat", terminalFeeSat = "terminal_fee_sat", networkFeeMsat = "network_fee_msat"
    }
}

private struct CreditConfirmation: Encodable {
    let invoice: String
    let quote: EarnedCreditQuote
}

private func walletCreditCommand(configPath: String, arguments: [String], input: Data = Data()) async throws -> WalletCreditResult {
    try await Task.detached(priority: .userInitiated) {
        guard let binary = Bundle.main.url(forResource: "nvpn", withExtension: nil) else {
            throw CocoaError(.fileNoSuchFile)
        }
        let process = Process()
        let output = Pipe()
        let stdin = Pipe()
        process.executableURL = binary
        process.arguments = ["paid-exit", "wallet", "--config", configPath, "--json"] + arguments
        process.standardInput = stdin
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        try stdin.fileHandleForWriting.write(contentsOf: input)
        try stdin.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "NostrVPN.Wallet", code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "The wallet could not complete the request. Check that the tunnel and payment peer are available."])
        }
        return try JSONDecoder().decode(WalletCreditResult.self, from: data)
    }.value
}

private struct WalletCreditPaymentView: View {
    let configPath: String
    @Binding var invoice: String
    @State private var quote: EarnedCreditQuote?
    @State private var reviewedInvoice = ""
    @State private var reviewedDebit: UInt64 = 0
    @State private var busy = false
    @State private var message = ""
    @State private var pendingHash = ""
    @State private var scanning = false

    private var pendingKey: String { "wallet.credit.pending." + configPath }
    private var trimmedInvoice: String {
        let text = invoice.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.lowercased().hasPrefix("lightning:") ? String(text.dropFirst(10)) : text
    }

    var body: some View {
        GroupBox("Lightning") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    TextField("Paste Lightning invoice", text: $invoice)
                    Button { scanning = true } label: { Label("Scan QR", systemImage: "camera.viewfinder") }
                }
                .disabled(busy || !pendingHash.isEmpty)
                if let quote, reviewedInvoice == trimmedInvoice {
                    Text("Recipient receives \(quote.amount_sat) sat")
                    Text("You spend \(reviewedDebit) sat of earned credit, including a \(quote.fee_sat) sat fee.")
                    Button("Confirm payment") { submit(quote) }
                        .disabled(busy || !pendingHash.isEmpty)
                } else if pendingHash.isEmpty {
                    Button("Review payment") { review() }
                        .disabled(busy || trimmedInvoice.isEmpty)
                }
                if !pendingHash.isEmpty {
                    Text("Payment pending").accessibilityIdentifier("credit-payment-pending")
                    Button("Check payment") { checkPayment() }.disabled(busy)
                }
                if !message.isEmpty { Text(message).font(.callout).textSelection(.enabled) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
        .sheet(isPresented: $scanning) { QRCodeScannerSheet { invoice = $0 } }
        .onAppear { pendingHash = UserDefaults.standard.string(forKey: pendingKey) ?? "" }
        .onChange(of: invoice) { _, _ in quote = nil; message = "" }
    }
    private func review() {
        let original = trimmedInvoice
        busy = true
        message = ""
        Task { @MainActor in
            defer { busy = false }
            do {
                let result = try await walletCreditCommand(configPath: configPath, arguments: ["withdraw", "-", "--credit"], input: Data(original.utf8))
                guard original == trimmedInvoice, let received = result.quote, let debit = result.costCreditSat,
                      debit >= received.amount_sat, debit - received.amount_sat == received.fee_sat else { return }
                reviewedDebit = debit
                reviewedInvoice = original
                quote = received
            } catch { message = error.localizedDescription }
        }
    }
    private func submit(_ selected: EarnedCreditQuote) {
        guard reviewedInvoice == trimmedInvoice else { return }
        busy = true
        message = ""
        pendingHash = selected.payment_hash
        UserDefaults.standard.set(pendingHash, forKey: pendingKey)
        Task { @MainActor in
            defer { busy = false }
            do {
                let payload = try JSONEncoder().encode(CreditConfirmation(invoice: reviewedInvoice, quote: selected))
                let result = try await walletCreditCommand(configPath: configPath, arguments: ["withdraw", "-", "--confirm-credit", "-"], input: payload)
                apply(result)
            } catch { message = error.localizedDescription }
        }
    }
    private func checkPayment() {
        busy = true
        message = ""
        Task { @MainActor in
            defer { busy = false }
            do { apply(try await walletCreditCommand(configPath: configPath, arguments: ["payment-status", pendingHash])) }
            catch { message = error.localizedDescription }
        }
    }
    private func apply(_ result: WalletCreditResult) {
        guard result.state == "paid" || result.state == "unsubmitted" else { return }
        quote = nil
        pendingHash = ""
        UserDefaults.standard.removeObject(forKey: pendingKey)
        message = result.state == "paid" ? "Invoice paid." : "No payment was submitted. Review a fresh quote."
    }
}

private struct CreditSchedule: Decodable, Sendable {
    let min_sat: UInt64
    let max_sat: UInt64
    let max_fee_sat: UInt64
    let interval_secs: UInt64
}

struct WalletCreditAccountView: View {
    let configPath: String
    @State private var account: WalletCreditResult?
    @State private var expanded = false
    @State private var network = ""
    @State private var schedule: CreditSchedule?
    @State private var allowTrial = false
    @State private var minimum = "21"
    @State private var maximum = "100"
    @State private var fee = "0"
    @State private var minutes = "60"
    @State private var message = ""
    @State private var busy = false

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 9) {
                if account?.earnedCreditSat != nil {
                    if let forward = account?.forwardingFeeSat, let terminal = account?.terminalFeeSat,
                       let spent = account?.networkFeeMsat, forward > 0 || terminal > 0 || spent > 0 {
                        Text("Forwarding fees \(forward) sat · Payout fees \(terminal) sat · Lightning fees paid \(spent) msat")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if network.isEmpty {
                        Button("Connect my Lightning node") { run(["connect-lightning"]) }
                    } else {
                        Label("Lightning node connected · \(network)", systemImage: "checkmark.circle.fill")
                        if let schedule {
                            Text("Cash out \(schedule.min_sat)–\(schedule.max_sat) sat every \(schedule.interval_secs / 60) min, with a fee limit of \(schedule.max_fee_sat) sat.")
                            Button("Stop automatic cash-out") { run(["stop-auto-cashout"]) }
                        } else {
                            Grid(alignment: .leading) {
                                GridRow { Text("Minimum (sat)"); TextField("21", text: $minimum) }
                                GridRow { Text("Maximum per payment (sat)"); TextField("100", text: $maximum) }
                                GridRow { Text("Maximum fee (sat)"); TextField("0", text: $fee) }
                                GridRow { Text("Interval (minutes)"); TextField("60", text: $minutes) }
                            }
                            Button("Start automatic cash-out") {
                                if let args = scheduleArguments { run(args) }
                            }.disabled(scheduleArguments == nil)
                        }
                    }
                } else if account?.configured == true {
                    Text("Restart the tunnel to activate this account.")
                } else if account != nil {
                    Toggle("Allow a 1 sat trial per new peer, up to 10 sat total", isOn: $allowTrial)
                    Button("Enable earned credit") {
                        run(allowTrial ? ["enable-credit", "--trial-peer-sat", "1", "--trial-pool-sat", "10"] : ["enable-credit"])
                    }
                }
                if !message.isEmpty { Text(message).font(.callout).textSelection(.enabled) }
            }
            .padding(.vertical, 5)
            .disabled(busy)
        } label: {
            HStack {
                Text("Earned credit")
                if let balance = account?.earnedCreditSat { Text("\(balance) sat").foregroundStyle(.secondary) }
            }
        }
        .task(id: configPath) { await refresh() }
    }

    private var scheduleArguments: [String]? {
        guard let low = UInt64(minimum), low > 0, let high = UInt64(maximum), high >= low,
              let cost = UInt64(fee), let delay = UInt64(minutes), delay > 0, delay <= UInt64.max / 60 else { return nil }
        return ["auto-cashout", "--min-sat", String(low), "--max-sat", String(high), "--max-fee-sat", String(cost), "--interval-secs", String(delay * 60)]
    }

    @MainActor private func refresh() async {
        account = try? await walletCreditCommand(configPath: configPath, arguments: ["credit-balance"])
    }

    private func run(_ args: [String]) {
        guard !busy else { return }
        busy = true
        message = ""
        Task { @MainActor in
            defer { busy = false }
            do {
                let result = try await walletCreditCommand(configPath: configPath, arguments: args)
                if let connected = result.network { network = connected }
                schedule = result.autoCashout
                if args.first == "enable-credit" { message = "Restart the tunnel to activate earned credit." }
                await refresh()
            } catch {
                message = args == ["connect-lightning"]
                    ? "No local Core Lightning node responded. Start your node and try again."
                    : error.localizedDescription
            }
        }
    }
}
