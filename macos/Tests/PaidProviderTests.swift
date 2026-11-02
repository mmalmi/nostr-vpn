import AppKit
import SwiftUI

@main
struct PaidProviderTests {
    @MainActor static func main() throws {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        app.appearance = NSAppearance(named: .darkAqua)
        UserDefaults.standard.set(true, forKey: "updates.autoCheck")
        let manager = AppManager()
        precondition(manager.fixtureMode)
        precondition(UserDefaults.standard.bool(forKey: "updates.autoCheck"), "Fixture mode must preserve update preferences")
        // Deep links must stage for user confirmation instead of dispatching.
        let joinLink = URL(string: "nvpn://join-request/nvpn1requestpayload")!
        manager.handle(url: joinLink)
        precondition(manager.deepLinkJoinRequest == joinLink.absoluteString, "Join deep links must stage for the confirm alert")
        precondition(!manager.actionInFlight && manager.actionStatus.isEmpty, "Join deep links must not dispatch an import")
        manager.deepLinkJoinRequest = nil
        let link = URL(string: "nvpn://paid-exit/@npub1example?maxMsatPerGb=1000")!
        manager.handle(url: link)
        precondition(manager.paidExitChooserRequested)
        precondition(manager.deepLinkPaidExit == link.absoluteString, "Paid-exit deep links must stage for the market field")
        precondition(manager.pendingPaidExitLink == nil, "Paid-exit deep links must not queue a dispatch")
        precondition(manager.openingPaidExitLink == nil, "Paid-exit deep links must not dispatch")
        manager.deepLinkPaidExit = nil
        manager.paidExitChooserRequested = false
        var offer = manager.state.paidRouteMarket.offers[1]
        offer.acceptedMints = ["https://testnut.cashu.space", "https://mint.example/Bitcoin"]
        manager.state.paidRouteMarket.offers[1] = offer
        manager.state.paidRouteMarket.visibleOffers = manager.state.paidRouteMarket.offers
        let session = manager.state.paidRouteMarket.sessions[0]
        let channel = manager.state.paidRouteMarket.channels[0]
        let reasons = [
            "Seller did not acknowledge the session within 30 seconds",
            "Payment setup failed at https://mint.example/Bitcoin: connection refused",
            "Cannot resolve payment mint mint.example: hostname not found",
        ]
        manager.state.paidRouteMarket.sessions = reasons.enumerated().map { index, reason in
            var failed = session
            failed.sessionId = "failed-session-\(index)"
            failed.channelId = "failed-channel-\(index)"
            failed.lifecycleStatus = "failed"
            failed.titleText = "Connection failed"
            failed.statusText = reason
            failed.allowRouting = false
            failed.paymentChannelReady = false
            failed.canRate = false
            failed.usageText = "0 B used"
            failed.paidText = "0 sat paid"
            return failed
        }
        manager.state.paidRouteMarket.channels = reasons.enumerated().map { index, reason in
            var failed = channel
            failed.channelId = "failed-channel-\(index)"
            failed.status = "failed"
            failed.error = reason
            return failed
        }
        manager.state.exitNodeActive = false
        manager.state.exitNodeBlocked = true
        manager.state.exitNodeStatusText = "Automatic paid exit · Payment unavailable · mint.example · Connection refused · Trying another provider · Internet paused by nvpn to prevent leaks"
        let view = NSHostingView(rootView: RootView(manager: manager))
        let rect = NSRect(x: 0, y: 0, width: 1100, height: 900)
        let window = NSWindow(contentRect: rect, styleMask: [.borderless], backing: .buffered, defer: false)
        window.contentView = view
        view.frame = rect
        view.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.2))
        view.layoutSubtreeIfNeeded()
        // Exercise the actual text field's Paste command while an action is queued.
        manager.paidExitChooserRequested = true
        let deadline = Date(timeIntervalSinceNow: 3)
        while providerField(in: view) == nil && Date() < deadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.02))
        }
        guard let field = providerField(in: view) else { fatalError("Provider field is missing") }
        let clipboard = NSPasteboard.general.pasteboardItems?.map { item in
            item.types.compactMap { type in item.data(forType: type).map { (type, $0) } }
        } ?? []
        defer {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.writeObjects(clipboard.map { values in
                let item = NSPasteboardItem()
                for (type, data) in values { item.setData(data, forType: type) }
                return item
            })
        }
        let pasted = "nvpn://paid-exit/npub12mh8r6uetvj9fptwua9gtng0ycz8uvzn0vmxsaddk7vfegeu29ts3qngt3?maxMsatPerGb=1000"
        manager.actionInFlight = true
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(pasted, forType: .string)
        window.makeFirstResponder(field)
        guard let editor = window.firstResponder as? NSTextView else { fatalError("Provider field did not focus") }
        editor.selectAll(nil)
        editor.insertText("nvpn://paid-exit/", replacementRange: editor.selectedRange())
        precondition(manager.pendingPaidExitLink == nil, "Typing an incomplete link must not open it")
        editor.selectAll(nil)
        editor.paste(nil)
        let pasteDeadline = Date(timeIntervalSinceNow: 3)
        while manager.pendingPaidExitLink == nil && Date() < pasteDeadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.02))
        }
        precondition(manager.pendingPaidExitLink == pasted, "Pasting must open the provider without a button")
        manager.actionInFlight = false
        manager.openPendingPaidExitLink()
        precondition(manager.pendingPaidExitLink == nil)
        window.makeFirstResponder(nil)
        manager.openingPaidExitLink = pasted
        manager.actionInFlight = true
        let busyDeadline = Date(timeIntervalSinceNow: 3)
        while field.isEnabled && Date() < busyDeadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.02))
        }
        precondition(!field.isEnabled && !field.isEditable, "Opening a provider must disable the native input")
        if CommandLine.arguments.count > 1 {
            view.layoutSubtreeIfNeeded()
            try snapshot(view, to: CommandLine.arguments[1] + ".opening.png")
        }
        manager.openingPaidExitLink = nil
        manager.actionInFlight = false
        let readyDeadline = Date(timeIntervalSinceNow: 3)
        while !field.isEnabled && Date() < readyDeadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.02))
        }
        precondition(field.isEnabled && field.isEditable, "Completion must restore the provider input")
        manager.state.paidRouteMarket.manualProviderLink = pasted
        manager.state.rev += 1
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))
        manager.state.internetSource = "direct"
        manager.state.paidRouteMarket.manualProviderLink = ""
        manager.state.rev += 1
        let clearedDeadline = Date(timeIntervalSinceNow: 3)
        while !field.stringValue.isEmpty && Date() < clearedDeadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.02))
        }
        precondition(field.stringValue.isEmpty, "Cancelling the provider choice must clear the pasted link")
        guard CommandLine.arguments.count > 1 else {
            print("Provider URL queue passed")
            return
        }
        try snapshot(view, to: CommandLine.arguments[1])
        print("Provider URL queue and failure-reason UI rendering passed")
    }

    @MainActor static func snapshot(_ view: NSView, to path: String) throws {
        guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { fatalError("No bitmap") }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
    }

    @MainActor static func providerField(in view: NSView) -> NSTextField? {
        if let field = view as? NSTextField,
           field.placeholderString == "Provider npub or paid exit link" { return field }
        return view.subviews.lazy.compactMap { providerField(in: $0) }.first
    }
}
