#!/usr/bin/env swift
import AppKit
import ApplicationServices
import Foundation

enum DriverError: Error, CustomStringConvertible {
    case usage(String)
    case accessibilityPermission
    case missing(String)
    case action(String, AXError)
    case value(String, AXError)
    case invalidState(String)

    var description: String {
        switch self {
        case .usage(let message):
            return message
        case .accessibilityPermission:
            return "Accessibility permission is required for the macOS Exit DNS gate"
        case .missing(let identifier):
            return "visible control did not appear: \(identifier)"
        case .action(let identifier, let error):
            return "AX action failed for \(identifier): \(error.rawValue)"
        case .value(let identifier, let error):
            return "AX value update failed for \(identifier): \(error.rawValue)"
        case .invalidState(let message):
            return message
        }
    }
}

struct DnsCase {
    let slug: String
    let mode: String
    let modeLabel: String
    let provider: String?
    let providerLabel: String?
    let customURL: String?
    let bootstrapIPs: String?
    let throughServers: String?

    static func named(_ slug: String) throws -> DnsCase {
        switch slug {
        case "automatic":
            return DnsCase(
                slug: slug,
                mode: "automatic",
                modeLabel: "Automatic (recommended)",
                provider: nil,
                providerLabel: nil,
                customURL: nil,
                bootstrapIPs: nil,
                throughServers: nil
            )
        case "cloudflare":
            return DnsCase(
                slug: slug,
                mode: "encrypted",
                modeLabel: "Encrypted DNS",
                provider: "cloudflare",
                providerLabel: "Cloudflare",
                customURL: nil,
                bootstrapIPs: nil,
                throughServers: nil
            )
        case "quad9":
            return DnsCase(
                slug: slug,
                mode: "encrypted",
                modeLabel: "Encrypted DNS",
                provider: "quad9",
                providerLabel: "Quad9",
                customURL: nil,
                bootstrapIPs: nil,
                throughServers: nil
            )
        case "custom":
            return DnsCase(
                slug: slug,
                mode: "encrypted",
                modeLabel: "Encrypted DNS",
                provider: "custom",
                providerLabel: "Custom DoH",
                customURL: "https://dns.google/dns-query",
                bootstrapIPs: "8.8.8.8,8.8.4.4",
                throughServers: nil
            )
        case "through-exit":
            return DnsCase(
                slug: slug,
                mode: "through_exit",
                modeLabel: "DNS through exit",
                provider: nil,
                providerLabel: nil,
                customURL: nil,
                bootstrapIPs: nil,
                throughServers: "10.99.79.53"
            )
        default:
            throw DriverError.usage("unsupported Exit DNS case: \(slug)")
        }
    }
}

func attribute(_ element: AXUIElement, _ name: String) -> AnyObject? {
    var value: CFTypeRef?
    guard AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success else {
        return nil
    }
    return value
}

func stringAttribute(_ element: AXUIElement, _ name: String) -> String {
    attribute(element, name) as? String ?? ""
}

func boolAttribute(_ element: AXUIElement, _ name: String) -> Bool? {
    attribute(element, name) as? Bool
}

func toggleValue(_ element: AXUIElement) -> Bool? {
    if let value = attribute(element, kAXValueAttribute) as? NSNumber {
        return value.boolValue
    }
    return boolAttribute(element, kAXValueAttribute)
}

func descendants(_ root: AXUIElement) -> [AXUIElement] {
    var found: [AXUIElement] = []
    var pending = [root]
    var visited = 0
    while let element = pending.popLast(), visited < 20_000 {
        visited += 1
        found.append(element)
        if let children = attribute(element, kAXChildrenAttribute) as? [AXUIElement] {
            pending.append(contentsOf: children.reversed())
        }
    }
    return found
}

func visible(_ element: AXUIElement) -> Bool {
    boolAttribute(element, kAXHiddenAttribute) != true
}

func findNow(_ application: AXUIElement, identifier: String) -> AXUIElement? {
    descendants(application).first {
        stringAttribute($0, kAXIdentifierAttribute) == identifier && visible($0)
    }
}

func find(
    _ application: AXUIElement,
    identifier: String,
    timeout: TimeInterval = 12
) throws -> AXUIElement {
    let deadline = Date().addingTimeInterval(timeout)
    repeat {
        if let element = findNow(application, identifier: identifier) {
            return element
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline
    let finalElements = descendants(application)
    if let element = finalElements.first(where: {
        stringAttribute($0, kAXIdentifierAttribute) == identifier && visible($0)
    }) {
        return element
    }
    let identifiers = finalElements.compactMap { element -> String? in
        let identifier = stringAttribute(element, kAXIdentifierAttribute)
        guard !identifier.isEmpty, visible(element) else { return nil }
        return "\(stringAttribute(element, kAXRoleAttribute)):\(identifier)"
    }
    fputs("Visible AX identifiers: \(identifiers.joined(separator: ", "))\n", stderr)
    throw DriverError.missing(identifier)
}

func textCandidates(_ element: AXUIElement) -> [String] {
    [
        kAXValueAttribute,
        kAXTitleAttribute,
        kAXDescriptionAttribute,
        kAXHelpAttribute,
    ].compactMap { name in
        let text = stringAttribute(element, name)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }
}

func labelMatches(_ candidate: String, _ expected: String) -> Bool {
    candidate == expected
        || candidate.hasPrefix("\(expected),")
        || candidate.hasSuffix(", \(expected)")
}

func pickerReading(_ root: AXUIElement, expected: String) -> String? {
    for element in descendants(root) {
        for candidate in textCandidates(element) where labelMatches(candidate, expected) {
            return candidate
        }
    }
    return nil
}

func actionableElement(_ root: AXUIElement) -> AXUIElement? {
    var candidates = descendants(root)
    var parent = attribute(root, kAXParentAttribute) as! AXUIElement?
    for _ in 0..<5 {
        guard let current = parent else { break }
        candidates.append(current)
        parent = attribute(current, kAXParentAttribute) as! AXUIElement?
    }
    for element in candidates {
        var names: CFArray?
        if AXUIElementCopyActionNames(element, &names) == .success,
           let actions = names as? [String],
           actions.contains(kAXPressAction) {
            return element
        }
    }
    return nil
}

func pressElement(_ element: AXUIElement, label: String) throws {
    guard let target = actionableElement(element) else {
        throw DriverError.action(label, .actionUnsupported)
    }
    let error = AXUIElementPerformAction(target, kAXPressAction as CFString)
    guard error == .success else {
        throw DriverError.action(label, error)
    }
}

func press(
    _ application: AXUIElement,
    _ identifier: String,
    successIdentifier: String? = nil
) throws {
    let element = try find(application, identifier: identifier)
    try pressElement(element, label: identifier)
    let deadline = Date().addingTimeInterval(5)
    repeat {
        if let successIdentifier,
           findNow(application, identifier: successIdentifier) != nil {
            Thread.sleep(forTimeInterval: 0.15)
            return
        }
        if successIdentifier == nil {
            Thread.sleep(forTimeInterval: 0.2)
            return
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline
    throw DriverError.missing(successIdentifier ?? identifier)
}

func pressAndWaitForSaveCompletion(
    _ application: AXUIElement
) throws {
    let identifier = "exit-dns-save"
    let save = try find(application, identifier: identifier)
    guard boolAttribute(save, kAXEnabledAttribute) == true else {
        throw DriverError.invalidState("Exit DNS save was not actionable")
    }
    try pressElement(save, label: identifier)

    let inFlightProbeDeadline = Date().addingTimeInterval(5)
    var observedInFlight = false
    repeat {
        if let current = findNow(application, identifier: identifier),
           boolAttribute(current, kAXEnabledAttribute) == false {
            observedInFlight = true
            break
        }
        Thread.sleep(forTimeInterval: 0.02)
    } while Date() < inFlightProbeDeadline
    if !observedInFlight {
        guard let current = findNow(application, identifier: identifier),
              boolAttribute(current, kAXEnabledAttribute) == true else {
            throw DriverError.invalidState(
                "Exit DNS save was not actionable after the completion probe"
            )
        }
        if let modalText = blockingModalText(application) {
            throw DriverError.invalidState(
                "Exit DNS save failed: \(modalText)"
            )
        }
        return
    }

    let completedDeadline = Date().addingTimeInterval(75)
    repeat {
        if let current = findNow(application, identifier: identifier),
           boolAttribute(current, kAXEnabledAttribute) == true {
            Thread.sleep(forTimeInterval: 0.15)
            if let modalText = blockingModalText(application) {
                throw DriverError.invalidState(
                    "Exit DNS save failed: \(modalText)"
                )
            }
            return
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < completedDeadline
    throw DriverError.invalidState("Exit DNS save did not complete")
}

func pressAndWaitForSellerSaveCompletion(_ application: AXUIElement) throws {
    let identifier = "paid-exit-seller-save"
    let save = try find(application, identifier: identifier)
    guard boolAttribute(save, kAXEnabledAttribute) == true else {
        throw DriverError.invalidState("paid-exit seller save was not actionable")
    }
    try pressElement(save, label: identifier)
    Thread.sleep(forTimeInterval: 0.75)
    if let modalText = blockingModalText(application) {
        throw DriverError.invalidState("paid-exit seller save failed: \(modalText)")
    }
}

func blockingModalText(_ application: AXUIElement) -> String? {
    guard let modal = descendants(application).first(where: { element in
        let role = stringAttribute(element, kAXRoleAttribute)
        return visible(element) && (role == kAXSheetRole || role == "AXDialog")
    }) else {
        return nil
    }
    var seen = Set<String>()
    let text = descendants(modal)
        .flatMap(textCandidates)
        .filter { seen.insert($0).inserted }
        .joined(separator: " — ")
    return text.isEmpty ? "unknown app error" : text
}

func pressSidebar(
    _ application: AXUIElement,
    _ identifier: String,
    pid: pid_t
) throws {
    NSRunningApplication(processIdentifier: pid)?.activate(
        options: [.activateAllWindows]
    )
    Thread.sleep(forTimeInterval: 0.15)
    let actionDeadline = Date().addingTimeInterval(20)
    var lastActionError: AXError?
    repeat {
        if let modalText = blockingModalText(application) {
            throw DriverError.invalidState(
                "app modal blocked \(identifier): \(modalText)"
            )
        }
        if let window = findNow(
            application,
            identifier: "main-AppWindow-1"
        ),
           let element = findNow(window, identifier: identifier),
           boolAttribute(element, kAXEnabledAttribute) == true,
           let target = actionableElement(element),
           boolAttribute(target, kAXEnabledAttribute) == true {
            let error = AXUIElementPerformAction(
                target,
                kAXPressAction as CFString
            )
            if error == .success {
                Thread.sleep(forTimeInterval: 0.2)
                return
            }
            if error != .failure,
               error != .cannotComplete,
               error != .invalidUIElement {
                throw DriverError.action(identifier, error)
            }
            lastActionError = error
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < actionDeadline
    if let lastActionError {
        throw DriverError.action(identifier, lastActionError)
    }
    throw DriverError.invalidState(
        "sidebar control never became actionable: \(identifier)"
    )
}

func postKey(
    to pid: pid_t,
    keyCode: CGKeyCode,
    flags: CGEventFlags = []
) {
    let source = CGEventSource(stateID: .hidSystemState)
    for keyDown in [true, false] {
        let event = CGEvent(
            keyboardEventSource: source,
            virtualKey: keyCode,
            keyDown: keyDown
        )
        event?.flags = flags
        event?.postToPid(pid)
    }
}

func setText(
    _ application: AXUIElement,
    identifier: String,
    value: String,
    pid: pid_t
) throws {
    let element = try find(application, identifier: identifier)
    let focusError = AXUIElementSetAttributeValue(
        element,
        kAXFocusedAttribute as CFString,
        kCFBooleanTrue
    )
    guard focusError == .success else {
        throw DriverError.value(identifier, focusError)
    }
    postKey(to: pid, keyCode: 0, flags: .maskCommand)
    let utf16 = Array(value.utf16)
    let source = CGEventSource(stateID: .hidSystemState)
    let down = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true)
    utf16.withUnsafeBufferPointer { buffer in
        down?.keyboardSetUnicodeString(
            stringLength: buffer.count,
            unicodeString: buffer.baseAddress
        )
    }
    down?.postToPid(pid)
    CGEvent(
        keyboardEventSource: source,
        virtualKey: 0,
        keyDown: false
    )?.postToPid(pid)
    let deadline = Date().addingTimeInterval(3)
    repeat {
        if stringAttribute(element, kAXValueAttribute) == value {
            Thread.sleep(forTimeInterval: 0.1)
            return
        }
        Thread.sleep(forTimeInterval: 0.05)
    } while Date() < deadline
    throw DriverError.value(identifier, .cannotComplete)
}

func selectPicker(
    _ application: AXUIElement,
    identifier: String,
    expected: String
) throws -> String {
    var picker = try find(application, identifier: identifier)
    if let current = pickerReading(picker, expected: expected) {
        return current
    }
    if AXUIElementSetAttributeValue(
        picker,
        kAXValueAttribute as CFString,
        expected as CFTypeRef
    ) == .success {
        Thread.sleep(forTimeInterval: 0.2)
        picker = try find(application, identifier: identifier)
        if let current = pickerReading(picker, expected: expected) {
            return current
        }
    }
    try pressElement(picker, label: identifier)
    let menuDeadline = Date().addingTimeInterval(4)
    repeat {
        if let item = descendants(application).first(where: { element in
            stringAttribute(element, kAXRoleAttribute) == kAXMenuItemRole
                && textCandidates(element).contains(where: {
                    labelMatches($0, expected)
                })
        }) {
            try pressElement(item, label: "\(identifier)=\(expected)")
            break
        }
        Thread.sleep(forTimeInterval: 0.05)
    } while Date() < menuDeadline
    let selectedDeadline = Date().addingTimeInterval(4)
    repeat {
        picker = try find(application, identifier: identifier, timeout: 0.5)
        if let current = pickerReading(picker, expected: expected) {
            Thread.sleep(forTimeInterval: 0.15)
            return current
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < selectedDeadline
    throw DriverError.value(identifier, .cannotComplete)
}

func reveal(
    _ application: AXUIElement,
    identifier: String,
    pid: pid_t
) throws -> AXUIElement {
    if let element = findNow(application, identifier: identifier) {
        return element
    }
    for _ in 0..<8 {
        postKey(to: pid, keyCode: 121) // Page Down.
        Thread.sleep(forTimeInterval: 0.2)
        if let element = findNow(application, identifier: identifier) {
            return element
        }
    }
    return try find(application, identifier: identifier)
}

func createNetworkIfNeeded(
    _ application: AXUIElement,
    pid: pid_t
) throws -> Bool {
    try pressSidebar(application, "sidebar-internet", pid: pid)
    for _ in 0..<10 {
        if findNow(application, identifier: "exit-dns-mode") != nil {
            return false
        }
        postKey(to: pid, keyCode: 121) // Page Down.
        Thread.sleep(forTimeInterval: 0.15)
    }
    try pressSidebar(application, "sidebar-devices", pid: pid)
    guard findNow(application, identifier: "network-setup-create") != nil else {
        throw DriverError.invalidState(
            "Exit DNS controls are absent, but the shipped UI is not in first-run network setup"
        )
    }
    try press(
        application,
        "network-setup-create",
        successIdentifier: "network-create-name"
    )
    try setText(
        application,
        identifier: "network-create-name",
        value: "Release DNS UI Gate",
        pid: pid
    )
    try press(application, "network-create-submit")
    _ = try find(application, identifier: "sidebar-internet")
    try pressSidebar(application, "sidebar-internet", pid: pid)
    _ = try reveal(application, identifier: "exit-dns-mode", pid: pid)
    return true
}

func openPaidExitSeller(
    _ application: AXUIElement,
    pid: pid_t
) throws -> Bool {
    let created = try createNetworkIfNeeded(application, pid: pid)
    try pressSidebar(application, "sidebar-internet", pid: pid)
    _ = try reveal(application, identifier: "paid-exit-seller-open", pid: pid)
    try press(
        application,
        "paid-exit-seller-open",
        successIdentifier: "paid-exit-seller-enabled"
    )
    return created
}

func setPaidExitSellerEnabled(
    _ application: AXUIElement,
    enabled: Bool
) throws {
    var toggle = try find(application, identifier: "paid-exit-seller-enabled")
    if toggleValue(toggle) != enabled {
        try pressElement(toggle, label: "paid-exit-seller-enabled")
        let deadline = Date().addingTimeInterval(5)
        repeat {
            toggle = try find(
                application,
                identifier: "paid-exit-seller-enabled",
                timeout: 0.5
            )
            if toggleValue(toggle) == enabled {
                Thread.sleep(forTimeInterval: 0.25)
                return
            }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
    }
    guard toggleValue(toggle) == enabled else {
        throw DriverError.invalidState("paid-exit seller toggle did not retain its value")
    }
}

func observePaidExitSeller(
    _ application: AXUIElement,
    phase: String,
    pid: pid_t,
    processName: String,
    saved: Bool,
    networkCreated: Bool
) throws -> [String: Any] {
    let price = try textValue(
        application,
        identifier: "paid-exit-price-msat-per-gb"
    )
    let country = try textValue(
        application,
        identifier: "paid-exit-country-code"
    )
    let mint = try textValue(
        application,
        identifier: "paid-exit-accepted-mints"
    )
    let toggle = try find(application, identifier: "paid-exit-seller-enabled")
    guard price == "1000000", country == "FI",
          mint == "http://cashu-mint:3338", toggleValue(toggle) == true else {
        throw DriverError.invalidState("paid-exit seller public values changed")
    }
    return [
        "receiptSchema": 1,
        "phase": phase,
        "case": "paid-exit-seller",
        "pid": Int(pid),
        "processName": processName,
        "publicUiOnly": true,
        "privateStateRead": false,
        "savedViaShippedUi": saved,
        "enabledViaShippedUi": phase == "apply",
        "networkCreatedViaShippedUi": networkCreated,
        "visibleControlIdentifiers": [
            "paid-exit-seller-enabled",
            "paid-exit-price-msat-per-gb",
            "paid-exit-country-code",
            "paid-exit-accepted-mints",
            "paid-exit-seller-save",
        ].sorted(),
        "values": [
            "enabled": true,
            "priceMsatPerGb": 1_000_000,
            "countryCode": country,
            "acceptedMints": [mint],
        ],
        "observedAtUnixMilliseconds": Int64(
            (Date().timeIntervalSince1970 * 1_000).rounded(.down)
        ),
    ]
}

func assertConditionalControls(
    _ application: AXUIElement,
    spec: DnsCase,
    pid: pid_t
) throws {
    let expected = Set(
        ["exit-dns-mode", "exit-dns-save"]
            + (spec.providerLabel == nil ? [] : ["exit-dns-provider"])
            + (spec.customURL == nil
                ? []
                : ["exit-dns-custom-url", "exit-dns-bootstrap-ips"])
            + (spec.throughServers == nil ? [] : ["exit-dns-through-servers"])
    )
    for identifier in expected {
        _ = try reveal(application, identifier: identifier, pid: pid)
    }
    let conditional = Set([
        "exit-dns-provider",
        "exit-dns-custom-url",
        "exit-dns-bootstrap-ips",
        "exit-dns-through-servers",
    ])
    for identifier in conditional.subtracting(expected) {
        if findNow(application, identifier: identifier) != nil {
            throw DriverError.invalidState(
                "unexpected conditional Exit DNS control is visible: \(identifier)"
            )
        }
    }
}

func textValue(_ application: AXUIElement, identifier: String) throws -> String {
    let element = try find(application, identifier: identifier)
    return stringAttribute(element, kAXValueAttribute)
}

func canonicalCSV(_ value: String) -> String {
    Array(Set(
        value.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    )).sorted().joined(separator: ",")
}

func observe(
    _ application: AXUIElement,
    spec: DnsCase,
    phase: String,
    pid: pid_t,
    processName: String,
    saved: Bool,
    networkCreated: Bool
) throws -> [String: Any] {
    try assertConditionalControls(application, spec: spec, pid: pid)
    let modeRoot = try find(application, identifier: "exit-dns-mode")
    guard let rawMode = pickerReading(modeRoot, expected: spec.modeLabel) else {
        throw DriverError.invalidState(
            "Mode public value is not \(spec.modeLabel)"
        )
    }
    var values: [String: Any] = [
        "mode": spec.mode,
        "modeLabel": spec.modeLabel,
        "rawModeValue": rawMode,
    ]
    var identifiers = ["exit-dns-mode", "exit-dns-save"]
    if let provider = spec.provider,
       let providerLabel = spec.providerLabel {
        let providerRoot = try find(application, identifier: "exit-dns-provider")
        guard let rawProvider = pickerReading(
            providerRoot,
            expected: providerLabel
        ) else {
            throw DriverError.invalidState(
                "Provider public value is not \(providerLabel)"
            )
        }
        values["provider"] = provider
        values["providerLabel"] = providerLabel
        values["rawProviderValue"] = rawProvider
        identifiers.append("exit-dns-provider")
    }
    if let customURL = spec.customURL,
       let bootstrapIPs = spec.bootstrapIPs {
        let observedURL = try textValue(
            application,
            identifier: "exit-dns-custom-url"
        )
        let observedBootstrap = try textValue(
            application,
            identifier: "exit-dns-bootstrap-ips"
        )
        guard observedURL == customURL,
              canonicalCSV(observedBootstrap) == canonicalCSV(bootstrapIPs) else {
            throw DriverError.invalidState("custom Google DoH controls changed")
        }
        values["customUrl"] = customURL
        values["bootstrapIps"] = bootstrapIPs
        identifiers += ["exit-dns-custom-url", "exit-dns-bootstrap-ips"]
    }
    if let throughServers = spec.throughServers {
        let observed = try textValue(
            application,
            identifier: "exit-dns-through-servers"
        )
        guard observed == throughServers else {
            throw DriverError.invalidState("DNS-through-exit servers changed")
        }
        values["throughServers"] = observed
        identifiers.append("exit-dns-through-servers")
    }
    return [
        "receiptSchema": 1,
        "phase": phase,
        "case": spec.slug,
        "pid": Int(pid),
        "processName": processName,
        "publicUiOnly": true,
        "privateStateRead": false,
        "savedViaShippedUi": saved,
        "networkCreatedViaShippedUi": networkCreated,
        "visibleControlIdentifiers": identifiers.sorted(),
        "values": values,
        "observedAtUnixMilliseconds": Int64(
            (Date().timeIntervalSince1970 * 1_000).rounded(.down)
        ),
    ]
}

func writeJSON(_ value: [String: Any], path: String) throws {
    let data = try JSONSerialization.data(
        withJSONObject: value,
        options: [.prettyPrinted, .sortedKeys]
    )
    var terminated = data
    terminated.append(0x0a)
    try terminated.write(
        to: URL(fileURLWithPath: path),
        options: .atomic
    )
}

func run() throws {
    let args = CommandLine.arguments
    if args.count == 2, args[1] == "--check-accessibility" {
        guard AXIsProcessTrusted() else {
            throw DriverError.accessibilityPermission
        }
        print("MACOS_EXIT_DNS_AX_ACCESSIBILITY_READY")
        return
    }
    guard args.count == 6,
          let pid = pid_t(args[1]),
          ["apply", "readback"].contains(args[2]) else {
        throw DriverError.usage(
            "usage: macos-exit-dns-ax <pid> <apply|readback> <case> <output-json> <expected-process-name>"
        )
    }
    guard AXIsProcessTrusted() else {
        throw DriverError.accessibilityPermission
    }
    let phase = args[2]
    let application = AXUIElementCreateApplication(pid)
    let processName = stringAttribute(application, kAXTitleAttribute)
    if !processName.isEmpty, processName != args[5] {
        throw DriverError.invalidState(
            "AX PID \(pid) belongs to \(processName), expected \(args[5])"
        )
    }
    NSRunningApplication(processIdentifier: pid)?.activate(options: [.activateAllWindows])
    _ = try find(
        application,
        identifier: "main-AppWindow-1",
        timeout: 60
    )
    if args[3] == "paid-exit-seller" {
        let networkCreated = try openPaidExitSeller(application, pid: pid)
        for identifier in [
            "paid-exit-country-code",
            "paid-exit-price-msat-per-gb",
            "paid-exit-accepted-mints",
            "paid-exit-seller-save",
        ] {
            _ = try reveal(application, identifier: identifier, pid: pid)
        }
        if phase == "apply" {
            try setText(
                application,
                identifier: "paid-exit-country-code",
                value: "FI",
                pid: pid
            )
            try setText(
                application,
                identifier: "paid-exit-price-msat-per-gb",
                value: "1000000",
                pid: pid
            )
            try setText(
                application,
                identifier: "paid-exit-accepted-mints",
                value: "http://cashu-mint:3338",
                pid: pid
            )
            _ = try reveal(
                application,
                identifier: "paid-exit-seller-save",
                pid: pid
            )
            try pressAndWaitForSellerSaveCompletion(application)
            _ = try reveal(
                application,
                identifier: "paid-exit-seller-enabled",
                pid: pid
            )
            try setPaidExitSellerEnabled(application, enabled: true)
        }
        for identifier in [
            "paid-exit-country-code",
            "paid-exit-price-msat-per-gb",
            "paid-exit-accepted-mints",
            "paid-exit-seller-save",
            "paid-exit-seller-enabled",
        ] {
            _ = try reveal(application, identifier: identifier, pid: pid)
        }
        let receipt = try observePaidExitSeller(
            application,
            phase: phase,
            pid: pid,
            processName: processName.isEmpty ? args[5] : processName,
            saved: phase == "apply",
            networkCreated: networkCreated
        )
        try writeJSON(receipt, path: args[4])
        print("MACOS_PAID_EXIT_SELLER_AX_\(phase.uppercased())_OK")
        return
    }
    let spec = try DnsCase.named(args[3])
    let networkCreated = try createNetworkIfNeeded(application, pid: pid)
    _ = try reveal(application, identifier: "exit-dns-mode", pid: pid)
    if phase == "apply" {
        _ = try selectPicker(
            application,
            identifier: "exit-dns-mode",
            expected: spec.modeLabel
        )
        if let providerLabel = spec.providerLabel {
            _ = try reveal(
                application,
                identifier: "exit-dns-provider",
                pid: pid
            )
            _ = try selectPicker(
                application,
                identifier: "exit-dns-provider",
                expected: providerLabel
            )
        }
        if let customURL = spec.customURL,
           let bootstrapIPs = spec.bootstrapIPs {
            try setText(
                application,
                identifier: "exit-dns-custom-url",
                value: customURL,
                pid: pid
            )
            try setText(
                application,
                identifier: "exit-dns-bootstrap-ips",
                value: bootstrapIPs,
                pid: pid
            )
        }
        if let throughServers = spec.throughServers {
            try setText(
                application,
                identifier: "exit-dns-through-servers",
                value: throughServers,
                pid: pid
            )
        }
        try assertConditionalControls(application, spec: spec, pid: pid)
        try pressAndWaitForSaveCompletion(application)
    }
    let receipt = try observe(
        application,
        spec: spec,
        phase: phase,
        pid: pid,
        processName: processName.isEmpty ? args[5] : processName,
        saved: phase == "apply",
        networkCreated: networkCreated
    )
    try writeJSON(receipt, path: args[4])
    print("MACOS_EXIT_DNS_AX_\(phase.uppercased())_OK \(spec.slug)")
}

do {
    try run()
} catch {
    fputs("macOS Exit DNS AX driver failed: \(error)\n", stderr)
    exit(1)
}
