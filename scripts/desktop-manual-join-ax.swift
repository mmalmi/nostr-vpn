#!/usr/bin/env swift
import ApplicationServices
import Foundation

enum DriverError: Error, CustomStringConvertible {
    case usage(String)
    case accessibilityPermission
    case missing(String)
    case action(String, AXError)
    case value(String, AXError)
    case failedAction(String)

    var description: String {
        switch self {
        case .usage(let message): return message
        case .accessibilityPermission:
            return "Accessibility permission is required to drive the macOS release UI"
        case .missing(let identifier): return "visible control did not appear: \(identifier)"
        case .action(let identifier, let error):
            return "AXPress failed for \(identifier): \(error.rawValue)"
        case .value(let identifier, let error):
            return "AX value update failed for \(identifier): \(error.rawValue)"
        case .failedAction(let message):
            return "shipped UI reported Action failed: \(message)"
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

func find(
    _ application: AXUIElement,
    identifier: String,
    timeout: TimeInterval = 15
) throws -> AXUIElement {
    let deadline = Date().addingTimeInterval(timeout)
    repeat {
        if let element = descendants(application).first(where: {
            stringAttribute($0, kAXIdentifierAttribute) == identifier
                && boolAttribute($0, kAXHiddenAttribute) != true
        }) {
            return element
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline

    let controls = descendants(application).compactMap { element -> String? in
        let identifier = stringAttribute(element, kAXIdentifierAttribute)
        guard !identifier.isEmpty else { return nil }
        let role = stringAttribute(element, kAXRoleAttribute)
        return "\(role):\(identifier)"
    }
    fputs("Visible AX identifiers: \(controls.joined(separator: ", "))\n", stderr)
    throw DriverError.missing(identifier)
}

func visibleElements(_ application: AXUIElement) -> [AXUIElement] {
    descendants(application).filter { boolAttribute($0, kAXHiddenAttribute) != true }
}

func containsVisible(_ elements: [AXUIElement], identifier: String) -> Bool {
    elements.contains {
        stringAttribute($0, kAXIdentifierAttribute) == identifier
    }
}

func containsVisible(_ application: AXUIElement, identifier: String) -> Bool {
    containsVisible(visibleElements(application), identifier: identifier)
}

func visibleActionFailure(_ visible: [AXUIElement]) -> String? {
    guard visible.contains(where: { element in
        [kAXTitleAttribute, kAXValueAttribute, kAXDescriptionAttribute].contains {
            stringAttribute(element, $0) == "Action failed"
        }
    }) else {
        return nil
    }
    return visible.lazy.compactMap { element in
        [kAXValueAttribute, kAXDescriptionAttribute, kAXTitleAttribute]
            .map { stringAttribute(element, $0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .first { !$0.isEmpty && $0 != "Action failed" && $0 != "OK" }
    }.first ?? "unknown action error"
}

func requireSuccessfulCompletion(
    _ application: AXUIElement,
    _ dismissedIdentifier: String,
    _ visibleIdentifier: String,
    timeout: TimeInterval = 15
) throws {
    let deadline = Date().addingTimeInterval(timeout)
    repeat {
        let visible = visibleElements(application)
        if let failure = visibleActionFailure(visible) {
            throw DriverError.failedAction(failure)
        }
        if !containsVisible(visible, identifier: dismissedIdentifier),
           containsVisible(visible, identifier: visibleIdentifier) {
            Thread.sleep(forTimeInterval: 0.25)
            return
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline
    if let failure = visibleActionFailure(visibleElements(application)) {
        throw DriverError.failedAction(failure)
    }
    throw DriverError.missing(
        "successful completion: dismissed \(dismissedIdentifier), visible \(visibleIdentifier)"
    )
}

func press(
    _ application: AXUIElement,
    _ identifier: String
) throws {
    // A freshly imported bundle can take longer than five seconds to finish
    // its first LaunchServices registration and expose the SwiftUI AX tree.
    // Ready controls still return immediately; this only extends cold-start
    // polling before reporting a real missing/action failure.
    let deadline = Date().addingTimeInterval(20)
    var lastError = AXError.actionUnsupported
    repeat {
        let visible = visibleElements(application)
        let candidates = visible.filter {
            stringAttribute($0, kAXIdentifierAttribute) == identifier
        }
        if candidates.isEmpty {
            lastError = .cannotComplete
        } else {
            for candidate in candidates {
                var element = candidate
                for _ in 0..<8 {
                    var actionNames: CFArray?
                    let actionError = AXUIElementCopyActionNames(element, &actionNames)
                    if actionError == .success,
                       let names = actionNames as? [String],
                       names.contains(kAXPressAction) {
                        let error = AXUIElementPerformAction(element, kAXPressAction as CFString)
                        if error == .success {
                            Thread.sleep(forTimeInterval: 0.25)
                            return
                        }
                        lastError = error
                        break
                    }
                    guard let parent = attribute(element, kAXParentAttribute) else {
                        break
                    }
                    element = parent as! AXUIElement
                }
            }
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline
    throw DriverError.action(identifier, lastError)
}

func setValue(_ application: AXUIElement, _ identifier: String, _ value: String) throws {
    let element = try find(application, identifier: identifier)
    let focusError = AXUIElementSetAttributeValue(
        element,
        kAXFocusedAttribute as CFString,
        kCFBooleanTrue
    )
    guard focusError == .success else {
        throw DriverError.value(identifier, focusError)
    }
    var pid = pid_t()
    let pidError = AXUIElementGetPid(application, &pid)
    guard pidError == .success else {
        throw DriverError.value(identifier, pidError)
    }

    func postKey(_ keyCode: CGKeyCode, flags: CGEventFlags = []) {
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

    postKey(0, flags: .maskCommand) // Command-A
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
    CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false)?.postToPid(pid)

    let deadline = Date().addingTimeInterval(2)
    repeat {
        if stringAttribute(element, kAXValueAttribute) == value {
            Thread.sleep(forTimeInterval: 0.15)
            return
        }
        Thread.sleep(forTimeInterval: 0.05)
    } while Date() < deadline
    throw DriverError.value(identifier, .cannotComplete)
}

func publicValue(
    _ application: AXUIElement,
    identifier: String,
    validator: (String) -> Bool
) throws -> String {
    let element = try find(application, identifier: identifier)
    for attributeName in [
        kAXValueAttribute,
        kAXDescriptionAttribute,
        kAXTitleAttribute,
        kAXHelpAttribute,
    ] {
        let candidate = stringAttribute(element, attributeName)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if validator(candidate) {
            return candidate
        }
    }
    throw DriverError.value(identifier, .cannotComplete)
}

func validNpub(_ value: String) -> Bool {
    let allowed = Set("023456789acdefghjklmnpqrstuvwxyz")
    return value.count == 63
        && value.hasPrefix("npub1")
        && value.dropFirst(5).allSatisfy { allowed.contains($0) }
}

func openAddNetwork(_ application: AXUIElement, choice: String) throws {
    if !containsVisible(application, identifier: choice) {
        try press(application, "add-network-open")
    }
    try press(application, choice)
}

func emit(_ marker: String) {
    print("NVPN_RELEASE_JOIN_MARKER \(marker)")
    fflush(stdout)
}

func millisecondsSinceEpoch() -> Int64 {
    Int64((Date().timeIntervalSince1970 * 1_000).rounded(.down))
}

func run() throws {
    let args = CommandLine.arguments
    if args.count == 2 && args[1] == "--check-accessibility" {
        guard AXIsProcessTrusted() else {
            throw DriverError.accessibilityPermission
        }
        print("MACOS_AX_ACCESSIBILITY_READY")
        return
    }
    guard args.count == 6, let pid = pid_t(args[1]) else {
        throw DriverError.usage(
            "usage: desktop-manual-join-ax <pid> <phase> <value-1> <value-2> <expected-process-name>"
        )
    }
    guard AXIsProcessTrusted() else {
        throw DriverError.accessibilityPermission
    }
    let application = AXUIElementCreateApplication(pid)
    let processName = stringAttribute(application, kAXTitleAttribute)
    if !processName.isEmpty && processName != args[5] {
        throw DriverError.usage(
            "AX PID \(pid) belongs to \(processName), expected \(args[5])"
        )
    }

    switch args[2] {
    case "joiner":
        try press(application, "manual-join-choose-join")
        try press(application, "manual-join-expander")
        try setValue(application, "manual-join-admin-id", args[3])
        try setValue(application, "manual-join-network-id", args[4])
        try press(application, "manual-join-submit")
    case "admin":
        try press(application, "manual-join-admin-open")
        try setValue(application, "manual-join-admin-device-id", args[3])
        try setValue(application, "manual-join-admin-device-name", args[4])
        try press(application, "manual-join-admin-submit")
    case "joined":
        _ = try find(application, identifier: "vpn-service-toggle")
        let deadline = Date().addingTimeInterval(3)
        repeat {
            if containsVisible(application, identifier: "manual-join-choose-join") {
                throw DriverError.usage(
                    "joined roster is durable, but the shipped UI still shows first-run Join Network"
                )
            }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
    case "release-create-admin":
        try openAddNetwork(application, choice: "network-setup-create")
        try setValue(application, "network-create-name", args[3])
        try press(application, "network-create-submit")
        try requireSuccessfulCompletion(application, "network-create-name", "manual-join-admin-open")
        try press(application, "manual-join-admin-open")
        let admin = try publicValue(
            application,
            identifier: "admin-device-id-value",
            validator: validNpub
        )
        let network = try publicValue(
            application,
            identifier: "admin-network-id-value"
        ) { !$0.isEmpty && $0 != "-" }
        emit("NVPN_RELEASE_JOIN_ADMIN_ID=\(admin)")
        emit("NVPN_RELEASE_JOIN_NETWORK_ID=\(network.replacingOccurrences(of: "-", with: ""))")
        emit("NVPN_RELEASE_JOIN_ADMIN_READY=1")
    case "release-manual-join":
        try openAddNetwork(application, choice: "manual-join-choose-join")
        try press(application, "manual-join-expander")
        let joiner = try publicValue(
            application,
            identifier: "joiner-device-id-value",
            validator: validNpub
        )
        emit("NVPN_RELEASE_JOIN_JOINER_ID=\(joiner)")
        try setValue(application, "manual-join-admin-id", args[3])
        try setValue(application, "manual-join-network-id", args[4])
        try press(application, "manual-join-submit")
        emit("NVPN_RELEASE_JOIN_MANUAL_SUBMITTED=1")
        try requireSuccessfulCompletion(
            application, "manual-join-admin-id", "roster-participant-pending-\(args[3])"
        )
        emit("NVPN_RELEASE_JOIN_MANUAL_COMPLETE=\(args[3])")
        emit("NVPN_RELEASE_JOIN_MANUAL_COMPLETE_MS=\(millisecondsSinceEpoch())")
    case "release-joiner-id":
        try openAddNetwork(application, choice: "manual-join-choose-join")
        try press(application, "manual-join-expander")
        let joiner = try publicValue(
            application,
            identifier: "joiner-device-id-value",
            validator: validNpub
        )
        emit("NVPN_RELEASE_JOIN_JOINER_ID=\(joiner)")
    case "release-admin-add":
        try press(application, "manual-join-admin-open")
        try setValue(application, "manual-join-admin-device-id", args[3])
        try setValue(application, "manual-join-admin-device-name", args[4])
        emit("NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=\(millisecondsSinceEpoch())")
        try press(application, "manual-join-admin-submit")
        try requireSuccessfulCompletion(
            application, "manual-join-admin-device-id", "roster-participant-accepted-\(args[3])"
        )
        emit("NVPN_RELEASE_JOIN_ADMIN_ACCEPTED=\(args[3])")
        emit("NVPN_RELEASE_JOIN_ADMIN_ACCEPTED_MS=\(millisecondsSinceEpoch())")
    case "release-verify":
        _ = try find(
            application,
            identifier: "roster-participant-accepted-\(args[3])",
            timeout: 15
        )
        emit("NVPN_RELEASE_JOIN_ROSTER_PARTICIPANT=\(args[3])")
    case "paid-exit-discover":
        try press(application, "paid-exit-discover")
        let deadline = Date().addingTimeInterval(15)
        repeat {
            let visible = visibleElements(application)
            if let failure = visibleActionFailure(visible) {
                throw DriverError.failedAction(failure)
            }
            if let control = visible.first(where: {
                stringAttribute($0, kAXIdentifierAttribute) == "paid-exit-discover"
            }), boolAttribute(control, kAXEnabledAttribute) == true {
                Thread.sleep(forTimeInterval: 0.5)
                if let failure = visibleActionFailure(visibleElements(application)) {
                    throw DriverError.failedAction(failure)
                }
                emit("NVPN_PAID_EXIT_DISCOVER_COMPLETE=1")
                break
            }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
        guard Date() < deadline else {
            throw DriverError.missing("paid-exit discovery completion")
        }
    default:
        throw DriverError.usage(
            "unsupported phase \(args[2])"
        )
    }
    print("MACOS_MANUAL_JOIN_UI_\(args[2].uppercased())_OK")
}

do {
    try run()
} catch {
    fputs("macOS manual-join UI driver failed: \(error)\n", stderr)
    exit(1)
}
