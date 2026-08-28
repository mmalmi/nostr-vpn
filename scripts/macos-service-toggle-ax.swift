#!/usr/bin/env swift
import AppKit
import ApplicationServices
import Foundation

enum DriverError: Error, CustomStringConvertible {
    case usage
    case accessibilityPermission
    case missing(String)
    case action(String, AXError)

    var description: String {
        switch self {
        case .usage:
            return "usage: macos-service-toggle-ax <app-pid> <expected-process-name>"
        case .accessibilityPermission:
            return "Accessibility permission is required to drive the macOS release UI"
        case .missing(let description):
            return description
        case .action(let description, let error):
            return "\(description): AX error \(error.rawValue)"
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

func findIdentifier(
    _ application: AXUIElement,
    _ identifier: String,
    timeout: TimeInterval = 15
) throws -> AXUIElement {
    let deadline = Date().addingTimeInterval(timeout)
    repeat {
        if let element = descendants(application).first(where: {
            stringAttribute($0, kAXIdentifierAttribute) == identifier
                && boolAttribute($0, kAXHiddenAttribute) != true
                && boolAttribute($0, kAXEnabledAttribute) == true
        }) {
            return element
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline
    let controls = descendants(application).compactMap { element -> String? in
        let identifier = stringAttribute(element, kAXIdentifierAttribute)
        guard !identifier.isEmpty,
              boolAttribute(element, kAXHiddenAttribute) != true else {
            return nil
        }
        let role = stringAttribute(element, kAXRoleAttribute)
        let enabled = boolAttribute(element, kAXEnabledAttribute)
        return "\(role):\(identifier):enabled=\(enabled.map { String($0) } ?? "unset")"
    }
    fputs("Visible AX identifiers: \(controls.joined(separator: ", "))\n", stderr)
    throw DriverError.missing("visible control did not appear: \(identifier)")
}

func findVisibleIdentifier(
    _ application: AXUIElement,
    _ identifier: String,
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
    throw DriverError.missing("visible element did not appear: \(identifier)")
}

func press(_ element: AXUIElement, description: String) throws {
    var candidate = element
    for _ in 0..<8 {
        var actionNames: CFArray?
        if AXUIElementCopyActionNames(candidate, &actionNames) == .success,
           let names = actionNames as? [String],
           names.contains(kAXPressAction) {
            let error = AXUIElementPerformAction(candidate, kAXPressAction as CFString)
            guard error == .success else {
                throw DriverError.action("AXPress failed for \(description)", error)
            }
            return
        }
        guard let parent = attribute(candidate, kAXParentAttribute) else {
            break
        }
        candidate = parent as! AXUIElement
    }
    throw DriverError.action("no press action for \(description)", .actionUnsupported)
}

func securityAgentProcessIdentifiers() -> [pid_t] {
    let process = Process()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
    process.arguments = ["-x", "SecurityAgent"]
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        return []
    }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    return String(decoding: data, as: UTF8.self)
        .split(whereSeparator: \.isNewline)
        .compactMap { pid_t($0) }
}

func visibleWindows(_ application: AXUIElement) -> [AXUIElement] {
    descendants(application).filter {
        stringAttribute($0, kAXRoleAttribute) == kAXWindowRole
            && boolAttribute($0, kAXHiddenAttribute) != true
    }
}

func cancelAuthorizationPrompt(
    appApplication: AXUIElement,
    timeout: TimeInterval = 20
) throws {
    let deadline = Date().addingTimeInterval(timeout)
    var diagnostics: [String] = []
    repeat {
        for pid in securityAgentProcessIdentifiers() {
            let application = AXUIElementCreateApplication(pid)
            let elements = descendants(application)
            diagnostics = elements.compactMap { element in
                let role = stringAttribute(element, kAXRoleAttribute)
                let title = stringAttribute(element, kAXTitleAttribute)
                let description = stringAttribute(element, kAXDescriptionAttribute)
                guard !role.isEmpty || !title.isEmpty || !description.isEmpty else {
                    return nil
                }
                return "\(role)|\(title)|\(description)"
            }
            if let cancel = elements.first(where: { element in
                guard stringAttribute(element, kAXRoleAttribute) == kAXButtonRole else {
                    return false
                }
                let title = stringAttribute(element, kAXTitleAttribute)
                let description = stringAttribute(element, kAXDescriptionAttribute)
                return title == "Cancel" || description == "Cancel"
            }) {
                try press(cancel, description: "SecurityAgent Cancel")
                let closeDeadline = Date().addingTimeInterval(5)
                repeat {
                    if visibleWindows(application).isEmpty {
                        print("MACOS_SERVICE_TOGGLE_AUTHORIZATION_CANCELLED_OK")
                        return
                    }
                    Thread.sleep(forTimeInterval: 0.1)
                } while Date() < closeDeadline
                throw DriverError.missing("SecurityAgent prompt remained visible after Cancel")
            }
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline

    if !diagnostics.isEmpty {
        fputs("SecurityAgent AX tree: \(diagnostics.joined(separator: ", "))\n", stderr)
    }
    let appDiagnostics = descendants(appApplication).compactMap { element -> String? in
        let role = stringAttribute(element, kAXRoleAttribute)
        let title = stringAttribute(element, kAXTitleAttribute)
        let description = stringAttribute(element, kAXDescriptionAttribute)
        let value = stringAttribute(element, kAXValueAttribute)
        guard !role.isEmpty || !title.isEmpty || !description.isEmpty || !value.isEmpty else {
            return nil
        }
        return "\(role)|\(title)|\(description)|\(value)"
    }
    fputs("App AX tree after toggle: \(appDiagnostics.joined(separator: ", "))\n", stderr)
    throw DriverError.missing("VPN toggle did not open a cancellable SecurityAgent prompt")
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
    guard args.count == 3, let pid = pid_t(args[1]) else {
        throw DriverError.usage
    }
    guard AXIsProcessTrusted() else {
        throw DriverError.accessibilityPermission
    }

    let application = AXUIElementCreateApplication(pid)
    let processName = stringAttribute(application, kAXTitleAttribute)
    if !processName.isEmpty && processName != args[2] {
        throw DriverError.missing(
            "AX PID \(pid) belongs to \(processName), expected \(args[2])"
        )
    }
    NSRunningApplication(processIdentifier: pid)?.activate(
        options: [.activateAllWindows]
    )
    _ = try findVisibleIdentifier(application, "main-AppWindow-1", timeout: 60)
    let toggle = try findIdentifier(application, "vpn-service-toggle")
    try press(toggle, description: "VPN service toggle")
    try cancelAuthorizationPrompt(appApplication: application)
}

do {
    try run()
} catch {
    fputs("macOS service-toggle UI driver failed: \(error)\n", stderr)
    exit(1)
}
