import Foundation
import XCTest

extension NostrVpnReleaseNetworkUITests {
    func openInternetTab() {
        let tab = app.tabBars.buttons["Internet"]
        XCTAssertTrue(tab.waitForExistence(timeout: 8))
        tab.tap()
    }

    func selectMenu(picker: String, option: String) {
        scrollToElement(picker).tap()
        let choice = element(option)
        XCTAssertTrue(choice.waitForExistence(timeout: 3), "\(option) was unavailable")
        choice.tap()
        waitForActionToSettle()
    }

    func assertPicker(_ identifier: String, contains expected: String) {
        let picker = scrollToElement(identifier)
        let summary = "\(picker.label) \(picker.value as? String ?? "")"
        XCTAssertTrue(
            summary.localizedCaseInsensitiveContains(expected),
            "\(identifier) was \(summary), expected \(expected)"
        )
    }

    func assertInternetStatus(contains expected: String) {
        let status = scrollToElement("internet-source-status")
        let summary = "\(status.label) \(status.value as? String ?? "")"
        XCTAssertTrue(
            summary.localizedCaseInsensitiveContains(expected),
            "Internet status was \(summary), expected \(expected)"
        )
    }

    func vpnToggle() throws -> XCUIElement {
        let deadline = Date().addingTimeInterval(8)
        repeat {
            for label in ["Turn VPN off", "Turn VPN on"] {
                if let toggle = try vpnControl(label: label),
                   toggle.exists, toggle.isEnabled {
                    return toggle
                }
            }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
        throw gateError("Shipped VPN toggle was unavailable")
    }

    func vpnButton(forState on: Bool) -> XCUIElement? {
        let label = on ? "Turn VPN off" : "Turn VPN on"
        return try? vpnControl(label: label)
    }

    private func vpnControl(label: String) throws -> XCUIElement? {
        let matches = app.buttons.matching(
            NSPredicate(
                format: "identifier == %@ AND label == %@",
                "vpn-toggle",
                label
            )
        )
        let count = matches.count
        guard count > 0 else {
            return nil
        }
        guard count == 1 else {
            throw gateError("Shipped VPN control was not unique")
        }
        return matches.firstMatch
    }

    func waitForVPNState(on: Bool, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            acknowledgeVPNPrompts(timeout: 0)
            if let toggle = vpnButton(forState: on), toggle.exists {
                return true
            }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
        return false
    }

    func vpnIsOn(_ element: XCUIElement) -> Bool {
        let value = "\(element.value as? String ?? "") \(element.label)".lowercased()
        if value.contains("turn vpn off") {
            return true
        }
        if value.contains("turn vpn on") {
            return false
        }
        let tokens = value.split(separator: " ")
        return tokens.contains("on") || tokens.contains("1")
    }

    func wireGuardIsOn(_ element: XCUIElement) -> Bool {
        let value = "\(element.value as? String ?? "") \(element.label)".lowercased()
        return value.contains("wireguard upstream on")
            || value.split(separator: " ").contains("on")
            || value.split(separator: " ").contains("1")
    }

    @discardableResult
    func setStartVpnAutomatically(_ enabled: Bool) throws -> Bool {
        let settings = app.tabBars.buttons["Settings"]
        guard settings.waitForExistence(timeout: 8), settings.isHittable else {
            throw gateError("Shipped Settings tab was unavailable")
        }
        settings.tap()
        let toggle = scrollToElement("autoconnect-toggle")
        let readyDeadline = Date().addingTimeInterval(12)
        while !(toggle.exists && toggle.isHittable && toggle.isEnabled),
              Date() < readyDeadline
        {
            Thread.sleep(forTimeInterval: 0.1)
        }
        guard toggle.exists, toggle.isHittable, toggle.isEnabled else {
            throw gateError("Start VPN automatically remained busy")
        }
        let wasEnabled = toggleIsOn(toggle)
        if wasEnabled != enabled {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
            waitForActionToSettle()
            guard toggleIsOn(scrollToElement("autoconnect-toggle")) == enabled else {
                throw gateError("Start VPN automatically did not save through its shipped control")
            }
        }
        return wasEnabled
    }

    func toggleIsOn(_ element: XCUIElement) -> Bool {
        let value = "\(element.value as? String ?? "") \(element.label)".lowercased()
        let tokens = value.split(separator: " ")
        return tokens.contains("on") || tokens.contains("1")
    }

    func acknowledgeVPNPrompts(timeout: TimeInterval) {
        let deadline = Date().addingTimeInterval(timeout)
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        repeat {
            let disclosure = app.buttons["Continue"]
            if disclosure.exists, disclosure.isHittable {
                disclosure.tap()
            }
            let allow = springboard.alerts.buttons["Allow"]
            if allow.exists, allow.isHittable {
                allow.tap()
            }
            if timeout == 0 {
                return
            }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
    }

    @discardableResult
    func waitForSourceIP(
        _ rawURL: String,
        expected: String? = nil,
        rejecting: String? = nil,
        timeout: TimeInterval
    ) throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        var lastError: Error?
        repeat {
            do {
                let observed = try NostrVpnReleaseNetworkProbe.sourceIP(rawURL)
                if expected.map({ observed == $0 }) ?? true,
                   rejecting.map({ observed != $0 }) ?? true
                {
                    return observed
                }
                lastError = gateError("Observed unexpected source IP \(observed)")
            } catch {
                lastError = error
            }
            Thread.sleep(forTimeInterval: 0.2)
        } while Date() < deadline
        throw lastError ?? gateError("Source-IP probe timed out")
    }

    func relaunch() {
        app.terminate()
        app.launchArguments = []
        app.launchEnvironment = [:]
        app.launch()
        XCTAssertTrue(waitForApplicationState(.runningForeground, timeout: 10))
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 5))
    }

    func waitForApplicationState(
        _ expected: XCUIApplication.State,
        timeout: TimeInterval
    ) -> Bool {
        waitForApplicationState(app, expected, timeout: timeout)
    }

    func waitForApplicationState(
        _ application: XCUIApplication,
        _ expected: XCUIApplication.State,
        timeout: TimeInterval
    ) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if application.state == expected {
                return true
            }
            Thread.sleep(forTimeInterval: 0.05)
        } while Date() < deadline
        return false
    }

    func waitForActionToSettle() {
        Thread.sleep(forTimeInterval: 0.5)
    }

    func waitForInternetTransitionToSettle(
        timeout: TimeInterval = 30
    ) throws {
        let status = element("internet-settings-status")
        let transientMessages = [
            "Saving internet",
            "Updating VPN routes",
            "Restoring VPN",
            "Turning VPN on",
        ]
        let transient = NSCompoundPredicate(orPredicateWithSubpredicates:
            transientMessages.map {
                NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", $0, $0)
            }
        )
        // Query text and existence in one snapshot: a completed transition can
        // remove the notice between an exists check and a separate label read.
        let unexpectedStatus = app.descendants(matching: .any)
            .matching(identifier: "internet-settings-status")
            .matching(NSCompoundPredicate(notPredicateWithSubpredicate: transient))
            .firstMatch
        let deadline = Date().addingTimeInterval(timeout)
        var quietSince: Date?
        repeat {
            if unexpectedStatus.exists {
                throw gateError("VPN route transition reported an unexpected status")
            }
            if status.exists {
                quietSince = nil
            } else if let quietSince {
                if Date().timeIntervalSince(quietSince) >= 1 {
                    return
                }
            } else {
                quietSince = Date()
            }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
        throw gateError("VPN route transition did not settle within \(Int(timeout))s")
    }

    func element(_ identifier: String) -> XCUIElement {
        app.descendants(matching: .any)[identifier]
    }

    func scrollToElement(_ identifier: String) -> XCUIElement {
        let target = element(identifier)
        for _ in 0..<10 {
            if target.isHittable {
                break
            }
            if target.exists, target.frame.midY < app.frame.midY {
                app.swipeDown()
            } else {
                app.swipeUp()
            }
        }
        XCTAssertTrue(
            target.waitForExistence(timeout: 3) && target.isHittable,
            "\(identifier) was unavailable"
        )
        return target
    }

    func replaceText(_ field: XCUIElement, with value: String) {
        XCTAssertTrue(
            ShippedUIInteraction.replaceText(field, with: value, in: app),
            "Shipped text control did not retain the exact supplied value"
        )
    }

    func enteredText(_ field: XCUIElement) -> String {
        let value = field.value as? String ?? ""
        return value == field.placeholderValue ? "" : value
    }

}
