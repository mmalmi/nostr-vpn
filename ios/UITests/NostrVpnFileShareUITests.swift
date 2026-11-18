import CryptoKit
import Foundation
import XCTest

/// The host prepares an isolated recipient snapshot and verifies the durable
/// command and copied bytes through USB after this real Files share-sheet flow.
final class NostrVpnFileShareUITests: XCTestCase {
    func testFilesShareQueuesWithMainAppClosed() throws {
        guard let recipient = ProcessInfo.processInfo.environment["NVPN_XCUITEST_FILE_SHARE_PEER_NAME"],
              !recipient.isEmpty else {
            throw XCTSkip("Requires an explicitly prepared file-share recipient")
        }
        continueAfterFailure = false
        PhysicalGateMarker.reset()
        let nvpn = XCUIApplication(bundleIdentifier: "fi.siriusbusiness.nvpn")
        XCTAssertEqual(nvpn.state, .notRunning, "The host must preserve a stopped app baseline")
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let name = "nvpn-share-check-\(UUID().uuidString.prefix(8)).txt"
        let bytes = Data(String(repeating: "nvpn file transfer verification\n", count: 6000).utf8)
        let source = documents.appendingPathComponent(name)
        try bytes.write(to: source, options: .withoutOverwriting)
        let receipt: [String: Any] = [
            "filename": name,
            "bytes": bytes.count,
            "sha256": SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(),
            "recipient": recipient,
        ]
        try JSONSerialization.data(withJSONObject: receipt).write(
            to: documents.appendingPathComponent("nvpn-file-share-source.json"), options: .atomic)

        let files = XCUIApplication(bundleIdentifier: "com.apple.DocumentsApp")
        files.launch()
        tap("Browse", in: files)
        tap("On My iPhone", in: files)
        tap("Nostr VPN Test Files", in: files)
        let displayName = source.deletingPathExtension().lastPathComponent
        let file = files.cells.matching(NSPredicate(
            format: "label BEGINSWITH %@ OR identifier BEGINSWITH %@", displayName, displayName
        )).firstMatch
        XCTAssertTrue(file.waitForExistence(timeout: 8), files.debugDescription)
        file.press(forDuration: 1)
        tap("Share", in: files)
        let activity = files.buttons["nvpn"].firstMatch
        if !activity.waitForExistence(timeout: 3) { tap("More", in: files) }
        tap("nvpn", in: files)
        XCTAssertTrue(files.staticTexts["Send files with nvpn"].waitForExistence(timeout: 8), files.debugDescription)
        screenshot("file-share-device-picker")
        tap(recipient, in: files)
        let queued = files.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "Queued for \(recipient)")).firstMatch
        XCTAssertTrue(queued.waitForExistence(timeout: 15), files.debugDescription)
        XCTAssertTrue(queued.label.contains("If VPN is off"))
        screenshot("file-share-queued")
        tap("Done", in: files)
        XCTAssertEqual(nvpn.state, .notRunning, "Sharing must not require launching the main app")
        XCTAssertEqual(try Data(contentsOf: source), bytes, "Sharing must preserve the original")
        PhysicalGateMarker.emit("NVPN_FILE_SHARE_QUEUED=1")
    }

    private func tap(_ label: String, in app: XCUIApplication) {
        let target = app.descendants(matching: .any).matching(NSPredicate(
            format: "label == %@ OR identifier == %@", label, label
        )).firstMatch
        XCTAssertTrue(target.waitForExistence(timeout: 5), app.debugDescription)
        target.tap()
    }

    private func screenshot(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
