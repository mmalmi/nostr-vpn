import CryptoKit
import Foundation
import XCTest

/// The entitled test runner owns a reversible fixture; the release app is unchanged.
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
        let bytes = Data(String(repeating: "nvpn file transfer verification\n", count: 32).utf8)
        let source = documents.appendingPathComponent(name)
        let fixture = try FileShareFixture.prepare(recipient: recipient, filename: name, bytes: bytes)
        addTeardownBlock { try fixture.restore() }
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
        file.tap()
        tap("Share", in: files)
        screenshot("file-share-system-sheet")
        let sheet = files.otherElements["ActivityListView"].firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 5), files.debugDescription)
        let appRow = sheet.scrollViews.firstMatch
        let activity = appRow.cells.matching(NSPredicate(format: "label == %@", "Nostr VPN")).firstMatch
        for _ in 0..<4 {
            if activity.exists && activity.isHittable && appRow.frame.contains(activity.frame) { break }
            appRow.coordinate(withNormalizedOffset: CGVector(dx: 0.85, dy: 0.45)).press(
                forDuration: 0.1,
                thenDragTo: appRow.coordinate(withNormalizedOffset: CGVector(dx: 0.15, dy: 0.45)))
        }
        XCTAssertTrue(activity.exists && activity.isHittable && appRow.frame.contains(activity.frame), sheet.debugDescription)
        activity.tap()
        screenshot("file-share-selected")
        let sharing = files
        XCTAssertTrue(sharing.staticTexts["Send files with nvpn"].waitForExistence(timeout: 8), sharing.debugDescription)
        screenshot("file-share-device-picker")
        tap(recipient, in: sharing)
        let queued = sharing.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "Queued for \(recipient)")).firstMatch
        XCTAssertTrue(queued.waitForExistence(timeout: 15), sharing.debugDescription)
        XCTAssertTrue(queued.label.contains("If VPN is off"))
        screenshot("file-share-queued")
        tap("Done", in: sharing)
        XCTAssertEqual(nvpn.state, .notRunning, "Sharing must not require launching the main app")
        XCTAssertEqual(try Data(contentsOf: source), bytes, "Sharing must preserve the original")
        try fixture.verifyQueued(bytes: bytes)
        PhysicalGateMarker.emit("NVPN_FILE_SHARE_QUEUED=1")
    }

    /// Explicit recovery after an interrupted test, before the host resumes the app.
    func testRestoreInterruptedFileShareFixture() throws {
        guard ProcessInfo.processInfo.environment["NVPN_XCUITEST_FILE_SHARE_RESTORE"] == "1" else {
            throw XCTSkip("Explicit interrupted-fixture recovery only")
        }
        continueAfterFailure = false
        guard XCUIApplication(bundleIdentifier: "fi.siriusbusiness.nvpn").state == .notRunning else {
            throw CocoaError(.fileWriteFileExists)
        }
        let fixture = try FileShareFixture.pending()
        try fixture.restore()
    }

    private func tap(_ label: String, in app: XCUIElement) {
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
