import XCTest

/// The rig on the Simulator: no Bluetooth there, so the probes time out,
/// but the Detached button's mechanics can be watched: `perform()`
/// returns, the detached work asks reloads, and the widget's caption shows
/// when the provider ran after the tap. The phone decides the numbers
/// (README, "Detached tap measurement").
final class RigUITests: XCTestCase {
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    private let app = XCUIApplication()

    func testTheAppLaunches() {
        app.launch()
        XCTAssertTrue(app.staticTexts["BLE Widget Rig"].waitForExistence(timeout: 5))
    }

    func testADetachedTapRedrawsTheWidgetAfterTheReturn() throws {
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10))
        XCUIDevice.shared.press(.home)
        XCTAssertTrue(springboard.wait(for: .runningForeground, timeout: 5))
        app.terminate()

        if !springboard.buttons["Detached"].waitForExistence(timeout: 2) {
            try addWidget()
        }
        XCTAssertTrue(springboard.buttons["Detached"].waitForExistence(timeout: 20), springboard.debugDescription)
        let captions = springboard.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'run '"))
        XCTAssertTrue(captions.firstMatch.waitForExistence(timeout: 10), springboard.debugDescription)
        let before = captions.firstMatch.label
        springboard.buttons["Detached"].tap()
        // The system's own reload after the intent returns draws a new
        // caption with the provider's lag after this tap, which proves the
        // mark crosses the Keychain; a caption left by an earlier tap does
        // not count. Whether the reloads asked at 2, 6 and 12 s also run is
        // read from the logs (the phone decides).
        let fresh = NSPredicate { object, _ in
            guard let label = (object as? XCUIElementAttributes)?.label, label != before, let range = label.range(of: "tap +") else { return false }
            let seconds = Double(label[range.upperBound...].prefix { "0123456789.".contains($0) }) ?? .infinity
            return seconds < 20
        }
        let redrawn = springboard.staticTexts.matching(fresh).firstMatch
        XCTAssertTrue(redrawn.waitForExistence(timeout: 20), "no fresh caption after the tap; before: \(before)\n\(springboard.debugDescription)")
        XCTAssertFalse(app.wait(for: .runningForeground, timeout: 1), "a detached tap opened the app")
    }

    /// The Live button with the app quit: the activity starts from the
    /// background (Apple's `LiveActivityIntent` rule), the app stays closed,
    /// and the app's log has the request, every update and the end. Whether
    /// the updates draw live is the phone's question (README, "Live
    /// Activity measurement"): the Simulator drew every widget reload too.
    func testALiveTapStartsAnActivityWithTheAppClosed() throws {
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10))
        XCUIDevice.shared.press(.home)
        XCTAssertTrue(springboard.wait(for: .runningForeground, timeout: 5))
        app.terminate()

        if !springboard.buttons["Live"].waitForExistence(timeout: 2) {
            try addWidget()
        }
        XCTAssertTrue(springboard.buttons["Live"].waitForExistence(timeout: 20), springboard.debugDescription)
        springboard.buttons["Live"].tap()
        XCTAssertFalse(app.wait(for: .runningForeground, timeout: 3), "a Live tap opened the app")
        // `launch()`, and `activate()` on a process XCTest did not launch,
        // start a new process and kill the one the intent runs in (it died
        // at +19 s that way); wait out its 20 s and the end first.
        // A screenshot mid-run, kept, to look at the Island's two clocks.
        sleep(5)
        let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        shot.name = "live-island"
        shot.lifetime = .keepAlways
        add(shot)
        sleep(25)
        app.activate()
        let log = app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'live: ended'")).firstMatch
        let refresh = app.buttons["Refresh"]
        let deadline = Date().addingTimeInterval(40)
        while !log.exists, Date() < deadline {
            sleep(2)
            refresh.tap()
        }
        XCTAssertTrue(log.exists, app.debugDescription)
        XCTAssertTrue(log.label.contains("live: request ok"), log.label)
        XCTAssertTrue(log.label.contains("live: +\(20) s sent"), log.label)
        XCTAssertTrue(log.label.contains("app state background"), "the Live tap did not run in the background: \(log.label)")
    }

    /// Long-press the Home Screen → Edit → Add Widget → search → add.
    private func addWidget() throws {
        springboard.activate()
        XCTAssertTrue(springboard.icons.firstMatch.waitForExistence(timeout: 5), springboard.debugDescription)
        let icon = try XCTUnwrap(
            springboard.icons.allElementsBoundByIndex.first { $0.isHittable && $0.frame.width > 0 },
            springboard.debugDescription)
        icon.press(forDuration: 2)
        let edit = springboard.buttons["Edit Home Screen"]
        if edit.waitForExistence(timeout: 3) { edit.tap() }
        let editMenu = springboard.buttons["Edit"]
        XCTAssertTrue(editMenu.waitForExistence(timeout: 5), springboard.debugDescription)
        editMenu.tap()
        let addWidget = springboard.buttons["Add Widget"]
        XCTAssertTrue(addWidget.waitForExistence(timeout: 5), springboard.debugDescription)
        addWidget.tap()
        let search = springboard.searchFields.firstMatch
        XCTAssertTrue(search.waitForExistence(timeout: 5), springboard.debugDescription)
        search.tap()
        search.typeText("BLEWidgetRig")
        let result = springboard.staticTexts["BLEWidgetRig"].firstMatch
        XCTAssertTrue(result.waitForExistence(timeout: 5), springboard.debugDescription)
        result.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
        XCTAssertTrue(springboard.staticTexts["BLE Rig"].waitForExistence(timeout: 10), springboard.debugDescription)
        springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.905)).tap()
        let done = springboard.buttons["Done"]
        if done.waitForExistence(timeout: 3) { done.tap() }
    }
}
