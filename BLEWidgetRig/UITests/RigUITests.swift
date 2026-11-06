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
        springboard.buttons["Detached"].tap()
        // The reloads asked at 2, 6 and 12 s after the return redraw the
        // caption with the provider's lag after the tap.
        let redrawn = springboard.staticTexts.matching(NSPredicate(format: "label CONTAINS 'tap +'")).firstMatch
        XCTAssertTrue(redrawn.waitForExistence(timeout: 20), springboard.debugDescription)
        XCTAssertFalse(app.wait(for: .runningForeground, timeout: 1), "a detached tap opened the app")
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
