import XCTest

/// The widget on the Simulator: added through SpringBoard's own gallery, it
/// draws two buttons before it has a lock list and shows its sign-in caption
/// (the 2026-11-01 bug). The tap itself is an expected failure here; see below.
///
/// Run: `xcodebuild test -project AugustUnlock/AugustUnlock.xcodeproj -scheme
/// AugustUnlockUITests -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
/// -allowProvisioningUpdates` (the README's Tests section).
final class WidgetTapTests: XCTestCase {
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    private let app = XCUIApplication()

    func testWidgetTapStaysInWidget() throws {
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10))
        XCUIDevice.shared.press(.home)
        XCTAssertTrue(springboard.wait(for: .runningForeground, timeout: 5))

        if !springboard.staticTexts["Door 1"].waitForExistence(timeout: 2) {
            try addWidget()
        }
        XCTAssertTrue(springboard.staticTexts["Door 1"].waitForExistence(timeout: 20), springboard.debugDescription)
        XCTAssertTrue(springboard.staticTexts["Door 2"].exists, "two doors before any lock list")
        XCTAssertTrue(springboard.staticTexts["Open the app to sign in"].exists, springboard.debugDescription)

        // The button is the lock icon alone; the name under it is a sibling
        // (the cue cannot live inside the button, Logbook 2026-11-02).
        let doors = springboard.buttons.matching(identifier: "Unlock")
        XCTAssertEqual(doors.count, 2, springboard.debugDescription)
        let door = doors.element(boundBy: 0)

        // On the Simulator the intent registry (linkd) rejects the widget for
        // want of a team identifier, so the tap falls through and opens the
        // app; only a signed device build can pass this part (Logbook,
        // 2026-11-01). Expected failure here, so the day it works it turns green.
        XCTExpectFailure("Simulator: widget intents don't dispatch (no team identifier)", options: .nonStrict()) {
            door.tap()
            XCTAssertFalse(app.wait(for: .runningForeground, timeout: 3), "a widget tap opened the app")
        }
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
        search.typeText("AugustUnlock")
        let result = springboard.staticTexts["AugustUnlock"].firstMatch
        XCTAssertTrue(result.waitForExistence(timeout: 5), springboard.debugDescription)
        // The row, not the text, takes the tap.
        result.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
        // The gallery's "Add Widget" bar has no accessible name; it sits at
        // the bottom of the sheet.
        XCTAssertTrue(springboard.staticTexts["Doors"].waitForExistence(timeout: 10), springboard.debugDescription)
        springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.905)).tap()
        let done = springboard.buttons["Done"]
        if done.waitForExistence(timeout: 3) { done.tap() }
    }
}
