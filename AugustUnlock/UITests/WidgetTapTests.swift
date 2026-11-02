import XCTest

/// The widget on the Simulator: added through SpringBoard's own gallery, it
/// draws two buttons before it has a lock list and shows its sign-in caption
/// (the 2026-11-01 bug), and a tap on a button runs in the widget: the app
/// stays closed.
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

        // The button is the lock icon alone, labelled with the door's name
        // for VoiceOver; the name under it is a sibling text (the cue cannot
        // live inside the button, Logbook 2026-11-02).
        let door = springboard.buttons["Door 1"]
        XCTAssertTrue(door.exists, springboard.debugDescription)
        XCTAssertTrue(springboard.buttons["Door 2"].exists, springboard.debugDescription)

        // The Simulator dispatches the intent (`OpenFirstDoorIntent.perform()
        // finished` in its log, 2026-11-02); a tap that opens the app is the
        // inert-button bug, not a Simulator limit (Logbook, 2026-11-02).
        door.tap()
        XCTAssertFalse(app.wait(for: .runningForeground, timeout: 3), "a widget tap opened the app")
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
