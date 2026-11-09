import XCTest

/// The widget on the Simulator: added through SpringBoard's own gallery, it
/// draws its buttons before it has a lock list and shows its sign-in caption
/// (the 2026-11-01 bug), and a tap anywhere on a button's column runs in the
/// app's process in the background against `FakeAugust`: the tapped button
/// shows its progress and result, the app stays closed. A tap on the
/// widget's body (the caption under the doors) opens the app, as on any
/// widget, and the app logs it.
///
/// Run: `xcodebuild test -project AugustUnlock/AugustUnlock.xcodeproj -scheme
/// AugustUnlockUITests -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
/// -allowProvisioningUpdates` (the README's Tests section).
/// `DoorState.hold` in the app, which a UI test cannot import.
private let DoorStateHold: TimeInterval = 12

final class WidgetTapTests: XCTestCase {
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    private let app = XCUIApplication()

    /// Starts with the app quit, the common case on the phone (5 minutes in
    /// the background), so a tap launches it in the background.
    private func addWidgetWithTheAppQuit(_ env: [String: String]) throws {
        app.launchEnvironment = ["AUGUST_FAKE": "1", "AUGUST_FAKE_ONE_LOCK_FAILS": "0"].merging(env) { $1 }
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10))
        XCUIDevice.shared.press(.home)
        XCTAssertTrue(springboard.wait(for: .runningForeground, timeout: 5))
        app.terminate()

        // The switch keeps its name while a result shows; its text does not.
        if !springboard.switches["Door 1"].waitForExistence(timeout: 2) {
            try addWidget()
        }
        // An earlier test's results may still be held.
        XCTAssertTrue(springboard.staticTexts["Door 1"].waitForExistence(timeout: DoorStateHold + 20), springboard.debugDescription)
        XCTAssertTrue(springboard.staticTexts["Door 2"].waitForExistence(timeout: DoorStateHold + 20), "two doors before any lock list")
        XCTAssertTrue(springboard.switches["Lock Both"].exists, springboard.debugDescription)
    }

    func testWidgetTapStaysInWidget() throws {
        try addWidgetWithTheAppQuit(["AUGUST_SLOW_WIDGET_TAP": "1"])
        XCTAssertTrue(springboard.staticTexts["Open the app to sign in"].exists, springboard.debugDescription)

        // Each door is a toggle (a switch to accessibility), labelled with its name.
        let door = springboard.switches["Door 1"]
        XCTAssertTrue(door.exists, springboard.debugDescription)
        XCTAssertTrue(springboard.switches["Door 2"].exists, springboard.debugDescription)

        // The Simulator dispatches the intent (`OpenFirstDoorIntent.perform()
        // finished` in its log, 2026-11-02); a tap that opens the app is the
        // inert-button bug, not a Simulator limit (Logbook, 2026-11-02). The
        // tap lands near the corner of the column: with only the icon and the
        // caption live, this opened the app (2026-11-05).
        door.coordinate(withNormalizedOffset: CGVector(dx: 0.08, dy: 0.12)).tap()
        // The toggle flips at once: the tapped door alone reads "Unlocking…"
        // while the (slowed) tap runs in the app's background process.
        XCTAssertTrue(springboard.staticTexts["Unlocking\u{2026}"].waitForExistence(timeout: 2), springboard.debugDescription)
        XCTAssertTrue(springboard.staticTexts["Door 2"].exists, "the other door must not move")
        // Then the widget reads its result from the Keychain (the fake's
        // one-second reply), holds it, then clears it.
        XCTAssertTrue(springboard.staticTexts["Unlocked"].waitForExistence(timeout: 15), springboard.debugDescription)
        XCTAssertTrue(springboard.staticTexts["Door 2"].exists, "the other door must not move")
        XCTAssertTrue(springboard.staticTexts["Door 1"].waitForExistence(timeout: DoorStateHold + 10), "the result must clear")
        XCTAssertFalse(app.wait(for: .runningForeground, timeout: 1), "a widget tap opened the app")

        // The caption is the widget's body: a tap there opens the app, which
        // logs "opened by the widget body" (checked by hand in app.log).
        springboard.staticTexts["Open the app to sign in"].tap()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10), "a body tap must open the app")
    }

    func testLockBothLocksThenClears() throws {
        try addWidgetWithTheAppQuit(["AUGUST_SLOW_WIDGET_TAP": "1"])
        // Near the column's corner: the whole column is the button.
        // The button's own text: the Live Activity has the same words.
        let center = springboard.switches["Lock Both"]
        center.coordinate(withNormalizedOffset: CGVector(dx: 0.08, dy: 0.12)).tap()
        XCTAssertTrue(center.staticTexts["Locking\u{2026}"].waitForExistence(timeout: 2), springboard.debugDescription)
        XCTAssertTrue(springboard.staticTexts["Door 1"].exists, "the doors must not move")
        XCTAssertTrue(springboard.staticTexts["Door 2"].exists, "the doors must not move")
        XCTAssertTrue(center.staticTexts["Locked"].waitForExistence(timeout: 15), springboard.debugDescription)
        XCTAssertTrue(springboard.staticTexts["Door 1"].exists, "a locked door shows its name")
        XCTAssertTrue(springboard.staticTexts["Door 2"].exists, "a locked door shows its name")
        XCTAssertTrue(center.staticTexts["Lock Both"].waitForExistence(timeout: DoorStateHold + 10), "the result must clear")
        XCTAssertFalse(app.wait(for: .runningForeground, timeout: 1), "a widget tap opened the app")
    }

    /// One door fails: the center is not "Locked", and that door says so.
    func testLockBothNamesTheDoorThatFailed() throws {
        try addWidgetWithTheAppQuit(["AUGUST_SLOW_WIDGET_TAP": "0", "AUGUST_FAKE_ONE_LOCK_FAILS": "1"])
        springboard.switches["Lock Both"].tap()
        // The center and one door, by button: the Live Activity also says
        // "Failed". A redraw between the two writes shows the door's first.
        let both = expectation(for: NSPredicate(format: "count == 2"), evaluatedWith: springboard.switches.containing(.staticText, identifier: "Failed"))
        wait(for: [both], timeout: 15)
        XCTAssertTrue(springboard.switches["Lock Both"].staticTexts["Failed"].exists, springboard.debugDescription)
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
