import XCTest

/// The app's command flows on the Simulator against `FakeAugust`: the
/// properties `formal/august_unlock_command.qnt` pins, seen through the real
/// screens (Amit, 2026-11-01: local tests first, the phone only confirms).
final class AppFlowTests: XCTestCase {
    private var app: XCUIApplication!

    /// Launches signed in, with every command answering after `reply` seconds.
    private func launch(reply: Int, extra: [String: String] = [:]) {
        app = XCUIApplication()
        app.launchEnvironment = [
            "AUGUST_FAKE": "1", "AUGUST_FAKE_SIGNED_IN": "1", "AUGUST_FAKE_REPLY_SECONDS": "\(reply)",
            "AUGUST_SLOW_WIDGET_TAP": "0", "AUGUST_FAKE_ONE_LOCK_FAILS": "0",
        ].merging(extra) { $1 }
        app.launch()
    }

    /// `CommandDeadline` in the app, which a UI test cannot import.
    private let deadlineSeconds: UInt32 = 30
    private let timedOut = "Timed out \u{2014} tap to retry"
    private let tapToUnlock = "Tap to unlock"
    private let unlocked = "Unlocked \u{2014} tap to lock"
    private let unlocking = "Unlocking\u{2026} tap to lock"

    /// A whole card is one button, so its status is the button's value.
    private func statuses(_ text: String) -> XCUIElementQuery { app.buttons.matching(NSPredicate(format: "value CONTAINS %@", text)) }
    private func status(_ text: String) -> XCUIElement { statuses(text).firstMatch }
    private func sent(_ count: Int) -> XCUIElement { status("\(count) sent") }
    private var front: XCUIElement { app.buttons["Front Door"] }
    private var garage: XCUIElement { app.buttons["Garage Entrance"] }

    func testBothDoorsStackWithTheirTextToTheRight() {
        launch(reply: 1)
        XCTAssertTrue(front.waitForExistence(timeout: 5), app.debugDescription)
        let title = app.staticTexts["The gates of Eden"]
        XCTAssertTrue(title.exists, app.debugDescription)
        XCTAssertLessThanOrEqual(title.frame.maxY, front.frame.minY, "the title is above the doors")
        XCTAssertGreaterThanOrEqual(app.buttons["Sign Out"].frame.minY, garage.frame.maxY, "Sign Out is below the doors")
        XCTAssertTrue(garage.exists, app.debugDescription)
        XCTAssertGreaterThanOrEqual(garage.frame.minY, front.frame.maxY, "one below the other")
        XCTAssertEqual(garage.frame.minX, front.frame.minX, accuracy: 1)
    }

    func testOpeningSendsNothing() {
        launch(reply: 1)
        XCTAssertTrue(status(tapToUnlock).waitForExistence(timeout: 5), app.debugDescription)
        sleep(3)
        XCTAssertEqual(statuses(tapToUnlock).count, 2, app.debugDescription)
        XCTAssertFalse(status(unlocking).exists)
        XCTAssertFalse(sent(1).exists)
    }

    func testTheFirstTapOnEitherDoorUnlocksOnlyThatDoor() {
        launch(reply: 1)
        XCTAssertTrue(garage.waitForExistence(timeout: 5))
        garage.tap()
        XCTAssertTrue(status(unlocked).waitForExistence(timeout: 6), app.debugDescription)
        XCTAssertEqual(statuses(tapToUnlock).count, 1, "the other door must not move")
        XCTAssertTrue(sent(1).exists)
        front.tap()
        let bothUnlocked = NSPredicate(format: "count == 2")
        expectation(for: bothUnlocked, evaluatedWith: statuses(unlocked))
        waitForExpectations(timeout: 6)
        XCTAssertTrue(sent(2).exists)
    }

    func testTheDoorsRunSideBySide() {
        launch(reply: 4)
        XCTAssertTrue(front.waitForExistence(timeout: 5))
        front.tap()
        garage.tap()
        expectation(for: NSPredicate(format: "count == 2"), evaluatedWith: statuses(unlocking))
        waitForExpectations(timeout: 3)
    }

    func testTheNextTapLocks() {
        launch(reply: 1)
        XCTAssertTrue(front.waitForExistence(timeout: 5))
        front.tap()
        XCTAssertTrue(status(unlocked).waitForExistence(timeout: 6), app.debugDescription)
        front.tap()
        XCTAssertTrue(status("Locked \u{2014} tap to unlock").waitForExistence(timeout: 6), app.debugDescription)
        XCTAssertTrue(sent(2).exists)
    }

    func testTapWhilePendingSendsTheOpposite() {
        launch(reply: 4)
        XCTAssertTrue(front.waitForExistence(timeout: 5))
        front.tap()
        XCTAssertTrue(status(unlocking).waitForExistence(timeout: 3))
        // The line under it names the path the client took (the fake's: Bluetooth).
        XCTAssertTrue(status("Over Bluetooth").waitForExistence(timeout: 2), app.debugDescription)
        front.tap()
        XCTAssertTrue(status("Locking\u{2026} tap to unlock").waitForExistence(timeout: 2), app.debugDescription)
        XCTAssertTrue(status("Locked").waitForExistence(timeout: 8), app.debugDescription)
        // Two taps: two commands, no more.
        XCTAssertTrue(sent(2).exists)
    }

    func testDoubleTapIsOneTap() {
        launch(reply: 4)
        XCTAssertTrue(front.waitForExistence(timeout: 5))
        front.tap()
        XCTAssertTrue(status(unlocking).waitForExistence(timeout: 3))
        sleep(1)
        front.tap()
        front.tap()
        XCTAssertTrue(status("Locking\u{2026} tap to unlock").waitForExistence(timeout: 2))
        XCTAssertTrue(status("Locked").waitForExistence(timeout: 8), app.debugDescription)
        XCTAssertTrue(sent(2).exists)
    }

    /// A request already with August (the fake's cloud path) outlives the
    /// 30 s deadline: the screen says it was sent and warns, the request
    /// runs on, and its reply comes in as a line, never as a success.
    func testACloudRequestPastTheDeadlineShowsItsLateReply() {
        launch(reply: 38, extra: ["AUGUST_FAKE_PATH": "cloud"])
        XCTAssertTrue(front.waitForExistence(timeout: 5))
        front.tap()
        XCTAssertTrue(status("Over the cloud").waitForExistence(timeout: 3), app.debugDescription)
        XCTAssertTrue(status("Sent to August, no reply yet \u{2014} tap to retry").waitForExistence(timeout: 35), app.debugDescription)
        XCTAssertTrue(status("An earlier request may still move the door").waitForExistence(timeout: 6), app.debugDescription)
        let late = status("Late reply: Unlocked after")
        XCTAssertTrue(late.waitForExistence(timeout: 15), app.debugDescription)
        XCTAssertFalse(status("An earlier request may still move the door").exists, "the late request is done")
    }

    func testNoStuckCommand_deadlineEndsASilentCommand() {
        launch(reply: 90)
        XCTAssertTrue(front.waitForExistence(timeout: 5))
        front.tap()
        XCTAssertTrue(status(unlocking).waitForExistence(timeout: 3))
        XCTAssertTrue(status(timedOut).waitForExistence(timeout: 35), app.debugDescription)
        // The next tap is the user's: it unlocks again.
        front.tap()
        XCTAssertTrue(status(unlocking).waitForExistence(timeout: 2), app.debugDescription)
    }

    func testSignOutWhilePendingGoesToSignIn() {
        launch(reply: 20)
        XCTAssertTrue(front.waitForExistence(timeout: 5))
        front.tap()
        XCTAssertTrue(status(unlocking).waitForExistence(timeout: 3))
        app.buttons["Sign Out"].tap()
        XCTAssertTrue(app.staticTexts["Sign in to August"].waitForExistence(timeout: 3), app.debugDescription)
    }

    func testSigningInShowsTheDoorsAndSendsNothing() {
        app = XCUIApplication()
        app.launchEnvironment = ["AUGUST_FAKE": "1", "AUGUST_FAKE_REPLY_SECONDS": "1", "AUGUST_FAKE_ONE_LOCK_FAILS": "0"]
        app.launch()
        XCTAssertTrue(app.staticTexts["Sign in to August"].waitForExistence(timeout: 3))
        XCUIDevice.shared.press(.home)
        sleep(2)
        app.activate()
        XCTAssertTrue(app.staticTexts["Sign in to August"].waitForExistence(timeout: 3))
        app.textFields["Email"].tap()
        app.textFields["Email"].typeText("test@example.com")
        app.secureTextFields["Password"].tap()
        app.secureTextFields["Password"].typeText("fake")
        app.buttons["Sign In"].tap()
        // iOS offers to save the password; the sheet covers the doors, and a
        // tap while it animates in is lost, so tap until it is gone.
        let savePassword = app.sheets["Save Password?"]
        for _ in 0..<3 where savePassword.waitForExistence(timeout: 2) {
            app.buttons["Not Now"].tap()
            if savePassword.waitForNonExistence(timeout: 3) { break }
        }
        XCTAssertTrue(front.waitForExistence(timeout: 3), app.debugDescription)
        XCTAssertEqual(statuses(tapToUnlock).count, 2, app.debugDescription)
        XCTAssertFalse(sent(1).exists)
    }

    /// The door may have moved while the app was away, so a return reads
    /// "Tap to unlock" again, sends nothing, and the first tap unlocks.
    func testAReturnSendsNothingAndTheFirstTapUnlocks() {
        launch(reply: 1)
        XCTAssertTrue(front.waitForExistence(timeout: 5))
        front.tap()
        XCTAssertTrue(status(unlocked).waitForExistence(timeout: 6), app.debugDescription)
        XCUIDevice.shared.press(.home)
        sleep(2)
        app.activate()
        expectation(for: NSPredicate(format: "count == 2"), evaluatedWith: statuses(tapToUnlock))
        waitForExpectations(timeout: 3)
        XCTAssertFalse(sent(2).exists, "the return sent nothing")
        front.tap()
        XCTAssertTrue(status(unlocked).waitForExistence(timeout: 6), app.debugDescription)
        XCTAssertTrue(sent(2).exists)
    }

    func testResumeAfterAStallTimesOutAndDoesNotUnlockByItself() {
        launch(reply: 90)
        XCTAssertTrue(front.waitForExistence(timeout: 5))
        front.tap()
        XCTAssertTrue(status(unlocking).waitForExistence(timeout: 3))
        XCUIDevice.shared.press(.home)
        sleep(deadlineSeconds + 3)
        app.activate()
        // The command is past its deadline: the return ends it and sends nothing.
        XCTAssertTrue(status(timedOut).waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertFalse(status(unlocking).exists)
        // A plain later return sends nothing either.
        XCUIDevice.shared.press(.home)
        sleep(2)
        app.activate()
        sleep(2)
        XCTAssertFalse(status(unlocking).exists, app.debugDescription)
    }
}
