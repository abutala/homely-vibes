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
            "AUGUST_SLOW_WIDGET_TAP": "0",
        ].merging(extra) { $1 }
        app.launch()
    }

    /// `CommandDeadline` in the app, which a UI test cannot import.
    private let deadlineSeconds: UInt32 = 30
    private let timedOut = "Timed out \u{2014} tap to retry"

    private func status(_ text: String) -> XCUIElement { app.staticTexts[text] }
    private var circle: XCUIElement { app.buttons.firstMatch }

    func testOpeningUnlocks() {
        launch(reply: 1)
        XCTAssertTrue(status("Unlocked \u{2014} tap to lock").waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format: "label CONTAINS '1 sent'")).firstMatch.exists)
    }

    func testTapWhilePendingSendsTheOpposite() {
        launch(reply: 4)
        XCTAssertTrue(status("Unlocking\u{2026} tap to lock").waitForExistence(timeout: 3))
        // The line under it names the path the client took (the fake's: Bluetooth).
        XCTAssertTrue(status("Over Bluetooth").waitForExistence(timeout: 2), app.debugDescription)
        circle.tap()
        XCTAssertTrue(status("Locking\u{2026} tap to unlock").waitForExistence(timeout: 2), app.debugDescription)
        XCTAssertTrue(status("Locked").waitForExistence(timeout: 8), app.debugDescription)
        // The open-unlock and the tap: two commands, no more.
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format: "label CONTAINS '2 sent'")).firstMatch.exists)
    }

    func testDoubleTapIsOneTap() {
        launch(reply: 4)
        XCTAssertTrue(status("Unlocking\u{2026} tap to lock").waitForExistence(timeout: 3))
        circle.tap()
        circle.tap()
        XCTAssertTrue(status("Locking\u{2026} tap to unlock").waitForExistence(timeout: 2))
        XCTAssertTrue(status("Locked").waitForExistence(timeout: 8), app.debugDescription)
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format: "label CONTAINS '2 sent'")).firstMatch.exists)
    }

    func testNoStuckCommand_deadlineEndsASilentCommand() {
        launch(reply: 90)
        XCTAssertTrue(status("Unlocking\u{2026} tap to lock").waitForExistence(timeout: 3))
        XCTAssertTrue(status(timedOut).waitForExistence(timeout: 35), app.debugDescription)
        // The next tap is the user's: it unlocks again.
        circle.tap()
        XCTAssertTrue(status("Unlocking\u{2026} tap to lock").waitForExistence(timeout: 2), app.debugDescription)
    }

    func testChangeLockWhilePending() {
        launch(reply: 20)
        XCTAssertTrue(status("Unlocking\u{2026} tap to lock").waitForExistence(timeout: 3))
        app.buttons["Change Lock"].tap()
        XCTAssertTrue(status("The previous command may still complete.").waitForExistence(timeout: 3), app.debugDescription)
        app.buttons["Garage Entrance"].tap()
        XCTAssertTrue(status("Garage Entrance").waitForExistence(timeout: 3), app.debugDescription)
        XCTAssertTrue(status("Unlocking\u{2026} tap to lock").exists)
    }

    func testReturnToTheSignInScreenSendsNothing() {
        app = XCUIApplication()
        app.launchEnvironment = ["AUGUST_FAKE": "1", "AUGUST_FAKE_REPLY_SECONDS": "1"]
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
        // iOS offers to save the password; the sheet covers the picker, and a
        // tap while it animates in is lost, so tap until it is gone.
        let savePassword = app.sheets["Save Password?"]
        for _ in 0..<3 where savePassword.waitForExistence(timeout: 2) {
            app.buttons["Not Now"].tap()
            if savePassword.waitForNonExistence(timeout: 3) { break }
        }
        XCTAssertTrue(app.buttons["Front Door"].waitForExistence(timeout: 3), app.debugDescription)
        app.buttons["Front Door"].tap()
        XCTAssertTrue(status("Unlocked \u{2014} tap to lock").waitForExistence(timeout: 5), app.debugDescription)
        // Only the pick's open-unlock: the return to the sign-in screen sent nothing.
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format: "label CONTAINS '1 sent'")).firstMatch.exists, app.debugDescription)
    }

    func testResumeAfterAStallTimesOutAndDoesNotUnlockByItself() {
        launch(reply: 90)
        XCTAssertTrue(status("Unlocking\u{2026} tap to lock").waitForExistence(timeout: 3))
        XCUIDevice.shared.press(.home)
        sleep(deadlineSeconds + 3)
        app.activate()
        // The command is past its deadline: the return ends it and sends nothing.
        XCTAssertTrue(status(timedOut).waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertFalse(status("Unlocking\u{2026} tap to lock").exists)
        // A plain later return unlocks, as opening the app always does.
        XCUIDevice.shared.press(.home)
        sleep(2)
        app.activate()
        XCTAssertTrue(status("Unlocking\u{2026} tap to lock").waitForExistence(timeout: 5), app.debugDescription)
    }
}
