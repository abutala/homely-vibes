import XCTest

@testable import AugustBLEProtocol

/// The screen's "may still move the door" window per lock, fed by widget taps.
final class OpenTailsTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_000_000)
    private let window = CommandMachine.mayStillMoveWindow

    func testAnOpenTailWarnsUntilAugustConfirms() {
        let tails = OpenTails()
        let tail = tails.opened("a", at: t0)
        XCTAssertTrue(tails.mayStillMove("a", at: t0 + 1))
        XCTAssertFalse(tails.mayStillMove("b", at: t0 + 1), "the other lock has none")
        XCTAssertEqual(tails.running, 1)
        tails.ended(tail, confirmed: true)
        XCTAssertFalse(tails.mayStillMove("a", at: t0 + 2))
        XCTAssertEqual(tails.running, 0)
    }

    func testAnUnconfirmedTailWarnsForItsWindow() {
        let tails = OpenTails()
        tails.ended(tails.opened("a", at: t0), confirmed: false)
        XCTAssertEqual(tails.running, 0, "the exit waits no longer")
        XCTAssertTrue(tails.mayStillMove("a", at: t0 + window - 1))
        XCTAssertFalse(tails.mayStillMove("a", at: t0 + window))
    }

    /// An unlock cut off with August's copy out, then a lock that August
    /// confirms: the unlock can still land, so the warning stays.
    func testALaterConfirmationDoesNotClearAnOlderCommand() {
        let tails = OpenTails()
        tails.ended(tails.opened("a", at: t0), confirmed: false)
        tails.ended(tails.opened("a", at: t0 + 30), confirmed: true)
        XCTAssertTrue(tails.mayStillMove("a", at: t0 + 40))
        XCTAssertFalse(tails.mayStillMove("a", at: t0 + window))
    }

    func testACommandTheTapGaveUpOnWarns() {
        let tails = OpenTails()
        tails.unanswered("a", at: t0)
        XCTAssertTrue(tails.mayStillMove("a", at: t0 + 1))
        XCTAssertEqual(tails.running, 0)
        XCTAssertFalse(tails.mayStillMove("a", at: t0 + window))
    }
}
