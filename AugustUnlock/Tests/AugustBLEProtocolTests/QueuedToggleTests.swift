import XCTest

@testable import AugustBLEProtocol

final class QueuedToggleTests: XCTestCase {
    func testStartsEmpty() {
        XCTAssertNil(QueuedToggle().unlocking)
    }

    func testTapDuringUnlockQueuesLock() {
        var q = QueuedToggle()
        q.tap(inFlightUnlocking: true)
        XCTAssertEqual(q.unlocking, false)
    }

    func testTapDuringLockQueuesUnlock() {
        var q = QueuedToggle()
        q.tap(inFlightUnlocking: false)
        XCTAssertEqual(q.unlocking, true)
    }

    func testSecondTapClearsQueue() {
        var q = QueuedToggle()
        q.tap(inFlightUnlocking: true)
        q.tap(inFlightUnlocking: true)
        XCTAssertNil(q.unlocking)
    }

    func testTakeReturnsQueuedCommandOnce() {
        var q = QueuedToggle()
        q.tap(inFlightUnlocking: true)
        XCTAssertEqual(q.take(), false)
        XCTAssertNil(q.take())
    }

    func testClearDropsQueuedCommand() {
        var q = QueuedToggle()
        q.tap(inFlightUnlocking: false)
        q.clear()
        XCTAssertNil(q.take())
    }
}
