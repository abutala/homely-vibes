import XCTest

@testable import AugustBLEProtocol

final class WidgetTapPolicyTests: XCTestCase {
    private let start = Date(timeIntervalSinceReferenceDate: 1000)

    func testDefaultMemoryIsThreeMinutes() {
        XCTAssertEqual(WidgetTapPolicy.defaultUnlockedMemory, 180)
    }

    func testFirstTapUnlocks() {
        XCTAssertTrue(WidgetTapPolicy().nextTapUnlocks(at: start))
    }

    func testTapWhileUnlockingLocks() {
        var p = WidgetTapPolicy()
        p.didSend(unlocking: true)
        XCTAssertFalse(p.nextTapUnlocks(at: start))
    }

    func testTapWhileLockingUnlocks() {
        var p = WidgetTapPolicy()
        p.didSend(unlocking: false)
        XCTAssertTrue(p.nextTapUnlocks(at: start))
    }

    func testTapSoonAfterUnlockLocks() {
        var p = WidgetTapPolicy(unlockedMemory: 180)
        p.didSend(unlocking: true)
        p.didFinish(reportedUnlocked: true, at: start)
        XCTAssertFalse(p.nextTapUnlocks(at: start.addingTimeInterval(179)))
    }

    func testTapLongAfterUnlockUnlocksAgain() {
        var p = WidgetTapPolicy(unlockedMemory: 180)
        p.didSend(unlocking: true)
        p.didFinish(reportedUnlocked: true, at: start)
        XCTAssertTrue(p.nextTapUnlocks(at: start.addingTimeInterval(180)))
    }

    func testTapAfterLockUnlocks() {
        var p = WidgetTapPolicy()
        p.didSend(unlocking: false)
        p.didFinish(reportedUnlocked: false, at: start)
        XCTAssertTrue(p.nextTapUnlocks(at: start.addingTimeInterval(1)))
    }

    func testFailureForgetsTheUnlock() {
        var p = WidgetTapPolicy()
        p.didFinish(reportedUnlocked: true, at: start)
        p.didSend(unlocking: false)
        p.didFinish(reportedUnlocked: false, at: start.addingTimeInterval(5))
        XCTAssertTrue(p.nextTapUnlocks(at: start.addingTimeInterval(6)))
    }

    func testOverrideBackToUnlockRecordsTheReply() {
        var p = WidgetTapPolicy()
        p.didSend(unlocking: true)
        p.didSend(unlocking: false)
        p.didSend(unlocking: true)
        p.didFinish(reportedUnlocked: true, at: start)
        XCTAssertFalse(p.nextTapUnlocks(at: start.addingTimeInterval(1)))
    }
}
