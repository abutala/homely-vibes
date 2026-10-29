import XCTest

@testable import AugustBLEProtocol

final class DoorTapPolicyTests: XCTestCase {
    private let start = Date(timeIntervalSinceReferenceDate: 1000)
    private let widget = DoorTapPolicy.widgetUnlockedTrust
    private let app = TimeInterval.infinity

    func testWidgetTrustIsThreeMinutes() {
        XCTAssertEqual(DoorTapPolicy.widgetUnlockedTrust, 180)
    }

    func testFirstTapUnlocks() {
        XCTAssertTrue(DoorTapPolicy().nextTapUnlocks(at: start, trustUnlockedFor: widget))
        XCTAssertTrue(DoorTapPolicy().nextTapUnlocks(at: start, trustUnlockedFor: app))
    }

    func testTapWhileUnlockingLocks() {
        var p = DoorTapPolicy()
        p.didSend(unlocking: true)
        XCTAssertFalse(p.nextTapUnlocks(at: start, trustUnlockedFor: widget))
    }

    func testTapWhileLockingUnlocks() {
        var p = DoorTapPolicy()
        p.didSend(unlocking: false)
        XCTAssertTrue(p.nextTapUnlocks(at: start, trustUnlockedFor: widget))
    }

    func testTapSoonAfterUnlockLocks() {
        var p = DoorTapPolicy()
        p.didSend(unlocking: true)
        p.didFinish(reportedUnlocked: true, at: start)
        XCTAssertFalse(p.nextTapUnlocks(at: start.addingTimeInterval(179), trustUnlockedFor: widget))
    }

    func testWidgetTapLongAfterUnlockUnlocksAgain() {
        var p = DoorTapPolicy()
        p.didSend(unlocking: true)
        p.didFinish(reportedUnlocked: true, at: start)
        XCTAssertTrue(p.nextTapUnlocks(at: start.addingTimeInterval(180), trustUnlockedFor: widget))
    }

    func testAppTapLongAfterUnlockStillLocks() {
        var p = DoorTapPolicy()
        p.didSend(unlocking: true)
        p.didFinish(reportedUnlocked: true, at: start)
        XCTAssertFalse(p.nextTapUnlocks(at: start.addingTimeInterval(3600), trustUnlockedFor: app))
    }

    func testTapAfterLockUnlocks() {
        var p = DoorTapPolicy()
        p.didSend(unlocking: false)
        p.didFinish(reportedUnlocked: false, at: start)
        XCTAssertTrue(p.nextTapUnlocks(at: start.addingTimeInterval(1), trustUnlockedFor: app))
    }

    func testFailureForgetsTheUnlock() {
        var p = DoorTapPolicy()
        p.didFinish(reportedUnlocked: true, at: start)
        p.didSend(unlocking: false)
        p.didFinish(reportedUnlocked: false, at: start.addingTimeInterval(5))
        XCTAssertTrue(p.nextTapUnlocks(at: start.addingTimeInterval(6), trustUnlockedFor: app))
    }

    func testOverrideBackToUnlockRecordsTheReply() {
        var p = DoorTapPolicy()
        p.didSend(unlocking: true)
        p.didSend(unlocking: false)
        p.didSend(unlocking: true)
        p.didFinish(reportedUnlocked: true, at: start)
        XCTAssertFalse(p.nextTapUnlocks(at: start.addingTimeInterval(1), trustUnlockedFor: widget))
    }
}
