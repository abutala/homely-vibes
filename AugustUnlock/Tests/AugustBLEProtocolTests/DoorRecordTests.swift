import XCTest

@testable import AugustBLEProtocol

final class DoorRecordTests: XCTestCase {
    private let start = Date(timeIntervalSinceReferenceDate: 1000)
    private let widget = DoorRecord.widgetUnlockedTrust
    private let app = TimeInterval.infinity

    private func record(_ state: DoorRecord.State, running: Bool? = nil, age: TimeInterval = 0) -> DoorRecord {
        DoorRecord(state: state, running: running, at: start.addingTimeInterval(-age))
    }

    func testWidgetTrustIsThreeMinutesAndRunsExpireAt45s() {
        XCTAssertEqual(DoorRecord.widgetUnlockedTrust, 180)
        XCTAssertEqual(DoorRecord.runningTimeout, 45)
    }

    func testNoHistoryUnlocks() {
        XCTAssertTrue(DoorRecord(at: .distantPast).nextTapUnlocks(at: start, trustUnlockedFor: widget))
    }

    func testTapWhileUnlockingLocksAndWhileLockingUnlocks() {
        XCTAssertFalse(record(.unknown, running: true).nextTapUnlocks(at: start, trustUnlockedFor: widget))
        XCTAssertTrue(record(.unknown, running: false).nextTapUnlocks(at: start, trustUnlockedFor: widget))
    }

    func testStaleRunReadsAsUnknownAndUnlocks() {
        let stale = record(.unknown, running: true, age: 45)
        XCTAssertEqual(stale.effective(at: start, trustUnlockedFor: widget), record(.unknown, age: 45))
        XCTAssertTrue(stale.nextTapUnlocks(at: start, trustUnlockedFor: widget))
    }

    func testRecentUnlockLocks() {
        XCTAssertFalse(record(.unlocked, age: 179).nextTapUnlocks(at: start, trustUnlockedFor: widget))
    }

    func testWidgetForgetsUnlockAfterTrust_AppDoesNot() {
        let old = record(.unlocked, age: 180)
        XCTAssertTrue(old.nextTapUnlocks(at: start, trustUnlockedFor: widget))
        XCTAssertFalse(old.nextTapUnlocks(at: start, trustUnlockedFor: app))
    }

    func testLockedOrUnknownUnlocks() {
        XCTAssertTrue(record(.locked).nextTapUnlocks(at: start, trustUnlockedFor: app))
        XCTAssertTrue(record(.unknown).nextTapUnlocks(at: start, trustUnlockedFor: app))
    }

    func testNextChangeTimes() {
        XCTAssertEqual(record(.unknown, running: true).nextChange(after: start, trustUnlockedFor: widget), start.addingTimeInterval(45))
        XCTAssertEqual(record(.unlocked).nextChange(after: start, trustUnlockedFor: widget), start.addingTimeInterval(180))
        XCTAssertNil(record(.unlocked).nextChange(after: start, trustUnlockedFor: app))
        XCTAssertNil(record(.locked).nextChange(after: start, trustUnlockedFor: widget))
    }
}
