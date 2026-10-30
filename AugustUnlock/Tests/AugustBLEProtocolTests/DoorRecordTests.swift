import XCTest

@testable import AugustBLEProtocol

final class DoorRecordTests: XCTestCase {
    private let start = Date(timeIntervalSinceReferenceDate: 1000)

    private func record(_ state: DoorRecord.State, running: Bool? = nil, age: TimeInterval = 0) -> DoorRecord {
        DoorRecord(state: state, running: running, at: start.addingTimeInterval(-age))
    }

    func testTrustIsThreeMinutesAndRunsExpireAt45s() {
        XCTAssertEqual(DoorRecord.unlockedTrust, 180)
        XCTAssertEqual(DoorRecord.runningTimeout, 45)
    }

    func testNoHistoryUnlocks() {
        XCTAssertTrue(DoorRecord(at: .distantPast).nextTapUnlocks(at: start))
    }

    func testTapWhileUnlockingLocksAndWhileLockingUnlocks() {
        XCTAssertFalse(record(.unknown, running: true).nextTapUnlocks(at: start))
        XCTAssertTrue(record(.unknown, running: false).nextTapUnlocks(at: start))
    }

    func testStaleRunReadsAsUnknownAndUnlocks() {
        let stale = record(.unknown, running: true, age: 45)
        XCTAssertEqual(stale.effective(at: start), record(.unknown, age: 45))
        XCTAssertTrue(stale.nextTapUnlocks(at: start))
    }

    func testRecentUnlockLocks() {
        XCTAssertFalse(record(.unlocked, age: 179).nextTapUnlocks(at: start))
    }

    func testUnlockIsForgottenAfterTrust() {
        XCTAssertTrue(record(.unlocked, age: 180).nextTapUnlocks(at: start))
    }

    func testLockedOrUnknownUnlocks() {
        XCTAssertTrue(record(.locked).nextTapUnlocks(at: start))
        XCTAssertTrue(record(.unknown).nextTapUnlocks(at: start))
    }

    func testNextChangeTimes() {
        XCTAssertEqual(record(.unknown, running: true).nextChange(), start.addingTimeInterval(45))
        XCTAssertEqual(record(.unlocked).nextChange(), start.addingTimeInterval(180))
        XCTAssertNil(record(.locked).nextChange())
    }

    func testAugustStatusStrings() {
        XCTAssertEqual(DoorRecord.State(augustStatus: "kAugLockState_Locked"), .locked)
        XCTAssertEqual(DoorRecord.State(augustStatus: "unlatched"), .unlocked)
        XCTAssertEqual(DoorRecord.State(augustStatus: "kAugLockState_Jammed"), .unknown)
        XCTAssertEqual(DoorRecord.State(augustStatus: nil), .unknown)
    }
}
