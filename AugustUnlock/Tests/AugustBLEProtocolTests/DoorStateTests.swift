import XCTest

@testable import AugustBLEProtocol

/// The per-door marks the widget shows: only the tapped door moves, a
/// result holds for `DoorState.hold`, then clears on its own entry.
final class DoorStateTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_000_000)

    func testOnlyTheTappedDoorRuns() {
        var state = DoorState()
        _ = state.start(1, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.none, .running])
    }

    func testAnOldTapCannotClearANewerTapsMark() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        XCTAssertTrue(state.start(0, at: t0 + DoorState.runningLimit + 1), "the old tap's mark expired")
        state.finish(0, startedAt: t0, outcome: .ok, at: t0 + DoorState.runningLimit + 2)
        XCTAssertEqual(state.marks(count: 1, at: t0 + DoorState.runningLimit + 2), [.running], "the newer tap still runs")
        state.finish(0, startedAt: t0 + DoorState.runningLimit + 1, outcome: .failed, at: t0 + DoorState.runningLimit + 3)
        XCTAssertEqual(state.marks(count: 1, at: t0 + DoorState.runningLimit + 3), [.failed])
    }

    func testAResultHoldsThenClears() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(0, startedAt: t0, outcome: .ok, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.ok, .none])
        XCTAssertEqual(state.marks(count: 2, at: t0 + DoorState.hold - 0.1), [.ok, .none])
        XCTAssertEqual(state.marks(count: 2, at: t0 + DoorState.hold), [.none, .none])
        XCTAssertEqual(state.clearDates(at: t0), [t0 + DoorState.hold])
        XCTAssertEqual(state.clearDates(at: t0 + DoorState.hold), [])
    }

    func testAFailureShowsAndANewTapReplacesIt() {
        var state = DoorState()
        state.finish(1, startedAt: t0, outcome: .failed, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.none, .failed])
        _ = state.start(1, at: t0 + 1)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.none, .running])
        XCTAssertEqual(state.clearDates(at: t0 + 1), [t0 + 1 + DoorState.runningLimit])
    }

    func testTwoDoorsKeepTheirOwnState() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        _ = state.start(1, at: t0)
        state.finish(0, startedAt: t0, outcome: .ok, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.ok, .running])
        // Door 1 clears at its own hold; door 2's limit is a later entry.
        XCTAssertEqual(state.clearDates(at: t0), [t0 + DoorState.hold, t0 + DoorState.runningLimit])
        XCTAssertEqual(state.marks(count: 2, at: t0 + DoorState.hold), [.none, .running])
    }

    func testATapWhoseProcessDiedExpires() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0 + DoorState.runningLimit - 1), [.running, .none])
        XCTAssertEqual(state.marks(count: 2, at: t0 + DoorState.runningLimit), [.none, .none])
        XCTAssertEqual(state.clearDates(at: t0 + DoorState.runningLimit), [])
    }

    func testARepeatTapOnARunningDoorIsRefused() {
        var state = DoorState()
        XCTAssertTrue(state.start(0, at: t0))
        XCTAssertFalse(state.start(0, at: t0 + 1))
        XCTAssertTrue(state.start(1, at: t0 + 1), "the other door is free")
        XCTAssertTrue(state.start(0, at: t0 + DoorState.runningLimit), "an expired tap is over")
    }

    func testACloudLegCutOffAfterItsSendShowsNoReply() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(0, startedAt: t0, outcome: .noReply, at: t0 + 28)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 28), [.noReply, .none])
        XCTAssertEqual(state.marks(count: 2, at: t0 + 28 + DoorState.hold), [.none, .none])
    }

    /// iOS ends a background intent at about 30 s (Apple, `LongRunningIntent`):
    /// a tap must write its result before that, and a mark must outlive a tap
    /// that died, with room for the result write and the reload.
    func testATapFitsTheIntentCapAndTheLimitOutlivesIt() {
        XCTAssertLessThan(DoorState.tapLimit, 30)
        XCTAssertGreaterThanOrEqual(DoorState.runningLimit, DoorState.tapLimit + 5)
    }

    // MARK: - Lock Both

    private let center = DoorState.lockBothPosition

    func testLockBothHasItsOwnMark() {
        var state = DoorState()
        XCTAssertTrue(state.start(center, at: t0))
        XCTAssertFalse(state.start(center, at: t0 + 1), "a repeat tap is refused")
        XCTAssertEqual(state.marks(count: DoorState.positionCount, at: t0), [.none, .none, .running])
    }

    func testBothLockedReadsOk() {
        var state = DoorState()
        XCTAssertEqual(state.recordLocks([.ok, .ok], at: t0), .ok)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.none, .none], "a locked door shows its name")
    }

    func testOneFailedDoorFailsTheWholeAndShowsOnThatDoor() {
        var state = DoorState()
        XCTAssertEqual(state.recordLocks([.ok, .failed], at: t0), .failed)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.none, .failed])
    }

    func testAFailureOutranksNoReply() {
        var state = DoorState()
        XCTAssertEqual(state.recordLocks([.noReply, .failed], at: t0), .failed)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.noReply, .failed])
    }

    func testNoReplyOnOneDoorIsNotLocked() {
        var state = DoorState()
        XCTAssertEqual(state.recordLocks([.noReply, .ok], at: t0), .noReply)
    }

    func testNoDoorsIsNotLocked() {
        var state = DoorState()
        XCTAssertEqual(state.recordLocks([], at: t0), .failed)
    }

    func testALockClearsAnOldUnlockResult() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(0, startedAt: t0, outcome: .ok, at: t0)
        _ = state.recordLocks([.ok, .ok], at: t0 + 1)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.none, .none], "the door no longer reads Unlocked")
    }

    func testALockLeavesARunningDoorAlone() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        _ = state.recordLocks([.failed, .ok], at: t0 + 1)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.running, .none])
    }

    /// An unlock August still holds can land after the lock (the ghost of
    /// `formal/ghost_order.qnt`): the widget must not say "Locked" over it.
    func testAnUnansweredUnlockStopsLockedForItsWindow() {
        var state = DoorState()
        _ = state.start(1, at: t0)
        state.finish(1, startedAt: t0, outcome: .noReply, at: t0 + 28)
        XCTAssertEqual(state.recordLocks([.ok, .ok], at: t0 + 30), .noReply)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 30), [.none, .noReply])
        XCTAssertEqual(state.recordLocks([.ok, .ok], at: t0 + 28 + DoorState.unansweredWindow), .ok, "the window is over")
    }

    func testAnUnansweredLockDoesNotStopLocked() {
        var state = DoorState()
        _ = state.recordLocks([.noReply, .ok], at: t0)
        XCTAssertEqual(state.recordLocks([.ok, .ok], at: t0 + 1), .ok, "a held lock moves the door the same way")
    }

    func testTheWindowMatchesTheScreens() {
        XCTAssertEqual(DoorState.unansweredWindow, CommandMachine.mayStillMoveWindow)
    }

    func testALockReplyCountsOnlyWhenLocked() {
        XCTAssertEqual(LockState.locked.lockOutcome, .ok)
        XCTAssertEqual(LockState.unlocked.lockOutcome, .failed)
        XCTAssertEqual(LockState.unknown.lockOutcome, .noReply)
    }

    func testRoundTripsThroughJSON() throws {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(1, startedAt: t0, outcome: .failed, at: t0)
        let data = try JSONEncoder().encode(state)
        XCTAssertEqual(try JSONDecoder().decode(DoorState.self, from: data), state)
    }
}
