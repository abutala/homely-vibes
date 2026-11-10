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
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0, at: t0), .ok)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.none, .none], "a locked door shows its name")
    }

    func testOneFailedDoorFailsTheWholeAndShowsOnThatDoor() {
        var state = DoorState()
        XCTAssertEqual(state.recordLocks([.ok, .failed], startedAt: t0, at: t0), .failed)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.none, .failed])
    }

    func testAFailureOutranksNoReply() {
        var state = DoorState()
        XCTAssertEqual(state.recordLocks([.noReply, .failed], startedAt: t0, at: t0), .failed)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.noReply, .failed])
    }

    func testNoReplyOnOneDoorIsNotLocked() {
        var state = DoorState()
        XCTAssertEqual(state.recordLocks([.noReply, .ok], startedAt: t0, at: t0), .noReply)
    }

    func testNoDoorsIsNotLocked() {
        var state = DoorState()
        XCTAssertEqual(state.recordLocks([], startedAt: t0, at: t0), .failed)
    }

    func testALockClearsAnOldUnlockResult() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(0, startedAt: t0, outcome: .ok, at: t0)
        _ = state.recordLocks([.ok, .ok], startedAt: t0 + 1, at: t0 + 1)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.none, .none], "the door no longer reads Unlocked")
    }

    func testALockLeavesARunningDoorAlone() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        _ = state.recordLocks([.failed, .ok], startedAt: t0 + 1, at: t0 + 1)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.running, .none])
    }

    /// An unlock August still holds can land after the lock (the ghost of
    /// `formal/ghost_order.qnt`): the widget must not say "Locked" over it.
    func testAnUnansweredUnlockStopsLockedForItsWindow() {
        var state = DoorState()
        _ = state.start(1, at: t0)
        state.finish(1, startedAt: t0, outcome: .noReply, at: t0 + 28)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 30, at: t0 + 30), .noReply)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 30), [.none, .noReply])
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 28 + DoorState.unansweredWindow, at: t0 + 28 + DoorState.unansweredWindow), .ok, "the window is over")
    }

    /// A cloud unlock that ended in an error was still sent, so it counts too.
    func testAFailedUnlockStopsLockedForItsWindow() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(0, startedAt: t0, outcome: .failed, at: t0 + 5)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 6, at: t0 + 7), .noReply)
    }

    func testAnOkUnlockDoesNotStopLocked() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(0, startedAt: t0, outcome: .ok, at: t0 + 5)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 6, at: t0 + 7), .ok)
    }

    /// Door 0 locks fast, an unlock tap on it succeeds, then the slow door
    /// locks: door 0 is open, so the center must not say "Locked", and the
    /// door keeps its own "Unlocked".
    func testAnUnlockTappedDuringLockBothStopsLocked() {
        var state = DoorState()
        _ = state.start(center, at: t0)
        _ = state.start(0, at: t0 + 7)
        state.finish(0, startedAt: t0 + 7, outcome: .ok, at: t0 + 9)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0, at: t0 + 20), .noReply)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 20), [.ok, .none])
    }

    func testAnUnlockStillRunningWhenLockBothEndsStopsLocked() {
        var state = DoorState()
        _ = state.start(0, at: t0 + 7)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0, at: t0 + 20), .noReply)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 20), [.running, .none])
    }

    func testAnUnlockFromBeforeLockBothDoesNotStopLocked() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(0, startedAt: t0, outcome: .ok, at: t0 + 1)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 2, at: t0 + 3), .ok)
    }

    func testAnUnansweredLockDoesNotStopLocked() {
        var state = DoorState()
        _ = state.recordLocks([.noReply, .ok], startedAt: t0, at: t0)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 1, at: t0 + 1), .ok, "a held lock moves the door the same way")
    }

    /// Bluetooth unlocked the door and the cloud copy of the unlock is still
    /// on its way (both paths start together, 2026-11-09): it can land after
    /// the lock, so the center must not say "Locked" over it.
    func testAnUnlockStillOnItsWayStopsLocked() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(0, startedAt: t0, outcome: .ok, at: t0 + 2)
        state.tailOpened(0, at: t0 + 2)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 5, at: t0 + 8), .noReply)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 8), [.noReply, .none])
        let after = t0 + 2 + DoorState.unansweredWindow
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: after, at: after), .ok, "the window is over")
    }

    func testAugustsReplyLetsLockedShow() {
        var state = DoorState()
        state.tailOpened(0, at: t0)
        state.tailConfirmed(0, openedAt: t0)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 5, at: t0 + 8), .ok)
    }

    /// A process that died with the cloud copy out never reports it. The
    /// next tap's reply must not clear the older one's window.
    func testAReplyDoesNotClearAnOlderUnlockStillOnItsWay() {
        var state = DoorState()
        state.tailOpened(0, at: t0)
        state.tailOpened(0, at: t0 + 10)
        state.tailConfirmed(0, openedAt: t0 + 10)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 20, at: t0 + 20), .noReply)
        let after = t0 + DoorState.unansweredWindow
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: after, at: after), .ok, "the older one's window is over")
    }

    func testAnOlderTapsReplyDoesNotClearANewerOne() {
        var state = DoorState()
        state.tailOpened(0, at: t0)
        state.tailOpened(0, at: t0 + 10)
        state.tailConfirmed(0, openedAt: t0)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: t0 + 20, at: t0 + 20), .noReply)
    }

    /// The cloud unlock goes out when the tap starts. A process that dies
    /// before any answer writes no result: the tap's own start is the only
    /// trace, and that unlock can still land (`pathsNoRunning` in the model).
    func testAnUnlockTapThatNeverEndedStopsLocked() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        let later = t0 + DoorState.runningLimit + 5
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: later, at: later), .noReply)
        let after = t0 + DoorState.unansweredWindow
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: after, at: after), .ok, "the window is over")
    }

    func testADeadTapsUnlockOutlivesTheNextTap() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        let next = t0 + DoorState.runningLimit + 1
        XCTAssertTrue(state.start(0, at: next))
        state.finish(0, startedAt: next, outcome: .ok, at: next + 2)
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: next + 4, at: next + 4), .noReply, "the dead tap's unlock may still land")
        let after = t0 + DoorState.unansweredWindow
        XCTAssertEqual(state.recordLocks([.ok, .ok], startedAt: after, at: after), .ok)
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
        state.tailOpened(0, at: t0 + 1)
        let data = try JSONEncoder().encode(state)
        XCTAssertEqual(try JSONDecoder().decode(DoorState.self, from: data), state)
    }
}
