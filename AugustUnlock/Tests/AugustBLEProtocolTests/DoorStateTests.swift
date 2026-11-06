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

    func testAResultHoldsThenClears() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(0, outcome: .ok, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.ok, .none])
        XCTAssertEqual(state.marks(count: 2, at: t0 + DoorState.hold - 0.1), [.ok, .none])
        XCTAssertEqual(state.marks(count: 2, at: t0 + DoorState.hold), [.none, .none])
        XCTAssertEqual(state.clearDates(at: t0), [t0 + DoorState.hold])
        XCTAssertEqual(state.clearDates(at: t0 + DoorState.hold), [])
    }

    func testAFailureShowsAndANewTapReplacesIt() {
        var state = DoorState()
        state.finish(1, outcome: .failed, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.none, .failed])
        _ = state.start(1, at: t0 + 1)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.none, .running])
        XCTAssertEqual(state.clearDates(at: t0 + 1), [t0 + 1 + DoorState.runningLimit])
    }

    func testTwoDoorsKeepTheirOwnState() {
        var state = DoorState()
        _ = state.start(0, at: t0)
        _ = state.start(1, at: t0)
        state.finish(0, outcome: .ok, at: t0)
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
        state.finish(0, outcome: .noReply, at: t0 + 28)
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

    func testRoundTripsThroughJSON() throws {
        var state = DoorState()
        _ = state.start(0, at: t0)
        state.finish(1, outcome: .failed, at: t0)
        let data = try JSONEncoder().encode(state)
        XCTAssertEqual(try JSONDecoder().decode(DoorState.self, from: data), state)
    }
}
