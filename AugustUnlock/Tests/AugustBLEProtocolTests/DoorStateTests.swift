import XCTest

@testable import AugustBLEProtocol

/// The per-door marks the widget shows: only the tapped door moves, a
/// result holds for `DoorState.hold`, then clears on its own entry.
final class DoorStateTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_000_000)

    func testOnlyTheTappedDoorRuns() {
        var state = DoorState()
        state.start(1)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.none, .running])
    }

    func testAResultHoldsThenClears() {
        var state = DoorState()
        state.start(0)
        state.finish(0, ok: true, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.ok, .none])
        XCTAssertEqual(state.marks(count: 2, at: t0 + DoorState.hold - 0.1), [.ok, .none])
        XCTAssertEqual(state.marks(count: 2, at: t0 + DoorState.hold), [.none, .none])
        XCTAssertEqual(state.clearDate(at: t0), t0 + DoorState.hold)
        XCTAssertNil(state.clearDate(at: t0 + DoorState.hold))
    }

    func testAFailureShowsAndANewTapReplacesIt() {
        var state = DoorState()
        state.finish(1, ok: false, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.none, .failed])
        state.start(1)
        XCTAssertEqual(state.marks(count: 2, at: t0 + 1), [.none, .running])
        XCTAssertNil(state.clearDate(at: t0 + 1))
    }

    func testTwoDoorsKeepTheirOwnState() {
        var state = DoorState()
        state.start(0)
        state.start(1)
        state.finish(0, ok: true, at: t0)
        XCTAssertEqual(state.marks(count: 2, at: t0), [.ok, .running])
        XCTAssertEqual(state.clearDate(at: t0), t0 + DoorState.hold)
    }

    func testRoundTripsThroughJSON() throws {
        var state = DoorState()
        state.start(0)
        state.finish(1, ok: false, at: t0)
        let data = try JSONEncoder().encode(state)
        XCTAssertEqual(try JSONDecoder().decode(DoorState.self, from: data), state)
    }
}
