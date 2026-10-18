import XCTest

@testable import AugustBLEProtocol

final class BackgroundExitPolicyTests: XCTestCase {
    private let start = Date(timeIntervalSinceReferenceDate: 1000)

    private func policy(backgroundedAt: Date? = nil) -> BackgroundExitPolicy {
        var p = BackgroundExitPolicy(timeout: 300)
        if let backgroundedAt { p.didBackground(at: backgroundedAt) }
        return p
    }

    func testDefaultTimeoutIsFiveMinutes() {
        XCTAssertEqual(BackgroundExitPolicy.defaultTimeout, 300)
    }

    func testNeverBackgroundedNeverExits() {
        XCTAssertFalse(policy().shouldExit(at: start.addingTimeInterval(10_000), operationInFlight: false))
    }

    func testStaysBeforeTimeout() {
        let p = policy(backgroundedAt: start)
        XCTAssertFalse(p.shouldExit(at: start.addingTimeInterval(299), operationInFlight: false))
    }

    func testExitsAtAndAfterTimeout() {
        let p = policy(backgroundedAt: start)
        XCTAssertTrue(p.shouldExit(at: start.addingTimeInterval(300), operationInFlight: false))
        XCTAssertTrue(p.shouldExit(at: start.addingTimeInterval(900), operationInFlight: false))
    }

    func testInFlightOperationDefersExit() {
        let p = policy(backgroundedAt: start)
        XCTAssertFalse(p.shouldExit(at: start.addingTimeInterval(900), operationInFlight: true))
    }

    func testForegroundingBeforeTimeoutCancels() {
        var p = policy(backgroundedAt: start)
        p.didForeground()
        XCTAssertFalse(p.shouldExit(at: start.addingTimeInterval(900), operationInFlight: false))
    }

    func testRepeatedBackgroundKeepsFirstTimestamp() {
        var p = policy(backgroundedAt: start)
        p.didBackground(at: start.addingTimeInterval(200))
        XCTAssertTrue(p.shouldExit(at: start.addingTimeInterval(300), operationInFlight: false))
    }

    func testRemainingTimeCountsDown() {
        let p = policy(backgroundedAt: start)
        XCTAssertEqual(p.remaining(at: start.addingTimeInterval(100)), 200)
        XCTAssertEqual(p.remaining(at: start.addingTimeInterval(400)), 0)
        XCTAssertNil(policy().remaining(at: start))
    }
}
