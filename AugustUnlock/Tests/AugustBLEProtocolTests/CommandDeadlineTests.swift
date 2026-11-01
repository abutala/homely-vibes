import XCTest

@testable import AugustBLEProtocol

final class CommandDeadlineTests: XCTestCase {
    private let start = Date(timeIntervalSinceReferenceDate: 1000)

    func testLimitIsThirtySeconds() {
        XCTAssertEqual(CommandDeadline.limit, 30)
    }

    func testExpiresAtTheLimitNotBefore() {
        let deadline = CommandDeadline(startedAt: start)
        XCTAssertFalse(deadline.isExpired(at: start.addingTimeInterval(29.9)))
        XCTAssertTrue(deadline.isExpired(at: start.addingTimeInterval(30)))
        XCTAssertTrue(deadline.isExpired(at: start.addingTimeInterval(3600)))
    }
}
