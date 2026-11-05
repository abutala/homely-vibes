import XCTest

@testable import ClaudeUsageBar

/// A plan with no 5-hour limit (Ultra) gets no 5-hour segment. The signal is
/// the response's `limits` list: the 5-hour meter has `kind` `session`.
final class FiveHourLimitTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_786_940_000)

    private func snapshot(fiveHour: UsageWindow?, hasFiveHourLimit: Bool) -> UsageSnapshot {
        UsageSnapshot(
            fiveHour: fiveHour,
            sevenDay: UsageWindow(utilization: 37, resetsAt: now.addingTimeInterval(4.4 * 86400)),
            sevenDayOpus: nil, sevenDaySonnet: nil, spend: nil,
            hasFiveHourLimit: hasFiveHourLimit, fetchedAt: now
        )
    }

    private func title(_ snapshot: UsageSnapshot) -> String {
        UsageText.title(for: snapshot, now: now).string
    }

    func testNoSessionMeterMeansNoFiveHourLimit() {
        let json: [String: Any] = ["limits": [["kind": "weekly_all"], ["kind": "weekly_scoped"]]]
        XCTAssertFalse(UsageClient.hasFiveHourLimit(json))
    }

    func testSessionMeterMeansFiveHourLimit() {
        let json: [String: Any] = ["limits": [["kind": "session"], ["kind": "weekly_all"]]]
        XCTAssertTrue(UsageClient.hasFiveHourLimit(json))
    }

    /// An older payload with no `limits` list keeps the 5-hour segment.
    func testMissingLimitsListAssumesFiveHourLimit() {
        XCTAssertTrue(UsageClient.hasFiveHourLimit([:]))
    }

    func testTitleOmitsFiveHourSegmentWithoutLimit() {
        XCTAssertEqual(title(snapshot(fiveHour: nil, hasFiveHourLimit: false)), "7d: 63% 4.4d")
    }

    /// With a limit, an absent window still means nothing spent yet.
    func testTitleShowsFullFiveHourWindowWhenLimitApplies() {
        XCTAssertEqual(title(snapshot(fiveHour: nil, hasFiveHourLimit: true)), "100% 5.0h \u{00B7} 63% 4.4d")
    }
}
