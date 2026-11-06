import XCTest
@testable import MergeQueueBar

final class ClientTests: XCTestCase {
    func testDayStartIsLocalMidnightWithOffset() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "America/Los_Angeles")!
        // 2026-11-05 15:00 PST
        let now = Date(timeIntervalSince1970: 1_793_919_600)
        XCTAssertEqual(DayStart.isoString(now: now, calendar: calendar), "2026-11-05T00:00:00-08:00")
    }

    func testQueriesScopeToOrgAndDay() {
        let q = QueueQueries(org: "acme", dayStart: "2026-11-05T00:00:00-08:00")
        XCTAssertEqual(q.queued, "org:acme is:pr is:open label:\"ready to review\" -label:\"automerge failed\" -label:nomerge")
        XCTAssertEqual(q.landedToday, "org:acme is:pr is:merged label:autolanded merged:>=2026-11-05T00:00:00-08:00")
        XCTAssertEqual(q.mineOpen, "org:acme is:pr is:open author:@me")
    }

    func testFetchPassesEveryQueryVariableToGh() throws {
        var captured: [String] = []
        let body = #"{"data":{"queued":{"issueCount":0,"nodes":[]},"landed":{"issueCount":3},"failed":{"issueCount":0,"nodes":[]},"mineOpen":{"issueCount":0,"nodes":[]},"mineMerged":{"issueCount":2}}}"#
        let s = try GitHubClient.fetch(
            org: "acme", now: Date(),
            locate: { URL(fileURLWithPath: "/bin/gh") },
            run: { _, args in captured = args; return Data(body.utf8) }
        )
        XCTAssertEqual(s.landedToday, 3)
        XCTAssertEqual(Array(captured.prefix(2)), ["api", "graphql"])
        for name in ["queued", "landed", "failed", "mineOpen", "mineMerged"] {
            XCTAssertTrue(captured.contains { $0.hasPrefix("\(name)=org:acme ") }, name)
        }
    }

    func testMissingGhIsReported() {
        XCTAssertThrowsError(try GitHubClient.fetch(locate: { nil }, run: { _, _ in Data() })) {
            XCTAssertEqual($0 as? GitHubClientError, .ghNotFound)
        }
    }

    func testRefreshIntervalDefaultsToTwoMinutes() {
        XCTAssertEqual(RefreshInterval.resolve(stored: 0), 120)
        XCTAssertEqual(RefreshInterval.resolve(stored: 45), 120)
        XCTAssertEqual(RefreshInterval.resolve(stored: 300), 300)
        XCTAssertEqual(RefreshInterval.choices.map(RefreshInterval.label(for:)),
                       ["1 min", "2 min", "5 min", "10 min"])
    }
}
