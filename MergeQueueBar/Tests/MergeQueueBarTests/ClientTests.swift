import XCTest
@testable import MergeQueueBar

final class ClientTests: XCTestCase {
    private let pst: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "America/Los_Angeles")!
        return calendar
    }()

    func testDayStartsAreSevenLocalMidnightsAcrossDST() {
        // 2026-11-05 15:00 PST; 2026-11-01 is the DST change.
        let now = Date(timeIntervalSince1970: 1_793_919_600)
        let days = DayStart.isoStrings(now: now, calendar: pst)
        XCTAssertEqual(days.count, 7)
        XCTAssertEqual(days.first, "2026-10-30T00:00:00-07:00")
        XCTAssertEqual(days.last, "2026-11-05T00:00:00-08:00")
    }

    func testQueriesScopeToOrgAndDay() {
        let q = QueueQueries(org: "acme", dayStarts: ["2026-11-04T00:00:00-08:00", "2026-11-05T00:00:00-08:00"])
        let byAlias = Dictionary(uniqueKeysWithValues: q.searches.map { ($0.alias, $0.query) })
        XCTAssertEqual(byAlias["queued"], "org:acme is:pr is:open label:\"ready to review\" -label:\"automerge failed\" -label:nomerge")
        XCTAssertEqual(byAlias["landed"], "org:acme is:pr is:merged label:autolanded merged:>=2026-11-05T00:00:00-08:00")
        XCTAssertEqual(byAlias["mineOpen"], "is:pr author:@me is:open")
        XCTAssertEqual(byAlias["mineMerged"], "is:pr author:@me is:merged -label:autolanded merged:>=2026-11-05T00:00:00-08:00")
        XCTAssertEqual(byAlias["landedWeek"], "org:acme is:pr is:merged label:autolanded merged:>=2026-11-04T00:00:00-08:00")
        XCTAssertEqual(byAlias["mineMergedWeek"], "is:pr author:@me is:merged -label:autolanded merged:>=2026-11-04T00:00:00-08:00")
    }

    func testFetchPassesEverySearchToGh() throws {
        var captured: [String] = []
        let body = #"{"data":{"queued":{"issueCount":0,"nodes":[]},"landed":{"issueCount":3},"failed":{"issueCount":0,"nodes":[]},"mineOpen":{"issueCount":0,"nodes":[]},"mineMerged":{"issueCount":2},"landedWeek":{"issueCount":9},"mineMergedWeek":{"issueCount":4}}}"#
        let s = try GitHubClient.fetch(
            org: "acme", now: Date(),
            locate: { URL(fileURLWithPath: "/bin/gh") },
            run: { _, args in captured = args; return Data(body.utf8) }
        )
        XCTAssertEqual(s.landedWeek, 9)
        XCTAssertEqual(Array(captured.prefix(2)), ["api", "graphql"])
        // Queue searches are org-scoped; my searches cover every repo.
        XCTAssertEqual(captured.filter { $0.contains("=org:acme ") }.count, 4)
        XCTAssertEqual(captured.filter { $0.contains("=is:pr author:@me ") }.count, 3)
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
