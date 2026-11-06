import XCTest
@testable import MergeQueueBar

final class SnapshotTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_793_000_000)

    private func node(_ number: Int, labels: [String] = [], draft: Bool = false) -> String {
        let labelNodes = labels.map { "{\"name\":\"\($0)\"}" }.joined(separator: ",")
        return """
        {"number":\(number),"title":"PR \(number)","url":"https://github.com/o/r/pull/\(number)",
         "isDraft":\(draft),"repository":{"name":"r"},"labels":{"nodes":[\(labelNodes)]}}
        """
    }

    private func response(queued: [String] = [], queuedCount: Int? = nil, landed: Int = 0,
                          failed: [String] = [], mine: [String] = [], mineMerged: Int = 0,
                          landedPast: [Int] = [0, 0, 0, 0, 0, 0], minePast: [Int] = [0, 0, 0, 0, 0, 0]) -> Data {
        let history = landedPast.enumerated().map { "\"landedDay\($0.offset)\":{\"issueCount\":\($0.element)}" }
            + minePast.enumerated().map { "\"mineMergedDay\($0.offset)\":{\"issueCount\":\($0.element)}" }
        return """
        {"data":{
          \(history.joined(separator: ",")),
          "queued":{"issueCount":\(queuedCount ?? queued.count),"nodes":[\(queued.joined(separator: ","))]},
          "landed":{"issueCount":\(landed)},
          "failed":{"issueCount":\(failed.count),"nodes":[\(failed.joined(separator: ","))]},
          "mineOpen":{"issueCount":\(mine.count),"nodes":[\(mine.joined(separator: ","))]},
          "mineMerged":{"issueCount":\(mineMerged)}
        }}
        """.data(using: .utf8)!
    }

    func testTotalsCountTaggedLandedAndFailed() throws {
        let data = response(queued: [node(1, labels: ["ready to review"])], landed: 5,
                            failed: [node(2, labels: ["automerge failed"])],
                            mine: [node(3)], mineMerged: 4)
        let s = try SnapshotDecoder.decode(data, fetchedAt: now)
        XCTAssertEqual(s.queueTotalToday, 7)
        XCTAssertEqual(s.mineTotalToday, 5)
        XCTAssertEqual(SummaryText.title(s), "MQ 1/7 \u{00B7} Me 1/5 \u{2717}1")
    }

    func testTitleHasNoFailMarkWhenNothingBounced() throws {
        let s = try SnapshotDecoder.decode(response(landed: 28, mineMerged: 24), fetchedAt: now)
        XCTAssertEqual(SummaryText.title(s), "MQ 0/28 \u{00B7} Me 0/24")
    }

    func testMyOpenPRsLeaveOutOnlyTheOnesWithTheLander() throws {
        let mine = [node(1), node(2, labels: ["ready to review"]),
                    node(3, labels: ["ready to review", "autolanding"]), node(4, draft: true),
                    node(5, labels: ["ready to review", "automerge failed"]),
                    node(6, labels: ["ready to review", "nomerge"])]
        let s = try SnapshotDecoder.decode(response(mine: mine), fetchedAt: now)
        XCTAssertEqual(s.mineOpen.map(\.number), [1, 4, 5, 6])
        XCTAssertEqual(s.mineOpenCount, 4)
    }

    func testHistoryIsOldestFirstEndingToday() throws {
        let data = response(landed: 7, mineMerged: 3, landedPast: [1, 2, 3, 4, 5, 6], minePast: [0, 0, 0, 0, 0, 9])
        let s = try SnapshotDecoder.decode(data, fetchedAt: now)
        XCTAssertEqual(s.landedByDay, [1, 2, 3, 4, 5, 6, 7])
        XCTAssertEqual(SummaryText.historyLine(s.landedByDay), "7d: 1 2 3 4 5 6 7 = 28")
        XCTAssertEqual(s.mineMergedByDay, [0, 0, 0, 0, 0, 9, 3])
    }

    func testMissingHistoryDayIsMalformed() {
        XCTAssertThrowsError(try SnapshotDecoder.decode(response(landedPast: [1, 2]), fetchedAt: now)) {
            XCTAssertEqual($0 as? SnapshotDecodeError, .malformed)
        }
    }

    func testCountsComeFromIssueCountNotTheList() throws {
        let s = try SnapshotDecoder.decode(response(queued: [node(1)], queuedCount: 51), fetchedAt: now)
        XCTAssertEqual(s.queuedCount, 51)
        XCTAssertEqual(SummaryText.moreLine(shown: s.queued.count, total: s.queuedCount), "\u{2026} and 50 more")
    }

    func testNonPullRequestNodeIsSkipped() throws {
        let s = try SnapshotDecoder.decode(response(queued: ["{}", node(7)]), fetchedAt: now)
        XCTAssertEqual(s.queued.map(\.number), [7])
    }

    func testGraphQLErrorIsReported() {
        let data = #"{"errors":[{"message":"Bad credentials"}]}"#.data(using: .utf8)!
        XCTAssertThrowsError(try SnapshotDecoder.decode(data, fetchedAt: now)) {
            XCTAssertEqual($0 as? SnapshotDecodeError, .graphQL("Bad credentials"))
        }
    }

    func testHTTPErrorBodyIsReported() {
        let data = #"{"message":"Bad credentials","status":"401"}"#.data(using: .utf8)!
        XCTAssertThrowsError(try SnapshotDecoder.decode(data, fetchedAt: now)) {
            XCTAssertEqual($0 as? SnapshotDecodeError, .graphQL("Bad credentials"))
        }
    }

    func testNonJSONIsMalformed() {
        XCTAssertThrowsError(try SnapshotDecoder.decode(Data("oops".utf8), fetchedAt: now)) {
            XCTAssertEqual($0 as? SnapshotDecodeError, .malformed)
        }
    }

    func testRowMarksLandingAndDraftAndTruncates() {
        let url = URL(string: "https://github.com/o/r/pull/9")!
        let long = String(repeating: "x", count: 80)
        let pr = PullRequest(repo: "r", number: 9, title: long, url: url, isDraft: true,
                             labels: ["autolanding"])
        let row = SummaryText.row(pr)
        XCTAssertTrue(row.hasPrefix("\u{25B6} r#9 "))
        XCTAssertTrue(row.hasSuffix("\u{2026} (draft)"))
        XCTAssertEqual(SummaryText.truncate(long).count, SummaryText.titleLimit)
    }
}
