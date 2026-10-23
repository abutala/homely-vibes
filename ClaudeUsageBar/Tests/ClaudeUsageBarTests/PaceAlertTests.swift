import XCTest

@testable import ClaudeUsageBar

/// `now` is injected throughout. Windows are built from the share of the
/// window still left, so each case reads like the design table.
final class PaceAlertTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_786_940_000)
    private let length = PaceAlert.fiveHourLength

    private func alert(used: Double, timeLeftShare: Double, length: TimeInterval? = nil) -> PaceAlert {
        let length = length ?? self.length
        let window = UsageWindow(utilization: used, resetsAt: now.addingTimeInterval(timeLeftShare * length))
        return PaceAlert.evaluate(window, length: length, now: now)
    }

    // MARK: - warning threshold: used > 100 - 75 × timeLeftShare

    func testWarnsJustAboveThresholdAcrossTheWindow() {
        for (share, threshold) in [(0.9, 32.5), (0.5, 62.5), (0.1, 92.5)] {
            XCTAssertEqual(alert(used: threshold.rounded(.up) + 1, timeLeftShare: share), .warning, "share \(share)")
            XCTAssertEqual(alert(used: threshold.rounded(.down) - 1, timeLeftShare: share), .none, "share \(share)")
        }
    }

    /// "More than 25%": a needed cut of exactly 25% does not warn.
    func testExactlyTwentyFivePercentCutDoesNotWarn() {
        XCTAssertEqual(alert(used: 25, timeLeftShare: 1.0), .none)
        XCTAssertEqual(alert(used: 85, timeLeftShare: 0.2), .none)
        XCTAssertEqual(alert(used: 86, timeLeftShare: 0.2), .warning)
    }

    func testSameRuleForTheSevenDayWindow() {
        XCTAssertEqual(alert(used: 64, timeLeftShare: 0.5, length: PaceAlert.sevenDayLength), .warning)
        XCTAssertEqual(alert(used: 61, timeLeftShare: 0.5, length: PaceAlert.sevenDayLength), .none)
    }

    /// A reset further out than the window length (clock skew) clamps to a
    /// full window rather than loosening the threshold.
    func testTimeLeftBeyondWindowLengthClamps() {
        XCTAssertEqual(alert(used: 26, timeLeftShare: 1.5), .warning)
    }

    // MARK: - over

    func testOverAtOneHundredPercentAndAbove() {
        XCTAssertEqual(alert(used: 100, timeLeftShare: 0.5), .over)
        XCTAssertEqual(alert(used: 104, timeLeftShare: 0.9), .over)
    }

    /// Judged on the displayed percent: 99.6 shows as 100%, so it is `!`;
    /// 99.4 shows as 99%, so it is only behind pace.
    func testOverUsesTheRoundedPercent() {
        XCTAssertEqual(alert(used: 99.6, timeLeftShare: 0.5), .over)
        XCTAssertEqual(alert(used: 99.4, timeLeftShare: 0.5), .warning)
    }

    // MARK: - dead window

    func testNoIconOnceTheWindowHasReset() {
        XCTAssertEqual(alert(used: 104, timeLeftShare: 0), .none)
        XCTAssertEqual(alert(used: 104, timeLeftShare: -0.1), .none)
    }
}

final class UsageTextTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_786_940_000)

    private func window(used: Double, secondsLeft: TimeInterval) -> UsageWindow {
        UsageWindow(utilization: used, resetsAt: now.addingTimeInterval(secondsLeft))
    }

    private func snapshot(fiveHour: UsageWindow?, sevenDay: UsageWindow?) -> UsageSnapshot {
        UsageSnapshot(
            fiveHour: fiveHour, sevenDay: sevenDay, sevenDayOpus: nil, sevenDaySonnet: nil,
            spend: nil, fetchedAt: now
        )
    }

    func testTitleWithoutIcons() {
        let snap = snapshot(fiveHour: window(used: 42, secondsLeft: 2.4 * 3600), sevenDay: window(used: 18, secondsLeft: 3.1 * 86400))
        XCTAssertEqual(UsageText.title(for: snap, now: now), "58% 2.4h \u{00B7} 82% 3.1d")
    }

    /// The icon prefixes the window it judges; left% clamps at 0 when spent.
    func testTitlePrefixesEachWindowWithItsIcon() {
        let snap = snapshot(fiveHour: window(used: 90, secondsLeft: 2.5 * 3600), sevenDay: window(used: 103, secondsLeft: 3 * 86400))
        XCTAssertEqual(UsageText.title(for: snap, now: now), "\u{26A0}\u{FE0E}10% 2.5h \u{00B7} !0% 3.0d")
    }

    func testAbsentFiveHourWindowGetsNoIcon() {
        let snap = snapshot(fiveHour: nil, sevenDay: window(used: 18, secondsLeft: 3.1 * 86400))
        XCTAssertEqual(UsageText.title(for: snap, now: now), "100% 5.0h \u{00B7} 82% 3.1d")
    }

    func testTitleWithNoWindowsIsADash() {
        XCTAssertEqual(UsageText.title(for: snapshot(fiveHour: nil, sevenDay: nil), now: now), "Claude: \u{2014}")
    }

    func testRowAppendsIconOnlyWhenThereIsOne() {
        let behind = UsageText.row(label: "5-hour session", window: window(used: 90, secondsLeft: 2.5 * 3600), length: PaceAlert.fiveHourLength, now: now)
        let onPace = UsageText.row(label: "5-hour session", window: window(used: 10, secondsLeft: 2.5 * 3600), length: PaceAlert.fiveHourLength, now: now)
        XCTAssertTrue(behind.hasPrefix("5-hour session: 90% \u{2014} resets "))
        XCTAssertTrue(behind.hasSuffix("(in 2h 30m) \u{26A0}\u{FE0E}"))
        XCTAssertTrue(onPace.hasSuffix("(in 2h 30m)"))
    }
}
