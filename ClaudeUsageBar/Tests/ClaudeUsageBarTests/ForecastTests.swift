import XCTest

@testable import ClaudeUsageBar

/// 5-hour window unless a case says otherwise. Numbers are worked by hand:
/// half the window gone with 25% used projects 50% at reset.
final class ForecastTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_786_940_000)
    private let length = PaceAlert.fiveHourLength

    private func window(used: Double, secondsLeft: TimeInterval) -> UsageWindow {
        UsageWindow(utilization: used, resetsAt: now.addingTimeInterval(secondsLeft))
    }

    private func forecast(used: Double, secondsLeft: TimeInterval) -> Forecast? {
        Forecast.make(window(used: used, secondsLeft: secondsLeft), length: length, now: now)
    }

    func testOnTrackProjectsUseAtReset() throws {
        guard case .atReset(let used) = try XCTUnwrap(forecast(used: 25, secondsLeft: 9000)) else {
            return XCTFail("expected atReset")
        }
        XCTAssertEqual(used, 50, accuracy: 1e-9)
    }

    /// 75% in 2.5h is 30%/h: 100% lands 3h20m in, 50m from now.
    func testAheadOfPaceRunsOutBeforeReset() throws {
        guard case .runsOut(let date) = try XCTUnwrap(forecast(used: 75, secondsLeft: 9000)) else {
            return XCTFail("expected runsOut")
        }
        XCTAssertEqual(date.timeIntervalSince(now), 3000, accuracy: 1e-6)
    }

    /// Exactly 100% at reset still fits: no run-out time.
    func testExactlyFullAtResetIsNotRunningOut() {
        XCTAssertEqual(forecast(used: 50, secondsLeft: 9000), .atReset(100))
    }

    func testTooEarlyInTheWindow() {
        XCTAssertEqual(forecast(used: 5, secondsLeft: 0.97 * length), .tooEarly)
    }

    func testSpentOrResetWindowHasNoForecast() {
        XCTAssertNil(forecast(used: 100, secondsLeft: 9000))
        XCTAssertNil(forecast(used: 40, secondsLeft: 0))
    }

    /// A reset further out than the window length clamps to a full window.
    func testResetBeyondWindowLengthIsTooEarly() {
        XCTAssertEqual(forecast(used: 30, secondsLeft: 1.2 * length), .tooEarly)
    }

    // MARK: - row text

    private func text(used: Double, secondsLeft: TimeInterval, length: TimeInterval? = nil) -> String {
        UsageText.forecastText(window: window(used: used, secondsLeft: secondsLeft), length: length ?? self.length, now: now)
    }

    func testTextOnTrack() {
        XCTAssertEqual(text(used: 25, secondsLeft: 9000), "At this pace: 50% left at reset")
    }

    /// Runs out 50m from now, resets 2.5h from now: 1h 40m locked out.
    func testTextRunsOutShowsOnlyTheCoolDown() {
        XCTAssertEqual(text(used: 75, secondsLeft: 9000), "At this pace: cool down of 1h 40m")
    }

    /// 51% used 9170s in runs out ~20s before reset: floors at 1m, never `0m`.
    func testTextCoolDownUnderAMinuteReadsOneMinute() {
        XCTAssertEqual(text(used: 51, secondsLeft: 8830), "At this pace: cool down of 1m")
    }

    /// 7-day, 50% used 2 days in: runs out 2 days from now, 5 days before reset.
    func testTextSevenDayCoolDownInDays() {
        XCTAssertEqual(text(used: 50, secondsLeft: 5 * 86400, length: PaceAlert.sevenDayLength), "At this pace: cool down of 3d 0h")
    }

    /// Margin, not use: 80% used at reset reads as 20% left. 7-day, 42% used
    /// with 3.675 of 7 days gone projects 80%.
    func testTextShowsMarginLeftAtReset() {
        XCTAssertEqual(text(used: 42, secondsLeft: 3.325 * 86400, length: PaceAlert.sevenDayLength), "At this pace: 20% left at reset")
    }

    func testTextTooEarly() {
        XCTAssertEqual(text(used: 0, secondsLeft: length), "Too early to project")
    }

    func testTextSpent() {
        XCTAssertEqual(text(used: 100, secondsLeft: 9000), "Spent until reset")
    }

    /// A stale snapshot past its reset says so, even if it was spent.
    func testTextPastResetSaysResetting() {
        XCTAssertEqual(text(used: 100, secondsLeft: -60), "Resetting now")
        XCTAssertEqual(text(used: 40, secondsLeft: 0), "Resetting now")
    }

    func testSevenDayWindow() {
        XCTAssertEqual(text(used: 25, secondsLeft: 3.5 * 86400, length: PaceAlert.sevenDayLength), "At this pace: 50% left at reset")
    }
}
