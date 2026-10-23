import XCTest

@testable import ClaudeUsageBar

/// 5-hour window, rates per hour, unless a case says otherwise. Numbers are
/// worked by hand: half the window gone with 25% used projects 50% at reset.
final class ForecastTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_786_940_000)
    private let length = PaceAlert.fiveHourLength

    private func window(used: Double, secondsLeft: TimeInterval) -> UsageWindow {
        UsageWindow(utilization: used, resetsAt: now.addingTimeInterval(secondsLeft))
    }

    private func forecast(used: Double, secondsLeft: TimeInterval) -> Forecast? {
        Forecast.make(window(used: used, secondsLeft: secondsLeft), length: length, unit: 3600, now: now)
    }

    func testOnTrackProjectsUseAtReset() throws {
        let f = try XCTUnwrap(forecast(used: 25, secondsLeft: 9000))
        XCTAssertEqual(try XCTUnwrap(f.atReset), 50, accuracy: 1e-9)
        XCTAssertNil(f.runsOutAt)
        XCTAssertEqual(f.roomRate, 30, accuracy: 1e-9)
    }

    /// 75% in 2.5h is 30%/h: 100% lands 3h20m in, 50m from now, 1h40m early.
    func testAheadOfPaceRunsOutBeforeReset() throws {
        let f = try XCTUnwrap(forecast(used: 75, secondsLeft: 9000))
        XCTAssertEqual(try XCTUnwrap(f.atReset), 150, accuracy: 1e-9)
        XCTAssertEqual(try XCTUnwrap(f.runsOutAt).timeIntervalSince(now), 3000, accuracy: 1e-6)
    }

    func testTooEarlyInTheWindowHasNoProjection() throws {
        let f = try XCTUnwrap(forecast(used: 5, secondsLeft: 0.97 * length))
        XCTAssertNil(f.atReset)
        XCTAssertNil(f.runsOutAt)
    }

    func testSpentOrResetWindowHasNoForecast() {
        XCTAssertNil(forecast(used: 100, secondsLeft: 9000))
        XCTAssertNil(forecast(used: 40, secondsLeft: 0))
    }

    // MARK: - row text

    private func text(used: Double, secondsLeft: TimeInterval, length: TimeInterval? = nil) -> String {
        UsageText.forecastText(window: window(used: used, secondsLeft: secondsLeft), length: length ?? self.length, now: now)
    }

    func testTextOnTrack() {
        XCTAssertEqual(text(used: 25, secondsLeft: 9000), "At this pace: 50% at reset \u{00B7} room 30%/h")
    }

    func testTextRunsOutNamesTheTime() {
        let row = text(used: 75, secondsLeft: 9000)
        XCTAssertTrue(row.hasPrefix("At this pace: out ~"), row)
        XCTAssertTrue(row.hasSuffix("(in 50m) \u{00B7} room 10%/h"), row)
    }

    func testTextTooEarly() {
        XCTAssertEqual(text(used: 0, secondsLeft: length), "Too early to project \u{00B7} room 20%/h")
    }

    func testTextSpent() {
        XCTAssertEqual(text(used: 100, secondsLeft: 9000), "Spent until reset")
    }

    func testSevenDayWindowUsesPerDayRates() {
        XCTAssertEqual(
            text(used: 25, secondsLeft: 3.5 * 86400, length: PaceAlert.sevenDayLength),
            "At this pace: 50% at reset \u{00B7} room 21%/day"
        )
    }
}
