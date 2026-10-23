import Foundation

/// Where a window ends up if the average rate so far holds.
///
/// The window starts `length` before its reset, so the average rate is
/// `used / elapsed`.
enum Forecast: Equatable {
    /// Projected percent used at reset, at or under 100.
    case atReset(Double)
    /// 100% is reached at this time, before the reset.
    case runsOut(Date)
    /// Too little of the window has elapsed for a projection to mean much.
    case tooEarly

    /// Below this share of the window elapsed, a projection is mostly noise.
    static let minElapsedShare = 0.05

    /// `nil` for a spent or already-reset window: there is nothing to forecast.
    static func make(_ window: UsageWindow, length: TimeInterval, now: Date = Date()) -> Forecast? {
        let timeLeft = min(window.resetsAt.timeIntervalSince(now), length)
        let used = window.utilization.rounded()
        guard timeLeft > 0, used < 100 else { return nil }

        let elapsed = length - timeLeft
        guard elapsed >= minElapsedShare * length else { return .tooEarly }

        let averageRate = used / elapsed
        let atReset = averageRate * length
        guard atReset > 100 else { return .atReset(atReset) }
        return .runsOut(window.resetsAt.addingTimeInterval(-length + 100 / averageRate))
    }
}
