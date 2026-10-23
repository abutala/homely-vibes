import Foundation

/// Where a window ends up if the average rate so far holds, and how fast the
/// rest of the budget may be spent.
///
/// The window starts `length` before its reset, so the average rate is
/// `used / elapsed`. Rates are in percent per `unit` (an hour for the 5-hour
/// window, a day for the 7-day ones), so they read the same way on both.
struct Forecast: Equatable {
    /// Projected percent used at reset; `nil` too early in the window to say.
    let atReset: Double?
    /// When 100% is reached at the average rate, if that is before the reset.
    let runsOutAt: Date?
    /// Rate that spends exactly the rest of the budget by the reset.
    let roomRate: Double
    /// Rate that spends 100% evenly over the whole window.
    let evenRate: Double

    /// Below this share of the window elapsed, a projection is mostly noise.
    static let minElapsedShare = 0.05

    /// `nil` for a spent or already-reset window: there is nothing to forecast.
    static func make(_ window: UsageWindow, length: TimeInterval, unit: TimeInterval, now: Date = Date()) -> Forecast? {
        let timeLeft = min(window.resetsAt.timeIntervalSince(now), length)
        let used = window.utilization.rounded()
        guard timeLeft > 0, used < 100 else { return nil }

        let elapsed = length - timeLeft
        let roomRate = (100 - used) / timeLeft * unit
        let evenRate = 100 / length * unit
        guard elapsed >= minElapsedShare * length else {
            return Forecast(atReset: nil, runsOutAt: nil, roomRate: roomRate, evenRate: evenRate)
        }

        let averageRate = used / elapsed
        let atReset = averageRate * length
        let runsOutAt = atReset > 100
            ? window.resetsAt.addingTimeInterval(-length + 100 / averageRate)
            : nil
        return Forecast(atReset: atReset, runsOutAt: runsOutAt, roomRate: roomRate, evenRate: evenRate)
    }
}
