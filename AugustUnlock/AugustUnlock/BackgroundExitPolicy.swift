import Foundation

/// When the app should quit itself after sitting in the background. Pure:
/// every method takes the time as a parameter, so tests need no clock.
struct BackgroundExitPolicy {
    /// How long the app may stay backgrounded before it quits.
    static let defaultTimeout: TimeInterval = 5 * 60

    let timeout: TimeInterval
    private var backgroundedAt: Date?

    init(timeout: TimeInterval = BackgroundExitPolicy.defaultTimeout) {
        self.timeout = timeout
    }

    /// Keeps the first timestamp: a repeat call must not extend the deadline.
    mutating func didBackground(at now: Date) {
        if backgroundedAt == nil { backgroundedAt = now }
    }

    mutating func didForeground() {
        backgroundedAt = nil
    }

    /// Seconds until the deadline, nil while in the foreground.
    func remaining(at now: Date) -> TimeInterval? {
        guard let backgroundedAt else { return nil }
        return max(0, timeout - now.timeIntervalSince(backgroundedAt))
    }

    /// An operation in flight defers the exit; the caller asks again when it ends.
    func shouldExit(at now: Date, operationInFlight: Bool) -> Bool {
        guard let remaining = remaining(at: now) else { return false }
        return remaining == 0 && !operationInFlight
    }
}
