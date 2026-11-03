import Foundation

/// What the widget shows per door while a tap runs and just after: handed
/// from the app process, where the tap runs, to the widget. Pure value;
/// `DoorStateStore` keeps it in the Keychain, the one store both bundles
/// share under this signing (no App Group).
struct DoorState: Codable, Equatable {
    struct Result: Codable, Equatable {
        let ok: Bool
        let at: Date
    }

    /// Taps in flight: when each started, keyed by the position's text (JSON).
    var running: [String: Date] = [:]
    /// The last result per position, keyed by the position's text (JSON).
    var results: [String: Result] = [:]

    /// How long a result stays on the widget. WidgetKit draws a reload some
    /// seconds after it is asked for, so a short hold was gone before it
    /// was drawn (phone, 2026-11-03).
    static let hold: TimeInterval = 12
    /// A tap older than this is over whatever happened: the process that ran
    /// it may have died before it wrote the result.
    static let runningLimit: TimeInterval = 45

    enum Mark: Equatable {
        case none, running, ok, failed
    }

    /// Starts the tap unless one is already running on that door: a repeat
    /// tap would only queue a duplicate command.
    mutating func start(_ position: Int, at now: Date) -> Bool {
        if let started = running[String(position)], now < started + Self.runningLimit { return false }
        running[String(position)] = now
        results[String(position)] = nil
        return true
    }

    mutating func finish(_ position: Int, ok: Bool, at now: Date) {
        running[String(position)] = nil
        results[String(position)] = Result(ok: ok, at: now)
    }

    /// The mark per position at `now`: a result older than `hold` is gone,
    /// and so is a tap older than `runningLimit`.
    func marks(count: Int, at now: Date) -> [Mark] {
        (0..<count).map { position in
            if let started = running[String(position)], now < started + Self.runningLimit { return .running }
            guard let result = results[String(position)], now < result.at + Self.hold else { return .none }
            return result.ok ? .ok : .failed
        }
    }

    /// Every moment after `now` at which a showing mark clears on its own: a
    /// held result at its hold, a running tap at its limit. One timeline
    /// entry per moment, so each door clears on its own time.
    func clearDates(at now: Date) -> [Date] {
        let ends = results.values.map { $0.at + Self.hold } + running.values.map { $0 + Self.runningLimit }
        return Array(Set(ends.filter { $0 > now })).sorted()
    }
}
