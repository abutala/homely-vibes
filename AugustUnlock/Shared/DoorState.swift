import Foundation

/// What the widget shows per door while a tap runs and just after: handed
/// from the app process, where the tap runs, to the widget. Pure value;
/// `DoorStateStore` keeps it in the Keychain, the one store both bundles
/// share under this signing (no App Group).
struct DoorState: Codable, Equatable {
    /// How a tap ended. `noReply`: the cloud request was sent and the tap ran
    /// out of time before August answered; August may still run it.
    enum Outcome: String, Codable {
        case ok, failed, noReply
    }

    struct Result: Codable, Equatable {
        let outcome: Outcome
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
    /// A tap's whole time, gate wait included, from the moment the intent
    /// starts: iOS ends a background intent at about 30 s (Apple,
    /// `LongRunningIntent`), and a tap ended that way writes no result.
    static let tapLimit: TimeInterval = 28
    /// A tap older than this is over whatever happened: the process that ran
    /// it may have died before it wrote the result. `tapLimit`, then the
    /// result write and the reload.
    static let runningLimit: TimeInterval = 35

    enum Mark: Equatable {
        case none, running, ok, failed, noReply
    }

    /// Starts the tap unless one is already running on that door: a repeat
    /// tap would only queue a duplicate command.
    mutating func start(_ position: Int, at now: Date) -> Bool {
        if let started = running[String(position)], now < started + Self.runningLimit { return false }
        running[String(position)] = now
        results[String(position)] = nil
        return true
    }

    /// Ends the tap that started at `startedAt`. A tap that outlived
    /// `runningLimit` (a frozen process) writes nothing over a newer tap's
    /// mark; a door with no mark (it was never started here) takes the result.
    mutating func finish(_ position: Int, startedAt: Date, outcome: Outcome, at now: Date) {
        if let current = running[String(position)], current != startedAt { return }
        running[String(position)] = nil
        results[String(position)] = Result(outcome: outcome, at: now)
    }

    /// The mark per position at `now`: a result older than `hold` is gone,
    /// and so is a tap older than `runningLimit`.
    func marks(count: Int, at now: Date) -> [Mark] {
        (0..<count).map { position in
            if let started = running[String(position)], now < started + Self.runningLimit { return .running }
            guard let result = results[String(position)], now < result.at + Self.hold else { return .none }
            switch result.outcome {
            case .ok: return .ok
            case .failed: return .failed
            case .noReply: return .noReply
            }
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
