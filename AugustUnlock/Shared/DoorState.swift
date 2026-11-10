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
    /// When a door's unlock tap ended without a confirmed reply: August may
    /// still run it, even after an error, since the request may have gone out.
    var unanswered: [String: Date] = [:]
    /// When each door's last unlock tap started.
    var unlockStarted: [String: Date] = [:]
    /// When Bluetooth unlocked a door while the cloud copy of the unlock was
    /// still on its way (both go out together, 2026-11-09). Written before
    /// the tap returns and removed only by August's reply, so a process that
    /// dies in between leaves it.
    var tails: [String: Date] = [:]

    /// The widget's center button, after the two doors.
    static let lockBothPosition = 2
    static let positionCount = 3
    /// How long an unanswered unlock can still land: a bridged lock's ~60 s,
    /// the screen's `CommandMachine.mayStillMoveWindow`.
    static let unansweredWindow: TimeInterval = 60

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
    /// tap would only queue a duplicate command. An older unlock tap still
    /// marked running never ended (its process died with the cloud unlock
    /// out): it keeps its own window as an unanswered unlock.
    mutating func start(_ position: Int, at now: Date) -> Bool {
        let key = String(position)
        if let started = running[key], now < started + Self.runningLimit { return false }
        if let dead = running[key], position != Self.lockBothPosition { unanswered[key] = max(dead, unanswered[key] ?? dead) }
        running[String(position)] = now
        results[String(position)] = nil
        if position != Self.lockBothPosition { unlockStarted[String(position)] = now }
        return true
    }

    /// Ends the tap that started at `startedAt`. A tap that outlived
    /// `runningLimit` (a frozen process) writes nothing over a newer tap's
    /// mark; a door with no mark (it was never started here) takes the result.
    mutating func finish(_ position: Int, startedAt: Date, outcome: Outcome, at now: Date) {
        if let current = running[String(position)], current != startedAt { return }
        running[String(position)] = nil
        results[String(position)] = Result(outcome: outcome, at: now)
        if outcome != .ok, position != Self.lockBothPosition { unanswered[String(position)] = now }
    }

    /// Bluetooth unlocked the door; August still holds the same unlock. An
    /// older one still here was never answered (its process died): it keeps
    /// its own window as an unanswered unlock.
    mutating func tailOpened(_ position: Int, at now: Date) {
        let key = String(position)
        if let old = tails[key] { unanswered[key] = max(old, unanswered[key] ?? old) }
        tails[key] = now
    }

    /// August answered the unlock that `tailOpened` recorded at `openedAt`.
    mutating func tailConfirmed(_ position: Int, openedAt: Date) {
        if tails[String(position)] == openedAt { tails[String(position)] = nil }
    }

    /// An unlock for this door may still reach the lock: one that ended
    /// without a confirmed reply, one August has not answered after a
    /// Bluetooth win, or a tap with no end at all (the cloud unlock goes out
    /// when the tap starts, and a process that dies writes nothing).
    private func unlockMayStillLand(_ key: String, at now: Date) -> Bool {
        [unanswered[key], tails[key], running[key]].contains { sent in sent.map { now < $0 + Self.unansweredWindow } ?? false }
    }

    /// Lock Both's replies, one per door by position, written together when
    /// the tap ends so a fast door's mark is still held when the widget draws
    /// (it redraws only after the tap). A locked door drops any old mark; a
    /// door that did not lock shows why; a door tapped since `startedAt` keeps
    /// its own mark, and so does one running its own tap. Returns the center's
    /// result: "Locked" only if every door locked, none was tapped to unlock
    /// meanwhile, and no unanswered unlock can still land after it.
    mutating func recordLocks(_ outcomes: [Outcome], startedAt: Date, at now: Date) -> Outcome {
        let settled = outcomes.enumerated().map { position, outcome -> Outcome in
            let key = String(position)
            let held = unlockMayStillLand(key, at: now)
            let tapped = unlockStarted[key].map { $0 >= startedAt } ?? false
            let settled: Outcome = outcome == .ok && (held || tapped) ? .noReply : outcome
            if running[key] == nil, !tapped { results[key] = settled == .ok ? nil : Result(outcome: settled, at: now) }
            return settled
        }
        if settled.isEmpty || settled.contains(.failed) { return .failed }
        return settled.contains(.noReply) ? .noReply : .ok
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
