import Foundation

enum LockState: Equatable {
    case locked
    case unlocked
    /// Jammed, mid-motion, or a value August hasn't sent before.
    case unknown

    /// The status strings yalexs' `determine_lock_status()` (lock.py)
    /// recognizes — August sends both the short and `kAugLockState_` forms.
    /// Unlatched counts as unlocked: the door opens either way.
    init(augustStatus: String?) {
        switch augustStatus {
        case "lock", "locked", "kAugLockState_Locked", "kAugLockState_SecureMode":
            self = .locked
        case "unlock", "unlocked", "kAugLockState_Unlocked", "unlatched", "kAugLockState_Unlatched":
            self = .unlocked
        default:
            self = .unknown
        }
    }
}

/// The app's one command at a time, as a pure value: the Quint model
/// `formal/august_unlock_command.qnt` in Swift. `ContentView` feeds it the
/// events (a tap, an open, a resume, a reply, the deadline) and runs the
/// effect it returns; nothing here touches the network, a clock or the UI,
/// so the tests and the model can drive it the same way.
struct CommandMachine: Equatable {
    enum Op: Equatable {
        case idle
        case inProgress(unlocking: Bool)
        case success
        case failure(String)
    }

    enum Effect: Equatable {
        /// Start this command (cancelling the one in flight).
        case send(unlocking: Bool)
        /// Stop the command in flight; its late reply must write nothing.
        case cancel
        case none
    }

    /// A second tap within this gap is the same tap, not a new command.
    static let tapGap: TimeInterval = 0.75

    private(set) var op: Op = .idle
    /// What August last reported, never what was requested.
    private(set) var door: LockState = .unknown
    private(set) var startedAt: Date?
    private(set) var lastTapAt: Date = .distantPast
    /// A timeout fired while the app was away; the next return must not
    /// unlock by itself (a stale unlock could undo a lock the user tapped).
    private(set) var timedOutWhileAway = false

    var isOperating: Bool {
        if case .inProgress = op { return true }
        return false
    }

    func isExpired(at now: Date) -> Bool {
        guard isOperating, let startedAt else { return false }
        return CommandDeadline(startedAt: startedAt).isExpired(at: now)
    }

    // MARK: - Events

    /// Opening the app — cold launch or finishing setup — unlocks at once;
    /// opening the app is the confirmation. No status fetch first.
    mutating func open(at now: Date) -> Effect {
        door = .unknown
        return send(unlocking: true, at: now)
    }

    /// The button: lock if shown unlocked, else unlock; the opposite of a
    /// command in flight. Over Bluetooth the cancel before the write drops
    /// the first command; a cloud command August already holds runs anyway.
    mutating func tap(at now: Date) -> Effect {
        guard now.timeIntervalSince(lastTapAt) >= Self.tapGap else { return .none }
        lastTapAt = now
        let unlocking: Bool
        if case .inProgress(let inFlightUnlocking) = op {
            unlocking = !inFlightUnlocking
        } else {
            unlocking = door != .unlocked
        }
        return send(unlocking: unlocking, at: now)
    }

    /// Back to the foreground after a real background: a command past its
    /// deadline (the phone slept, and its timers with it) fails now; a
    /// timeout that fired while away clears instead of unlocking; an idle
    /// app unlocks; a command still running is left to report.
    mutating func resume(at now: Date) -> Effect {
        if isExpired(at: now) {
            return timeOut(away: false)
        }
        if timedOutWhileAway {
            timedOutWhileAway = false
            return .none
        }
        if isOperating { return .none }
        return send(unlocking: true, at: now)
    }

    /// The deadline task: `away` is whether the app was in the background.
    mutating func deadlineFired(away: Bool) -> Effect {
        guard isOperating else { return .none }
        return timeOut(away: away)
    }

    mutating func replied(_ state: LockState) {
        door = state
        op = .success
    }

    mutating func failed(_ message: String) {
        op = .failure(message)
    }

    /// The 2 s reset after a result.
    mutating func settle() {
        switch op {
        case .success, .failure: op = .idle
        case .idle, .inProgress: break
        }
    }

    /// Change Lock or Sign Out: drop the command without a result.
    mutating func cancelForChange() -> Effect {
        door = .unknown
        guard isOperating else { return .none }
        op = .idle
        return .cancel
    }

    /// iOS took the background time back: the command is dropped, and the
    /// next open unlocks again.
    mutating func keepAliveExpired() {
        if isOperating { op = .idle }
    }

    // MARK: - Private

    private mutating func send(unlocking: Bool, at now: Date) -> Effect {
        op = .inProgress(unlocking: unlocking)
        startedAt = now
        timedOutWhileAway = false
        return .send(unlocking: unlocking)
    }

    private mutating func timeOut(away: Bool) -> Effect {
        op = .failure(CommandDeadline.timedOutMessage)
        door = .unknown
        timedOutWhileAway = away
        return .cancel
    }
}
