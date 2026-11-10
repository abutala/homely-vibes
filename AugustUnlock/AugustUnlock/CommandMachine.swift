import Foundation

nonisolated enum LockState: Equatable {
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

    var label: String {
        switch self {
        case .locked: "Locked"
        case .unlocked: "Unlocked"
        case .unknown: "State unknown"
        }
    }

    /// A lock command's reply as a widget result: "Locked" only on the state
    /// the lock reported.
    var lockOutcome: DoorState.Outcome {
        switch self {
        case .locked: .ok
        case .unlocked: .failed
        case .unknown: .noReply
        }
    }
}

/// One door's one command at a time, as a pure value: the Quint model
/// `formal/august_unlock_command.qnt` in Swift. `DoorController` feeds it the
/// events (a tap, a resume, a reply, the deadline) and runs the effect it
/// returns; nothing here touches the network, a clock or the UI, so the tests
/// and the model can drive it the same way. Only a tap sends a command.
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
        /// The deadline found the request already with August: let it run to
        /// `CommandDeadline.lateLimit`; its reply comes in as a late note.
        case letRun
        case none
    }

    /// A second tap within this gap is the same tap, not a new command.
    static let tapGap: TimeInterval = 0.75
    /// A cloud request the phone dropped may still run at August; a bridged
    /// lock can take ~60 s. Shown that long after the drop.
    static let mayStillMoveWarning = "An earlier request may still move the door"
    static let mayStillMoveWindow: TimeInterval = 60

    private(set) var op: Op = .idle
    /// What August last reported, never what was requested.
    private(set) var door: LockState = .unknown
    private(set) var startedAt: Date?
    private(set) var lastTapAt: Date = .distantPast
    /// The direction of the command that failed or timed out: the next tap
    /// repeats it. With the door unknown, a tap after a failed lock would
    /// otherwise unlock (TRIAL 2026-11-07, seen on the phone).
    private(set) var retry: Bool?
    /// The command in flight reached the cloud: August holds it now.
    private(set) var cloudReached = false
    /// The deadline passed while that request was with August; it still runs.
    private(set) var isLate = false
    private(set) var mayStillMoveUntil: Date?
    /// The late request's reply, shown under the result.
    private(set) var lateNote: String?

    var isOperating: Bool {
        if case .inProgress = op { return true }
        return false
    }

    func isExpired(at now: Date) -> Bool {
        guard isOperating, let startedAt else { return false }
        return CommandDeadline(startedAt: startedAt).isExpired(at: now)
    }

    // MARK: - Events

    /// The button: lock if shown unlocked, else unlock; the opposite of a
    /// command in flight; after a failure, the failed command again. Over
    /// Bluetooth the cancel before the write drops the first command; a
    /// cloud command August already holds runs anyway, so dropping one warns.
    mutating func tap(at now: Date) -> Effect {
        guard now.timeIntervalSince(lastTapAt) >= Self.tapGap else { return .none }
        lastTapAt = now
        let unlocking: Bool
        if case .inProgress(let inFlightUnlocking) = op {
            unlocking = !inFlightUnlocking
            dropInFlight(at: now)
        } else {
            unlocking = nextTapUnlocks
        }
        return send(unlocking: unlocking, at: now)
    }

    /// What a tap does when no command runs: the failed command again, or
    /// the opposite of the door shown. The screen's "tap to …" reads it.
    var nextTapUnlocks: Bool { retry ?? (door != .unlocked) }

    /// The client reported the cloud path for the command in flight.
    mutating func reachedCloud() {
        if isOperating { cloudReached = true }
    }

    /// The text under the result while a dropped cloud request may still run.
    func warning(at now: Date) -> String? {
        guard let until = mayStillMoveUntil, now < until else { return nil }
        return Self.mayStillMoveWarning
    }

    /// Back to the foreground after a real background: a command past its
    /// deadline (the phone slept, and its timers with it) fails now; a command
    /// still running or late is left to report; a retry is kept, so a failed
    /// lock is never tapped into an unlock. Otherwise the door may have moved
    /// while the app was away, so it is unknown and the next tap unlocks.
    /// A return never sends a command.
    mutating func resume(at now: Date) -> Effect {
        if isExpired(at: now) { return timeOut(at: now) }
        guard !isOperating, !isLate, retry == nil else { return .none }
        door = .unknown
        op = .idle
        return .none
    }

    /// The deadline task.
    mutating func deadlineFired(at now: Date) -> Effect {
        guard isOperating else { return .none }
        return timeOut(at: now)
    }

    /// The command's reply after `seconds`. A late one (past the deadline)
    /// sets the door and a note, and never turns the failure into a success.
    mutating func replied(_ state: LockState, after seconds: TimeInterval) {
        if isLate {
            isLate = false
            door = state
            retry = nil
            mayStillMoveUntil = nil
            lateNote = "Late reply: \(state.label) after \(Int(seconds)) s"
            return
        }
        guard isOperating else { return }
        door = state
        retry = nil
        op = .success
    }

    /// A late request's failure keeps the "sent" text: it says more.
    mutating func failed(_ message: String) {
        if isLate {
            isLate = false
            return
        }
        if case .inProgress(let unlocking) = op { retry = unlocking }
        door = .unknown
        op = .failure(message)
    }

    /// The late request reached `CommandDeadline.lateLimit` and was dropped.
    mutating func lateGaveUp() {
        isLate = false
    }

    /// The 2 s reset after a result.
    mutating func settle() {
        switch op {
        case .success, .failure: op = .idle
        case .idle, .inProgress: break
        }
    }

    /// Sign Out: drop the command, a late one included, without a result.
    /// The lines about the door go with it.
    mutating func cancelForSignOut(at now: Date) -> Effect {
        door = .unknown
        retry = nil
        mayStillMoveUntil = nil
        lateNote = nil
        let wasLate = isLate
        isLate = false
        guard isOperating else { return wasLate ? .cancel : .none }
        op = .idle
        return .cancel
    }

    /// iOS took the background time back: the command is dropped. A written
    /// Bluetooth command may have moved the door, so it is unknown.
    mutating func keepAliveExpired(at now: Date) {
        isLate = false
        guard isOperating else { return }
        dropInFlight(at: now)
        door = .unknown
        op = .idle
    }

    // MARK: - Private

    private mutating func send(unlocking: Bool, at now: Date) -> Effect {
        op = .inProgress(unlocking: unlocking)
        startedAt = now
        cloudReached = false
        isLate = false
        lateNote = nil
        return .send(unlocking: unlocking)
    }

    /// The command in flight is being dropped: one August holds may still run.
    private mutating func dropInFlight(at now: Date) {
        if cloudReached { mayStillMoveUntil = now.addingTimeInterval(Self.mayStillMoveWindow) }
    }

    private mutating func timeOut(at now: Date) -> Effect {
        if case .inProgress(let unlocking) = op { retry = unlocking }
        door = .unknown
        guard cloudReached else {
            op = .failure(CommandDeadline.timedOutMessage)
            return .cancel
        }
        op = .failure(CommandDeadline.sentNoReplyMessage)
        isLate = true
        mayStillMoveUntil = now.addingTimeInterval(Self.mayStillMoveWindow)
        return .letRun
    }
}
