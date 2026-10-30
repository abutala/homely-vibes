import Foundation

/// One door's last known state, as the widget's own last command left it.
/// Pure: every method takes the time as a parameter, so tests need no clock.
///
/// A tap while a command is running sends the opposite. Otherwise a tap
/// locks a door that reported unlocked within `unlockedTrust` and unlocks in
/// every other case. The widget can't refresh state, so past that window the
/// door may have auto-locked, and unlocking is what the app is for.
struct DoorRecord: Codable, Equatable {
    enum State: String, Codable {
        case locked, unlocked, unknown

        /// The status strings yalexs' `determine_lock_status()` (lock.py)
        /// recognizes; the app's `LockState` reads the same list.
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

    static let unlockedTrust: TimeInterval = 3 * 60
    /// A command older than this never reported back (the process died or
    /// hung), so readers treat the door as unknown instead of "running" forever.
    static let runningTimeout: TimeInterval = 45

    var state: State = .unknown
    /// True while unlocking, false while locking, nil when idle.
    var running: Bool?
    var at: Date

    /// What a reader should show now: expired runs and stale unlocks fall to unknown.
    func effective(at now: Date) -> DoorRecord {
        var record = self
        if running != nil, now.timeIntervalSince(at) >= Self.runningTimeout {
            record.running = nil
            record.state = .unknown
        }
        if record.running == nil, record.state == .unlocked, now.timeIntervalSince(at) >= Self.unlockedTrust {
            record.state = .unknown
        }
        return record
    }

    /// True to unlock, false to lock.
    func nextTapUnlocks(at now: Date) -> Bool {
        let current = effective(at: now)
        if let running = current.running { return !running }
        return current.state != .unlocked
    }

    /// When `effective` would next change, if ever: the widget redraws then.
    func nextChange() -> Date? {
        if running != nil { return at.addingTimeInterval(Self.runningTimeout) }
        if state == .unlocked { return at.addingTimeInterval(Self.unlockedTrust) }
        return nil
    }
}
