import Foundation

/// One door's last known state, as the app or the widget last wrote it.
/// Pure: every method takes the time as a parameter, so tests need no clock.
///
/// A tap while a command is running sends the opposite. Otherwise a tap
/// locks a door that reported unlocked within the caller's trust window and
/// unlocks in every other case. The app shows the state it fetched, so it
/// trusts a reported unlock for as long as it shows it; the widget can't
/// refresh, so it trusts it for `widgetUnlockedTrust`: past that the door may
/// have auto-locked, and unlocking is what the app is for.
struct DoorRecord: Codable, Equatable {
    enum State: String, Codable {
        case locked, unlocked, unknown
    }

    static let widgetUnlockedTrust: TimeInterval = 3 * 60
    /// A command older than this never reported back (the process died or
    /// hung), so readers treat the door as unknown instead of "running" forever.
    static let runningTimeout: TimeInterval = 45

    var state: State = .unknown
    /// True while unlocking, false while locking, nil when idle.
    var running: Bool?
    var at: Date

    /// What a reader should show now: expired runs and stale unlocks fall to unknown.
    func effective(at now: Date, trustUnlockedFor trust: TimeInterval) -> DoorRecord {
        var record = self
        if running != nil, now.timeIntervalSince(at) >= Self.runningTimeout {
            record.running = nil
            record.state = .unknown
        }
        if record.running == nil, record.state == .unlocked, now.timeIntervalSince(at) >= trust {
            record.state = .unknown
        }
        return record
    }

    /// True to unlock, false to lock.
    func nextTapUnlocks(at now: Date, trustUnlockedFor trust: TimeInterval) -> Bool {
        let current = effective(at: now, trustUnlockedFor: trust)
        if let running = current.running { return !running }
        return current.state != .unlocked
    }

    /// When `effective` would next change, if ever: the widget redraws then.
    func nextChange(after now: Date, trustUnlockedFor trust: TimeInterval) -> Date? {
        if running != nil { return at.addingTimeInterval(Self.runningTimeout) }
        if state == .unlocked, trust.isFinite { return at.addingTimeInterval(trust) }
        return nil
    }
}
