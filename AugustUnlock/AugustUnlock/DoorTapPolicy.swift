import Foundation

/// What a tap on one door's circle sends — the same rule for the app and the
/// widget. Pure: every method takes the time as a parameter, so tests need
/// no clock.
///
/// A tap while a command is in flight sends the opposite. Otherwise a tap
/// locks a door that reported unlocked within the caller's trust window, and
/// unlocks in every other case. The app shows the state, so it trusts a
/// reported unlock for as long as it shows it; the widget shows none, so it
/// trusts it for `widgetUnlockedTrust`: past that the door may have
/// auto-locked or been locked by hand, and unlocking is what the app is for.
struct DoorTapPolicy {
    static let widgetUnlockedTrust: TimeInterval = 3 * 60

    private var inFlightUnlocking: Bool?
    private var unlockedAt: Date?

    /// True to unlock, false to lock.
    func nextTapUnlocks(at now: Date, trustUnlockedFor trust: TimeInterval) -> Bool {
        if let inFlightUnlocking { return !inFlightUnlocking }
        guard let unlockedAt else { return true }
        return now.timeIntervalSince(unlockedAt) >= trust
    }

    mutating func didSend(unlocking: Bool) {
        inFlightUnlocking = unlocking
    }

    /// A failed command passes false: its state is unknown, so the next tap unlocks.
    mutating func didFinish(reportedUnlocked: Bool, at now: Date) {
        inFlightUnlocking = nil
        unlockedAt = reportedUnlocked ? now : nil
    }
}
