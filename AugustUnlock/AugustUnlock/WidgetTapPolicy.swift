import Foundation

/// What a widget tap sends to one door — the app button's rules, for a widget
/// that shows no state. Pure: every method takes the time as a parameter, so
/// tests need no clock.
///
/// A tap while a command is in flight sends the opposite. Otherwise a tap
/// locks a door that reported unlocked in the last `unlockedMemory` seconds,
/// and unlocks in every other case: past that, the door may have auto-locked
/// or been locked by hand, and unlocking is what the app is for.
struct WidgetTapPolicy {
    static let defaultUnlockedMemory: TimeInterval = 3 * 60

    let unlockedMemory: TimeInterval
    private var inFlightUnlocking: Bool?
    private var unlockedAt: Date?

    init(unlockedMemory: TimeInterval = WidgetTapPolicy.defaultUnlockedMemory) {
        self.unlockedMemory = unlockedMemory
    }

    /// True to unlock, false to lock.
    func nextTapUnlocks(at now: Date) -> Bool {
        if let inFlightUnlocking { return !inFlightUnlocking }
        guard let unlockedAt else { return true }
        return now.timeIntervalSince(unlockedAt) >= unlockedMemory
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
