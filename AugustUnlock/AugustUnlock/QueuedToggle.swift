import Foundation

/// A tap while a lock or unlock is in flight queues the opposite command, to
/// run the moment the first one ends. It never cancels the first: a cancelled
/// cloud command can still reach the lock after its replacement — see the
/// Logbook. Pure, so `swift test` covers it.
struct QueuedToggle {
    /// The command to run next: true unlocks, false locks, nil runs nothing.
    private(set) var unlocking: Bool?

    /// A first tap queues the opposite of the in-flight command; a second clears it.
    mutating func tap(inFlightUnlocking: Bool) {
        unlocking = unlocking == nil ? !inFlightUnlocking : nil
    }

    /// Hands back the queued command once.
    mutating func take() -> Bool? {
        defer { unlocking = nil }
        return unlocking
    }

    mutating func clear() {
        unlocking = nil
    }
}
