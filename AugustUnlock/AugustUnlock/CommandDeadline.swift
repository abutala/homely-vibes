import Foundation

/// How long one lock/unlock may run before the app gives up on it. Pure:
/// every method takes the time as a parameter, so tests need no clock.
///
/// 30 s is tight on purpose (Amit, 2026-11-01): a WiFi-bridge lock can take
/// ~60 s to answer through the cloud, and that reply is lost; the door may
/// still move. The old app had no deadline at all, and a command stalled
/// while the phone slept blocked the screen until it answered.
struct CommandDeadline {
    static let limit: TimeInterval = 30
    static let timedOutMessage = "Timed out — tap to retry"

    /// The screen's Bluetooth budgets, inside `limit`. The person is at the
    /// door, and a connect took 9.4 s on 2026-11-03 while the Wi-Fi bridge
    /// held the lock after a cloud command; a 6 s budget sent that tap to
    /// the cloud, which sent the bridge back to the lock. The operation
    /// budget is short because the work after the session has taken 1.4 s
    /// at most. `cloudWindowAfterBluetooth` is what the cloud keeps when
    /// both run out; the test pins it.
    static let screenBluetoothSetup: TimeInterval = 12
    static let screenBluetoothOperation: TimeInterval = 6
    static var cloudWindowAfterBluetooth: TimeInterval { limit - screenBluetoothSetup - screenBluetoothOperation }

    let startedAt: Date
    let limit: TimeInterval

    init(startedAt: Date, limit: TimeInterval = CommandDeadline.limit) {
        self.startedAt = startedAt
        self.limit = limit
    }

    func isExpired(at now: Date) -> Bool {
        now.timeIntervalSince(startedAt) >= limit
    }
}
