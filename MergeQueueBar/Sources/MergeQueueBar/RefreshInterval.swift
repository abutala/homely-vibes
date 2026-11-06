import Foundation

/// Poll cadence, persisted in UserDefaults so a choice survives relaunch.
enum RefreshInterval {
    static let defaultSeconds: TimeInterval = 120
    static let choices: [TimeInterval] = [60, 120, 300, 600]

    private static let key = "refreshIntervalSeconds"

    /// A stored value outside the choices (unset, hand-edited, retired) falls
    /// back to the default, so a 0 never spins the timer hot.
    static func resolve(stored: TimeInterval) -> TimeInterval {
        choices.contains(stored) ? stored : defaultSeconds
    }

    static var current: TimeInterval {
        get { resolve(stored: UserDefaults.standard.double(forKey: key)) }
        set { UserDefaults.standard.set(newValue, forKey: key) }
    }

    static func label(for seconds: TimeInterval) -> String {
        "\(Int(seconds / 60)) min"
    }
}
