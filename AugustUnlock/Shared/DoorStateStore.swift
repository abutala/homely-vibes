import Foundation
import os

/// `DoorState` in the Keychain: the app process writes it during a widget
/// tap, the widget reads it when it renders. The widget's sign-in read
/// crosses the same way (`WidgetCloud`).
enum DoorStateStore {
    private static let account = "august_door_state"
    /// Two doors' intents run at once in the app process; each
    /// load-change-write is one step.
    private static let lock = OSAllocatedUnfairLock()

    static func load() -> DoorState {
        guard let data = KeychainStore.getData(account), let state = try? JSONDecoder().decode(DoorState.self, from: data) else {
            return DoorState()
        }
        return state
    }

    @discardableResult
    static func update<T>(_ change: (inout DoorState) -> T) -> T {
        lock.withLock {
            var state = load()
            let result = change(&state)
            if let data = try? JSONEncoder().encode(state) { KeychainStore.setData(data, forKey: account) }
            return result
        }
    }
}
