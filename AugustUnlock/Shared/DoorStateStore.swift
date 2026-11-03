import Foundation
import Security

/// `DoorState` in the Keychain: the app process writes it during a widget
/// tap, the widget reads it when it renders. The widget's sign-in read
/// already crosses the same way (`WidgetCloud`).
enum DoorStateStore {
    private static let account = "august_door_state"

    /// The Keychain's answer to the last read or write, for the logs.
    nonisolated(unsafe) static var lastStatus: OSStatus = errSecSuccess

    static func load() -> DoorState {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        lastStatus = SecItemCopyMatching(query as CFDictionary, &item)
        guard lastStatus == errSecSuccess, let data = item as? Data,
            let state = try? JSONDecoder().decode(DoorState.self, from: data)
        else { return DoorState() }
        return state
    }

    static func update(_ change: (inout DoorState) -> Void) {
        var state = load()
        change(&state)
        guard let data = try? JSONEncoder().encode(state) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        lastStatus = SecItemAdd(attributes as CFDictionary, nil)
    }
}
