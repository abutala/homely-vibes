import Foundation
import Security

/// Generic-password Keychain items, by account name, in the access group
/// both the app and the widget share. Values are strings or raw data. A
/// write updates the item in place and adds it only when it is missing, so
/// a reader never lands in a delete-then-add gap (the widget reads the door
/// state while the app writes it).
enum KeychainStore {
    /// The Keychain's answer to the last call, for the logs.
    nonisolated(unsafe) static var lastStatus: OSStatus = errSecSuccess

    static func set(_ value: String, forKey key: String) {
        setData(Data(value.utf8), forKey: key)
    }

    static func setData(_ data: Data, forKey key: String) {
        let query = query(key)
        lastStatus = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        guard lastStatus == errSecItemNotFound else { return }
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        lastStatus = SecItemAdd(attributes as CFDictionary, nil)
    }

    static func get(_ key: String) -> String? {
        getData(key).flatMap { String(data: $0, encoding: .utf8) }
    }

    static func getData(_ key: String) -> Data? {
        var query = query(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        lastStatus = SecItemCopyMatching(query as CFDictionary, &item)
        guard lastStatus == errSecSuccess else { return nil }
        return item as? Data
    }

    static func remove(_ key: String) {
        SecItemDelete(query(key) as CFDictionary)
    }

    private static func query(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: key]
    }
}
