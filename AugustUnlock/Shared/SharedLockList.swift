import Foundation
import Security

/// The account's lock names, in widget-button order: the app writes them, the
/// widget reads them for its labels. Both name one Keychain access group,
/// `<team>.com.deviationlabs.AugustUnlock.shared`. A signer that grants
/// neither process that group makes both calls fail, and the widget falls back
/// to "Door 1", "Door 2" — taps still work, since they run in the app. See the
/// Logbook for what Sideloadly grants.
nonisolated enum SharedLockList {
    private static let account = "august_lock_names"
    private static let groupSuffix = "com.deviationlabs.AugustUnlock.shared"
    private static let probeAccount = "august_access_group_probe"

    static func write(_ names: [String]) {
        guard let group = accessGroup, let data = try? JSONEncoder().encode(names) else { return }
        let query = baseQuery(group: group)
        SecItemDelete(query as CFDictionary)
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(attributes as CFDictionary, nil)
    }

    static func read() -> [String]? {
        guard let group = accessGroup else { return nil }
        var query = baseQuery(group: group)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return try? JSONDecoder().decode([String].self, from: data)
    }

    static func clear() {
        guard let group = accessGroup else { return }
        SecItemDelete(baseQuery(group: group) as CFDictionary)
    }

    private static func baseQuery(group: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: group,
        ]
    }

    /// The team prefix is known only at run time (each signer has its own), so
    /// read it off an item in this process's default access group.
    private static var accessGroup: String? {
        let probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: probeAccount,
            kSecReturnAttributes as String: true,
        ]
        var result: CFTypeRef?
        var status = SecItemCopyMatching(probe as CFDictionary, &result)
        if status == errSecItemNotFound {
            status = SecItemAdd(probe as CFDictionary, &result)
        }
        guard status == errSecSuccess,
            let attributes = result as? [String: Any],
            let group = attributes[kSecAttrAccessGroup as String] as? String,
            let dot = group.firstIndex(of: ".")
        else { return nil }
        return "\(group[..<dot]).\(groupSuffix)"
    }
}
