import Foundation
import Security
import os

/// The one value the app's process hands the widget's: when the last
/// Detached tap started, as seconds since 1970. The Keychain is the one
/// store both bundles share under Sideloadly's signing (no App Group),
/// as AugustUnlock's door state does. Written in place; added once.
enum RigMark {
    private static let account = "rig_detached_tap"

    static func set(_ started: Date) {
        let data = Data(String(started.timeIntervalSince1970).utf8)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: account]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { return RigNote.write("rig.log", "mark: update failed, status \(status)") }
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let added = SecItemAdd(attributes as CFDictionary, nil)
        if added != errSecSuccess { RigNote.write("rig.log", "mark: add failed, status \(added)") }
    }

    static func get() -> Date? {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: account]
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status != errSecSuccess, status != errSecItemNotFound { RigNote.write("rig-widget.log", "mark: read failed, status \(status)") }
        guard status == errSecSuccess, let data = item as? Data,
            let seconds = String(data: data, encoding: .utf8).flatMap(Double.init)
        else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }
}

/// A line log in the current process's Caches: `rig.log` in the app,
/// `rig-widget.log` in the widget. Both read off the phone with
/// `xcrun devicectl device copy from --domain-type appDataContainer`.
enum RigNote {
    private static let lock = OSAllocatedUnfairLock()
    private static let log = Logger(subsystem: "BLEWidgetRig", category: "note")

    static func write(_ file: String, _ message: String) {
        log.notice("\(message, privacy: .public)")
        let url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent(file)
        lock.withLock {
            let stamp = ISO8601DateFormatter.withFractionalSeconds.string(from: Date())
            var lines = (try? String(contentsOf: url, encoding: .utf8))?.split(separator: "\n").map(String.init) ?? []
            lines.append("\(stamp) \(message)")
            try? lines.suffix(300).joined(separator: "\n").appending("\n").write(to: url, atomically: true, encoding: .utf8)
        }
    }
}

nonisolated extension ISO8601DateFormatter {
    static let withFractionalSeconds: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}
