import Foundation
import Security
import os

/// The widget's own path to August's cloud. It only reads the app's sign-in
/// from the Keychain (Sideloadly gives both targets the same default access
/// group, see the Logbook) and never writes it: a token refresh, a lock pick
/// or the Bluetooth key stay the app's alone. On a 401 the widget shows
/// "Open the app to sign in"; the app signs in again on its next request.
/// The request shape copies the app's `AugustClient`.
enum WidgetCloud {
    enum Failure: LocalizedError {
        case signedOut
        case server(Int)

        var errorDescription: String? {
            switch self {
            case .signedOut: return "Open the app to sign in"
            case .server(let code): return "August server error \(code)"
            }
        }
    }

    struct Lock: Codable, Equatable {
        let id: String
        let name: String
    }

    private static let baseURL = "https://api-production.august.com"
    private static let lockAPIKey = "66814fd9-af2c-426c-9710-b37e7eadfb51"  // # nosecret: public client key, same as AugustClient.lockAPIKey
    private static let userAgent = "August/Luna-22.17.0 (Android; SDK 31; gphone64_arm64)"
    private static let session = URLSession(configuration: .ephemeral)
    private static let log = Logger(subsystem: "AugustUnlock", category: "widget")

    /// Every lock on the account, sorted by lock ID so a door keeps its place
    /// in the widget. Each door shows the name August has for it.
    static func fetchLocks() async throws -> [Lock] {
        let data = try await send(method: "GET", path: "/users/locks/mine")
        let raw = try JSONSerialization.jsonObject(with: data) as? [String: [String: Any]] ?? [:]
        return raw.sorted { $0.key < $1.key }.compactMap { id, fields in
            (fields["LockName"] as? String).map { Lock(id: id, name: $0) }
        }
    }

    /// Returns the state the lock reported back, not the state requested.
    static func operate(lockID: String, unlocking: Bool) async throws -> DoorRecord.State {
        let action = unlocking ? "unlock" : "lock"
        let data = try await send(method: "PUT", path: "/remoteoperate/\(lockID)/\(action)")
        let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        return DoorRecord.State(augustStatus: json?["status"] as? String)
    }

    private static func send(method: String, path: String) async throws -> Data {
        guard let token = keychainString("august_access_token") else { throw Failure.signedOut }
        var request = URLRequest(url: URL(string: baseURL + path)!)
        request.httpMethod = method
        request.setValue(lockAPIKey, forHTTPHeaderField: "x-august-api-key")
        request.setValue("august", forHTTPHeaderField: "x-august-branding")
        request.setValue("0.0.1", forHTTPHeaderField: "Accept-Version")
        request.setValue("application/json; charset=UTF-8", forHTTPHeaderField: "Content-Type")
        request.setValue("US", forHTTPHeaderField: "x-august-country")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(token, forHTTPHeaderField: "x-august-access-token")

        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        log.notice("\(method, privacy: .public) \(path, privacy: .public) -> \(status)")
        if status == 401 { throw Failure.signedOut }
        guard (200...299).contains(status) else { throw Failure.server(status) }
        return data
    }

    private static func keychainString(_ key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}

/// The widget's own memory: the lock list and each door's `DoorRecord`, in
/// the extension's UserDefaults. The app never reads or writes it.
enum WidgetStore {
    private static let defaults = UserDefaults.standard
    private static let locksKey = "locks"

    static var locks: [WidgetCloud.Lock] {
        get { decode([WidgetCloud.Lock].self, locksKey) ?? [] }
        set { encode(newValue, locksKey) }
    }

    static func record(for lockID: String) -> DoorRecord {
        decode(DoorRecord.self, "door_\(lockID)") ?? DoorRecord(at: .distantPast)
    }

    static func write(_ record: DoorRecord, for lockID: String) {
        encode(record, "door_\(lockID)")
    }

    private static func decode<T: Decodable>(_ type: T.Type, _ key: String) -> T? {
        defaults.data(forKey: key).flatMap { try? JSONDecoder().decode(type, from: $0) }
    }

    private static func encode<T: Encodable>(_ value: T, _ key: String) {
        defaults.set(try? JSONEncoder().encode(value), forKey: key)
    }
}
