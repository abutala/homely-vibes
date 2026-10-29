import Foundation

/// Every door's `DoorRecord`, keyed by lock ID, in one Keychain item the app
/// and the widget both read and write (see the Logbook: Sideloadly gives
/// both the same default access group). Writes replace the item in place.
enum DoorStateStore {
    private static let key = "august_door_states"

    static func read() -> [String: DoorRecord] {
        guard let json = KeychainStore.get(key),
            let records = try? JSONDecoder().decode([String: DoorRecord].self, from: Data(json.utf8))
        else { return [:] }
        return records
    }

    static func record(for id: String) -> DoorRecord {
        read()[id] ?? DoorRecord(at: .distantPast)
    }

    static func write(_ record: DoorRecord, for id: String) {
        var records = read()
        records[id] = record
        guard let json = try? JSONEncoder().encode(records) else { return }
        KeychainStore.set(String(decoding: json, as: UTF8.self), forKey: key)
    }

    static func clear() {
        KeychainStore.remove(key)
    }
}
