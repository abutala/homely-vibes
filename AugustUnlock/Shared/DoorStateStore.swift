import Foundation

/// Each door's `DoorRecord`, one Keychain item per lock ID, read and written
/// by the app and the widget (see the Logbook: Sideloadly gives both the same
/// default access group). One item per door, replaced in place, so a write
/// from one process can never revert the other's write for a different door.
enum DoorStateStore {
    private static func key(_ id: String) -> String { "august_door_state_\(id)" }

    static func record(for id: String) -> DoorRecord {
        guard let json = KeychainStore.get(key(id)),
            let record = try? JSONDecoder().decode(DoorRecord.self, from: Data(json.utf8))
        else { return DoorRecord(at: .distantPast) }
        return record
    }

    static func write(_ record: DoorRecord, for id: String) {
        guard let json = try? JSONEncoder().encode(record) else { return }
        KeychainStore.set(String(decoding: json, as: UTF8.self), forKey: key(id))
    }

    static func clear(ids: [String]) {
        ids.forEach { KeychainStore.remove(key($0)) }
    }
}
