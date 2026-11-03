import Foundation

/// Milliseconds from the start of a Bluetooth operation to each stage.
nonisolated struct AugustBLETiming: CustomStringConvertible, Equatable {
    var found: Int?
    var connected: Int?
    var session: Int?
    var written: Int?
    var done: Int?

    var description: String {
        let marks = [("found", found), ("connected", connected), ("session", session), ("written", written), ("done", done)]
        return marks.map { "\($0.0) \($0.1.map(String.init) ?? "-")" }.joined(separator: ", ")
    }
}
