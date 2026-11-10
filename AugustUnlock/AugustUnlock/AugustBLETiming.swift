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
        return marks.map { "\($0.0) \($0.1.map(String.init) ?? "-")" }.joined(separator: ", ") + (movedNothing ? "; no motion: the lock was probably in that state already" : "")
    }

    /// The lock answered too fast to have moved, so it was probably in the
    /// asked state already: another path (the cloud, a hand) moved it first.
    /// Seen on the garage: 158 ms with no motion frame, against 1.0–2.1 s
    /// for a real motion (Logbook 2026-11-09). No front-door sample.
    var movedNothing: Bool {
        guard let written, let done else { return false }
        return done - written < Self.shortestMotionMs
    }

    static let shortestMotionMs = 500
}
