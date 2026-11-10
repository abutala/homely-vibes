import Foundation
import os

/// A small log file in Caches that the phone keeps and `devicectl` can copy:
/// `xcrun devicectl device copy from --domain-type appDataContainer
/// --domain-identifier <bundle id> --source Library/Caches/<file>`. Lines
/// come from several tasks at once; each read-append-write is one step.
/// The same line goes to the system log at `.notice`, which persists where
/// `.info` does not (Logbook 2026-10-18).
final class LineLog: Sendable {
    private let url: URL
    private let keep: Int
    private let logger: Logger
    private let lock = OSAllocatedUnfairLock()

    init(file: String, keep: Int, category: String) {
        url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent(file)
        self.keep = keep
        logger = Logger(subsystem: "AugustUnlock", category: category)
    }

    func note(_ message: String) {
        logger.notice("\(message, privacy: .public)")
        lock.withLock {
            let stamp = ISO8601DateFormatter().string(from: Date())
            var lines = (try? String(contentsOf: url, encoding: .utf8))?.split(separator: "\n").map(String.init) ?? []
            lines.append("\(stamp) \(message)")
            try? lines.suffix(keep).joined(separator: "\n").appending("\n").write(to: url, atomically: true, encoding: .utf8)
        }
    }
}
