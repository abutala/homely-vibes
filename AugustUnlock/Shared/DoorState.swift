import Foundation

/// What the widget shows per door while a tap runs and just after: handed
/// from the app process, where the tap runs, to the widget. Pure value;
/// `DoorStateStore` keeps it in the Keychain, the one store both bundles
/// share under this signing (no App Group).
struct DoorState: Codable, Equatable {
    struct Result: Codable, Equatable {
        let ok: Bool
        let at: Date
    }

    /// Positions with a tap in flight.
    var running: Set<Int> = []
    /// The last result per position, keyed by the position's text (JSON).
    var results: [String: Result] = [:]

    /// How long a result stays on the widget.
    static let hold: TimeInterval = 4

    enum Mark: Equatable {
        case none, running, ok, failed
    }

    mutating func start(_ position: Int) {
        running.insert(position)
        results[String(position)] = nil
    }

    mutating func finish(_ position: Int, ok: Bool, at now: Date) {
        running.remove(position)
        results[String(position)] = Result(ok: ok, at: now)
    }

    /// The mark per position at `now`: a result older than `hold` is gone.
    func marks(count: Int, at now: Date) -> [Mark] {
        (0..<count).map { position in
            if running.contains(position) { return .running }
            guard let result = results[String(position)], now < result.at + Self.hold else { return .none }
            return result.ok ? .ok : .failed
        }
    }

    /// When the last held result clears, if any is still showing at `now`.
    func clearDate(at now: Date) -> Date? {
        results.values.map { $0.at + Self.hold }.filter { $0 > now }.max()
    }
}
