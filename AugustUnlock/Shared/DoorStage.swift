import Foundation

/// Where a widget tap is, for its Live Activity (`DoorLiveActivity`). The
/// client reports `bluetooth` or `cloud` when it takes that path, after the
/// command gate and the key check, so a door that waits for the other
/// door's command still reads `unlocking`. The tap ends on the stage of its
/// outcome.
nonisolated enum DoorStage: String, Codable, Hashable, Sendable, CaseIterable {
    case unlocking, bluetooth, cloud, unlocked, failed, noReply

    var isFinal: Bool { self == .unlocked || self == .failed || self == .noReply }

    static func final(_ outcome: DoorState.Outcome) -> DoorStage {
        switch outcome {
        case .ok: .unlocked
        case .failed: .failed
        case .noReply: .noReply
        }
    }

    /// `seconds`: the tap's time, shown after "Unlocked" only.
    func caption(seconds: Double?) -> String {
        switch self {
        case .unlocking: "Unlocking\u{2026}"
        case .bluetooth: "Bluetooth\u{2026}"
        case .cloud: "Cloud\u{2026}"
        case .unlocked: seconds.map { String(format: "Unlocked %.1f s", $0) } ?? "Unlocked"
        case .failed: "Failed"
        case .noReply: "No reply"
        }
    }
}
