import Foundation

/// Where a widget tap is, for its Live Activity (`DoorLiveActivity`). The
/// client reports `bluetooth` or `cloud` when it takes that path, after the
/// command gate and the key check, so a door that waits for the other
/// door's command still reads `unlocking` or `locking`. The tap ends on the
/// stage of its outcome.
nonisolated enum DoorStage: String, Codable, Hashable, Sendable, CaseIterable {
    case unlocking, bluetooth, cloud, unlocked, failed, noReply, locking, locked

    var isFinal: Bool { self == .unlocked || self == .failed || self == .noReply || self == .locked }

    static func final(_ outcome: DoorState.Outcome) -> DoorStage {
        switch outcome {
        case .ok: .unlocked
        case .failed: .failed
        case .noReply: .noReply
        }
    }

    static func finalForLock(_ outcome: DoorState.Outcome) -> DoorStage {
        outcome == .ok ? .locked : final(outcome)
    }

    /// The app screen's line under "Unlocking…": the path so far, from the
    /// stages the command reported, oldest first.
    static func pathNote(_ seen: [DoorStage]) -> String? {
        switch seen.last {
        case .bluetooth: "Over Bluetooth"
        case .cloud: seen.contains(.bluetooth) ? "Bluetooth failed, trying the cloud" : "Over the cloud"
        default: nil
        }
    }

    /// `seconds`: the tap's time, shown after "Unlocked" and "Locked" only.
    func caption(seconds: Double?) -> String {
        switch self {
        case .unlocking: "Unlocking\u{2026}"
        case .bluetooth: "Bluetooth\u{2026}"
        case .cloud: "Cloud\u{2026}"
        case .unlocked: seconds.map { String(format: "Unlocked %.1f s", $0) } ?? "Unlocked"
        case .locking: "Locking\u{2026}"
        case .locked: seconds.map { String(format: "Locked %.1f s", $0) } ?? "Locked"
        case .failed: "Failed"
        case .noReply: "No reply"
        }
    }
}
