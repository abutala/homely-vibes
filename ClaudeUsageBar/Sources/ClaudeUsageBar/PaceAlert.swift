import Foundation

/// Whether a window's spend needs attention: spent (`!`), or ahead of pace by
/// enough that the rest of the window needs a real cut (`⚠︎`).
///
/// "Ahead of pace" compares the rate needed to fit the remaining budget into
/// the remaining time against the even-spend rate (100% over the whole window).
/// It warns when the needed rate is more than 25% below even spend. The same
/// overshoot matters more late in a window, so the alarm tightens as it ends:
/// with 90% of the window left it fires above 32.5% used, with 10% left above
/// 92.5%.
enum PaceAlert: Equatable {
    case none
    case warning
    case over

    static let fiveHourLength: TimeInterval = 5 * 3600
    static let sevenDayLength: TimeInterval = 7 * 86400

    /// The needed rate may fall to this share of even spend before warning.
    private static let neededRateFloor = 0.75

    /// Judged on the displayed (rounded) percent, so the icon never disagrees
    /// with the number beside it. A window past its reset is dead data: no icon.
    static func evaluate(_ window: UsageWindow, length: TimeInterval, now: Date = Date()) -> PaceAlert {
        let timeLeft = window.resetsAt.timeIntervalSince(now)
        guard timeLeft > 0 else { return .none }
        let used = window.utilization.rounded()
        if used >= 100 { return .over }
        let timeLeftShare = min(timeLeft, length) / length
        return 100 - used < 100 * neededRateFloor * timeLeftShare ? .warning : .none
    }

    var icon: String {
        switch self {
        case .none: return ""
        case .warning: return "\u{26A0}\u{FE0E}"
        case .over: return "!"
        }
    }
}
