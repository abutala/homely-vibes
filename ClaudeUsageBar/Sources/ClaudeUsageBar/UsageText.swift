import Foundation

/// Menu bar title and dropdown row text for a snapshot.
///
/// Pure and `now`-injectable, like `ResetFormatter`, so the icon placement and
/// the absent-window cases are testable without AppKit.
enum UsageText {
    private static let fullFiveHourWindow = "5.0h"

    /// Title reports what is *left* (budget and clock); the dropdown reports
    /// what was consumed. An absent five_hour window means nothing has been
    /// spent yet, so it reads as a full budget on a full clock — but only when
    /// the response is otherwise healthy, hence the guard.
    static func title(for snapshot: UsageSnapshot, now: Date = Date()) -> String {
        guard snapshot.fiveHour != nil || snapshot.sevenDay != nil else {
            return "Claude: \u{2014}"
        }
        var parts: [String] = []
        if let fiveHour = snapshot.fiveHour {
            parts.append(titleSegment(fiveHour, length: PaceAlert.fiveHourLength, now: now))
        } else {
            parts.append("100% \(fullFiveHourWindow)")
        }
        if let sevenDay = snapshot.sevenDay {
            parts.append(titleSegment(sevenDay, length: PaceAlert.sevenDayLength, now: now))
        }
        return parts.joined(separator: " \u{00B7} ")
    }

    /// `5-hour session: 42% — resets 11:20 PM (in 1h 43m)`, with the pace icon
    /// appended when there is one.
    static func row(label: String, window: UsageWindow, length: TimeInterval, now: Date = Date()) -> String {
        let pct = Int(window.utilization.rounded())
        let text = "\(label): \(pct)% \u{2014} resets \(ResetFormatter.description(for: window.resetsAt, now: now))"
        let icon = PaceAlert.evaluate(window, length: length, now: now).icon
        return icon.isEmpty ? text : "\(text) \(icon)"
    }

    private static func titleSegment(_ window: UsageWindow, length: TimeInterval, now: Date) -> String {
        let icon = PaceAlert.evaluate(window, length: length, now: now).icon
        // From the rounded used percent, so it agrees with the icon and the dropdown row.
        let left = max(0, 100 - Int(window.utilization.rounded()))
        return "\(left)% \(ResetFormatter.compactTimeLeft(window.resetsAt, now: now))\(icon)"
    }
}
