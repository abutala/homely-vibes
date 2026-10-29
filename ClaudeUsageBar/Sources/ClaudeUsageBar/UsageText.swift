import AppKit

/// Menu bar title and dropdown row text for a snapshot.
///
/// Pure and `now`-injectable, like `ResetFormatter`, so the icon placement,
/// its color and the absent-window cases are testable without a status item.
/// Setting an attributed title drops AppKit's default font and color, so both
/// are set here; `labelColor` is dynamic and follows the menu bar appearance.
enum UsageText {
    private static let fullFiveHourWindow = "5.0h"

    /// Marks a failed refresh: stale numbers in the title, the reason in the
    /// dropdown. Its own glyph, so `⚠︎` only ever means a pace warning.
    static let refreshFailedMarker = "\u{21BB}"

    /// Title reports what is *left* (budget and clock); the dropdown reports
    /// what was consumed. An absent five_hour window means nothing has been
    /// spent yet, so it reads as a full budget on a full clock — but only when
    /// the response is otherwise healthy, hence the guard.
    static func title(
        for snapshot: UsageSnapshot, font: NSFont = .menuBarFont(ofSize: 0), now: Date = Date()
    ) -> NSAttributedString {
        let result = NSMutableAttributedString()
        guard snapshot.fiveHour != nil || snapshot.sevenDay != nil else {
            result.append(plain("Claude: \u{2014}", font: font))
            return result
        }
        if let fiveHour = snapshot.fiveHour {
            result.append(titleSegment(fiveHour, length: PaceAlert.fiveHourLength, font: font, now: now))
        } else {
            result.append(plain("100% \(fullFiveHourWindow)", font: font))
        }
        if let sevenDay = snapshot.sevenDay {
            result.append(plain(" \u{00B7} ", font: font))
            result.append(titleSegment(sevenDay, length: PaceAlert.sevenDayLength, font: font, now: now))
        }
        return result
    }

    /// `5-hour: 42% — resets 11:20 PM (in 1h 43m)`, with the pace icon
    /// appended when there is one.
    static func row(
        label: String, window: UsageWindow, length: TimeInterval,
        font: NSFont = .menuFont(ofSize: 0), now: Date = Date()
    ) -> NSAttributedString {
        let pct = Int(window.utilization.rounded())
        let text = "\(label): \(pct)% \u{2014} resets \(ResetFormatter.description(for: window.resetsAt, now: now))"
        let result = NSMutableAttributedString(attributedString: plain(text, font: font))
        let alert = PaceAlert.evaluate(window, length: length, now: now)
        if alert != .none {
            result.append(plain(" ", font: font))
            result.append(icon(alert, font: font))
        }
        return result
    }

    /// Second line under a window row: the margin left at reset at the average
    /// rate so far — `At this pace: 64% left at reset`, matching the title's
    /// percent-left convention — or, when 100% comes before the reset, only
    /// the cool-down from run-out to reset: `At this pace: cool down of 2d 12h`.
    static func forecastRow(
        window: UsageWindow, length: TimeInterval,
        font: NSFont = .menuFont(ofSize: 0), now: Date = Date()
    ) -> NSAttributedString {
        plain(forecastText(window: window, length: length, now: now), font: font)
    }

    static func forecastText(window: UsageWindow, length: TimeInterval, now: Date = Date()) -> String {
        switch Forecast.make(window, length: length, now: now) {
        case .atReset(let used): return "At this pace: \(100 - Int(used.rounded()))% left at reset"
        case .runsOut(let date):
            // A run-out seconds before reset still reads `1m`, never `0m`.
            let start = min(date, window.resetsAt.addingTimeInterval(-60))
            return "At this pace: cool down of \(ResetFormatter.countdown(to: window.resetsAt, now: start))"
        case .tooEarly: return "Too early to project"
        case nil: return window.resetsAt <= now ? "Resetting now" : "Spent until reset"
        }
    }

    static func plain(_ text: String, font: NSFont) -> NSAttributedString {
        NSAttributedString(string: text, attributes: [.font: font, .foregroundColor: NSColor.labelColor])
    }

    /// Yellow for over pace, red for spent.
    static func color(for alert: PaceAlert) -> NSColor {
        alert == .over ? .systemRed : .systemYellow
    }

    private static func icon(_ alert: PaceAlert, font: NSFont) -> NSAttributedString {
        NSAttributedString(string: alert.icon, attributes: [.font: font, .foregroundColor: color(for: alert)])
    }

    private static func titleSegment(
        _ window: UsageWindow, length: TimeInterval, font: NSFont, now: Date
    ) -> NSAttributedString {
        // From the rounded used percent, so it agrees with the icon and the dropdown row.
        let left = max(0, 100 - Int(window.utilization.rounded()))
        let result = NSMutableAttributedString(
            attributedString: plain("\(left)% \(ResetFormatter.compactTimeLeft(window.resetsAt, now: now))", font: font)
        )
        let alert = PaceAlert.evaluate(window, length: length, now: now)
        if alert != .none { result.append(icon(alert, font: font)) }
        return result
    }
}
