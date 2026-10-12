import Foundation

/// Rendering of "when does this window reset" in the two registers the UI uses.
///
/// Split out of `StatusItemController` because it is pure, `now`-injectable
/// logic with no AppKit or main-actor involvement — which is exactly what makes
/// it testable without mocking the clock.
enum ResetFormatter {
    /// Menu bar register: largest non-zero unit only, kept deliberately terse
    /// because the title competes for menu bar width. Days and hours carry one
    /// decimal (`4.2h`), minutes none. Integer division floors, so this
    /// understates time left rather than overstating it, and the `max(0,`
    /// keeps an already-elapsed reset from rendering negative.
    static func compactTimeLeft(_ date: Date, now: Date = Date()) -> String {
        let seconds = Int(max(0, date.timeIntervalSince(now)))
        if seconds >= 86400 { return tenths(seconds, per: 86400, unit: "d") }
        if seconds >= 3600 { return tenths(seconds, per: 3600, unit: "h") }
        return "\(seconds / 60)m"
    }

    private static func tenths(_ seconds: Int, per unitSeconds: Int, unit: String) -> String {
        let tenths = seconds * 10 / unitSeconds
        return "\(tenths / 10).\(tenths % 10)\(unit)"
    }

    /// Dropdown register: absolute wall-clock plus a two-unit countdown —
    /// `11:20 PM (in 1h 43m)`. The weekday is prefixed only when the reset
    /// falls on a different day, so same-day rows stay short.
    static func description(for date: Date, now: Date = Date()) -> String {
        let clock = DateFormatter()
        clock.dateStyle = .none
        clock.timeStyle = .short
        var stamp = clock.string(from: date)

        if !Calendar.current.isDate(date, inSameDayAs: now) {
            let weekday = DateFormatter()
            weekday.setLocalizedDateFormatFromTemplate("EEE")
            stamp = "\(weekday.string(from: date)) \(stamp)"
        }
        return "\(stamp) (in \(countdown(to: date, now: now)))"
    }

    /// Two units, largest first: `1d 0h`, `1h 43m`, `43m`. One unit alone
    /// ("in 1 hr.") is what made the old dropdown too coarse to act on.
    static func countdown(to date: Date, now: Date = Date()) -> String {
        let seconds = Int(max(0, date.timeIntervalSince(now)))
        let days = seconds / 86400
        let hours = (seconds % 86400) / 3600
        let minutes = (seconds % 3600) / 60
        if days > 0 { return "\(days)d \(hours)h" }
        if hours > 0 { return "\(hours)h \(minutes)m" }
        return "\(minutes)m"
    }
}
