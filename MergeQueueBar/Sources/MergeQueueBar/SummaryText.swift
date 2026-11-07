import Foundation

/// Plain strings for the menu bar title and dropdown rows. No AppKit, so tests cover them.
enum SummaryText {
    static let staleMarker = "\u{21BB}"
    static let titleLimit = 60

    /// The warning sign in text style (U+FE0E), so it draws as a monochrome menu bar glyph.
    static let failMark = "\u{26A0}\u{FE0E}"

    /// `MQ 2/30 (⚠︎1) Me 3/25`: `(⚠︎N)` marks N open bounced PRs and shows only when N > 0.
    static func title(_ s: QueueSnapshot) -> String {
        let failed = s.failedCount > 0 ? " (\(failMark)\(s.failedCount))" : ""
        return "MQ \(s.queuedCount)/\(s.queueTotalToday)\(failed) Me \(s.mineOpenCount)/\(s.mineTotalToday)"
    }

    static func queueLine(_ s: QueueSnapshot) -> String {
        "Merge queue: \(s.queuedCount) tagged \u{00B7} \(s.landedToday) landed today \u{00B7} \(s.failedCount) failed"
    }

    /// `My PRs: 3 open, 1 in MQ · 18 merged today`: the ones in MQ show in the queue list.
    static func mineLine(_ s: QueueSnapshot) -> String {
        let inQueue = s.mineInQueueCount > 0 ? ", \(s.mineInQueueCount) in MQ" : ""
        return "My PRs: \(s.mineOpenCount) open\(inQueue) \u{00B7} \(s.mineMergedToday) merged today"
    }

    /// `Last 7d: MQ 91 landed (13/day) · Me 44 merged (6/day)`.
    static func weekLine(_ s: QueueSnapshot) -> String {
        let days = QueueQueries.historyDays
        func perDay(_ n: Int) -> Int { Int((Double(n) / Double(days)).rounded()) }
        return "Last \(days)d: MQ \(s.landedWeek) landed (\(perDay(s.landedWeek))/day)"
            + " \u{00B7} Me \(s.mineMergedWeek) merged (\(perDay(s.mineMergedWeek))/day)"
    }

    /// `▶ repo#12 Title…`: `▶` marks the PR the lander is on now; `(draft)` a draft.
    static func row(_ pr: PullRequest) -> String {
        let marker = pr.isLanding ? "\u{25B6} " : ""
        let draft = pr.isDraft ? " (draft)" : ""
        return "\(marker)\(pr.repo)#\(pr.number) \(truncate(pr.title))\(draft)"
    }

    /// Shown when a list holds fewer PRs than its count (GitHub returns 50 at most).
    static func moreLine(shown: Int, total: Int) -> String? {
        total > shown ? "\u{2026} and \(total - shown) more" : nil
    }

    static func truncate(_ text: String, limit: Int = titleLimit) -> String {
        text.count <= limit ? text : String(text.prefix(limit - 1)) + "\u{2026}"
    }

    static func describe(_ error: Error) -> String {
        switch error {
        case GitHubClientError.ghNotFound: return "gh not found (brew install gh)"
        case GitHubClientError.ghFailed(let message): return "gh: \(message)"
        case SnapshotDecodeError.graphQL(let message): return "GitHub: \(message)"
        case SnapshotDecodeError.malformed: return "unexpected response"
        default: return error.localizedDescription
        }
    }
}
