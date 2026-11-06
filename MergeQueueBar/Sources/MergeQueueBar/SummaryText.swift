import Foundation

/// Plain strings for the menu bar title and dropdown rows. No AppKit, so tests cover them.
enum SummaryText {
    static let staleMarker = "\u{21BB}"
    static let titleLimit = 60

    /// `MQ 2/30 · Me 1/25`, plus `✗1` when a PR bounced today.
    static func title(_ s: QueueSnapshot) -> String {
        var title = "MQ \(s.queuedCount)/\(s.queueTotalToday) · Me \(s.mineOpenCount)/\(s.mineTotalToday)"
        if s.failedTodayCount > 0 { title += " \u{2717}\(s.failedTodayCount)" }
        return title
    }

    static func queueLine(_ s: QueueSnapshot) -> String {
        "Merge queue: \(s.queuedCount) tagged · \(s.landedToday) landed · \(s.failedTodayCount) failed today"
    }

    static func mineLine(_ s: QueueSnapshot) -> String {
        "My PRs: \(s.mineOpenCount) open · \(s.mineMergedToday) merged today"
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
