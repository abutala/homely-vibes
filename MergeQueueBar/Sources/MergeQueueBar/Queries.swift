import Foundation

/// Label names the pr-lander uses. `ready to review` queues a PR,
/// `autolanding` marks the one being landed, `autolanded` marks a PR the
/// lander merged, `automerge failed` marks a bounce. A bounce keeps
/// `ready to review`, so the queue search excludes bounced and `nomerge` PRs.
enum LanderLabel {
    static let queued = "ready to review"
    static let landing = "autolanding"
    static let landed = "autolanded"
    static let failed = "automerge failed"
    static let noMerge = "nomerge"
}

/// One GitHub search in the query. `listSize` PRs come back with the count; 0 means the count only.
struct SearchSpec: Equatable {
    let alias: String
    let query: String
    let listSize: Int
}

/// The GitHub searches for one snapshot. MQ searches are scoped to the org;
/// my searches cover every repo and count every PR I authored, the lander's
/// included. Day bounds are local midnights sent with their UTC offset, so
/// "today" is local, not left to GitHub.
struct QueueQueries: Equatable {
    static let historyDays = 7

    let searches: [SearchSpec]

    /// `dayStarts`: local midnights, oldest first; the first starts the 7-day
    /// window, the last is today.
    init(org: String, dayStarts: [String]) {
        let base = "org:\(org) is:pr"
        let landed = "\(base) is:merged label:\(LanderLabel.landed)"
        let mine = "is:pr author:@me"
        let mineMerged = "\(mine) is:merged"
        let today = dayStarts.last ?? ""
        let weekStart = dayStarts.first ?? ""
        searches = [
            SearchSpec(alias: "queued", query: "\(base) is:open label:\"\(LanderLabel.queued)\" -label:\"\(LanderLabel.failed)\" -label:\(LanderLabel.noMerge)", listSize: 50),
            SearchSpec(alias: "landed", query: "\(landed) merged:>=\(today)", listSize: 0),
            SearchSpec(alias: "failed", query: "\(base) is:open label:\"\(LanderLabel.failed)\"", listSize: 50),
            SearchSpec(alias: "mineOpen", query: "\(mine) is:open", listSize: 100),
            SearchSpec(alias: "mineMerged", query: "\(mineMerged) merged:>=\(today)", listSize: 0),
            SearchSpec(alias: "landedWeek", query: "\(landed) merged:>=\(weekStart)", listSize: 0),
            SearchSpec(alias: "mineMergedWeek", query: "\(mineMerged) merged:>=\(weekStart)", listSize: 0),
        ]
    }

    var graphQL: String {
        let params = searches.map { "$\($0.alias):String!" }.joined(separator: ",")
        let fields = searches.map { s in
            let nodes = s.listSize > 0 ? " nodes{...pr}" : ""
            return "  \(s.alias): search(query:$\(s.alias),type:ISSUE,first:\(max(s.listSize, 1))){issueCount\(nodes)}"
        }.joined(separator: "\n")
        return """
        query(\(params)){
        \(fields)
        }
        fragment pr on PullRequest {
          number title url isDraft repository{name} labels(first:20){nodes{name}}
        }
        """
    }
}

enum DayStart {
    /// The local midnights of the last `days` days as ISO-8601 with offset,
    /// oldest first, ending with today's, e.g. `2026-11-05T00:00:00-08:00`.
    static func isoStrings(now: Date, days: Int = QueueQueries.historyDays, calendar: Calendar = .current) -> [String] {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = calendar.timeZone
        formatter.formatOptions = [.withInternetDateTime]
        let today = calendar.startOfDay(for: now)
        return (0..<days).reversed().compactMap { back in
            calendar.date(byAdding: .day, value: -back, to: today).map(formatter.string(from:))
        }
    }
}
