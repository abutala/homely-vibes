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

/// GitHub search strings for one snapshot. "Today" starts at local midnight,
/// sent with its UTC offset so "today" is local, not left to GitHub.
struct QueueQueries: Equatable {
    let queued: String
    let landedToday: String
    let failedToday: String
    let mineOpen: String
    let mineMergedToday: String

    init(org: String, dayStart: String) {
        let base = "org:\(org) is:pr"
        queued = "\(base) is:open label:\"\(LanderLabel.queued)\" -label:\"\(LanderLabel.failed)\" -label:\(LanderLabel.noMerge)"
        landedToday = "\(base) is:merged label:\(LanderLabel.landed) merged:>=\(dayStart)"
        failedToday = "\(base) is:open label:\"\(LanderLabel.failed)\" updated:>=\(dayStart)"
        mineOpen = "\(base) is:open author:@me"
        mineMergedToday = "\(base) is:merged author:@me merged:>=\(dayStart)"
    }

    var variables: [(name: String, value: String)] {
        [("queued", queued), ("landed", landedToday), ("failed", failedToday),
         ("mineOpen", mineOpen), ("mineMerged", mineMergedToday)]
    }

    static let graphQL = """
    query($queued:String!,$landed:String!,$failed:String!,$mineOpen:String!,$mineMerged:String!){
      queued: search(query:$queued,type:ISSUE,first:50){issueCount nodes{...pr}}
      landed: search(query:$landed,type:ISSUE,first:1){issueCount}
      failed: search(query:$failed,type:ISSUE,first:50){issueCount nodes{...pr}}
      mineOpen: search(query:$mineOpen,type:ISSUE,first:50){issueCount nodes{...pr}}
      mineMerged: search(query:$mineMerged,type:ISSUE,first:1){issueCount}
    }
    fragment pr on PullRequest {
      number title url isDraft repository{name} labels(first:20){nodes{name}}
    }
    """
}

enum DayStart {
    /// Local midnight of `now` as ISO-8601 with offset, e.g. `2026-11-05T00:00:00-08:00`.
    static func isoString(now: Date, calendar: Calendar = .current) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = calendar.timeZone
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: calendar.startOfDay(for: now))
    }
}
