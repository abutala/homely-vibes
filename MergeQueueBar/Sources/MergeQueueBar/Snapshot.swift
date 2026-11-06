import Foundation

struct PullRequest: Equatable {
    let repo: String
    let number: Int
    let title: String
    let url: URL
    let isDraft: Bool
    let labels: [String]

    var isLanding: Bool { labels.contains(LanderLabel.landing) }
    /// The lander handles it: tagged, and neither bounced nor held with `nomerge`.
    var isWithLander: Bool {
        labels.contains(LanderLabel.queued)
            && !labels.contains(LanderLabel.failed) && !labels.contains(LanderLabel.noMerge)
    }
}

/// One fetch of the queue and of my PRs. Counts come from GitHub's
/// `issueCount`, so they stay right past the 50 PRs a list holds.
struct QueueSnapshot: Equatable {
    let queued: [PullRequest]
    let queuedCount: Int
    let landedToday: Int
    let failedToday: [PullRequest]
    let failedTodayCount: Int
    /// My open PRs in every repo, without the ones the lander handles.
    let mineOpen: [PullRequest]
    let mineOpenCount: Int
    /// My PRs merged today in every repo, without the ones the lander merged.
    let mineMergedToday: Int
    /// PRs the lander merged per day, oldest first, ending with today.
    let landedByDay: [Int]
    /// My PRs merged per day, oldest first, ending with today.
    let mineMergedByDay: [Int]
    let fetchedAt: Date

    /// Every PR the queue held today: still tagged, landed, or bounced.
    var queueTotalToday: Int { queuedCount + landedToday + failedTodayCount }
    /// Every PR of mine alive today: still open, or merged today.
    var mineTotalToday: Int { mineOpenCount + mineMergedToday }
}

enum SnapshotDecodeError: Error, Equatable {
    case graphQL(String)
    case malformed
}

enum SnapshotDecoder {
    static func decode(_ data: Data, fetchedAt: Date) throws -> QueueSnapshot {
        let response: Response
        do {
            response = try JSONDecoder().decode(Response.self, from: data)
        } catch {
            throw SnapshotDecodeError.malformed
        }
        // `errors[]` is a GraphQL error; a top-level `message` is an HTTP
        // error body (bad token, rate limit) that `gh` prints on stdout.
        if let message = response.errors?.first?.message ?? response.message {
            throw SnapshotDecodeError.graphQL(message)
        }
        guard let d = response.data else { throw SnapshotDecodeError.malformed }
        func search(_ alias: String) throws -> Search {
            guard let s = d[alias] else { throw SnapshotDecodeError.malformed }
            return s
        }
        let pastDays = 0..<(QueueQueries.historyDays - 1)
        let queued = try search("queued"), failed = try search("failed"), mineOpen = try search("mineOpen")
        let landedToday = try search("landed").issueCount
        let mineMergedToday = try search("mineMerged").issueCount
        return QueueSnapshot(
            queued: queued.pullRequests,
            queuedCount: queued.issueCount,
            landedToday: landedToday,
            failedToday: failed.pullRequests,
            failedTodayCount: failed.issueCount,
            mineOpen: mineOpen.pullRequests.filter { !$0.isWithLander },
            // Exact while all my open PRs fit in the list (100).
            mineOpenCount: mineOpen.issueCount - mineOpen.pullRequests.filter(\.isWithLander).count,
            mineMergedToday: mineMergedToday,
            landedByDay: try pastDays.map { try search(QueueQueries.landedAlias($0)).issueCount } + [landedToday],
            mineMergedByDay: try pastDays.map { try search(QueueQueries.mineAlias($0)).issueCount } + [mineMergedToday],
            fetchedAt: fetchedAt
        )
    }

    private struct Response: Decodable {
        let data: [String: Search]?
        let errors: [GraphQLError]?
        let message: String?
    }

    private struct GraphQLError: Decodable {
        let message: String
    }

    private struct Search: Decodable {
        let issueCount: Int
        let nodes: [Node]?

        var pullRequests: [PullRequest] { (nodes ?? []).compactMap(\.pullRequest) }
    }

    /// A search node is empty (`{}`) when it is not a PR, so every field is optional.
    private struct Node: Decodable {
        let number: Int?
        let title: String?
        let url: String?
        let isDraft: Bool?
        let repository: Repository?
        let labels: Labels?

        var pullRequest: PullRequest? {
            guard let number, let title, let url = url.flatMap(URL.init(string:)),
                  let repo = repository?.name else { return nil }
            return PullRequest(
                repo: repo, number: number, title: title, url: url,
                isDraft: isDraft ?? false, labels: labels?.nodes.map(\.name) ?? []
            )
        }
    }

    private struct Repository: Decodable { let name: String }
    private struct Labels: Decodable { let nodes: [Label] }
    private struct Label: Decodable { let name: String }
}
