import Foundation

struct PullRequest: Equatable {
    let repo: String
    let number: Int
    let title: String
    let url: URL
    let isDraft: Bool
    let labels: [String]

    var isLanding: Bool { labels.contains(LanderLabel.landing) }
    /// In the queue: tagged, and neither bounced nor held with `nomerge`.
    var isQueued: Bool {
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
    let mineOpen: [PullRequest]
    let mineOpenCount: Int
    let mineMergedToday: Int
    let fetchedAt: Date

    /// Every PR the queue held today: still tagged, landed, or bounced.
    var queueTotalToday: Int { queuedCount + landedToday + failedTodayCount }
    /// Every PR of mine alive today: still open, or merged today.
    var mineTotalToday: Int { mineOpenCount + mineMergedToday }
    var mineNotQueued: [PullRequest] { mineOpen.filter { !$0.isQueued && !$0.isLanding } }
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
        return QueueSnapshot(
            queued: d.queued.pullRequests,
            queuedCount: d.queued.issueCount,
            landedToday: d.landed.issueCount,
            failedToday: d.failed.pullRequests,
            failedTodayCount: d.failed.issueCount,
            mineOpen: d.mineOpen.pullRequests,
            mineOpenCount: d.mineOpen.issueCount,
            mineMergedToday: d.mineMerged.issueCount,
            fetchedAt: fetchedAt
        )
    }

    private struct Response: Decodable {
        let data: Searches?
        let errors: [GraphQLError]?
        let message: String?
    }

    private struct GraphQLError: Decodable {
        let message: String
    }

    private struct Searches: Decodable {
        let queued, landed, failed, mineOpen, mineMerged: Search
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
