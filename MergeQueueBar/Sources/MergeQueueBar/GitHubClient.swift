import Foundation

enum GitHubClientError: Error, Equatable {
    case ghNotFound
    case ghFailed(String)
}

/// Runs a command and returns its stdout. Injected so tests never spawn `gh`.
typealias CommandRunner = (_ executable: URL, _ arguments: [String]) throws -> Data

enum GitHubClient {
    /// The org whose merge queue the bar shows. Override:
    /// `defaults write com.deviationlabs.MergeQueueBar org <name>`.
    static var org: String {
        UserDefaults.standard.string(forKey: "org") ?? "mastrix-ai"
    }

    /// A GUI app gets launchd's PATH, which lacks Homebrew, so `gh` is found by path.
    static let ghCandidates = ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"]

    static func fetch(
        org: String = org,
        now: Date = Date(),
        locate: () -> URL? = locateGh,
        run: CommandRunner = runProcess
    ) throws -> QueueSnapshot {
        guard let gh = locate() else { throw GitHubClientError.ghNotFound }
        let queries = QueueQueries(org: org, dayStart: DayStart.isoString(now: now))
        let data = try run(gh, arguments(for: queries))
        return try SnapshotDecoder.decode(data, fetchedAt: now)
    }

    static func arguments(for queries: QueueQueries) -> [String] {
        var args = ["api", "graphql", "-f", "query=\(QueueQueries.graphQL)"]
        for variable in queries.variables {
            args += ["-f", "\(variable.name)=\(variable.value)"]
        }
        return args
    }

    static func locateGh() -> URL? {
        ghCandidates
            .first { FileManager.default.isExecutableFile(atPath: $0) }
            .map(URL.init(fileURLWithPath:))
    }

    /// `gh api graphql` prints the GraphQL `errors` body on stdout and exits 1,
    /// so a non-empty stdout is returned for the decoder to report.
    static func runProcess(_ executable: URL, _ arguments: [String]) throws -> Data {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        let out = stdout.fileHandleForReading.readDataToEndOfFile()
        let err = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        if process.terminationStatus == 0 || !out.isEmpty { return out }
        let message = String(decoding: err, as: UTF8.self)
            .split(separator: "\n").first.map(String.init) ?? "exit \(process.terminationStatus)"
        throw GitHubClientError.ghFailed(message)
    }
}
