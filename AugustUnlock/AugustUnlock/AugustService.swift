import Foundation

/// What the screen needs from August: the real client (`AugustClient`) or,
/// on the Simulator under a UI test, `FakeAugust`, scripted by environment
/// variables so the whole app can be driven without an account, a lock or a
/// network (Amit, 2026-11-01: local tests first, the phone only confirms).
protocol AugustService: AnyObject {
    var isReady: Bool { get }
    var lockName: String? { get }
    var hasSelectedLock: Bool { get }
    func login(email: String, password: String) async throws -> Bool
    func sendVerificationCode() async throws
    func validateCode(_ code: String) async throws
    func fetchLocks() async throws -> [AugustLock]
    func selectLock(_ lock: AugustLock)
    func signOut()
    func unlock() async throws -> OperationReply
    func lock() async throws -> OperationReply
}

extension AugustClient: AugustService {}

enum August {
    /// `AUGUST_FAKE=1` in the launch environment picks the fake; the UI tests
    /// set it, nothing else does.
    static let shared: any AugustService =
        ProcessInfo.processInfo.environment["AUGUST_FAKE"] == "1" ? FakeAugust() : AugustClient.shared
}

/// A scripted August for the Simulator. Environment:
/// - `AUGUST_FAKE_SIGNED_IN=1`: start signed in with the first lock picked.
/// - `AUGUST_FAKE_REPLY_SECONDS=n`: every command answers after n seconds
///   (default 1). Above the deadline, the command times out on screen.
/// - `AUGUST_FAKE_PATH=bluetooth|cloud`: the path a reply reports (default
///   bluetooth).
/// - `AUGUST_FAKE_FAIL=1`: every command fails with "no reply".
/// Every command is counted in `commandsSent`, so a test can read it back
/// through the timing caption ("via …, 3 sent").
final class FakeAugust: AugustService {
    private let env = ProcessInfo.processInfo.environment
    private var signedIn: Bool
    private var selected: AugustLock?
    private(set) var commandsSent = 0

    private let locks = [
        AugustLock(id: "fake-front", name: "Front Door"),
        AugustLock(id: "fake-garage", name: "Garage Entrance"),
    ]

    init() {
        signedIn = env["AUGUST_FAKE_SIGNED_IN"] == "1"
        selected = signedIn ? locks[0] : nil
    }

    var isReady: Bool { signedIn && selected != nil }
    var lockName: String? { selected?.name }
    var hasSelectedLock: Bool { selected != nil }

    func login(email: String, password: String) async throws -> Bool {
        signedIn = true
        return true
    }

    func sendVerificationCode() async throws {}
    func validateCode(_ code: String) async throws {}
    func fetchLocks() async throws -> [AugustLock] { locks }
    func selectLock(_ lock: AugustLock) { selected = lock }

    func signOut() {
        signedIn = false
        selected = nil
    }

    func unlock() async throws -> OperationReply { try await operate(success: .unlocked) }
    func lock() async throws -> OperationReply { try await operate(success: .locked) }

    private func operate(success: LockState) async throws -> OperationReply {
        commandsSent += 1
        let seconds = Double(env["AUGUST_FAKE_REPLY_SECONDS"] ?? "1") ?? 1
        try await Task.sleep(for: .seconds(seconds))
        try Task.checkCancellation()
        if env["AUGUST_FAKE_FAIL"] == "1" { throw AugustError.server(0, "no reply") }
        let path: OperationReply.Path = env["AUGUST_FAKE_PATH"] == "cloud" ? .cloud : .bluetooth
        return OperationReply(state: success, path: path)
    }
}
