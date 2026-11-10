import Foundation

/// What the sign-in and the door list need from August: the real client
/// (`AugustClient`) or, on the Simulator under a UI test, `FakeAugust`, scripted
/// by environment variables so the whole app can be driven without an account,
/// a lock or a network (Amit, 2026-11-01: local tests first, the phone only
/// confirms).
protocol AugustService: AnyObject {
    var hasSession: Bool { get }
    var cachedLocks: [AugustLock] { get }
    func login(email: String, password: String) async throws -> Bool
    func sendVerificationCode() async throws
    func validateCode(_ code: String) async throws
    func fetchLocks() async throws -> [AugustLock]
    func signOut()
}

/// How a command reaches the lock.
enum DoorPaths: Sendable {
    /// Bluetooth for its setup budget, then the cloud: the screen's taps,
    /// where a tap can reverse a command in flight.
    case bluetoothThenCloud
    /// Bluetooth and the cloud at the same moment; the first to move the
    /// door answers (`ParallelPaths`): the widget's taps (Amit, 2026-11-09).
    case both
}

/// One door's command by lock ID, under the caller's budgets. The real client
/// or `FakeAugust`, passed in as a parameter so the Simulator's tests can run
/// a tap end to end. `onStage` hears `.bluetooth` or `.cloud` as the path is
/// taken; with `.both` there is no path to report.
protocol DoorCommands: AnyObject {
    func unlock(
        lockID: String, paths: DoorPaths, bluetoothSetupBudget: TimeInterval, bluetoothOperationBudget: TimeInterval,
        deadline: ContinuousClock.Instant?, keepLink: Bool, onStage: @escaping @Sendable (DoorStage) -> Void
    ) async throws -> OperationReply
    func lock(
        lockID: String, paths: DoorPaths, bluetoothSetupBudget: TimeInterval, bluetoothOperationBudget: TimeInterval,
        deadline: ContinuousClock.Instant?, keepLink: Bool, onStage: @escaping @Sendable (DoorStage) -> Void
    ) async throws -> OperationReply
}

extension DoorCommands {
    /// The screen's command: its Bluetooth budgets, no client deadline (the
    /// screen runs its own), and a link kept for the next tap.
    func screenCommand(unlocking: Bool, lockID: String, onStage: @escaping @Sendable (DoorStage) -> Void) async throws -> OperationReply {
        let setup = CommandDeadline.screenBluetoothSetup
        let operation = CommandDeadline.screenBluetoothOperation
        if unlocking {
            return try await unlock(
                lockID: lockID, paths: .bluetoothThenCloud, bluetoothSetupBudget: setup, bluetoothOperationBudget: operation, deadline: nil, keepLink: true, onStage: onStage)
        }
        return try await lock(
            lockID: lockID, paths: .bluetoothThenCloud, bluetoothSetupBudget: setup, bluetoothOperationBudget: operation, deadline: nil, keepLink: true, onStage: onStage)
    }
}

extension AugustClient: AugustService, DoorCommands {}

enum August {
    /// `AUGUST_FAKE=1` in the launch environment picks the fake; the UI tests
    /// set it, nothing else does. A widget tap's background launch has no
    /// environment, so the fake also follows the marker that launch left
    /// (`TestHooks`).
    static let shared: any AugustService & DoorCommands =
        ProcessInfo.processInfo.environment["AUGUST_FAKE"] == "1" || TestHooks.fakeAugust ? FakeAugust() : AugustClient.shared
}

/// A scripted August for the Simulator. Environment:
/// - `AUGUST_FAKE_SIGNED_IN=1`: start signed in, with the door list cached.
/// - `AUGUST_FAKE_REPLY_SECONDS=n`: every command answers after n seconds
///   (default 1). Above the deadline, the command times out on screen.
/// - `AUGUST_FAKE_PATH=bluetooth|cloud`: the path a reply reports (default
///   bluetooth).
/// - `AUGUST_FAKE_FAIL=1`: every command fails with "no reply".
/// Markers, so a widget tap's background launch reads them too (`TestHooks`):
/// - `AUGUST_FAKE_ONE_LOCK_FAILS=1`: every second lock command fails.
/// - `AUGUST_FAKE_TAIL_OPEN=1`: August never answers a command sent on both
///   paths, so Bluetooth answers it and August's copy stays out.
/// A command on both paths (a widget tap) goes through `BothCommand`, as the
/// real client's does: Bluetooth answers after the reply seconds, August half
/// a second later. `AUGUST_FAKE_PATH=cloud` gives the lock no Bluetooth key.
/// Every command is counted in `commandsSent`, so a test can read it back
/// through the timing caption ("via …, 3 sent").
final class FakeAugust: AugustService, DoorCommands {
    private let env = ProcessInfo.processInfo.environment
    private var signedIn: Bool
    private(set) var commandsSent = 0
    private var locksSent = 0

    private let locks = [
        AugustLock(id: "fake-front", name: "Front Door"),
        AugustLock(id: "fake-garage", name: "Garage Entrance"),
    ]

    init() {
        signedIn = env["AUGUST_FAKE_SIGNED_IN"] == "1"
    }

    var hasSession: Bool { signedIn }
    var cachedLocks: [AugustLock] { signedIn ? locks : [] }

    func login(email: String, password: String) async throws -> Bool {
        signedIn = true
        return true
    }

    func sendVerificationCode() async throws {}
    func validateCode(_ code: String) async throws {}
    func fetchLocks() async throws -> [AugustLock] { locks }
    func signOut() { signedIn = false }

    private var scriptedPath: DoorStage { env["AUGUST_FAKE_PATH"] == "cloud" ? .cloud : .bluetooth }

    /// The same scripted reply, whatever the door.
    func unlock(
        lockID: String, paths: DoorPaths, bluetoothSetupBudget: TimeInterval, bluetoothOperationBudget: TimeInterval,
        deadline: ContinuousClock.Instant?, keepLink: Bool, onStage: @escaping @Sendable (DoorStage) -> Void
    ) async throws -> OperationReply {
        if paths == .both { return try await operateBoth(lockID: lockID, success: .unlocked, deadline: deadline) }
        onStage(scriptedPath)
        return try await operate(success: .unlocked)
    }

    func lock(
        lockID: String, paths: DoorPaths, bluetoothSetupBudget: TimeInterval, bluetoothOperationBudget: TimeInterval,
        deadline: ContinuousClock.Instant?, keepLink: Bool, onStage: @escaping @Sendable (DoorStage) -> Void
    ) async throws -> OperationReply {
        locksSent += 1
        let fails = TestHooks.oneLockFails && locksSent % 2 == 0
        let reply: OperationReply
        if paths == .both {
            reply = try await operateBoth(lockID: lockID, success: .locked, deadline: deadline)
        } else {
            onStage(scriptedPath)
            reply = try await operate(success: .locked)
        }
        if fails { throw AugustError.server(0, "lock failed") }
        return reply
    }

    private var replySeconds: Double { Double(env["AUGUST_FAKE_REPLY_SECONDS"] ?? "1") ?? 1 }
    private var failing: Bool { env["AUGUST_FAKE_FAIL"] == "1" }

    private func operate(success: LockState) async throws -> OperationReply {
        commandsSent += 1
        try await Task.sleep(for: .seconds(replySeconds))
        try Task.checkCancellation()
        if failing { throw AugustError.server(0, "no reply") }
        let path: OperationReply.Path = env["AUGUST_FAKE_PATH"] == "cloud" ? .cloud : .bluetooth
        return OperationReply(state: success, path: path)
    }

    /// The fake has no lock identity, so each command gets its own gate.
    private func operateBoth(lockID: String, success: LockState, deadline: ContinuousClock.Instant?) async throws -> OperationReply {
        commandsSent += 1
        let (seconds, failing, tailOpen) = (replySeconds, failing, TestHooks.tailOpen)
        let path: @Sendable (Double) async throws -> Void = { wait in
            try await Task.sleep(for: .seconds(wait))
            if failing { throw AugustError.server(0, "no reply") }
        }
        let bluetooth: (@Sendable () async throws -> String)? = env["AUGUST_FAKE_PATH"] == "cloud" ? nil : { @Sendable in try await path(seconds); return "fake" }
        return try await BothCommand.run(
            lockID: lockID, action: success == .unlocked ? "unlock" : "lock", gate: CommandGate(), success: success, deadline: deadline,
            bluetooth: bluetooth,
            cloud: { try await path(tailOpen ? 3600 : seconds + 0.5); return success },
            isJam: { _ in false }, readDoorLater: { _ in })
    }
}
