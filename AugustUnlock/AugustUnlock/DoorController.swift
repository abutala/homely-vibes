import Observation
import SwiftUI

/// One door's row on the screen: its command state machine (`CommandMachine`,
/// mirrored by `formal/august_unlock_command.qnt`), and the tasks that run the
/// effects it returns. Doors are independent: each has its own machine, and
/// the client has a gate per lock.
@Observable
final class DoorController: Identifiable {
    /// The name may change with a refreshed list; the ID never does.
    var lock: AugustLock
    var id: String { lock.id }

    private(set) var machine = CommandMachine()
    /// The running command's path so far: a stage from a cancelled command is
    /// dropped.
    private(set) var seenStages: [DoorStage] = []
    /// Wall time of the last command, tap to reply, and the path that carried
    /// it: lag can be read off the phone without Console.
    private(set) var lastTiming: LastTiming?

    @ObservationIgnored private var stagesCommand = UUID()
    /// The command in flight, kept so a newer one can cancel it: see `run(_:)`.
    @ObservationIgnored private var operationTask: Task<Void, Never>?
    @ObservationIgnored private var deadlineTask: Task<Void, Never>?
    @ObservationIgnored private let onCommandEnded: () -> Void

    struct LastTiming {
        /// "Last unlock: 1.2 s"
        let summary: String
        let path: OperationReply.Path
    }

    init(lock: AugustLock, onCommandEnded: @escaping () -> Void) {
        self.lock = lock
        self.onCommandEnded = onCommandEnded
    }

    var commandInFlight: Bool { machine.isOperating || machine.isLate }

    /// The orange line under the door: a request this screen dropped, or a
    /// widget tap's cloud command still on its way to this lock (`OpenTails`).
    func warning(at now: Date) -> String? {
        machine.warning(at: now) ?? (OpenTails.shared.mayStillMove(lock.id, at: now) ? CommandMachine.mayStillMoveWarning : nil)
    }

    /// The button: the machine decides (the first tap unlocks; then lock,
    /// unlock, the opposite of a command in flight, or nothing for a double
    /// tap).
    func tap() {
        let replacing = machine.isOperating
        let effect = machine.tap(at: Date())
        if case .send = effect, replacing { UIImpactFeedbackGenerator(style: .medium).impactOccurred() }
        perform(effect)
    }

    /// Back from a real background. Sends nothing: see `CommandMachine.resume`.
    func resume() {
        perform(machine.resume(at: Date()))
    }

    func cancelForSignOut() {
        perform(machine.cancelForSignOut(at: Date()))
        lastTiming = nil
    }

    private func perform(_ effect: CommandMachine.Effect) {
        switch effect {
        case .send(let unlocking):
            run { [self] in try await performOperation(unlocking: unlocking) }
        case .cancel:
            operationTask?.cancel()
            operationTask = nil
            deadlineTask?.cancel()
            if case .failure = machine.op { UINotificationFeedbackGenerator().notificationOccurred(.error) }
        case .letRun:
            UINotificationFeedbackGenerator().notificationOccurred(.warning)
            capLateRequest()
        case .none:
            break
        }
    }

    private func performOperation(unlocking: Bool) async throws {
        let start = ContinuousClock.now
        let command = UUID()
        stagesCommand = command
        seenStages = []
        let (stages, report) = AsyncStream.makeStream(of: DoorStage.self)
        let watcher = Task {
            for await stage in stages where stagesCommand == command {
                seenStages.append(stage)
                if stage == .cloud { machine.reachedCloud() }
            }
        }
        defer { report.finish() }
        let onStage: @Sendable (DoorStage) -> Void = { report.yield($0) }
        let reply = try await August.shared.screenCommand(unlocking: unlocking, lockID: lock.id, onStage: onStage)
        report.finish()
        await watcher.value
        try Task.checkCancellation()
        let late = machine.isLate
        let elapsed = ContinuousClock.now - start
        let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        let sent = (August.shared as? FakeAugust).map { ", \($0.commandsSent) sent" } ?? ""
        lastTiming = LastTiming(
            summary: "Last \(unlocking ? "unlock" : "lock"): \(String(format: "%.1f", seconds)) s\(sent)", path: reply.path)
        machine.replied(reply.state, after: seconds)
        AppLog.note("screen \(unlocking ? "unlock" : "lock") lock=\(lock.id.suffix(4)) \(late ? "late reply" : "reply") \(reply.state.label) via \(reply.path.rawValue) in \(String(format: "%.1f", seconds)) s")
        if !late { UINotificationFeedbackGenerator().notificationOccurred(.success) }
    }

    /// Runs one operation at a time on this door, cancelling any still in
    /// flight. Every state write in an operation follows a cancellation check,
    /// so a cancelled one's late reply can't overwrite its replacement's. The
    /// operation keeps running if the app is backgrounded mid-flight, and the
    /// app may suspend once it ends. If iOS takes the time back first, the
    /// operation is dropped.
    private func run(_ operation: @escaping () async throws -> Void) {
        operationTask?.cancel()
        deadlineTask?.cancel()
        var task: Task<Void, Never>?
        let keepAlive = BackgroundTask(name: "AugustOperation") {
            Task { @MainActor [self] in
                task?.cancel()
                if task == operationTask { machine.keepAliveExpired(at: Date()) }
            }
        }
        task = Task { [self] in
            do {
                try await operation()
            } catch {
                if !Task.isCancelled {
                    let late = machine.isLate
                    machine.failed(error.localizedDescription)
                    if late {
                        AppLog.note("screen late request failed lock=\(lock.id.suffix(4)): \(error.localizedDescription)")
                    } else {
                        UINotificationFeedbackGenerator().notificationOccurred(.error)
                    }
                }
            }
            keepAlive.end()
            guard !Task.isCancelled else { return }
            deadlineTask?.cancel()
            onCommandEnded()
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            machine.settle()
        }
        operationTask = task
        // The deadline: `Task.sleep` counts on the continuous clock, so a
        // sleep that outlives the phone's nap fires on wake; the resume path
        // checks the wall clock as well, in case it does not.
        deadlineTask = Task { [self] in
            try? await Task.sleep(for: .seconds(CommandDeadline.limit))
            guard !Task.isCancelled, task == operationTask else { return }
            let effect = machine.deadlineFired(at: Date())
            AppLog.note("screen deadline lock=\(lock.id.suffix(4)): \(effect == .letRun ? "sent to August, running on" : "nothing sent, cancelled")")
            perform(effect)
        }
    }

    /// A request already with August runs to `lateLimit` from its start,
    /// then is dropped, whichever path (the deadline or a resume) let it run.
    private func capLateRequest() {
        guard let task = operationTask, let startedAt = machine.startedAt else { return }
        let left = max(0, CommandDeadline.lateLimit - Date().timeIntervalSince(startedAt))
        Task { [self] in
            try? await Task.sleep(for: .seconds(left))
            guard task == operationTask, machine.isLate else { return }
            task.cancel()
            machine.lateGaveUp()
            AppLog.note("screen late request dropped at \(Int(CommandDeadline.lateLimit)) s lock=\(lock.id.suffix(4))")
        }
    }
}

/// The door list and the app's life around it: which rows show, what a return
/// to the foreground does to them, and the 5-minute background exit.
@Observable
final class DoorsModel {
    private(set) var doors: [DoorController] = []

    /// Quits the app after `BackgroundExitPolicy.defaultTimeout` in the
    /// background. Checked on a timer (runs only while iOS keeps the process
    /// awake) and again on return to the foreground (the case that matters,
    /// since a suspended process runs no timers) — see the Logbook.
    @ObservationIgnored private var exitPolicy = BackgroundExitPolicy()
    @ObservationIgnored private var exitTimer: Task<Void, Never>?
    /// Set when the scene actually reaches `.background`, consumed on the
    /// next `.active`. A real background resume is `.background -> .inactive
    /// -> .active` (two onChange calls, never one direct `.background ->
    /// .active` pairing), so this can't be a same-call oldPhase/newPhase check;
    /// a transient interruption (Control Center, an incoming-call banner) is
    /// `.active -> .inactive -> .active` and never touches `.background`.
    @ObservationIgnored private var wasBackgrounded = false

    /// A door keeps its row, and its command, across a refreshed list, even
    /// when it was renamed.
    func show(_ locks: [AugustLock]) {
        doors = locks.map { lock in
            guard let door = doors.first(where: { $0.id == lock.id }) else {
                return DoorController(lock: lock) { [weak self] in self?.exitIfExpired() }
            }
            door.lock = lock
            return door
        }
    }

    func signOut() {
        doors.forEach { $0.cancelForSignOut() }
        doors = []
    }

    func scenePhaseChanged(to phase: ScenePhase) {
        switch phase {
        case .background:
            wasBackgrounded = true
            exitPolicy.didBackground(at: Date())
            armExitTimer()
            // A kept Bluetooth link would block the official app and the
            // widget: it closes once any running command has its result.
            AugustBLELink.applicationDidEnterBackground()
        case .active:
            AugustBLELink.applicationDidBecomeActive()
            guard wasBackgrounded else { break }
            wasBackgrounded = false
            exitTimer?.cancel()
            let expired = exitPolicy.shouldExit(at: Date(), operationInFlight: commandInFlight)
            exitPolicy.didForeground()
            if expired { exit(0) }
            doors.forEach { $0.resume() }
        default:
            break
        }
    }

    /// Quits once the background deadline passes. A command still in flight
    /// postpones it; a door calls `exitIfExpired` again when its command ends.
    private func armExitTimer() {
        exitTimer?.cancel()
        guard let remaining = exitPolicy.remaining(at: Date()) else { return }
        exitTimer = Task { [self] in
            try? await Task.sleep(for: .seconds(remaining))
            guard !Task.isCancelled else { return }
            exitIfExpired()
        }
    }

    private func exitIfExpired() {
        if exitPolicy.shouldExit(at: Date(), operationInFlight: commandInFlight) { exit(0) }
    }

    /// A door's command, a widget tap running in this process, or a tap's
    /// cloud command still out: the exit waits for each (a tap killed by the
    /// exit would leave its door marked running with no result). After a tap
    /// defers it, the next return to the foreground exits.
    private var commandInFlight: Bool {
        doors.contains(where: \.commandInFlight) || AppDoorAction.inFlight > 0 || OpenTails.shared.running > 0
    }
}
