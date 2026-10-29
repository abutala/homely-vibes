import Observation
import SwiftUI
import os

/// Every door's state and command, shared by the app's circles and the
/// widget's taps (`ToggleDoorIntent` runs in this process). One command per
/// door at a time: a new one cancels that door's command in flight. Over
/// Bluetooth a cancel before the write means the first command never reaches
/// the lock; a cloud request August already holds can't be recalled — see
/// the Logbook. Which command a tap sends is `DoorTapPolicy`'s call.
@MainActor
@Observable
final class DoorController {
    static let shared = DoorController()

    /// Wall time of the last lock/unlock, tap or open to the reply, and the
    /// path that carried it — shown on screen so lag can be read off the
    /// phone without Console. One value, so the caption and its icon can't
    /// disagree.
    struct LastTiming {
        /// "Last Garage unlock: 1.2 s"
        let summary: String
        let path: OperationReply.Path

        var pathLabel: String { "via \(path.rawValue)" }
        /// The Bluetooth rune is a template vector in Assets.xcassets (SF
        /// Symbols has none: it is the Bluetooth SIG's mark); the cloud is a symbol.
        var icon: Image { path == .bluetooth ? Image("bluetooth") : Image(systemName: "cloud") }
        var tint: Color { path == .bluetooth ? .blue : .secondary }
    }

    /// The account's locks in door order (see `AugustClient.cachedLocks`).
    private(set) var doors: [AugustLock] = []
    private(set) var lastTiming: LastTiming?
    private(set) var lastError: String?
    /// The door `lastError` is about, so one door's command doesn't hide
    /// another door's error.
    private var lastErrorDoor: String?
    /// What August last reported per lock ID — taken from each command's
    /// reply, never inferred from the command sent.
    private var reported: [String: LockState] = [:]
    /// Lock ID → true while unlocking, false while locking.
    private var running: [String: Bool] = [:]
    private var policies: [String: DoorTapPolicy] = [:]
    private var tasks: [String: Task<Void, Never>] = [:]
    /// Bumped by sign-out, so a door-list fetch from before can't write after it.
    private var session = 0
    /// Widget taps still running, counted from the start: the lock lookup can
    /// wait on the network before any command exists.
    private var widgetTaps = 0

    private init() {}

    /// Read by the app's background exit check, so it never quits mid-command.
    var isBusy: Bool { !running.isEmpty || widgetTaps > 0 }

    func display(for id: String) -> DoorDisplay {
        if let unlocking = running[id] { return unlocking ? .unlocking : .locking }
        switch reported[id] {
        case .locked: return .locked
        case .unlocked: return .unlocked
        case .unknown, nil: return .unknown
        }
    }

    /// Opening the app — cold launch, finishing setup, or returning from the
    /// background — unlocks the picked door at once; opening the app is the
    /// confirmation (requested explicitly). No status fetch first: it cost a
    /// full cloud round trip before the command, and unlocking an unlocked
    /// door is a no-op. A command for it still in flight (a background resume)
    /// is left to report. The app shows only the picked door; the door list is
    /// loaded for the names in the timing caption and errors.
    func openUnlock() {
        doors = AugustClient.shared.cachedLocks ?? doors
        if let picked = AugustClient.shared.selectedLockID, running[picked] == nil {
            reported[picked] = nil
            send(picked, unlocking: true)
        }
        guard doors.isEmpty else { return }
        let session = session
        Task {
            let locks = (try? await AugustClient.shared.fetchLocks()) ?? []
            guard self.session == session else { return }
            doors = locks
        }
    }

    /// An app circle tap. The circle shows the state, so a reported unlock
    /// counts for as long as it is shown.
    func tap(_ id: String) {
        if running[id] != nil { UIImpactFeedbackGenerator(style: .medium).impactOccurred() }
        send(id, unlocking: nextTapUnlocks(id, trust: .infinity))
    }

    /// A widget tap. Waits for the reply, so iOS keeps the app running until
    /// it lands.
    func widgetTap(slot: Int) async throws {
        widgetTaps += 1
        defer { widgetTaps -= 1 }
        let door = try await AugustClient.shared.lock(atSlot: slot)
        doors = AugustClient.shared.cachedLocks ?? doors
        let unlocking = nextTapUnlocks(door.id, trust: DoorTapPolicy.widgetUnlockedTrust)
        Self.log.notice("Widget \(unlocking ? "unlock" : "lock", privacy: .public) for slot \(slot)")
        await send(door.id, unlocking: unlocking, fromWidget: true).value
    }

    func signOut() {
        session += 1
        tasks.values.forEach { $0.cancel() }
        doors = []
        lastTiming = nil
        lastError = nil
        lastErrorDoor = nil
        reported = [:]
        running = [:]
        policies = [:]
        tasks = [:]
    }

    private func nextTapUnlocks(_ id: String, trust: TimeInterval) -> Bool {
        (policies[id] ?? DoorTapPolicy()).nextTapUnlocks(at: Date(), trustUnlockedFor: trust)
    }

    /// Every state write follows a cancellation check, so a cancelled
    /// command's late reply can't overwrite its replacement's. The command
    /// keeps running if the app is backgrounded mid-flight; if iOS takes the
    /// time back first, it is dropped and the door shows unknown.
    @discardableResult
    private func send(_ id: String, unlocking: Bool, fromWidget: Bool = false) -> Task<Void, Never> {
        tasks[id]?.cancel()
        policies[id, default: DoorTapPolicy()].didSend(unlocking: unlocking)
        running[id] = unlocking
        if lastErrorDoor == id || lastErrorDoor == nil { setError(nil, door: nil) }
        let name = doors.first { $0.id == id }?.name ?? "door"

        var task: Task<Void, Never>?
        let keepAlive = BackgroundKeepAlive { [weak self] in
            task?.cancel()
            guard let self, let task, self.tasks[id] == task else { return }
            self.finish(id, state: .unknown)
        }
        task = Task {
            defer { keepAlive.end() }
            let start = ContinuousClock.now
            do {
                let reply = try await unlocking
                    ? AugustClient.shared.unlock(lockID: id) : AugustClient.shared.lock(lockID: id)
                try Task.checkCancellation()
                finish(id, state: reply.state)
                lastTiming = LastTiming(
                    summary: "Last \(name) \(unlocking ? "unlock" : "lock"): \(Self.seconds(since: start)) s",
                    path: reply.path)
                UINotificationFeedbackGenerator().notificationOccurred(.success)
            } catch {
                guard !Task.isCancelled else { return }
                finish(id, state: .unknown)
                setError("\(name): \(error.localizedDescription)", door: id)
                // A widget tap shows no result, so the log is its only trace.
                if fromWidget {
                    Self.log.error("Widget \(unlocking ? "unlock" : "lock", privacy: .public) of \(name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
                }
                UINotificationFeedbackGenerator().notificationOccurred(.error)
            }
        }
        tasks[id] = task
        return task!
    }

    private func finish(_ id: String, state: LockState) {
        running[id] = nil
        tasks[id] = nil
        reported[id] = state
        policies[id, default: DoorTapPolicy()].didFinish(reportedUnlocked: state == .unlocked, at: Date())
    }

    private func setError(_ message: String?, door: String?) {
        lastError = message
        lastErrorDoor = door
    }

    private static func seconds(since start: ContinuousClock.Instant) -> String {
        let elapsed = ContinuousClock.now - start
        let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        return String(format: "%.1f", seconds)
    }

    private static let log = Logger(subsystem: "AugustUnlock", category: "doors")
}

/// A UIKit background task: iOS otherwise suspends a backgrounded app within
/// seconds, and a lock/unlock reply still in flight comes back as "network
/// connection lost". `end()` is idempotent because both the command
/// finishing and iOS expiring the time call it.
@MainActor
private final class BackgroundKeepAlive {
    private var id = UIBackgroundTaskIdentifier.invalid

    init(onExpire: @escaping @MainActor () -> Void) {
        id = UIApplication.shared.beginBackgroundTask(withName: "AugustOperation") { [weak self] in
            MainActor.assumeIsolated {
                onExpire()
                self?.end()
            }
        }
    }

    func end() {
        guard id != .invalid else { return }
        UIApplication.shared.endBackgroundTask(id)
        id = .invalid
    }
}
