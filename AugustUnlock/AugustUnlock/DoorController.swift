import Observation
import SwiftUI
import WidgetKit
import os

/// The picked door's state and command for the app's circle. The state is
/// shared with the widget through `DoorStateStore`, so a widget tap shows
/// here and an app command shows there. One command at a time: a new one
/// cancels the one in flight. Over Bluetooth a cancel before the write means
/// the first command never reaches the lock; a cloud request August already
/// holds can't be recalled — see the Logbook. A widget command for the same
/// door can't be cancelled from here; the last reply wins.
@MainActor
@Observable
final class DoorController {
    static let shared = DoorController()

    /// A WiFi-bridge lock can take ~60 s (README); past this the circle
    /// goes gray and a tap retries, instead of pulsing on.
    static let deadline: TimeInterval = 30

    /// Wall time of the last lock/unlock, tap or open to the reply, and the
    /// path that carried it — shown on screen so lag can be read off the
    /// phone without Console. One value, so the caption and its icon can't
    /// disagree.
    struct LastTiming {
        /// "Last unlock: 1.2 s"
        let summary: String
        let path: OperationReply.Path

        var pathLabel: String { "via \(path.rawValue)" }
        /// The Bluetooth rune is a template vector in Assets.xcassets (SF
        /// Symbols has none: it is the Bluetooth SIG's mark); the cloud is a symbol.
        var icon: Image { path == .bluetooth ? Image("bluetooth") : Image(systemName: "cloud") }
        var tint: Color { path == .bluetooth ? .blue : .secondary }
    }

    private(set) var display: DoorDisplay = .unknown
    private(set) var lastTiming: LastTiming?
    private(set) var lastError: String?
    private(set) var isBusy = false
    private var lockID: String?
    private var task: Task<Void, Never>?
    private var keepAlive: BackgroundKeepAlive?
    /// Identifies the current command, so a late background-expiry from an
    /// older one is ignored.
    private var commandToken = UUID()

    private init() {}

    /// Opening the app — cold launch, finishing setup, or returning from the
    /// background — unlocks the picked door at once; opening the app is the
    /// confirmation (requested explicitly). No status fetch first: it cost a
    /// full cloud round trip before the command, and unlocking an unlocked
    /// door is a no-op. A command still in flight (a background resume) is
    /// left to report.
    func openUnlock() {
        guard let id = AugustClient.shared.selectedLockID else { return }
        if lockID != id {
            lockID = id
            task?.cancel()
            isBusy = false
        }
        guard !isBusy else { return }
        send(unlocking: true)
    }

    /// Circle tap: lock if it shows unlocked, else unlock; the opposite of a
    /// command still running.
    func tap() {
        if isBusy { UIImpactFeedbackGenerator(style: .medium).impactOccurred() }
        let unlocking: Bool
        switch display {
        case .unlocking, .unlocked: unlocking = false
        case .locking, .locked, .unknown: unlocking = true
        }
        send(unlocking: unlocking)
    }

    /// Picks up what the widget did to this door while the app was away.
    func refreshFromStore() {
        guard let lockID, !isBusy else { return }
        let record = DoorStateStore.record(for: lockID).effective(at: Date(), trustUnlockedFor: .infinity)
        display = Self.display(for: record)
    }

    func signOut() {
        task?.cancel()
        task = nil
        keepAlive?.end()
        isBusy = false
        lockID = nil
        display = .unknown
        lastTiming = nil
        lastError = nil
        DoorStateStore.clearAll()
        WidgetCenter.shared.reloadAllTimelines()
    }

    /// Every state write follows a cancellation check, so a cancelled
    /// command's late reply can't overwrite its replacement's. The command
    /// keeps running if the app is backgrounded mid-flight; if iOS takes the
    /// time back first, it is dropped and the door shows unknown.
    private func send(unlocking: Bool) {
        guard let id = lockID else { return }
        task?.cancel()
        keepAlive?.end()
        isBusy = true
        lastError = nil
        display = unlocking ? .unlocking : .locking
        share(DoorRecord(state: .unknown, running: unlocking, at: Date()), for: id)

        // The expiry handler acts only on the command it was made for: a
        // newer command has its own keep-alive, and this one's may fire late.
        let token = UUID()
        commandToken = token
        let keepAlive = BackgroundKeepAlive { [weak self] in
            guard let self, self.commandToken == token else { return }
            self.task?.cancel()
            self.finish(id: id, state: .unknown, error: "Interrupted — tap to retry")
        }
        self.keepAlive = keepAlive
        task = Task {
            defer { keepAlive.end() }
            let start = ContinuousClock.now
            do {
                let reply = try await withDeadline(seconds: Self.deadline) {
                    try await unlocking ? AugustClient.shared.unlock(lockID: id) : AugustClient.shared.lock(lockID: id)
                }
                try Task.checkCancellation()
                finish(id: id, state: reply.state, error: nil)
                lastTiming = LastTiming(
                    summary: "Last \(unlocking ? "unlock" : "lock"): \(Self.seconds(since: start)) s", path: reply.path)
                UINotificationFeedbackGenerator().notificationOccurred(.success)
            } catch {
                guard !Task.isCancelled else { return }
                finish(id: id, state: .unknown, error: error.localizedDescription)
                UINotificationFeedbackGenerator().notificationOccurred(.error)
            }
        }
    }

    private func finish(id: String, state: LockState, error: String?) {
        isBusy = false
        task = nil
        lastError = error
        let shared: DoorRecord.State = state == .unlocked ? .unlocked : state == .locked ? .locked : .unknown
        let record = DoorRecord(state: shared, running: nil, at: Date())
        display = Self.display(for: record)
        share(record, for: id)
    }

    private func share(_ record: DoorRecord, for id: String) {
        DoorStateStore.write(record, for: id)
        WidgetCenter.shared.reloadAllTimelines()
    }

    private static func display(for record: DoorRecord) -> DoorDisplay {
        if let running = record.running { return running ? .unlocking : .locking }
        switch record.state {
        case .locked: return .locked
        case .unlocked: return .unlocked
        case .unknown: return .unknown
        }
    }

    private static func seconds(since start: ContinuousClock.Instant) -> String {
        let elapsed = ContinuousClock.now - start
        let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        return String(format: "%.1f", seconds)
    }
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
