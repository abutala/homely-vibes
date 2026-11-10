import Foundation
import os

/// Cloud commands that may still reach a lock, per lock, in this process:
/// one still on its way after Bluetooth already moved the door
/// (`ParallelPaths`), or one a widget tap gave up on. The screen warns over
/// such a lock (the widget's tap and the screen share the client), and the
/// 5-minute exit waits while a wait for August runs. A command August
/// confirmed is gone at once; any other stays for
/// `CommandMachine.mayStillMoveWindow` from when it was recorded. Each
/// command has its own window, so one command's reply never clears another's.
nonisolated final class OpenTails: Sendable {
    static let shared = OpenTails()

    struct Window: Sendable {
        let lockID: String
        fileprivate let id = UUID()
    }

    private let state = OSAllocatedUnfairLock(initialState: (until: [String: [UUID: Date]](), running: 0))

    /// Bluetooth moved the door and the wait for August's copy starts.
    func opened(_ lockID: String, at now: Date) -> Window {
        let window = Window(lockID: lockID)
        state.withLock {
            Self.record(window.id, for: lockID, at: now, in: &$0.until)
            $0.running += 1
        }
        return window
    }

    /// The wait is over. Only August's confirmation closes the window early.
    func ended(_ window: Window, confirmed: Bool) {
        state.withLock {
            $0.running -= 1
            if confirmed { $0.until[window.lockID]?[window.id] = nil }
        }
    }

    /// A command went to August and the tap ended with no confirmed reply.
    func unanswered(_ lockID: String, at now: Date) {
        state.withLock { Self.record(UUID(), for: lockID, at: now, in: &$0.until) }
    }

    func mayStillMove(_ lockID: String, at now: Date) -> Bool {
        state.withLock { $0.until[lockID]?.contains { now < $0.value } ?? false }
    }

    /// A new window for the lock; its windows that are over go.
    private static func record(_ id: UUID, for lockID: String, at now: Date, in until: inout [String: [UUID: Date]]) {
        var windows = until[lockID]?.filter { now < $0.value } ?? [:]
        windows[id] = now.addingTimeInterval(CommandMachine.mayStillMoveWindow)
        until[lockID] = windows
    }

    var running: Int { state.withLock { $0.running } }
}
