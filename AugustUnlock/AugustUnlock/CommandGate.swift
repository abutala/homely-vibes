import Foundation
import os

/// A first-come queue: `enter` waits until the previous holder leaves, or
/// throws when its task is cancelled while waiting (a deadline must not
/// wait out a slow holder). An actor's own methods do not serialise across
/// an `await`, so the queue is explicit.
final class CommandGate: Sendable {
    private struct Waiter {
        let id: UInt64
        /// Resumed with `true` when handed the gate, `false` when cancelled.
        let continuation: CheckedContinuation<Bool, Never>
    }

    private let state = OSAllocatedUnfairLock(initialState: (busy: false, nextID: UInt64(0), waiters: [Waiter]()))

    func enter() async throws {
        let id = state.withLock { s -> UInt64? in
            if s.busy {
                s.nextID += 1
                return s.nextID
            }
            s.busy = true
            return nil
        }
        guard let id else { return }
        let handed = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let acquired = state.withLock { s -> Bool in
                    if s.busy {
                        s.waiters.append(Waiter(id: id, continuation: continuation))
                        return false
                    }
                    s.busy = true
                    return true
                }
                if acquired { continuation.resume(returning: true) }
            }
        } onCancel: {
            let waiter = state.withLock { s -> Waiter? in
                guard let index = s.waiters.firstIndex(where: { $0.id == id }) else { return nil }
                return s.waiters.remove(at: index)
            }
            waiter?.continuation.resume(returning: false)
        }
        guard handed else { throw CancellationError() }
    }

    func leave() {
        let next = state.withLock { s -> Waiter? in
            if s.waiters.isEmpty {
                s.busy = false
                return nil
            }
            return s.waiters.removeFirst()
        }
        next?.continuation.resume(returning: true)
    }
}
