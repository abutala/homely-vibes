import Foundation
import os

/// Runs one command over Bluetooth and the cloud at the same moment
/// (`ParallelPaths` decides; TRIAL 2026-11-09). The two paths come in as
/// closures, so `swift test` drives this with timed fakes.
///
/// One task takes the lock's gate, runs both paths and, after a Bluetooth
/// win, the wait for August (the "tail"), then leaves the gate. The deadline
/// cancels that one task, so the gate cannot leak (`formal/gate.qnt`; the
/// 2026-11-05 leak had two owners). The caller gets the first answer and
/// returns; the task runs on behind it, and the next command to this lock
/// waits for it at the gate, which keeps the two in order at the lock.
nonisolated enum BothPaths {
    enum Answer: Sendable {
        /// Bluetooth moved the door. `tail` ends when the command is over:
        /// true only if August's reply says the door is in the asked state.
        case bluetooth(tail: Task<Bool, Never>)
        /// August's reply decides, with the state it reported.
        case cloud(LockState)
    }

    /// The deadline passed after the cloud command went out: August holds it.
    struct CutOff: Error {}

    /// Both paths ended and neither left an error to report.
    struct NothingMoved: LocalizedError {
        var errorDescription: String? { "Neither Bluetooth nor the cloud moved the door" }
    }

    private enum PathEnd: Sendable {
        case bluetooth(Result<String, Error>)
        case cloud(Result<LockState, Error>)
    }

    private enum First: Sendable {
        case bluetooth
        case cloud(LockState)
    }

    /// `bluetooth` is nil for a lock with no loaded key; it returns a line
    /// for the log. With less than `minimumToSend` left after the wait at
    /// the gate, nothing is sent and the command fails as `DoorTimeout`.
    /// Throws `CutOff`, `DoorTimeout`, the Bluetooth error after a jam that
    /// August did not clear, the cloud's error when no path moved the door,
    /// or `CancellationError` when the caller's task is cancelled first.
    static func run(
        gate: CommandGate, expected: LockState, deadline: ContinuousClock.Instant?, minimumToSend: TimeInterval = 1,
        bluetooth: (@Sendable () async throws -> String)?, cloud: @escaping @Sendable () async throws -> LockState,
        isJam: @escaping @Sendable (Error) -> Bool, note: @escaping @Sendable (String) -> Void
    ) async throws -> Answer {
        let (answers, answer) = AsyncStream.makeStream(of: Result<First, Error>.self)
        let sent = OSAllocatedUnfairLock(initialState: false)
        let owner = Task<Bool, Never> {
            defer { answer.finish() }
            do {
                return try await bounded(by: deadline) {
                    try await gate.enter()
                    defer { gate.leave() }
                    if let deadline, secondsLeft(until: deadline) < minimumToSend { throw DoorTimeout() }
                    sent.withLock { $0 = true }
                    return try await holdingGate(expected: expected, bluetooth: bluetooth, cloud: cloud, isJam: isJam, note: note, answer: answer)
                }
            } catch {
                let cutOff = error is DoorTimeout && sent.withLock { $0 }
                if cutOff { note("cut off by the deadline; August holds the command") }
                answer.yield(.failure(cutOff ? CutOff() : error))
                return false
            }
        }
        return try await withTaskCancellationHandler {
            for await first in answers {
                switch try first.get() {
                case .bluetooth: return .bluetooth(tail: owner)
                case .cloud(let state): return .cloud(state)
                }
            }
            // The owner always answers before it ends, so only a cancel of
            // this task ends the wait with nothing.
            assert(Task.isCancelled, "BothPaths: the owner ended with no answer")
            throw CancellationError()
        } onCancel: {
            owner.cancel()
        }
    }

    /// Starts both paths, feeds each end to `ParallelPaths`, runs its
    /// actions. Returns when the command is over: whether August confirmed
    /// a command that Bluetooth carried out.
    private static func holdingGate(
        expected: LockState, bluetooth: (@Sendable () async throws -> String)?, cloud: @escaping @Sendable () async throws -> LockState,
        isJam: @escaping @Sendable (Error) -> Bool, note: @escaping @Sendable (String) -> Void,
        answer: AsyncStream<Result<First, Error>>.Continuation
    ) async throws -> Bool {
        var paths = ParallelPaths(expected: expected, hasBluetooth: bluetooth != nil)
        let start = ContinuousClock.now
        note("cloud sent\(bluetooth == nil ? ", no Bluetooth key" : ", Bluetooth started")")
        var bluetoothError: Error?
        var cloudError: Error?
        return try await withThrowingTaskGroup(of: PathEnd.self) { group in
            if let bluetooth {
                group.addTask {
                    do { return .bluetooth(.success(try await bluetooth())) } catch { return .bluetooth(.failure(error)) }
                }
            }
            group.addTask {
                do { return .cloud(.success(try await cloud())) } catch { return .cloud(.failure(error)) }
            }
            for try await end in group {
                // The deadline cancelled both paths: their ends say nothing.
                try Task.checkCancellation()
                let actions: [ParallelPaths.Action]
                switch end {
                case .bluetooth(.success(let detail)):
                    note("Bluetooth ok in \(ms(since: start)) ms (\(detail))")
                    actions = paths.bluetoothEnded(.ok)
                case .bluetooth(.failure(let error)):
                    bluetoothError = error
                    note("Bluetooth \(isJam(error) ? "jammed" : "failed") in \(ms(since: start)) ms: \(error.localizedDescription)")
                    actions = paths.bluetoothEnded(isJam(error) ? .jammed : .failed)
                case .cloud(.success(let state)):
                    note("cloud replied \(state.label) in \(ms(since: start)) ms")
                    actions = paths.cloudEnded(.replied(state))
                case .cloud(.failure(let error)):
                    cloudError = error
                    note("cloud failed in \(ms(since: start)) ms: \(error.localizedDescription)")
                    actions = paths.cloudEnded(.failed)
                }
                var confirmed = false
                for action in actions {
                    switch action {
                    case .report(.bluetooth): answer.yield(.success(.bluetooth))
                    case .report(.cloud(let state)): answer.yield(.success(.cloud(state)))
                    case .report(.jammed): answer.yield(.failure(bluetoothError ?? NothingMoved()))
                    case .report(.failed): answer.yield(.failure(cloudError ?? bluetoothError ?? NothingMoved()))
                    case .cancelBluetooth: group.cancelAll()
                    case .tailClosed(let august): confirmed = august
                    case .finish: return confirmed
                    }
                }
            }
            assertionFailure("BothPaths: both paths ended with no finish")
            answer.yield(.failure(NothingMoved()))
            return false
        }
    }

    private static func bounded<T: Sendable>(by deadline: ContinuousClock.Instant?, _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
        guard let deadline else { return try await operation() }
        return try await withDeadline(seconds: secondsLeft(until: deadline), operation)
    }

    private static func ms(since start: ContinuousClock.Instant) -> Int {
        let elapsed = ContinuousClock.now - start
        return Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
    }
}
