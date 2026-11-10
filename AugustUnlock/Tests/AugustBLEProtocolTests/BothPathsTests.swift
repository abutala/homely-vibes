import XCTest
import os

@testable import AugustBLEProtocol

/// `BothPaths.run` with timed fakes for the two paths: who answers, how long
/// the lock's gate is held, and what the deadline leaves behind
/// (`formal/widget_paths.qnt`, `formal/gate.qnt`).
final class BothPathsTests: XCTestCase {
    private struct Jam: Error {}
    private struct Down: Error {}

    private let noNote: @Sendable (String) -> Void = { _ in }
    private let isJam: @Sendable (Error) -> Bool = { $0 is Jam }

    /// A path that ends after `ms` with `result`, and says if it was cancelled.
    private func path<T: Sendable>(
        after ms: Int, _ result: Result<T, Error>, cancelled: OSAllocatedUnfairLock<Bool>? = nil, log: OSAllocatedUnfairLock<[String]>? = nil, name: String = ""
    ) -> @Sendable () async throws -> T {
        {
            log?.withLock { $0.append("\(name) start") }
            do {
                try await Task.sleep(for: .milliseconds(ms))
            } catch {
                cancelled?.withLock { $0 = true }
                throw error
            }
            log?.withLock { $0.append("\(name) end") }
            return try result.get()
        }
    }

    private func isFree(_ gate: CommandGate) async -> Bool {
        do {
            try await withDeadline(seconds: 0.05) { try await gate.enter() }
            gate.leave()
            return true
        } catch {
            return false
        }
    }

    private func deadline(in seconds: Double) -> ContinuousClock.Instant { .now + .milliseconds(Int(seconds * 1000)) }

    func testBluetoothFirstAnswersAtOnceAndTheGateWaitsForAugust() async throws {
        let gate = CommandGate()
        let start = ContinuousClock.now
        let answer = try await BothPaths.run(
            gate: gate, expected: .unlocked, deadline: nil,
            bluetooth: path(after: 20, .success("fast")), cloud: path(after: 1500, .success(.unlocked)), isJam: isJam, note: noNote)
        XCTAssertLessThan(start.duration(to: .now), .milliseconds(1000), "the tap must not wait for August")
        guard case .bluetooth(let tail) = answer else { return XCTFail("\(answer)") }
        let freeDuringTheTail = await isFree(gate)
        XCTAssertFalse(freeDuringTheTail, "the next command to this lock waits for August's copy")
        let confirmed = await tail.value
        XCTAssertTrue(confirmed)
        let freeAfter = await isFree(gate)
        XCTAssertTrue(freeAfter)
    }

    func testAugustFirstAnswersAndStopsBluetooth() async throws {
        let gate = CommandGate()
        let cancelled = OSAllocatedUnfairLock(initialState: false)
        let answer = try await BothPaths.run(
            gate: gate, expected: .locked, deadline: nil,
            bluetooth: path(after: 2000, .success("slow"), cancelled: cancelled), cloud: path(after: 20, .success(.locked)), isJam: isJam, note: noNote)
        guard case .cloud(.locked) = answer else { return XCTFail("\(answer)") }
        try await Task.sleep(for: .milliseconds(100))
        XCTAssertTrue(cancelled.withLock { $0 }, "a Bluetooth command not yet done is cancelled")
        let free = await isFree(gate)
        XCTAssertTrue(free)
    }

    func testTheDeadlineBeforeAnAnswerIsACutOff() async {
        let gate = CommandGate()
        do {
            _ = try await BothPaths.run(
                gate: gate, expected: .unlocked, deadline: deadline(in: 0.05), minimumToSend: 0,
                bluetooth: path(after: 2000, .success("slow")), cloud: path(after: 2000, .success(.unlocked)), isJam: isJam, note: noNote)
            XCTFail("no answer was due")
        } catch {
            XCTAssertTrue(error is BothPaths.CutOff, "\(error)")
        }
        let free = await isFree(gate)
        XCTAssertTrue(free)
    }

    /// August's copy is still out at the deadline: unconfirmed, and the gate
    /// is free again (`deadlineInTail` in the model).
    func testTheDeadlineAfterABluetoothWinLeavesTheUnlockUnconfirmed() async throws {
        let gate = CommandGate()
        let answer = try await BothPaths.run(
            gate: gate, expected: .unlocked, deadline: deadline(in: 1), minimumToSend: 0,
            bluetooth: path(after: 10, .success("fast")), cloud: path(after: 5000, .success(.unlocked)), isJam: isJam, note: noNote)
        guard case .bluetooth(let tail) = answer else { return XCTFail("\(answer)") }
        let confirmed = await tail.value
        XCTAssertFalse(confirmed)
        let free = await isFree(gate)
        XCTAssertTrue(free)
    }

    func testAnErrorFromAugustAfterABluetoothWinIsUnconfirmed() async throws {
        let answer = try await BothPaths.run(
            gate: CommandGate(), expected: .unlocked, deadline: nil,
            bluetooth: path(after: 10, .success("fast")), cloud: path(after: 50, .failure(Down())), isJam: isJam, note: noNote)
        guard case .bluetooth(let tail) = answer else { return XCTFail("\(answer)") }
        let confirmed = await tail.value
        XCTAssertFalse(confirmed, "an error is not proof the command did not go out")
    }

    func testNothingIsSentWithTooLittleTimeLeft() async {
        let log = OSAllocatedUnfairLock(initialState: [String]())
        do {
            _ = try await BothPaths.run(
                gate: CommandGate(), expected: .unlocked, deadline: deadline(in: 0.5),
                bluetooth: path(after: 1, .success("fast"), log: log, name: "bluetooth"),
                cloud: path(after: 1, .success(.unlocked), log: log, name: "cloud"), isJam: isJam, note: noNote)
            XCTFail("nothing was to be sent")
        } catch {
            XCTAssertTrue(error is DoorTimeout, "\(error)")
        }
        XCTAssertEqual(log.withLock { $0 }, [])
    }

    func testAJamFailsTheTapUnlessAugustSaysTheDoorMoved() async throws {
        do {
            _ = try await BothPaths.run(
                gate: CommandGate(), expected: .unlocked, deadline: nil,
                bluetooth: path(after: 10, .failure(Jam())), cloud: path(after: 30, .success(.unknown)), isJam: isJam, note: noNote)
            XCTFail("a jam with no confirmed move is a failure")
        } catch {
            XCTAssertTrue(error is Jam, "\(error)")
        }
        let answer = try await BothPaths.run(
            gate: CommandGate(), expected: .unlocked, deadline: nil,
            bluetooth: path(after: 10, .failure(Jam())), cloud: path(after: 30, .success(.unlocked)), isJam: isJam, note: noNote)
        guard case .cloud(.unlocked) = answer else { return XCTFail("\(answer)") }
    }

    func testBothPathsFailingGivesAugustsError() async {
        do {
            _ = try await BothPaths.run(
                gate: CommandGate(), expected: .unlocked, deadline: nil,
                bluetooth: path(after: 10, .failure(Down())), cloud: path(after: 30, .failure(Jam())), isJam: { _ in false }, note: noNote)
            XCTFail("no path moved the door")
        } catch {
            XCTAssertTrue(error is Jam, "the cloud's error: \(error)")
        }
    }

    /// The caller's task is cancelled before any answer: it gets a
    /// cancellation, both paths stop, and the gate is free.
    func testACancelledCallerStopsBothPathsAndFreesTheGate() async {
        let gate = CommandGate()
        let cancelled = OSAllocatedUnfairLock(initialState: false)
        let caller = Task { [isJam, noNote] in
            try await BothPaths.run(
                gate: gate, expected: .unlocked, deadline: nil,
                bluetooth: self.path(after: 5000, .success("slow"), cancelled: cancelled), cloud: self.path(after: 5000, .success(.unlocked)),
                isJam: isJam, note: noNote)
        }
        try? await Task.sleep(for: .milliseconds(50))
        caller.cancel()
        do {
            _ = try await caller.value
            XCTFail("no answer was due")
        } catch {
            XCTAssertTrue(error is CancellationError, "\(error)")
        }
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertTrue(cancelled.withLock { $0 })
        let free = await isFree(gate)
        XCTAssertTrue(free)
    }

    /// The order at the lock: a lock tapped after an unlock that Bluetooth
    /// carried out starts only when August's copy of the unlock has ended.
    func testTheNextCommandStartsAfterAugustsCopyEnded() async throws {
        let gate = CommandGate()
        let log = OSAllocatedUnfairLock(initialState: [String]())
        let unlock = try await BothPaths.run(
            gate: gate, expected: .unlocked, deadline: nil,
            bluetooth: path(after: 10, .success("fast")), cloud: path(after: 200, .success(.unlocked), log: log, name: "unlock"), isJam: isJam, note: noNote)
        guard case .bluetooth = unlock else { return XCTFail("\(unlock)") }
        _ = try await BothPaths.run(
            gate: gate, expected: .locked, deadline: nil,
            bluetooth: nil, cloud: path(after: 10, .success(.locked), log: log, name: "lock"), isJam: isJam, note: noNote)
        XCTAssertEqual(log.withLock { $0 }, ["unlock start", "unlock end", "lock start", "lock end"])
    }

    /// Deadlines that fire around each path's end, two commands at a time on
    /// one gate: the gate is never left held, and the cloud path of one
    /// command never runs beside the other's.
    func testDeadlinesNeverLeakTheGateOrOverlapCommands() async {
        var stuck = 0
        let overlap = OSAllocatedUnfairLock(initialState: (active: 0, worst: 0))
        for i in 0..<150 {
            let gate = CommandGate()
            let tails = await withTaskGroup(of: Task<Bool, Never>?.self) { group -> [Task<Bool, Never>] in
                for j in 0..<2 {
                    let bluetoothMs = 1 + (i + j) % 5
                    let cloudMs = 1 + (i * 3 + j) % 7
                    let limit = Double(2 + (i + 2 * j) % 6) / 1000
                    group.addTask { [isJam, noNote] in
                        let cloud: @Sendable () async throws -> LockState = {
                            overlap.withLock { $0.active += 1; $0.worst = max($0.worst, $0.active) }
                            defer { overlap.withLock { $0.active -= 1 } }
                            try await Task.sleep(for: .milliseconds(cloudMs))
                            return .unlocked
                        }
                        let bluetooth: @Sendable () async throws -> String = {
                            try await Task.sleep(for: .milliseconds(bluetoothMs))
                            return "ok"
                        }
                        let answer = try? await BothPaths.run(
                            gate: gate, expected: .unlocked, deadline: .now + .milliseconds(Int(limit * 1000)), minimumToSend: 0,
                            bluetooth: bluetooth, cloud: cloud, isJam: isJam, note: noNote)
                        if case .bluetooth(let tail)? = answer { return tail }
                        return nil
                    }
                }
                var tails: [Task<Bool, Never>] = []
                for await tail in group { if let tail { tails.append(tail) } }
                return tails
            }
            for tail in tails { _ = await tail.value }
            do {
                try await withDeadline(seconds: 0.5) { try await gate.enter() }
                gate.leave()
            } catch { stuck += 1 }
        }
        XCTAssertEqual(stuck, 0, "a gate was left held")
        XCTAssertEqual(overlap.withLock { $0.worst }, 1, "two commands ran on one lock at the same time")
    }
}
