import XCTest
import os

@testable import AugustBLEProtocol

/// One command at a time, and a waiter that is cancelled lets go.
final class CommandGateTests: XCTestCase {
    func testTheSecondCommandWaitsForTheFirst() async throws {
        let gate = CommandGate()
        try await gate.enter()
        let entered = OSAllocatedUnfairLock(initialState: false)
        let second = Task {
            try await gate.enter()
            entered.withLock { $0 = true }
            gate.leave()
        }
        try await Task.sleep(for: .milliseconds(150))
        XCTAssertFalse(entered.withLock { $0 }, "the first still holds the gate")
        gate.leave()
        try await second.value
        XCTAssertTrue(entered.withLock { $0 })
    }

    func testACancelledWaiterThrowsAndDoesNotTakeTheGate() async throws {
        let gate = CommandGate()
        try await gate.enter()
        let waiter = Task {
            try await gate.enter()
        }
        try await Task.sleep(for: .milliseconds(100))
        waiter.cancel()
        do {
            try await waiter.value
            XCTFail("the cancelled waiter entered")
        } catch is CancellationError {}
        // The holder still has it: a third caller must wait until it leaves.
        let third = Task { try await gate.enter() }
        try await Task.sleep(for: .milliseconds(100))
        gate.leave()
        try await third.value
        gate.leave()
    }

    func testWaitersAreServedInOrder() async throws {
        let gate = CommandGate()
        try await gate.enter()
        let order = OSAllocatedUnfairLock(initialState: [Int]())
        let tasks = (1...3).map { n in
            Task {
                try await Task.sleep(for: .milliseconds(20 * n))
                try await gate.enter()
                order.withLock { $0.append(n) }
                gate.leave()
            }
        }
        try await Task.sleep(for: .milliseconds(200))
        gate.leave()
        for task in tasks { try await task.value }
        XCTAssertEqual(order.withLock { $0 }, [1, 2, 3])
    }
}
