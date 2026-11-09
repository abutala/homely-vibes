import XCTest

@testable import AugustBLEProtocol

/// Mirrors `formal/august_unlock_command.qnt`: the three properties the model
/// pins for the app on `main`, as scenarios and as a seeded random run with
/// simulated Bluetooth and cloud replies, naps and returns.
final class CommandMachineTests: XCTestCase {
    private let t0 = Date(timeIntervalSinceReferenceDate: 0)
    private func at(_ s: TimeInterval) -> Date { t0.addingTimeInterval(s) }

    // MARK: - Scenarios

    func testFirstTapUnlocksAndTapWhileRunningSendsTheOpposite() {
        var m = CommandMachine()
        XCTAssertEqual(m.tap(at: at(0)), .send(unlocking: true))
        XCTAssertEqual(m.tap(at: at(1)), .send(unlocking: false))
        XCTAssertEqual(m.op, .inProgress(unlocking: false))
    }

    func testDoubleTapIsOneTap() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        XCTAssertEqual(m.tap(at: at(1)), .send(unlocking: false))
        XCTAssertEqual(m.tap(at: at(1.5)), .none)
        XCTAssertEqual(m.tap(at: at(1.8)), .send(unlocking: true))
    }

    func testTapLocksWhenShownUnlocked() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.replied(.unlocked, after: 1)
        m.settle()
        XCTAssertEqual(m.tap(at: at(5)), .send(unlocking: false))
    }

    func testNoStuckCommand_resumeEndsACommandPastItsDeadline() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        // The phone slept through the deadline; nothing fired.
        XCTAssertEqual(m.resume(at: at(CommandDeadline.limit + 1)), .cancel)
        XCTAssertEqual(m.op, .failure(CommandDeadline.timedOutMessage))
        XCTAssertEqual(m.door, .unknown)
        XCTAssertFalse(m.isOperating)
    }

    func testAReturnNeverSends() {
        var m = CommandMachine()
        XCTAssertEqual(m.resume(at: at(0)), .none)
        _ = m.tap(at: at(1))
        XCTAssertEqual(m.deadlineFired(at: at(32)), .cancel)
        m.settle()
        XCTAssertEqual(m.resume(at: at(40)), .none)
        XCTAssertEqual(m.resume(at: at(50)), .none)
    }

    /// The door may have moved while the app was away, so the first tap after
    /// a return unlocks, as it does after a launch.
    func testTheFirstTapAfterAReturnUnlocks() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.replied(.unlocked, after: 1)
        m.settle()
        XCTAssertEqual(m.resume(at: at(5)), .none)
        XCTAssertEqual(m.door, .unknown)
        XCTAssertEqual(m.op, .idle)
        XCTAssertEqual(m.tap(at: at(6)), .send(unlocking: true))
    }

    func testAReturnKeepsAFailedLocksRetry() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.replied(.unlocked, after: 1)
        m.settle()
        _ = m.tap(at: at(5))
        m.failed("The lock jammed")
        m.settle()
        XCTAssertEqual(m.resume(at: at(9)), .none)
        XCTAssertEqual(m.tap(at: at(10)), .send(unlocking: false), "a return must not turn the retried lock into an unlock")
    }

    func testAReturnLeavesARunningCommandToReport() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        XCTAssertEqual(m.resume(at: at(1)), .none)
        XCTAssertEqual(m.op, .inProgress(unlocking: true))
    }

    func testAReturnLeavesALateRequestToReport() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.reachedCloud()
        _ = m.deadlineFired(at: at(30))
        XCTAssertEqual(m.resume(at: at(31)), .none)
        XCTAssertTrue(m.isLate)
        XCTAssertEqual(m.tap(at: at(32)), .send(unlocking: true), "the retry repeats the unlock")
    }

    func testSignOutAlwaysPossible() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        XCTAssertTrue(m.isOperating)
        XCTAssertEqual(m.cancelForSignOut(at: at(0.5)), .cancel)
        XCTAssertEqual(m.op, .idle)
        XCTAssertEqual(m.tap(at: at(1)), .send(unlocking: true))
    }

    func testKeepAliveExpiryDropsTheCommand() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.keepAliveExpired(at: at(2))
        XCTAssertEqual(m.op, .idle)
        XCTAssertEqual(m.door, .unknown)
        XCTAssertEqual(m.resume(at: at(3)), .none)
    }

    // MARK: - TRIAL 2026-11-07

    func testATapAfterAFailedLockLocksAgain() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.replied(.unlocked, after: 1)
        m.settle()
        XCTAssertEqual(m.tap(at: at(5)), .send(unlocking: false))
        m.failed("The lock jammed")
        XCTAssertEqual(m.door, .unknown)
        XCTAssertEqual(m.tap(at: at(9)), .send(unlocking: false), "a retry repeats the failed lock, never unlocks")
    }

    func testATapAfterATimedOutLockLocksAgain() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.replied(.unlocked, after: 1)
        m.settle()
        _ = m.tap(at: at(5))
        XCTAssertEqual(m.deadlineFired(at: at(35)), .cancel)
        XCTAssertEqual(m.tap(at: at(36)), .send(unlocking: false))
    }

    func testASuccessClearsTheRetry() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.failed("no reply")
        _ = m.tap(at: at(2))
        m.replied(.unlocked, after: 1)
        m.settle()
        XCTAssertEqual(m.tap(at: at(5)), .send(unlocking: false))
    }

    func testATimeoutAfterTheCloudLetsTheRequestRunAndShowsItsLateReply() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.reachedCloud()
        XCTAssertEqual(m.deadlineFired(at: at(30)), .letRun)
        XCTAssertEqual(m.op, .failure(CommandDeadline.sentNoReplyMessage))
        XCTAssertEqual(m.warning(at: at(31)), CommandMachine.mayStillMoveWarning)
        m.replied(.unlocked, after: 41.2)
        XCTAssertEqual(m.op, .failure(CommandDeadline.sentNoReplyMessage), "a late reply is never shown as a success")
        XCTAssertEqual(m.door, .unlocked)
        XCTAssertEqual(m.lateNote, "Late reply: Unlocked after 41 s")
        XCTAssertNil(m.warning(at: at(42)), "the late command is done")
        XCTAssertEqual(m.tap(at: at(43)), .send(unlocking: false))
    }

    func testALateFailureKeepsTheSentMessage() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.reachedCloud()
        _ = m.deadlineFired(at: at(30))
        m.failed("The request timed out")
        XCTAssertEqual(m.op, .failure(CommandDeadline.sentNoReplyMessage))
        XCTAssertFalse(m.isLate)
        XCTAssertEqual(m.tap(at: at(45)), .send(unlocking: true), "the retry repeats the unlock")
    }

    func testATimeoutBeforeTheCloudCancelsAsBefore() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        XCTAssertEqual(m.deadlineFired(at: at(30)), .cancel)
        XCTAssertEqual(m.op, .failure(CommandDeadline.timedOutMessage))
        XCTAssertNil(m.warning(at: at(31)))
    }

    func testDroppingACloudCommandWarnsForAMinute() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.reachedCloud()
        XCTAssertEqual(m.tap(at: at(5)), .send(unlocking: false))
        XCTAssertEqual(m.warning(at: at(6)), CommandMachine.mayStillMoveWarning)
        XCTAssertNil(m.warning(at: at(65)))
    }

    func testSignOutClearsTheWarningButExpiryWarns() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.reachedCloud()
        _ = m.cancelForSignOut(at: at(3))
        XCTAssertNil(m.warning(at: at(4)), "the sign-in screen has no door to warn about")
        var n = CommandMachine()
        _ = n.tap(at: at(0))
        n.reachedCloud()
        n.keepAliveExpired(at: at(3))
        XCTAssertNotNil(n.warning(at: at(4)))
    }

    func testSignOutCancelsALateRequestAndClearsItsLines() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.reachedCloud()
        _ = m.deadlineFired(at: at(30))
        XCTAssertEqual(m.cancelForSignOut(at: at(31)), .cancel)
        XCTAssertFalse(m.isLate)
        XCTAssertNil(m.warning(at: at(32)))
        m.replied(.locked, after: 40)
        XCTAssertNotEqual(m.op, .success, "a reply after the drop writes nothing")
        XCTAssertEqual(m.door, .unknown)
    }

    func testAReplyWithNoCommandWritesNothing() {
        var m = CommandMachine()
        m.replied(.unlocked, after: 1)
        XCTAssertEqual(m.op, .idle)
        XCTAssertEqual(m.door, .unknown)
    }

    func testTheLateRunEndsAtItsCap() {
        var m = CommandMachine()
        _ = m.tap(at: at(0))
        m.reachedCloud()
        _ = m.deadlineFired(at: at(30))
        XCTAssertTrue(m.isLate)
        m.lateGaveUp()
        XCTAssertFalse(m.isLate)
        XCTAssertEqual(m.op, .failure(CommandDeadline.sentNoReplyMessage))
    }

    // MARK: - Stress: the model's random walk, with simulated transports

    /// One simulated August: a command goes over Bluetooth first and may fall
    /// to the cloud; replies take random time; the phone naps (no replies,
    /// no deadline), goes away and comes back. After every step the model's
    /// invariants must hold.
    func testRandomWalkKeepsTheInvariants() {
        var rng = SplitMix(seed: 0x5EED_2026_11_01)
        for run in 0..<400 {
            var world = World()
            for step in 0..<120 {
                world.step(&rng)
                XCTAssertFalse(
                    world.foreground && !world.asleep && world.m.isOperating && world.m.isExpired(at: world.now),
                    "run \(run) step \(step): a command older than the limit on screen (\(world.log.suffix(8)))")
                XCTAssertEqual(
                    world.returnSends, 0, "run \(run) step \(step): a return sent a command (\(world.log.suffix(8)))")
                XCTAssertEqual(
                    world.lateShownAsSuccess, 0, "run \(run) step \(step): a late reply shown as a success (\(world.log.suffix(8)))")
            }
        }
    }

    private struct World {
        var m = CommandMachine()
        var now = Date(timeIntervalSinceReferenceDate: 0)
        var foreground = true
        var asleep = false
        /// Seconds until the transport answers the command in flight.
        var secondsToReply: Int?
        var replyOk = true
        var returnSends = 0
        var lateShownAsSuccess = 0
        var log: [String] = []

        mutating func step(_ rng: inout SplitMix) {
            switch rng.next(upperBound: 10) {
            case 0, 1:
                if foreground && !asleep { apply(m.tap(at: now), "tap") }
            case 2: tick()
            case 3: tick()
            case 4:
                if !asleep && m.isOperating, secondsToReply == nil {
                    // Bluetooth failed: the cloud takes longer.
                    secondsToReply = 5 + Int(rng.next(upperBound: 60))
                    m.reachedCloud()
                    log.append("cloud")
                }
            case 5:
                if !asleep && foreground { asleep = true; foreground = false; log.append("sleep") }
            case 6:
                if asleep {
                    asleep = false
                    log.append("wake")
                    // A2: a deadline that passed during the nap fires on wake.
                    if m.isExpired(at: now) { apply(m.deadlineFired(at: now), "deadline") }
                }
            case 7:
                if foreground && !asleep { foreground = false; log.append("background") }
            case 8:
                if !foreground && !asleep {
                    foreground = true
                    let effect = m.resume(at: now)
                    apply(effect, "resume")
                    if case .send = effect { returnSends += 1 }
                }
            default:
                if foreground && !asleep {
                    apply(m.cancelForSignOut(at: now), "signOut")
                }
            }
            m.settle()
        }

        private mutating func tick() {
            now = now.addingTimeInterval(1)
            log.append("tick")
            guard !asleep else { return }
            if m.isOperating, m.isExpired(at: now) {
                apply(m.deadlineFired(at: now), "deadline")
                return
            }
            if m.isLate, let startedAt = m.startedAt, now >= startedAt.addingTimeInterval(CommandDeadline.lateLimit) {
                m.lateGaveUp()
                secondsToReply = nil
                log.append("lateCap")
                return
            }
            if let left = secondsToReply, m.isOperating || m.isLate {
                if left <= 1 {
                    secondsToReply = nil
                    let wasLate = m.isLate
                    if replyOk { m.replied(.unlocked, after: 1) } else { m.failed("no reply") }
                    if wasLate, m.op == .success { lateShownAsSuccess += 1 }
                    log.append(replyOk ? "ok" : "fail")
                } else {
                    secondsToReply = left - 1
                }
            }
        }

        private mutating func apply(_ effect: CommandMachine.Effect, _ what: String) {
            log.append(what)
            switch effect {
            case .send:
                // Bluetooth answers in 1–4 s; the cloud fallback may follow.
                secondsToReply = 1 + Int(now.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 4))
                replyOk = Int(now.timeIntervalSinceReferenceDate) % 7 != 0
            case .cancel:
                secondsToReply = nil
            case .letRun, .none:
                break
            }
        }
    }

    /// Deterministic generator, so a failing run can be replayed.
    private struct SplitMix {
        var state: UInt64
        init(seed: UInt64) { state = seed }
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
        mutating func next(upperBound: UInt64) -> UInt64 { next() % upperBound }
    }
}
