import XCTest

@testable import AugustBLEProtocol

/// The Bluetooth engine driven like a lock would drive it, with the wires
/// `scripts/gen_ble_vectors.py` prints from yalexs-ble's own classes: the
/// handshake, an unlock, a status push, then a lock on the same chain.
final class AugustBLEEngineTests: XCTestCase {
    private let offlineKey = bytes("000102030405060708090a0b0c0d0e0f")
    private let nonce = bytes("101112131415161718191a1b1c1d1e1f")
    // The phone's wires.
    private let cmd1 = bytes("8057b7a941466a2eac73547cf56b366e0f04")
    private let cmd2 = bytes("a983bea66fcd0e67d710046275dab5750f04")
    private let unlock1 = bytes("da1d4fc8a1a9a700e8dba8233005399a0200")
    private let lock2 = bytes("e948430bf75f67146fb05fc2a447dc910200")
    // The lock's wires, in chain order.
    private let reply1 = bytes("2d970bb8635a8bc893a0e8a2cf42b6360f04")
    private let reply2 = bytes("be4ec40c853ad15cb3ebf013edfca6dd0f04")
    private let ack1 = bytes("5801cbb04dfe6ed1bcf20e1fb278b2040200")
    private let op1 = bytes("27e489aee72fa7f91948b36d9dc226790000")
    private let push = bytes("baf371f0d7d27ee654f0cdfb4c3a3daa0000")
    private let ack2 = bytes("270079d770a7c8b864e96238af321a5e0200")
    private let op2 = bytes("c75d6bae875be9f59fa2588caa9876450000")

    private let secureWrite = AugustBLE.secureWriteUUID
    private let secureRead = AugustBLE.secureReadUUID
    private let write = AugustBLE.writeUUID
    private let read = AugustBLE.readUUID

    private var engine: AugustBLEEngine!
    private var now = 100.0

    override func setUp() {
        engine = AugustBLEEngine(offlineKey: offlineKey, slot: 4, nonce: { self.nonce })
    }

    private func send(_ input: AugustBLEEngine.Input, after seconds: Double = 0) -> [AugustBLEEngine.Output] {
        now += seconds
        return engine.handle(input, at: now)
    }

    private func command(_ token: Int, _ opcode: UInt8, keep: Bool = true) -> AugustBLEEngine.Input {
        .command(token, opcode: opcode, keepLink: keep, setupBudget: 3, operationBudget: 12)
    }

    /// Walks a fresh link to its open plain channel, as the lock would answer.
    @discardableResult
    private func openLink(firstToken token: Int = 1, opcode: UInt8 = AugustBLE.unlockOpcode, keep: Bool = true) -> [AugustBLEEngine.Output] {
        var out = send(command(token, opcode, keep: keep))
        XCTAssertEqual(out.first, .startLink)
        XCTAssertTrue(out.contains(.schedule(.setup(token), 3)))
        XCTAssertEqual(send(.connected, after: 0.6), [.discover])
        XCTAssertEqual(send(.characteristicsReady(true), after: 0.1), [.setNotify(secureRead)])
        XCTAssertEqual(send(.notifyEnabled(secureRead, error: nil), after: 0.1), [.write(secureWrite, cmd1)])
        XCTAssertEqual(send(.frame(secureRead, reply1), after: 0.1), [.write(secureWrite, cmd2)])
        out = send(.frame(secureRead, reply2), after: 0.1)
        XCTAssertEqual(out, [.setNotify(read), .schedule(.operation(token), 12)])
        return out
    }

    // MARK: - One command on a fresh link

    func testUnlockOnAFreshLinkThenKeepsIt() {
        openLink()
        // The plain notify confirms: the command goes after the 0.25 s cooldown from the last frame.
        let out = send(.notifyEnabled(read, error: nil), after: 0.05)
        XCTAssertEqual(out, [.schedule(.cooldown(1), 0.2)])
        XCTAssertEqual(send(.timer(.cooldown(1)), after: 0.2), [.write(write, unlock1)])
        XCTAssertEqual(send(.frame(read, ack1), after: 0.05), [])
        let done = send(.frame(read, op1), after: 0.05)
        guard case .complete(1, .ok(let timing))? = done.first else { return XCTFail("\(done)") }
        XCTAssertEqual(timing.connected, 600)
        XCTAssertNotNil(timing.session)
        XCTAssertNotNil(timing.written)
        XCTAssertEqual(done.dropFirst().first, .schedule(.keep(serial: 1), 5))
    }

    func testTheWidgetsCommandDoesNotKeepTheLink() {
        openLink(keep: false)
        writeFirstCommand()
        _ = send(.frame(read, ack1), after: 0.05)
        let done = send(.frame(read, op1), after: 0.05)
        XCTAssertEqual(done.count, 3, "\(done)")
        XCTAssertEqual(done[1], .write(secureWrite, engineShutdown()))
        XCTAssertEqual(done[2], .schedule(.close(epoch: 1), 0.3))
        XCTAssertEqual(send(.timer(.close(epoch: 1)), after: 0.3), [.disconnect])
    }

    // MARK: - The interrupt: a lock right after an unlock, on the same link

    /// After the plain notify, past the cooldown: the command is written at once.
    private func writeFirstCommand() {
        XCTAssertEqual(send(.notifyEnabled(read, error: nil), after: 0.3), [.write(write, unlock1)])
    }

    func testACancelAfterTheWriteRunsToItsResultAndTheOppositeReusesTheLink() {
        openLink()
        writeFirstCommand()
        // The screen cancels at once and sends the opposite.
        XCTAssertEqual(send(.cancel(1), after: 0.1), [.complete(1, .cancelled)])
        XCTAssertEqual(send(command(2, AugustBLE.lockOpcode)), [], "waits for the unlock's result")
        _ = send(.frame(read, ack1), after: 0.05)
        // The unlock's result is not reported again; the lock command starts
        // its budgets now and waits 1 s after the op-response before its write.
        let out = send(.frame(read, op1), after: 0.05)
        XCTAssertEqual(out, [.schedule(.operation(2), 12), .schedule(.cooldown(2), 1)])
        XCTAssertEqual(send(.timer(.cooldown(2)), after: 1), [.write(write, lock2)])
        _ = send(.frame(read, ack2), after: 0.05)
        let done = send(.frame(read, op2), after: 0.05)
        guard case .complete(2, .ok(let timing))? = done.first else { return XCTFail("\(done)") }
        XCTAssertNil(timing.connected, "no connect on a kept link")
        XCTAssertNil(timing.session)
        XCTAssertEqual(timing.written, 1000)
    }

    func testACancelBeforeTheWriteDropsOnlyTheCommand() {
        openLink()
        // Inside the cooldown: the write is still pending when the cancel lands.
        XCTAssertEqual(send(.notifyEnabled(read, error: nil), after: 0.05), [.schedule(.cooldown(1), 0.2)])
        XCTAssertEqual(send(.cancel(1)), [.complete(1, .cancelled), .schedule(.keep(serial: 1), 5)])
        // Its cooldown timer is stale now.
        XCTAssertEqual(send(.timer(.cooldown(1)), after: 0.2), [])
        let out = send(command(2, AugustBLE.unlockOpcode), after: 0.1)
        XCTAssertEqual(out, [.schedule(.operation(2), 12), .write(write, unlock1)], "the first command's wire was never sent, so this is the chain's first frame")
    }

    /// The garage on 2026-11-10T04:58:07Z: the cloud had unlocked it, and
    /// the Bluetooth unlock answered "ok" in 158 ms without moving anything.
    func testAnAnswerTooFastToHaveMovedSaysSo() {
        XCTAssertTrue(AugustBLETiming(written: 9582, done: 9740).movedNothing)
        XCTAssertTrue(AugustBLETiming(written: 9582, done: 9740).description.hasSuffix("no motion: the lock was probably in that state already"))
        XCTAssertFalse(AugustBLETiming(written: 6742, done: 8798).movedNothing, "a real lock motion")
        XCTAssertFalse(AugustBLETiming(written: 2996, done: 4145).movedNothing)
        XCTAssertFalse(AugustBLETiming().movedNothing)
    }

    /// An answer about the next command's opcode before that command is
    /// written (another channel's command, or a cancelled one's late
    /// answer) is logged and changes nothing: the command still waits.
    func testAnAnswerBeforeTheWriteIsLoggedNotTaken() {
        openLink()
        writeFirstCommand()
        _ = send(.frame(read, ack1), after: 0.05)
        _ = send(.frame(read, op1), after: 0.05)
        // The vectors' chain has the push between the two commands.
        _ = send(.frame(read, push), after: 0.05)
        let queued = send(command(2, AugustBLE.lockOpcode), after: 0.1)
        XCTAssertFalse(queued.contains { if case .write = $0 { return true } else { return false } }, "inside the gap after a result: not written yet")
        XCTAssertEqual(send(.frame(read, ack2), after: 0.05), [.note("lock acknowledged a command that is not waiting here")])
        XCTAssertEqual(send(.frame(read, op2), after: 0.05), [.note("lock answered a command that is not waiting here: result 0x00")])
    }

    func testAPushBetweenCommandsKeepsTheChainInStep() {
        openLink()
        writeFirstCommand()
        _ = send(.frame(read, ack1), after: 0.05)
        _ = send(.frame(read, op1), after: 0.05)
        XCTAssertEqual(send(.frame(read, push), after: 1), [.note("lock pushed bb2f0016000000000000000000000000")], "a status push is decrypted and logged, nothing more")
        let out = send(command(2, AugustBLE.lockOpcode), after: 0.5)
        XCTAssertEqual(out, [.schedule(.operation(2), 12), .write(write, lock2)])
        _ = send(.frame(read, ack2), after: 0.05)
        guard case .complete(2, .ok)? = send(.frame(read, op2), after: 0.05).first else { return XCTFail() }
    }

    func testASkippedPushGarblesOneFrameThenTheChainIsBackInStep() {
        openLink()
        writeFirstCommand()
        _ = send(.frame(read, ack1), after: 0.05)
        _ = send(.frame(read, op1), after: 0.05)
        // The push never reaches the engine: the lock's chain moved on, ours did not.
        _ = send(command(2, AugustBLE.lockOpcode), after: 1.5)
        XCTAssertEqual(send(.frame(read, ack2), after: 0.05), [], "garbled: dropped like a bad frame")
        // CBC re-synchronises on the next frame (yalexs: a skipped frame
        // garbles only the one after it), so the result still lands.
        let out = send(.frame(read, op2), after: 0.05)
        guard case .complete(2, .ok)? = out.first else { return XCTFail("\(out)") }
    }

    // MARK: - Keeping and closing

    func testTheKeepTimerClosesAnIdleLinkAndACommandDuringTheCloseWaits() {
        openLink()
        writeFirstCommand()
        _ = send(.frame(read, ack1), after: 0.05)
        _ = send(.frame(read, op1), after: 0.05)
        let closing = send(.timer(.keep(serial: 1)), after: 5)
        XCTAssertEqual(closing, [.write(secureWrite, engineShutdown()), .schedule(.close(epoch: 1), 0.3)])
        XCTAssertEqual(send(command(2, AugustBLE.lockOpcode), after: 0.1), [], "arrives while closing: waits")
        XCTAssertEqual(send(.timer(.close(epoch: 1)), after: 0.2), [.disconnect])
        let out = send(.disconnected(nil), after: 0.1)
        XCTAssertEqual(out.first, .startLink, "a new link for the waiting command")
        XCTAssertTrue(out.contains(.schedule(.setup(2), 3)))
    }

    func testAnEarlierKeepTimerDoesNotCloseAfterALaterCommand() {
        openLink()
        writeFirstCommand()
        _ = send(.frame(read, ack1), after: 0.05)
        _ = send(.frame(read, op1), after: 0.05)
        _ = send(command(2, AugustBLE.lockOpcode), after: 1.5)
        _ = send(.timer(.cooldown(2)), after: 1)
        _ = send(.frame(read, ack2), after: 0.05)
        let done = send(.frame(read, op2), after: 0.05)
        XCTAssertEqual(done.last, .schedule(.keep(serial: 2), 5))
        XCTAssertEqual(send(.timer(.keep(serial: 1)), after: 2.3), [], "the first command's keep timer must not close the link")
        XCTAssertEqual(send(.timer(.keep(serial: 2)), after: 2.7).first, .write(secureWrite, engineShutdown()))
    }

    func testALateDisconnectOfADroppedLinkIsIgnored() {
        _ = send(command(1, AugustBLE.unlockOpcode))
        _ = send(.connected, after: 0.6)
        _ = send(.timer(.setup(1)), after: 2.4)
        // The radio reports the failed link's disconnect late: nothing to do.
        XCTAssertEqual(send(.disconnected(nil), after: 0.1), [])
        XCTAssertEqual(send(command(2, AugustBLE.lockOpcode), after: 0.1).first, .startLink)
    }

    func testACommandJustBeforeTheKeepTimerKeepsTheLink() {
        openLink()
        writeFirstCommand()
        _ = send(.frame(read, ack1), after: 0.05)
        _ = send(.frame(read, op1), after: 0.05)
        let out = send(command(2, AugustBLE.lockOpcode), after: 4.99)
        XCTAssertEqual(out, [.schedule(.operation(2), 12), .write(write, lock2)])
        XCTAssertEqual(send(.timer(.keep(serial: 1)), after: 0.01), [], "the old keep timer is stale while a command runs")
    }

    func testBackgroundDropsAnIdleLinkAndWaitsForARunningOne() {
        openLink()
        writeFirstCommand()
        XCTAssertEqual(send(.background, after: 0.05), [], "a command is running: wait for it")
        _ = send(.frame(read, ack1), after: 0.05)
        let done = send(.frame(read, op1), after: 0.05)
        XCTAssertEqual(done.count, 3)
        XCTAssertEqual(done[1], .write(secureWrite, engineShutdown()))
        XCTAssertEqual(done[2], .schedule(.close(epoch: 1), 0.3))
    }

    func testAProcessThatStartsInTheBackgroundNeverKeeps() {
        engine = AugustBLEEngine(offlineKey: offlineKey, slot: 4, nonce: { self.nonce }, inBackground: true)
        openLink()
        writeFirstCommand()
        _ = send(.frame(read, ack1), after: 0.05)
        let done = send(.frame(read, op1), after: 0.05)
        XCTAssertEqual(done[1], .write(secureWrite, engineShutdown()))
    }

    // MARK: - Failures

    func testSetupTimesOutAtTheHeadCommandsBudgetAndDropsTheLink() {
        _ = send(command(1, AugustBLE.unlockOpcode))
        _ = send(.connected, after: 0.6)
        let out = send(.timer(.setup(1)), after: 2.4)
        XCTAssertEqual(out, [.complete(1, .setupTimedOut(stage: "discovering characteristics")), .disconnect])
    }

    func testALinkWhoseOnlyCommandWasCancelledDuringSetupKeepsOrCloses() {
        _ = send(command(1, AugustBLE.unlockOpcode))
        _ = send(.connected, after: 0.6)
        XCTAssertEqual(send(.cancel(1), after: 0.1), [.complete(1, .cancelled), .schedule(.grace(epoch: 1), 1)], "the link keeps coming up for a second")
        _ = send(.characteristicsReady(true), after: 0.1)
        _ = send(.notifyEnabled(secureRead, error: nil), after: 0.1)
        _ = send(.frame(secureRead, reply1), after: 0.1)
        _ = send(.frame(secureRead, reply2), after: 0.1)
        XCTAssertEqual(send(.notifyEnabled(read, error: nil), after: 0.05), [.schedule(.keep(serial: 1), 5)])
        XCTAssertEqual(send(.timer(.setup(1)), after: 1), [], "the cancelled command's setup timer is stale")
        // In the background the same link closes at once.
        engine = AugustBLEEngine(offlineKey: offlineKey, slot: 4, nonce: { self.nonce }, inBackground: true)
        _ = send(command(1, AugustBLE.unlockOpcode))
        _ = send(.connected, after: 0.6)
        _ = send(.cancel(1), after: 0.1)
        _ = send(.characteristicsReady(true), after: 0.1)
        _ = send(.notifyEnabled(secureRead, error: nil), after: 0.1)
        _ = send(.frame(secureRead, reply1), after: 0.1)
        _ = send(.frame(secureRead, reply2), after: 0.1)
        let out = send(.notifyEnabled(read, error: nil), after: 0.05)
        XCTAssertEqual(out, [.write(secureWrite, engineShutdown()), .schedule(.close(epoch: 1), 0.3)])
    }

    func testTheSetupTimerIsStaleOnceTheSessionOpened() {
        openLink()
        // Session open, plain notify still pending: the operation deadline owns it now.
        XCTAssertEqual(send(.timer(.setup(1)), after: 0.1), [])
        XCTAssertEqual(send(.notifyEnabled(read, error: nil), after: 0.3), [.write(write, unlock1)])
    }

    func testACancelDuringSetupWithNoReplacementClosesAfterAGrace() {
        _ = send(command(1, AugustBLE.unlockOpcode))
        XCTAssertEqual(send(.cancel(1), after: 0.8), [.complete(1, .cancelled), .schedule(.grace(epoch: 1), 1)])
        // Nothing came: the pending connect is dropped.
        XCTAssertEqual(send(.timer(.grace(epoch: 1)), after: 1), [.disconnect])
        XCTAssertEqual(send(.connected, after: 0.5), [], "a late connect of the dropped link does nothing")
    }

    func testTheOppositeCommandWithinTheGraceKeepsThePendingConnect() {
        _ = send(command(1, AugustBLE.unlockOpcode))
        _ = send(.cancel(1), after: 0.8)
        XCTAssertEqual(send(command(2, AugustBLE.lockOpcode), after: 0.1).first, .schedule(.setup(2), 3), "the link keeps coming up for it")
        XCTAssertEqual(send(.timer(.grace(epoch: 1)), after: 0.9), [], "the grace timer is stale once a command waits")
        XCTAssertEqual(send(.connected, after: 1), [.discover])
    }

    func testAQueuedCommandStartsItsBudgetsWhenItBecomesHead() {
        _ = send(command(1, AugustBLE.unlockOpcode))
        XCTAssertEqual(send(command(2, AugustBLE.lockOpcode), after: 0.5), [])
        XCTAssertEqual(send(.cancel(1), after: 0.5), [.complete(1, .cancelled), .schedule(.setup(2), 3)])
        XCTAssertEqual(send(.timer(.setup(1)), after: 2), [], "the cancelled command's setup timer is stale")
    }

    func testLinkLossFailsTheRunningCommandAndRebuildsForTheQueue() {
        openLink()
        writeFirstCommand()
        _ = send(command(2, AugustBLE.lockOpcode), after: 0.1)
        let out = send(.disconnected("gone"), after: 0.1)
        XCTAssertEqual(out.first, .complete(1, .link("disconnected while operating: gone")))
        XCTAssertEqual(out.dropFirst().first, .startLink)
        XCTAssertTrue(out.contains(.schedule(.setup(2), 3)))
    }

    func testBluetoothOffFailsEverything() {
        _ = send(command(1, AugustBLE.unlockOpcode))
        _ = send(command(2, AugustBLE.lockOpcode))
        let out = send(.centralState(poweredOn: false), after: 0.1)
        XCTAssertEqual(out, [.complete(1, .bluetoothUnavailable), .complete(2, .bluetoothUnavailable), .disconnect])
    }

    func testAMotorFaultIsReportedAndTheLinkStays() {
        openLink()
        writeFirstCommand()
        // The lock's chain, encrypted here for a result the vectors do not hold.
        let lockSide = AugustFrameCipher(key: bytes("10111213141516172021222324252627"), mode: .cbcZeroIV, encrypt: true)
        var ack = [UInt8](repeating: 0, count: 18)
        ack[0] = 0xAA; ack[1] = AugustBLE.unlockOpcode; ack[0x10] = 0x02
        ack[3] = AugustBLE.simpleChecksum(ack)
        XCTAssertEqual(lockSide.apply(ack), ack1, "the home-made chain agrees with yalexs's")
        var jam = [UInt8](repeating: 0, count: 18)
        jam[0] = 0xBB; jam[1] = AugustBLE.unlockOpcode; jam[AugustBLE.resultByte] = 0x1E
        jam[3] = AugustBLE.simpleChecksum(jam)
        _ = send(.frame(read, ack1), after: 0.05)
        let out = send(.frame(read, lockSide.apply(jam)), after: 0.05)
        XCTAssertEqual(out, [.complete(1, .operationFailed(0x1E)), .schedule(.keep(serial: 1), 5)])
    }

    func testAStaleOperationTimerDoesNothing() {
        openLink()
        writeFirstCommand()
        _ = send(.frame(read, ack1), after: 0.05)
        _ = send(.frame(read, op1), after: 0.05)
        _ = send(command(2, AugustBLE.lockOpcode), after: 1.5)
        XCTAssertEqual(send(.timer(.operation(1)), after: 1), [], "the first command's deadline must not end the second")
    }

    // MARK: - Helpers

    private func engineShutdown() -> [UInt8] {
        let handshake = AugustBLEHandshake(offlineKey: offlineKey, slot: 4, nonce: nonce)
        _ = try! handshake.initializationCommand(reply: reply1)
        _ = try! handshake.plainChannel(reply: reply2)
        return handshake.shutdownCommand()
    }
}
