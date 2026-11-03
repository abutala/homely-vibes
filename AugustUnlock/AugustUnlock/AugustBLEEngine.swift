import Foundation

/// The Bluetooth path to one lock as a pure state machine: no CoreBluetooth,
/// no clock, no timers of its own. The adapter (`AugustBLELink`) feeds it
/// every event with the time, runs the outputs, and arms the timers it asks
/// for. `swift test` drives it through the real handshake and commands with
/// the wires yalexs-ble's own classes produce (`scripts/gen_ble_vectors.py`).
///
/// A link, once open, stays open `keepSeconds` after a command, so the next
/// command (the screen's "tap while unlocking, to lock instead") skips the
/// connect and the key exchange. A cancelled command that was already written
/// runs to its result on the link, unreported; the next command follows it.
/// The link is dropped on a timeout, a failed write, link loss, Bluetooth
/// off, the app going to the background, or a command that asked not to
/// keep it (the widget's, whose process is in the background anyway).
nonisolated final class AugustBLEEngine {
    typealias Token = Int

    enum Timer: Equatable {
        case setup(Token)
        case operation(Token)
        case cooldown(Token)
        /// A keep timer is the latest one only: each completion arms a new
        /// one, and an earlier one firing must not close the link early.
        case keep(serial: Int)
        case close(epoch: Int)
    }

    enum Input {
        case command(Token, opcode: UInt8, keepLink: Bool, setupBudget: Double, operationBudget: Double)
        case cancel(Token)
        case centralState(poweredOn: Bool)
        case connected
        case connectFailed(String)
        case disconnected(String?)
        case characteristicsReady(Bool)
        case notifyEnabled(String, error: String?)
        case writeFailed(String)
        case frame(String, [UInt8])
        case timer(Timer)
        case background
        case foreground
    }

    enum Outcome: Equatable {
        case ok(AugustBLETiming)
        case cancelled
        case setupTimedOut(stage: String)
        case operationTimedOut(acknowledged: Bool)
        case operationFailed(UInt8)
        case link(String)
        case bluetoothUnavailable
    }

    enum Output: Equatable {
        /// Make or reuse the central, find the lock, connect; report `connected`.
        case startLink
        /// Discover the service and its characteristics; report `characteristicsReady`.
        case discover
        case setNotify(String)
        case write(String, [UInt8])
        case disconnect
        case schedule(Timer, Double)
        case complete(Token, Outcome)
    }

    private enum LinkState: Equatable {
        case none
        case connecting
        case discovering
        case keyExchange
        case initializing
        case opening
        case ready
        case closing
    }

    private struct Command {
        let token: Token
        let opcode: UInt8
        let keepLink: Bool
        let setupBudget: Double
        let operationBudget: Double
        var startedAt: Double?
        var written = false
        var acknowledged = false
        var cancelled = false
        /// The operation deadline is armed once: at session open for the
        /// command that built the link, else when the command begins.
        var deadlineArmed = false
        var timing = AugustBLETiming()
    }

    static let keepSeconds = 5.0
    /// yalexs-ble's wait after the last frame before a write: a lock sent
    /// commands too fast can crash and need a battery pull.
    static let cooldownSeconds = 0.25
    /// After an op-response, before the next command's write: the warm path
    /// is new ground that yalexs never treads, so it waits longer (TRIAL
    /// 2026-11-03, N1) until ten fast pairs at the door say otherwise.
    static let gapAfterResultSeconds = 1.0

    private let offlineKey: [UInt8]
    private let slot: UInt8
    private let nonce: () -> [UInt8]
    private var inBackground: Bool

    private var link = LinkState.none
    private var epoch = 0
    private var keepSerial = 0
    private var handshake: AugustBLEHandshake?
    private var channel: AugustBLEPlainChannel?
    private var linkStartedAt: Double?
    /// The command the link was built for: the only one whose timing
    /// carries the connect and the session.
    private var linkBuiltFor: Token?
    private var connectedAt: Double?
    private var sessionAt: Double?
    private var lastFrameAt: Double?
    private var lastResultAt: Double?
    /// The head is the active command; the rest wait.
    private var queue: [Command] = []

    init(offlineKey: [UInt8], slot: UInt8, nonce: @escaping () -> [UInt8], inBackground: Bool = false) {
        self.offlineKey = offlineKey
        self.slot = slot
        self.nonce = nonce
        self.inBackground = inBackground
    }

    var isIdle: Bool { link == .none && queue.isEmpty }

    func handle(_ input: Input, at now: Double) -> [Output] {
        switch input {
        case .command(let token, let opcode, let keepLink, let setupBudget, let operationBudget):
            queue.append(Command(token: token, opcode: opcode, keepLink: keepLink, setupBudget: setupBudget, operationBudget: operationBudget))
            if queue.count == 1 { return startHead(at: now) }
            return []
        case .cancel(let token):
            return cancel(token, at: now)
        case .centralState(let poweredOn):
            guard !poweredOn else { return [] }
            var out = failAll(.bluetoothUnavailable)
            if link != .none { out.append(.disconnect) }
            dropLink()
            return out
        case .connected:
            guard link == .connecting else { return [] }
            connectedAt = now
            link = .discovering
            return [.discover]
        case .connectFailed(let reason):
            guard link == .connecting else { return [] }
            dropLink()
            // `.disconnect` stops the scan too: nothing may connect uncalled.
            return failAll(.link("connect failed: \(reason)")) + [.disconnect]
        case .disconnected(let reason):
            return disconnected(reason, at: now)
        case .characteristicsReady(let ok):
            guard link == .discovering else { return [] }
            guard ok else { return failLink("missing characteristics", at: now) }
            return [.setNotify(AugustBLE.secureReadUUID)]
        case .notifyEnabled(let uuid, let error):
            if let error { return failLink("notify: \(error)", at: now) }
            if uuid == AugustBLE.secureReadUUID, link == .discovering {
                link = .keyExchange
                let handshake = AugustBLEHandshake(offlineKey: offlineKey, slot: slot, nonce: nonce())
                self.handshake = handshake
                return [.write(AugustBLE.secureWriteUUID, handshake.keyExchangeCommand())]
            }
            if uuid == AugustBLE.readUUID, link == .opening {
                link = .ready
                // Every command may have been cancelled while the link was
                // built: a ready link with nothing to do keeps or closes.
                if queue.isEmpty { return keepOrClose() }
                return beginHead(at: now)
            }
            return []
        case .writeFailed(let reason):
            return failLink("write: \(reason)", at: now)
        case .frame(let uuid, let bytes):
            lastFrameAt = now
            if uuid == AugustBLE.secureReadUUID { return secureFrame(bytes, at: now) }
            if uuid == AugustBLE.readUUID { return plainFrame(bytes, at: now) }
            return []
        case .timer(let timer):
            return fired(timer, at: now)
        case .background:
            inBackground = true
            if link == .ready, queue.isEmpty { return close() }
            return []
        case .foreground:
            inBackground = false
            return []
        }
    }

    // MARK: - Commands

    /// The head command starts: its budgets run from now. A link is built if
    /// there is none; a ready link takes the command at once.
    private func startHead(at now: Double) -> [Output] {
        guard !queue.isEmpty else { return [] }
        queue[0].startedAt = now
        switch link {
        case .none:
            epoch += 1
            link = .connecting
            linkStartedAt = now
            linkBuiltFor = queue[0].token
            connectedAt = nil
            sessionAt = nil
            return [.startLink, .schedule(.setup(queue[0].token), queue[0].setupBudget)]
        case .ready:
            return beginHead(at: now)
        case .closing:
            return []  // the disconnect brings a new link for it
        default:
            return [.schedule(.setup(queue[0].token), queue[0].setupBudget)]
        }
    }

    /// The link is open: arm the operation deadline and send after the cooldown.
    private func beginHead(at now: Double) -> [Output] {
        guard link == .ready, let head = queue.first, !head.written else { return [] }
        if queue[0].startedAt == nil { queue[0].startedAt = now }
        let token = head.token
        if linkBuiltFor == token {
            queue[0].timing.connected = connectedAt.map { ms($0, since: queue[0].startedAt!) }
            queue[0].timing.session = sessionAt.map { ms($0, since: queue[0].startedAt!) }
        }
        var out: [Output] = []
        if !head.deadlineArmed {
            queue[0].deadlineArmed = true
            out.append(.schedule(.operation(token), head.operationBudget))
        }
        let ready = max(lastFrameAt.map { $0 + Self.cooldownSeconds } ?? 0, lastResultAt.map { $0 + Self.gapAfterResultSeconds } ?? 0)
        if ready > now + 0.0005 {
            out.append(.schedule(.cooldown(token), (ready - now).rounded(toPlaces: 3)))
        } else {
            out.append(contentsOf: writeHead(at: now))
        }
        return out
    }

    private func writeHead(at now: Double) -> [Output] {
        guard link == .ready, let channel, !queue.isEmpty, !queue[0].written else { return [] }
        queue[0].written = true
        queue[0].timing.written = ms(now, since: queue[0].startedAt ?? now)
        return [.write(AugustBLE.writeUUID, channel.command(opcode: queue[0].opcode))]
    }

    private func cancel(_ token: Token, at now: Double) -> [Output] {
        guard let index = queue.firstIndex(where: { $0.token == token }), !queue[index].cancelled else { return [] }
        if index > 0 {
            queue.remove(at: index)
            return [.complete(token, .cancelled)]
        }
        if queue[0].written {
            // Already with the lock: let it finish, unreported; the next
            // command follows on the same link.
            queue[0].cancelled = true
            return [.complete(token, .cancelled)]
        }
        queue.removeFirst()
        var out: [Output] = [.complete(token, .cancelled)]
        out.append(contentsOf: afterHead(at: now))
        return out
    }

    /// The head is gone: start the next, or keep or close the link.
    private func afterHead(at now: Double) -> [Output] {
        if !queue.isEmpty {
            if link == .ready { return beginHead(at: now) }
            return startHead(at: now)
        }
        guard link == .ready else { return [] }
        return keepOrClose()
    }

    private func keepOrClose() -> [Output] {
        if inBackground { return close() }
        keepSerial += 1
        return [.schedule(.keep(serial: keepSerial), Self.keepSeconds)]
    }

    private func complete(_ outcome: Outcome, at now: Double) -> [Output] {
        guard !queue.isEmpty else { return [] }
        let head = queue.removeFirst()
        var out: [Output] = head.cancelled ? [] : [.complete(head.token, outcome)]
        if !head.keepLink, queue.isEmpty {
            out.append(contentsOf: close())
            return out
        }
        out.append(contentsOf: afterHead(at: now))
        return out
    }

    // MARK: - Frames

    private func secureFrame(_ bytes: [UInt8], at now: Double) -> [Output] {
        guard let handshake else { return [] }
        do {
            switch link {
            case .keyExchange:
                let command = try handshake.initializationCommand(reply: bytes)
                link = .initializing
                return [.write(AugustBLE.secureWriteUUID, command)]
            case .initializing:
                channel = try handshake.plainChannel(reply: bytes)
                sessionAt = now
                link = .opening
                var out: [Output] = [.setNotify(AugustBLE.readUUID)]
                if let head = queue.first, !head.deadlineArmed {
                    queue[0].deadlineArmed = true
                    out.append(.schedule(.operation(head.token), head.operationBudget))
                }
                return out
            default:
                return []  // the reply to DISCONNECT
            }
        } catch {
            return failLink(error.localizedDescription, at: now)
        }
    }

    /// Every plain frame goes through the decryptor: the lock's chain moves
    /// per frame it sends, pushes included. A bad frame is dropped, as
    /// yalexs does; the operation deadline is the backstop.
    private func plainFrame(_ bytes: [UInt8], at now: Double) -> [Output] {
        guard let channel else { return [] }
        let opcode = queue.first?.opcode ?? 0
        guard let reply = try? channel.receive(bytes, for: opcode), !queue.isEmpty, queue[0].written else { return [] }
        switch reply {
        case .ack:
            queue[0].acknowledged = true
            return []
        case .result(let code):
            lastResultAt = now
            queue[0].timing.done = ms(now, since: queue[0].startedAt ?? now)
            return complete(code == 0 ? .ok(queue[0].timing) : .operationFailed(code), at: now)
        case .other:
            return []
        }
    }

    // MARK: - Timers

    private func fired(_ timer: Timer, at now: Double) -> [Output] {
        switch timer {
        case .setup(let token):
            // Stale once the session opened: from `.opening` on, the
            // operation deadline owns the command.
            guard let head = queue.first, head.token == token, link != .ready, link != .opening, link != .none else { return [] }
            let stage = stageName
            var out: [Output] = [.complete(token, .setupTimedOut(stage: stage))]
            queue.removeFirst()
            out.append(.disconnect)
            dropLink()
            // Anything queued behind it goes to the cloud too.
            out.append(contentsOf: failAll(.setupTimedOut(stage: stage)))
            return out
        case .operation(let token):
            guard let head = queue.first, head.token == token, link == .ready || link == .opening else { return [] }
            var out: [Output] = head.cancelled ? [] : [.complete(token, .operationTimedOut(acknowledged: head.acknowledged))]
            queue.removeFirst()
            out.append(contentsOf: failAll(.operationTimedOut(acknowledged: false)))
            out.append(contentsOf: close())
            return out
        case .cooldown(let token):
            guard let head = queue.first, head.token == token, !head.written else { return [] }
            return writeHead(at: now)
        case .keep(let serial):
            guard serial == keepSerial, link == .ready, queue.isEmpty else { return [] }
            return close()
        case .close(let epoch):
            guard epoch == self.epoch, link == .closing else { return [] }
            return [.disconnect]
        }
    }

    // MARK: - Closing and failing

    /// Sends DISCONNECT on an open channel, then disconnects 0.3 s later.
    private func close() -> [Output] {
        guard link != .none, link != .closing else { return [] }
        var out: [Output] = []
        if let handshake, channel != nil { out.append(.write(AugustBLE.secureWriteUUID, handshake.shutdownCommand())) }
        link = .closing
        out.append(.schedule(.close(epoch: epoch), 0.3))
        return out
    }

    private func disconnected(_ reason: String?, at now: Double) -> [Output] {
        // A link already dropped (a failure's disconnect, reported late by
        // the radio) has nothing left to tell; a new command may be waiting
        // on a fresh link that the adapter starts once the old one is gone.
        guard link != .none else { return [] }
        let wasClosing = link == .closing
        let stage = stageName
        dropLink()
        var out: [Output] = []
        if !wasClosing, !queue.isEmpty {
            let head = queue.removeFirst()
            if !head.cancelled { out.append(.complete(head.token, .link("disconnected while \(stage)\(reason.map { ": \($0)" } ?? "")"))) }
        }
        if !queue.isEmpty { out.append(contentsOf: startHead(at: now)) }
        return out
    }

    private func failLink(_ reason: String, at now: Double) -> [Output] {
        var out: [Output] = []
        if !queue.isEmpty {
            let head = queue.removeFirst()
            if !head.cancelled { out.append(.complete(head.token, .link(reason))) }
        }
        out.append(.disconnect)
        dropLink()
        out.append(contentsOf: failAll(.link(reason)))
        return out
    }

    private func failAll(_ outcome: Outcome) -> [Output] {
        let out = queue.filter { !$0.cancelled }.map { Output.complete($0.token, outcome) }
        queue.removeAll()
        return out
    }

    private func dropLink() {
        link = .none
        handshake = nil
        channel = nil
        lastFrameAt = nil
        lastResultAt = nil
        connectedAt = nil
        sessionAt = nil
    }

    private var stageName: String {
        switch link {
        case .none: return "idle"
        case .connecting: return "connecting"
        case .discovering: return "discovering characteristics"
        case .keyExchange: return "exchanging keys"
        case .initializing: return "initializing the session"
        case .opening: return "opening the command channel"
        case .ready: return "operating"
        case .closing: return "closing"
        }
    }

    private func ms(_ now: Double, since start: Double) -> Int {
        Int(((now - start) * 1000).rounded())
    }
}

extension Double {
    fileprivate func rounded(toPlaces places: Int) -> Double {
        let factor = pow(10.0, Double(places))
        return (self * factor).rounded() / factor
    }
}
