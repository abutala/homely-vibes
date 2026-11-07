import CoreBluetooth
import Foundation
import UIKit
import os

nonisolated enum AugustBLEError: LocalizedError {
    case bluetoothUnavailable
    case setupTimedOut(stage: String)
    case operationTimedOut(acknowledged: Bool)
    case link(String)

    var errorDescription: String? {
        switch self {
        case .bluetoothUnavailable: return "Bluetooth unavailable"
        case .setupTimedOut(let stage): return "Bluetooth setup timed out while \(stage)"
        case .operationTimedOut(let acknowledged):
            return "No result from the lock\(acknowledged ? " after its acknowledgment" : ", not even an acknowledgment")"
        case .link(let detail): return "Bluetooth link: \(detail)"
        }
    }
}

/// The CoreBluetooth side of one lock's link: one per lock serial, kept for
/// the process. It owns the central, the peripheral and the characteristics,
/// turns every callback into an `AugustBLEEngine` input with the time, runs
/// the engine's outputs, and arms the timers it asks for. Every rule lives
/// in the engine; this file only talks to the radio. All state is touched on
/// `queue`.
nonisolated final class AugustBLELink: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate, @unchecked Sendable {
    private static let queue = DispatchQueue(label: "AugustUnlock.ble")
    nonisolated(unsafe) private static var links: [String: AugustBLELink] = [:]
    /// The screen clears this when it is active; a process launched for a
    /// widget tap never does, so its links never keep.
    nonisolated(unsafe) private static var inBackground = true

    /// One command. `setupBudget` covers the connect and the key exchange —
    /// past it, the caller falls back to the cloud; `operationBudget` runs
    /// from the session (or from the command's turn on an open link) to the
    /// op-response. `keepLink` false ends the link after this command (the
    /// widget's taps: a kept link would block the official app).
    static func run(
        opcode: UInt8, credentials: AugustBLECredentials,
        setupBudget: TimeInterval = 3, operationBudget: TimeInterval = 12, keepLink: Bool = true
    ) async throws -> AugustBLETiming {
        let link = await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: self.link(for: credentials)) }
        }
        let token = link.nextToken()
        // A cancel can be queued before the command is (the task was
        // cancelled before this point); the command's block then applies it
        // in order, so it is never lost (TRIAL 2026-11-07).
        let cancelled = OSAllocatedUnfairLock(initialState: false)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    link.continuations[token] = continuation
                    link.apply(link.engine.handle(
                        .command(token, opcode: opcode, keepLink: keepLink, setupBudget: setupBudget, operationBudget: operationBudget),
                        at: link.now))
                    if cancelled.withLock({ $0 }) { link.apply(link.engine.handle(.cancel(token), at: link.now)) }
                }
            }
        } onCancel: {
            cancelled.withLock { $0 = true }
            queue.async { link.apply(link.engine.handle(.cancel(token), at: link.now)) }
        }
    }

    /// The screen went to the background: every link closes (after a running
    /// command), inside a background task so the DISCONNECT and the
    /// teardown get their 0.3 s.
    static func applicationDidEnterBackground() {
        let task = BackgroundTask(name: "AugustBLEClose")
        queue.async {
            inBackground = true
            for link in links.values { link.apply(link.engine.handle(.background, at: link.now)) }
            queue.asyncAfter(deadline: .now() + 1.5) { task.end() }
        }
    }

    static func applicationDidBecomeActive() {
        queue.async {
            inBackground = false
            for link in links.values { link.apply(link.engine.handle(.foreground, at: link.now)) }
        }
    }

    private static func link(for credentials: AugustBLECredentials) -> AugustBLELink {
        if let link = links[credentials.serial] {
            if link.offlineKey == credentials.key, link.slot == credentials.slot { return link }
            // A new key for this lock: the old link's commands fail and its
            // radio link closes before it goes, so nothing waits on it forever.
            link.retire()
        }
        let link = AugustBLELink(credentials: credentials)
        links[credentials.serial] = link
        return link
    }

    /// Ends this link for good: every pending command fails, the radio
    /// link closes. On `queue`.
    private func retire() {
        apply(engine.handle(.centralState(poweredOn: false), at: now))
        central?.delegate = nil
    }

    private let offlineKey: [UInt8]
    private let slot: UInt8
    private let localName: String
    private let engine: AugustBLEEngine
    private let origin = ContinuousClock.now
    private var tokens = 0
    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var characteristics: [CBUUID: CBCharacteristic] = [:]
    private var continuations: [AugustBLEEngine.Token: CheckedContinuation<AugustBLETiming, Error>] = [:]
    private var wantsLink = false
    /// True from the engine's `startLink` to `connected` or `.disconnect`:
    /// a lock seen by the scan outside that window is left alone.
    private var connecting = false
    private var found: Int?
    private var linkStartedAt: Double?

    private init(credentials: AugustBLECredentials) {
        offlineKey = credentials.key
        slot = credentials.slot
        localName = AugustBLE.localName(serial: credentials.serial)
        engine = AugustBLEEngine(offlineKey: credentials.key, slot: credentials.slot, nonce: Self.randomNonce, inBackground: Self.inBackground)
        super.init()
    }

    /// Seconds since this link was made, on the continuous clock (counts
    /// through sleep, so an idle check after a nap is honest).
    private var now: Double {
        let elapsed = origin.duration(to: .now)
        return Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
    }

    private func nextToken() -> AugustBLEEngine.Token {
        Self.queue.sync {
            tokens += 1
            return tokens
        }
    }

    private static func randomNonce() -> [UInt8] {
        var nonce = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce)
        return nonce
    }

    // MARK: - Running the engine's outputs

    private func apply(_ outputs: [AugustBLEEngine.Output]) {
        for output in outputs {
            switch output {
            case .startLink:
                linkStartedAt = now
                found = nil
                if central == nil {
                    central = CBCentralManager(delegate: self, queue: Self.queue, options: [CBCentralManagerOptionShowPowerAlertKey: false])
                }
                // The last link may still be going down: the radio reports
                // that disconnect first, then the new connect starts.
                if central?.state == .poweredOn, peripheral == nil { findAndConnect() } else { wantsLink = true }
            case .discover:
                peripheral?.discoverServices([CBUUID(string: AugustBLE.serviceUUID)])
            case .setNotify(let uuid):
                guard let characteristic = characteristics[CBUUID(string: uuid)] else {
                    return apply(engine.handle(.notifyEnabled(uuid, error: "no such characteristic"), at: now))
                }
                peripheral?.setNotifyValue(true, for: characteristic)
            case .write(let uuid, let bytes):
                guard let characteristic = characteristics[CBUUID(string: uuid)], let peripheral else {
                    return apply(engine.handle(.writeFailed("no link"), at: now))
                }
                peripheral.writeValue(Data(bytes), for: characteristic, type: .withResponse)
            case .disconnect:
                note("disconnect (peripheral state \(peripheral?.state.rawValue ?? -1))")
                wantsLink = false
                connecting = false
                central?.stopScan()
                characteristics = [:]
                // The peripheral stays current until the radio reports the
                // disconnect, so that report reaches the engine.
                if let peripheral { central?.cancelPeripheralConnection(peripheral) }
            case .schedule(let timer, let seconds):
                Self.queue.asyncAfter(deadline: .now() + seconds) { [weak self] in
                    guard let self else { return }
                    apply(engine.handle(.timer(timer), at: now))
                }
            case .complete(let token, let outcome):
                guard let continuation = continuations.removeValue(forKey: token) else { continue }
                switch outcome {
                case .ok(var timing):
                    timing.found = found
                    continuation.resume(returning: timing)
                case .cancelled: continuation.resume(throwing: CancellationError())
                case .setupTimedOut(let stage):
                    note("setup timed out while \(stage); scan saw the lock: \(found == nil ? "no" : "yes")")
                    continuation.resume(throwing: AugustBLEError.setupTimedOut(stage: stage))
                case .operationTimedOut(let acknowledged): continuation.resume(throwing: AugustBLEError.operationTimedOut(acknowledged: acknowledged))
                case .operationFailed(let code): continuation.resume(throwing: AugustBLEProtocolError.operationFailed(code))
                case .link(let detail): continuation.resume(throwing: AugustBLEError.link(detail))
                case .bluetoothUnavailable: continuation.resume(throwing: AugustBLEError.bluetoothUnavailable)
                }
            }
        }
    }

    // MARK: - Finding and connecting

    private func findAndConnect() {
        guard let central else { return }
        wantsLink = false
        connecting = true
        if let known = Self.knownPeripheralID(localName),
            let peripheral = central.retrievePeripherals(withIdentifiers: [known]).first
        {
            note("retrieved, state \(peripheral.state.rawValue); connecting")
            connect(peripheral)
        } else {
            note("no remembered peripheral; scanning")
        }
        central.scanForPeripherals(withServices: nil)
    }

    private func connect(_ peripheral: CBPeripheral) {
        self.peripheral = peripheral
        peripheral.delegate = self
        central?.connect(peripheral)
    }

    /// The connect path, stage by stage, in `app.log`: the engine's timeout
    /// names only the stage it ended in.
    private func note(_ message: String) {
        let since = linkStartedAt.map { Int(((now - $0) * 1000).rounded()) } ?? 0
        AppLog.note("BLE link \(localName): \(message) at \(since) ms")
    }

    /// A scan can replace a remembered peripheral that never answered; the
    /// replaced one's late callbacks must not reach the engine.
    private func isCurrent(_ peripheral: CBPeripheral) -> Bool {
        peripheral.identifier == self.peripheral?.identifier
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            note("powered on")
            if wantsLink { findAndConnect() }
        case .unknown, .resetting:
            break
        default:
            note("bluetooth state \(central.state.rawValue)")
            // Bluetooth off: nothing may connect when it comes back unless a
            // new command asks (the engine has dropped the link by then).
            wantsLink = false
            peripheral = nil
            characteristics = [:]
            apply(engine.handle(.centralState(poweredOn: false), at: now))
        }
    }

    func centralManager(
        _ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any], rssi RSSI: NSNumber
    ) {
        let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name
        guard connecting, name == localName, peripheral.identifier != self.peripheral?.identifier else { return }
        if let stale = self.peripheral { central.cancelPeripheralConnection(stale) }
        found = linkStartedAt.map { Int(((now - $0) * 1000).rounded()) }
        note("found by scan, rssi \(RSSI); connecting")
        connect(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard isCurrent(peripheral) else { return }
        connecting = false
        central.stopScan()
        Self.remember(peripheral.identifier, for: localName)
        note("connected")
        apply(engine.handle(.connected, at: now))
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        guard isCurrent(peripheral) else { return }
        note("connect failed: \(error?.localizedDescription ?? "no reason")")
        self.peripheral = nil
        apply(engine.handle(.connectFailed(error?.localizedDescription ?? "no reason"), at: now))
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        note("disconnected\(isCurrent(peripheral) ? "" : " (an earlier link)"): \(error?.localizedDescription ?? "by us")")
        guard isCurrent(peripheral) else { return }
        self.peripheral = nil
        characteristics = [:]
        if wantsLink {
            // The link the engine already dropped is gone; the new command's
            // connect was waiting for exactly this.
            if central.state == .poweredOn { findAndConnect() }
            return
        }
        apply(engine.handle(.disconnected(error?.localizedDescription), at: now))
    }

    // MARK: - Services, characteristics, frames

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil,
            let service = peripheral.services?.first(where: { $0.uuid == CBUUID(string: AugustBLE.serviceUUID) })
        else { return apply(engine.handle(.characteristicsReady(false), at: now)) }
        let uuids = [AugustBLE.writeUUID, AugustBLE.readUUID, AugustBLE.secureWriteUUID, AugustBLE.secureReadUUID]
        peripheral.discoverCharacteristics(uuids.map { CBUUID(string: $0) }, for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        for characteristic in service.characteristics ?? [] {
            characteristics[characteristic.uuid] = characteristic
        }
        apply(engine.handle(.characteristicsReady(error == nil && characteristics.count == 4), at: now))
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        apply(engine.handle(.notifyEnabled(Self.name(of: characteristic.uuid), error: error?.localizedDescription), at: now))
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error { apply(engine.handle(.writeFailed(error.localizedDescription), at: now)) }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let value = characteristic.value, !value.isEmpty else { return }
        apply(engine.handle(.frame(Self.name(of: characteristic.uuid), [UInt8](value)), at: now))
    }

    /// The engine names characteristics by the protocol's UUID strings.
    private static func name(of uuid: CBUUID) -> String {
        [AugustBLE.writeUUID, AugustBLE.readUUID, AugustBLE.secureWriteUUID, AugustBLE.secureReadUUID]
            .first { CBUUID(string: $0) == uuid } ?? uuid.uuidString
    }

    private static func knownPeripheralID(_ localName: String) -> UUID? {
        UserDefaults.standard.string(forKey: "ble_peripheral_\(localName)").flatMap(UUID.init(uuidString:))
    }

    private static func remember(_ id: UUID, for localName: String) {
        UserDefaults.standard.set(id.uuidString, forKey: "ble_peripheral_\(localName)")
    }
}

/// A UIKit background task with an idempotent end: iOS otherwise suspends a
/// backgrounded app within seconds, and both the work finishing and iOS
/// expiring the time call `end()`.
final class BackgroundTask: Sendable {
    private let id: UIBackgroundTaskIdentifier
    private let ended = OSAllocatedUnfairLock(initialState: false)

    init(name: String, onExpire: (@Sendable () -> Void)? = nil) {
        var identifier = UIBackgroundTaskIdentifier.invalid
        let ended = ended
        identifier = UIApplication.shared.beginBackgroundTask(withName: name) {
            onExpire?()
            if !ended.withLock({ let was = $0; $0 = true; return was }) { UIApplication.shared.endBackgroundTask(identifier) }
        }
        id = identifier
    }

    func end() {
        guard id != .invalid, !ended.withLock({ let was = $0; $0 = true; return was }) else { return }
        let id = id
        DispatchQueue.main.async { UIApplication.shared.endBackgroundTask(id) }
    }
}
