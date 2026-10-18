import CoreBluetooth
import Foundation

nonisolated enum AugustBLEError: LocalizedError {
    case bluetoothUnavailable(CBManagerState)
    case setupTimedOut(stage: String)
    case operationTimedOut(acknowledged: Bool)
    case link(String)

    var errorDescription: String? {
        switch self {
        case .bluetoothUnavailable(let state): return "Bluetooth unavailable (state \(state.rawValue))"
        case .setupTimedOut(let stage): return "Bluetooth setup timed out while \(stage)"
        case .operationTimedOut(let acknowledged):
            return "No result from the lock\(acknowledged ? " after its acknowledgment" : ", not even an acknowledgment")"
        case .link(let detail): return "Bluetooth link: \(detail)"
        }
    }
}

/// Milliseconds from the start of a Bluetooth operation to each stage.
nonisolated struct AugustBLETiming: CustomStringConvertible {
    var found: Int?
    var connected: Int?
    var session: Int?
    var written: Int?
    var done: Int?

    var description: String {
        let marks = [("found", found), ("connected", connected), ("session", session), ("written", written), ("done", done)]
        return marks.map { "\($0.0) \($0.1.map(String.init) ?? "-")" }.joined(separator: ", ")
    }
}

/// One lock or unlock over Bluetooth, start to finish, then disconnect:
/// scan for the lock by its advertised name, connect, discover the four
/// characteristics, run the key exchange (`AugustBLEHandshake`), send the
/// command and wait for its op-response. Follows yalexs-ble `lock.py`
/// (`connect`, `_setup_session`, `_execute_operation`). Each operation owns its
/// own `CBCentralManager`, so nothing carries over between opens except the
/// peripheral identifier, which lets the next open connect without a scan.
nonisolated final class AugustBLEOperation: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate, @unchecked Sendable {
    private enum Stage: String {
        case poweringOn = "waiting for Bluetooth"
        case searching = "searching for the lock"
        case connecting = "connecting"
        case discovering = "discovering characteristics"
        case keyExchange = "exchanging keys"
        case initializing = "initializing the session"
        case opening = "opening the command channel"
        case operating = "operating"
    }

    /// All state below is touched only on this queue.
    private static let queue = DispatchQueue(label: "AugustUnlock.ble")
    /// yalexs-ble waits this long after the last frame before the next
    /// command: a lock sent commands too fast can crash and need a battery pull.
    private static let cooldown = 0.25

    private let opcode: UInt8
    private let localName: String
    private let handshake: AugustBLEHandshake
    private let setupBudget: TimeInterval
    private let operationBudget: TimeInterval
    private let started = DispatchTime.now()

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var characteristics: [CBUUID: CBCharacteristic] = [:]
    private var channel: AugustBLEPlainChannel?
    private var stage = Stage.poweringOn
    private var acknowledged = false
    private var cancelled = false
    private var lastFrame = DispatchTime(uptimeNanoseconds: 0)
    private var timing = AugustBLETiming()
    private var completion: ((Result<AugustBLETiming, Error>) -> Void)?
    /// Keeps the operation alive while CoreBluetooth calls back into it.
    private var retainSelf: AugustBLEOperation?

    /// `setupBudget` covers scan through key exchange — past it, the caller
    /// falls back to the cloud. `operationBudget` runs from the command write
    /// to the op-response (yalexs allows 8 s for the ack, 12 s in all).
    static func run(
        opcode: UInt8, credentials: AugustBLECredentials,
        setupBudget: TimeInterval = 3, operationBudget: TimeInterval = 8
    ) async throws -> AugustBLETiming {
        var nonce = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) == errSecSuccess else {
            throw AugustBLEError.link("no random bytes for the key exchange")
        }
        let operation = AugustBLEOperation(
            opcode: opcode, credentials: credentials, nonce: nonce,
            setupBudget: setupBudget, operationBudget: operationBudget)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                operation.start { continuation.resume(with: $0) }
            }
        } onCancel: {
            operation.cancel()
        }
    }

    private init(
        opcode: UInt8, credentials: AugustBLECredentials, nonce: [UInt8],
        setupBudget: TimeInterval, operationBudget: TimeInterval
    ) {
        self.opcode = opcode
        localName = AugustBLE.localName(serial: credentials.serial)
        handshake = AugustBLEHandshake(offlineKey: credentials.key, slot: credentials.slot, nonce: nonce)
        self.setupBudget = setupBudget
        self.operationBudget = operationBudget
    }

    private func start(_ completion: @escaping (Result<AugustBLETiming, Error>) -> Void) {
        Self.queue.async { [self] in
            self.completion = completion
            retainSelf = self
            if cancelled { return finish(.failure(CancellationError())) }
            central = CBCentralManager(
                delegate: self, queue: Self.queue, options: [CBCentralManagerOptionShowPowerAlertKey: false])
            Self.queue.asyncAfter(deadline: started + setupBudget) { [weak self] in
                guard let self, channel == nil else { return }
                finish(.failure(AugustBLEError.setupTimedOut(stage: stage.rawValue)))
            }
        }
    }

    private func cancel() {
        Self.queue.async { [self] in
            cancelled = true
            finish(.failure(CancellationError()))
        }
    }

    // MARK: - Finding and connecting

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            guard stage == .poweringOn else { return }
            stage = .searching
            if let known = Self.knownPeripheralID(localName),
                let peripheral = central.retrievePeripherals(withIdentifiers: [known]).first
            {
                connect(peripheral)
            }
            central.scanForPeripherals(withServices: nil)
        case .unknown, .resetting:
            break
        default:
            finish(.failure(AugustBLEError.bluetoothUnavailable(central.state)))
        }
    }

    func centralManager(
        _ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any], rssi RSSI: NSNumber
    ) {
        let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name
        guard name == localName, peripheral.identifier != self.peripheral?.identifier else { return }
        if let stale = self.peripheral { central.cancelPeripheralConnection(stale) }
        timing.found = elapsedMS()
        connect(peripheral)
    }

    /// A scan can replace a remembered peripheral that never answered; the
    /// replaced one's late callbacks must not end the operation.
    private func isCurrent(_ peripheral: CBPeripheral) -> Bool {
        peripheral.identifier == self.peripheral?.identifier
    }

    private func connect(_ peripheral: CBPeripheral) {
        self.peripheral = peripheral
        peripheral.delegate = self
        stage = .connecting
        central?.connect(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard isCurrent(peripheral) else { return }
        timing.connected = elapsedMS()
        central.stopScan()
        Self.remember(peripheral.identifier, for: localName)
        stage = .discovering
        peripheral.discoverServices([CBUUID(string: AugustBLE.serviceUUID)])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        guard isCurrent(peripheral) else { return }
        finish(.failure(AugustBLEError.link("connect failed: \(error?.localizedDescription ?? "no reason")")))
    }

    func centralManager(
        _ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?
    ) {
        guard isCurrent(peripheral) else { return }
        finish(.failure(AugustBLEError.link("disconnected while \(stage.rawValue)")))
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil,
            let service = peripheral.services?.first(where: { $0.uuid == CBUUID(string: AugustBLE.serviceUUID) })
        else { return finish(.failure(AugustBLEError.link("no lock service"))) }
        let uuids = [AugustBLE.writeUUID, AugustBLE.readUUID, AugustBLE.secureWriteUUID, AugustBLE.secureReadUUID]
        peripheral.discoverCharacteristics(uuids.map { CBUUID(string: $0) }, for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        for characteristic in service.characteristics ?? [] {
            characteristics[characteristic.uuid] = characteristic
        }
        guard error == nil, characteristics.count == 4, let secureRead = characteristic(AugustBLE.secureReadUUID)
        else { return finish(.failure(AugustBLEError.link("missing characteristics"))) }
        // yalexs: notify on the secure channel must start before the plain one.
        peripheral.setNotifyValue(true, for: secureRead)
    }

    // MARK: - Key exchange and command

    func peripheral(
        _ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?
    ) {
        if let error { return finish(.failure(AugustBLEError.link("notify: \(error.localizedDescription)"))) }
        switch characteristic.uuid {
        case CBUUID(string: AugustBLE.secureReadUUID):
            stage = .keyExchange
            write(handshake.keyExchangeCommand(), to: AugustBLE.secureWriteUUID)
        case CBUUID(string: AugustBLE.readUUID):
            sendCommandAfterCooldown()
        default:
            break
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error { finish(.failure(AugustBLEError.link("write: \(error.localizedDescription)"))) }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let value = characteristic.value, !value.isEmpty else { return }
        lastFrame = .now()
        let frame = [UInt8](value)
        do {
            switch characteristic.uuid {
            case CBUUID(string: AugustBLE.secureReadUUID): try handleSecure(frame)
            case CBUUID(string: AugustBLE.readUUID): try handlePlain(frame)
            default: break
            }
        } catch AugustBLEProtocolError.badFrame {
            // yalexs drops a bad frame and keeps waiting; the deadline is the backstop.
        } catch {
            finish(.failure(error))
        }
    }

    private func handleSecure(_ frame: [UInt8]) throws {
        switch stage {
        case .keyExchange:
            let command = try handshake.initializationCommand(reply: frame)
            stage = .initializing
            write(command, to: AugustBLE.secureWriteUUID)
        case .initializing:
            channel = try handshake.plainChannel(reply: frame)
            timing.session = elapsedMS()
            stage = .opening
            if let read = characteristic(AugustBLE.readUUID) { peripheral?.setNotifyValue(true, for: read) }
        default:
            break  // e.g. the reply to the shutdown command
        }
    }

    /// Every plain frame goes through the decryptor, even one that arrives
    /// before the command: the lock's CBC chain advances per frame it sends.
    private func handlePlain(_ frame: [UInt8]) throws {
        guard let channel else { return }
        switch try channel.receive(frame, for: opcode) {
        case .ack:
            acknowledged = true
        case .result(0):
            timing.done = elapsedMS()
            finish(.success(timing))
        case .result(let code):
            throw AugustBLEProtocolError.operationFailed(code)
        case .other:
            break
        }
    }

    private func sendCommandAfterCooldown() {
        let ready = lastFrame + Self.cooldown
        guard DispatchTime.now() >= ready else {
            Self.queue.asyncAfter(deadline: ready) { [weak self] in self?.sendCommandAfterCooldown() }
            return
        }
        guard completion != nil, stage == .opening, let channel else { return }
        stage = .operating
        write(channel.command(opcode: opcode), to: AugustBLE.writeUUID)
        timing.written = elapsedMS()
        Self.queue.asyncAfter(deadline: .now() + operationBudget) { [weak self] in
            guard let self else { return }
            finish(.failure(AugustBLEError.operationTimedOut(acknowledged: acknowledged)))
        }
    }

    private func write(_ frame: [UInt8], to uuid: String) {
        guard let characteristic = characteristic(uuid) else { return }
        peripheral?.writeValue(Data(frame), for: characteristic, type: .withResponse)
    }

    private func characteristic(_ uuid: String) -> CBCharacteristic? {
        characteristics[CBUUID(string: uuid)]
    }

    // MARK: - Finishing

    /// Reports once, then tears down. After a key exchange the lock gets the
    /// secure DISCONNECT first, as yalexs `_shutdown_connection` sends it.
    private func finish(_ result: Result<AugustBLETiming, Error>) {
        guard let completion else { return }
        self.completion = nil
        completion(result)
        central?.stopScan()
        if channel != nil, peripheral?.state == .connected {
            write(handshake.shutdownCommand(), to: AugustBLE.secureWriteUUID)
        }
        Self.queue.asyncAfter(deadline: .now() + 0.3) { [self] in
            if let peripheral { central?.cancelPeripheralConnection(peripheral) }
            central?.delegate = nil
            retainSelf = nil
        }
    }

    private func elapsedMS() -> Int {
        Int((DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1_000_000)
    }

    private static func knownPeripheralID(_ localName: String) -> UUID? {
        UserDefaults.standard.string(forKey: "ble_peripheral_\(localName)").flatMap(UUID.init(uuidString:))
    }

    private static func remember(_ id: UUID, for localName: String) {
        UserDefaults.standard.set(id.uuidString, forKey: "ble_peripheral_\(localName)")
    }
}
