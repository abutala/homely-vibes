import CoreBluetooth
import Foundation
import os

/// One probe: find the Mac's echo peripheral (`scripts/rig_peripheral.swift`),
/// connect, discover, write 16 bytes, wait for the echo, and log the time
/// of each stage. The shape of the lock's key exchange, with nothing at the
/// door. The caller decides which process and state runs it (a widget tap
/// in the background, a tap that opened the app, the app's own button).
nonisolated final class RigProbe: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    static let serviceUUID = CBUUID(string: "7E57A6B0-0001-4B1E-9A6E-000000000001")
    static let writeUUID = CBUUID(string: "7E57A6B0-0002-4B1E-9A6E-000000000002")
    static let notifyUUID = CBUUID(string: "7E57A6B0-0003-4B1E-9A6E-000000000003")
    private static let knownKey = "rig.peripheral"
    private static let queue = DispatchQueue(label: "BLEWidgetRig.probe")

    /// Runs one probe; the summary line is also in `rig.log`.
    static func run(label: String, budget: TimeInterval = 15) async -> String {
        let probe = RigProbe(label: label, budget: budget)
        return await withCheckedContinuation { continuation in
            probe.start { continuation.resume(returning: $0) }
        }
    }

    static var knownPeripheral: String? { UserDefaults.standard.string(forKey: knownKey) }
    static func forget() { UserDefaults.standard.removeObject(forKey: knownKey) }

    private let label: String
    private let budget: TimeInterval
    private let started = DispatchTime.now()
    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var notify: CBCharacteristic?
    private var write: CBCharacteristic?
    private var stages: [String] = []
    private var completion: ((String) -> Void)?
    private var retainSelf: RigProbe?

    private init(label: String, budget: TimeInterval) {
        self.label = label
        self.budget = budget
    }

    private func start(_ completion: @escaping (String) -> Void) {
        Self.queue.async { [self] in
            self.completion = completion
            retainSelf = self
            RigLog.note("\(label): start (known peripheral: \(Self.knownPeripheral.map { String($0.suffix(6)) } ?? "none"), app state: \(RigProbe.appState))")
            central = CBCentralManager(delegate: self, queue: Self.queue, options: [CBCentralManagerOptionShowPowerAlertKey: false])
            Self.queue.asyncAfter(deadline: started + budget) { [weak self] in
                self?.finish("timed out after \(self?.stages.last ?? "start")")
            }
        }
    }

    private func stage(_ name: String) {
        stages.append("\(name) \(elapsedMS())")
    }

    private func elapsedMS() -> Int {
        Int((DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1_000_000)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard completion != nil else { return }
        stage("powered \(central.state.rawValue)")
        guard central.state == .poweredOn else { return finish("bluetooth state \(central.state.rawValue)") }
        if let known = Self.knownPeripheral.flatMap(UUID.init(uuidString:)),
            let peripheral = central.retrievePeripherals(withIdentifiers: [known]).first
        {
            stage("retrieved")
            connect(peripheral)
        } else {
            stage("scanning")
            central.scanForPeripherals(withServices: [Self.serviceUUID])
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard self.peripheral == nil else { return }
        stage("found rssi \(RSSI)")
        central.stopScan()
        UserDefaults.standard.set(peripheral.identifier.uuidString, forKey: Self.knownKey)
        connect(peripheral)
    }

    private func connect(_ peripheral: CBPeripheral) {
        self.peripheral = peripheral
        peripheral.delegate = self
        central?.connect(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        stage("connected")
        peripheral.discoverServices([Self.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        finish("connect failed: \(error?.localizedDescription ?? "?")")
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if completion != nil { finish("disconnected: \(error?.localizedDescription ?? "by us")") }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let service = peripheral.services?.first(where: { $0.uuid == Self.serviceUUID }) else {
            return finish("no rig service: \(error?.localizedDescription ?? "absent")")
        }
        stage("services")
        peripheral.discoverCharacteristics([Self.writeUUID, Self.notifyUUID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        write = service.characteristics?.first { $0.uuid == Self.writeUUID }
        notify = service.characteristics?.first { $0.uuid == Self.notifyUUID }
        guard let notify, write != nil else { return finish("characteristics missing") }
        stage("characteristics")
        peripheral.setNotifyValue(true, for: notify)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard let write else { return }
        stage("subscribed")
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        peripheral.writeValue(Data(bytes), for: write, type: .withResponse)
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error { return finish("write failed: \(error.localizedDescription)") }
        stage("written")
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == Self.notifyUUID else { return }
        stage("echoed \(characteristic.value?.count ?? 0) bytes")
        finish("ok")
    }

    private func finish(_ outcome: String) {
        guard let completion else { return }
        self.completion = nil
        let summary = "\(label): \(outcome) in \(elapsedMS()) ms [\(stages.joined(separator: ", "))]"
        RigLog.note(summary)
        completion(summary)
        central?.stopScan()
        if let peripheral { central?.cancelPeripheralConnection(peripheral) }
        Self.queue.asyncAfter(deadline: .now() + 0.3) { [self] in
            central?.delegate = nil
            retainSelf = nil
        }
    }

    /// Foreground, background or inactive, as iOS sees this process.
    static var appState: String {
        #if canImport(UIKit)
            if Thread.isMainThread { return describe(UIApplication.shared.applicationState) }
            return DispatchQueue.main.sync { describe(UIApplication.shared.applicationState) }
        #else
            return "?"
        #endif
    }

    #if canImport(UIKit)
        private static func describe(_ state: UIApplication.State) -> String {
            switch state {
            case .active: return "active"
            case .inactive: return "inactive"
            case .background: return "background"
            @unknown default: return "?"
            }
        }
    #endif
}

#if canImport(UIKit)
    import UIKit
#endif

/// `Library/Caches/rig.log`, last 300 lines; readable off the phone with
/// `xcrun devicectl device copy from --domain-type appDataContainer
/// --domain-identifier <app bundle id> --source Library/Caches/rig.log`.
enum RigLog {
    private static var url: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("rig.log")
    }

    /// One writer for `rig.log`: the detached loop writes the same file
    /// through `RigNote`, so this goes through it too.
    static func note(_ message: String) {
        RigNote.write("rig.log", message)
    }

    static func tail(_ count: Int = 30) -> String {
        let lines = (try? String(contentsOf: url, encoding: .utf8))?.split(separator: "\n").map(String.init) ?? []
        return lines.suffix(count).joined(separator: "\n")
    }
}
