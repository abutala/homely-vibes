#!/usr/bin/env swift
// The rig's stand-in for the lock: a Bluetooth peripheral on this Mac that
// echoes every write back as a notification, which is the shape of the
// lock's key exchange (write a frame, wait for the lock's frame). Run it,
// then pair the phone's rig app to it once from the foreground; after that
// every widget tap probes it from the background.
//
//   BLEWidgetRig/scripts/run_peripheral.sh 2>&1 | tee /tmp/rig-peripheral-run.log
//
// Built into a small app bundle and opened by LaunchServices: a `swift`
// script or a bare binary carries no usage description that macOS accepts,
// and it kills the process at the first Bluetooth call (TCC). The app
// writes its lines to /tmp/rig-peripheral.log. macOS asks once for
// Bluetooth permission.
import CoreBluetooth
import Foundation

let serviceUUID = CBUUID(string: "7E57A6B0-0001-4B1E-9A6E-000000000001")
let writeUUID = CBUUID(string: "7E57A6B0-0002-4B1E-9A6E-000000000002")
let notifyUUID = CBUUID(string: "7E57A6B0-0003-4B1E-9A6E-000000000003")
let localName = "RigEcho"

final class Echo: NSObject, CBPeripheralManagerDelegate {
    var manager: CBPeripheralManager!
    let notify = CBMutableCharacteristic(type: notifyUUID, properties: [.notify], value: nil, permissions: [.readable])
    let write = CBMutableCharacteristic(type: writeUUID, properties: [.write], value: nil, permissions: [.writeable])
    var started = Date()

    func start() {
        manager = CBPeripheralManager(delegate: self, queue: nil)
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        print("\(stamp()) state \(peripheral.state.rawValue)")
        guard peripheral.state == .poweredOn else { return }
        let service = CBMutableService(type: serviceUUID, primary: true)
        service.characteristics = [write, notify]
        peripheral.add(service)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if let error { print("\(stamp()) add service failed: \(error)"); return }
        peripheral.startAdvertising([
            CBAdvertisementDataLocalNameKey: localName,
            CBAdvertisementDataServiceUUIDsKey: [serviceUUID],
        ])
        print("\(stamp()) advertising \(localName) with \(serviceUUID)")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        print("\(stamp()) central \(central.identifier) subscribed")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            let bytes = request.value ?? Data()
            peripheral.respond(to: request, withResult: .success)
            print("\(stamp()) write of \(bytes.count) bytes from \(request.central.identifier); echoing")
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                let sent = peripheral.updateValue(bytes, for: self.notify, onSubscribedCentrals: nil)
                print("\(self.stamp()) echo \(sent ? "sent" : "queued")")
            }
        }
    }

    func stamp() -> String { ISO8601DateFormatter().string(from: Date()) }
}

freopen("/tmp/rig-peripheral.log", "a", stdout)
setvbuf(stdout, nil, _IOLBF, 0)
let echo = Echo()
echo.start()
dispatchMain()
