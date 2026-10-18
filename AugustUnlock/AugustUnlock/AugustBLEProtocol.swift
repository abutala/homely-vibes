import CommonCrypto
import Foundation

/// The August/Yale Bluetooth wire format: frames, checksums, ciphers and the
/// two-step key exchange. A port of the minimum of yalexs-ble (Python, used
/// by Home Assistant): `const.py`, `util.py`, `session.py`,
/// `secure_session.py` and `lock.py::_setup_session`. Pure — no CoreBluetooth
/// here, so `swift test` covers it on the Mac (see `Package.swift`).
nonisolated enum AugustBLE {
    static let serviceUUID = "0000FE24-0000-1000-8000-00805F9B34FB"
    static let writeUUID = "BD4AC611-0B45-11E3-8FFD-0800200C9A66"
    static let readUUID = "BD4AC612-0B45-11E3-8FFD-0800200C9A66"
    static let secureWriteUUID = "BD4AC613-0B45-11E3-8FFD-0800200C9A66"
    static let secureReadUUID = "BD4AC614-0B45-11E3-8FFD-0800200C9A66"

    /// Every frame, sent or received: a 16-byte encrypted block plus two plain
    /// trailing bytes. Both checksums run over all 18.
    static let frameLength = 18
    static let unlockOpcode: UInt8 = 0x0A
    static let lockOpcode: UInt8 = 0x0B
    /// Result code of an op-response; 0x00 is success.
    static let resultByte = 0x0F

    /// Plain-channel checksum, stored at byte 3: makes the byte sum zero.
    static func simpleChecksum(_ frame: [UInt8]) -> UInt8 {
        let sum = frame.prefix(frameLength).reduce(0) { $0 &+ $1 }
        return 0 &- sum
    }

    /// Secure-channel checksum, stored little-endian at bytes 12-15. yalexs
    /// sums three little-endian ints (bytes 0-3, 4-7, 8-17) mod 2^32, which
    /// leaves only bytes 8-11 of the third one in play.
    static func securityChecksum(_ frame: [UInt8]) -> UInt32 {
        let words = [0, 4, 8].map { readUInt32LE(frame, at: $0) }
        return 0 &- (words[0] &+ words[1] &+ words[2])
    }

    /// The lock's name in its advertisement: the serial's first two and last
    /// five characters (yalexs `serial_to_local_name`). iOS hides MAC
    /// addresses, so this is how the scan finds the lock.
    static func localName(serial: String) -> String {
        String(serial.prefix(2)) + String(serial.suffix(5))
    }

    /// A plain-channel command, checksummed, before encryption.
    static func operationCommand(opcode: UInt8) -> [UInt8] {
        var frame = [UInt8](repeating: 0, count: frameLength)
        frame[0x00] = 0xEE
        frame[0x01] = opcode
        frame[0x10] = 0x02
        frame[0x03] = simpleChecksum(frame)
        return frame
    }

    /// A secure-channel command, checksummed, before encryption.
    static func secureCommand(opcode: UInt8, slot: UInt8, payload: [UInt8] = []) -> [UInt8] {
        var frame = [UInt8](repeating: 0, count: frameLength)
        frame[0x00] = opcode
        frame.replaceSubrange(0x04..<(0x04 + payload.count), with: payload)
        frame[0x10] = 0x0F
        frame[0x11] = slot
        frame.replaceSubrange(0x0C..<0x10, with: uint32LE(securityChecksum(frame)))
        return frame
    }

    static func isValidSecureReply(_ frame: [UInt8]) -> Bool {
        frame.count == frameLength && readUInt32LE(frame, at: 0x0C) == securityChecksum(frame)
    }

    static func isValidPlainReply(_ frame: [UInt8]) -> Bool {
        frame.count == frameLength && simpleChecksum(frame) == 0 && (frame[0] == 0xAA || frame[0] == 0xBB)
    }

    private static func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        (0..<4).reduce(0) { $0 | UInt32(bytes[offset + $1]) << (8 * $1) }
    }

    private static func uint32LE(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }
}

nonisolated enum AugustBLEProtocolError: LocalizedError, Equatable {
    case badFrame(String)
    /// The lock rejected the offline key or slot.
    case keyRejected(String)
    case operationFailed(UInt8)

    var errorDescription: String? {
        switch self {
        case .badFrame(let detail): return "Bad Bluetooth frame: \(detail)"
        case .keyRejected(let detail): return "Lock rejected the offline key: \(detail)"
        case .operationFailed(let code):
            return isMechanical
                ? String(format: "The lock jammed or stalled (0x%02X). Check the door.", code)
                : String(format: "Lock reported failure 0x%02X", code)
        }
    }

    /// yalexs `MECHANICAL_OPERATION_ERRORS` (0x1E-0x23): the motor stalled.
    /// Final — re-driving a stalled mechanism through the cloud is no recovery.
    var isMechanical: Bool {
        if case .operationFailed(let code) = self { return (0x1E...0x23).contains(code) }
        return false
    }
}

/// One AES-128 direction of a channel, kept for the whole connection. The
/// plain channel is CBC with a zero IV whose chain runs across frames, so the
/// CommonCrypto context must persist — re-creating it per frame restarts the
/// chain and the lock rejects everything after the first frame.
nonisolated final class AugustFrameCipher {
    enum Mode { case ecb, cbcZeroIV }

    private var cryptor: CCCryptorRef?

    init(key: [UInt8], mode: Mode, encrypt: Bool) {
        precondition(key.count == kCCKeySizeAES128)
        let iv = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        let status = CCCryptorCreateWithMode(
            CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
            CCMode(mode == .ecb ? kCCModeECB : kCCModeCBC),
            CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding),
            mode == .ecb ? nil : iv, key, key.count, nil, 0, 0, 0, &cryptor)
        precondition(status == kCCSuccess, "CCCryptorCreateWithMode failed: \(status)")
    }

    deinit { CCCryptorRelease(cryptor) }

    /// Runs the first 16 bytes through the cipher; the trailing two stay plain.
    func apply(_ frame: [UInt8]) -> [UInt8] {
        precondition(frame.count == AugustBLE.frameLength)
        var out = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        var moved = 0
        let status = CCCryptorUpdate(cryptor, Array(frame[0..<16]), 16, &out, out.count, &moved)
        precondition(status == kCCSuccess && moved == 16, "CCCryptorUpdate failed: \(status)")
        return out + frame[16..<18]
    }
}

/// The two-step key exchange of yalexs `_setup_session`, as a state machine
/// the Bluetooth client feeds wire frames into. Step 1 runs AES-ECB under the
/// offline key; the session key is our 8 random bytes plus 8 from the lock;
/// step 2 runs ECB under the session key, and so does every later secure
/// command. The plain channel then opens under the session key in CBC.
nonisolated final class AugustBLEHandshake {
    private let slot: UInt8
    private let nonce: [UInt8]
    private var encrypt: AugustFrameCipher
    private var decrypt: AugustFrameCipher
    private(set) var sessionKey: [UInt8]?

    /// `nonce` is 16 random bytes; tests pass a fixed one.
    init(offlineKey: [UInt8], slot: UInt8, nonce: [UInt8]) {
        precondition(nonce.count == 16)
        self.slot = slot
        self.nonce = nonce
        encrypt = AugustFrameCipher(key: offlineKey, mode: .ecb, encrypt: true)
        decrypt = AugustFrameCipher(key: offlineKey, mode: .ecb, encrypt: false)
    }

    /// SEC_LOCK_TO_MOBILE_KEY_EXCHANGE, ready for the secure write characteristic.
    func keyExchangeCommand() -> [UInt8] {
        encrypt.apply(AugustBLE.secureCommand(opcode: 0x01, slot: slot, payload: Array(nonce[0..<8])))
    }

    /// Takes the lock's reply to the key exchange; returns
    /// SEC_INITIALIZATION_COMMAND under the new session key.
    func initializationCommand(reply wire: [UInt8]) throws -> [UInt8] {
        let reply = try decryptSecure(wire)
        guard reply[0] == 0x02 else { throw AugustBLEProtocolError.keyRejected(hex(reply)) }
        let key = Array(nonce[0..<8]) + Array(reply[0x04..<0x0C])
        sessionKey = key
        encrypt = AugustFrameCipher(key: key, mode: .ecb, encrypt: true)
        decrypt = AugustFrameCipher(key: key, mode: .ecb, encrypt: false)
        return encrypt.apply(AugustBLE.secureCommand(opcode: 0x03, slot: slot, payload: Array(nonce[8..<16])))
    }

    /// Takes the lock's reply to the initialization; returns the plain channel.
    func plainChannel(reply wire: [UInt8]) throws -> AugustBLEPlainChannel {
        let reply = try decryptSecure(wire)
        guard reply[0] == 0x04, let sessionKey else { throw AugustBLEProtocolError.keyRejected(hex(reply)) }
        return AugustBLEPlainChannel(sessionKey: sessionKey)
    }

    /// Secure DISCONNECT (yalexs `_shutdown_connection`), sent best-effort.
    func shutdownCommand() -> [UInt8] {
        encrypt.apply(AugustBLE.secureCommand(opcode: 0x05, slot: 0x00))
    }

    private func decryptSecure(_ wire: [UInt8]) throws -> [UInt8] {
        guard wire.count == AugustBLE.frameLength else {
            throw AugustBLEProtocolError.badFrame("\(wire.count) bytes on the secure channel")
        }
        let frame = decrypt.apply(wire)
        guard AugustBLE.isValidSecureReply(frame) else {
            throw AugustBLEProtocolError.keyRejected("security checksum mismatch")
        }
        return frame
    }
}

/// The plain channel after the handshake. Its encrypt and decrypt chains are
/// independent and each persists for the connection.
nonisolated final class AugustBLEPlainChannel {
    enum Reply: Equatable {
        case ack
        case result(UInt8)
        /// A valid frame that is not about the pending operation (a status push).
        case other
    }

    private let encrypt: AugustFrameCipher
    private let decrypt: AugustFrameCipher

    init(sessionKey: [UInt8]) {
        encrypt = AugustFrameCipher(key: sessionKey, mode: .cbcZeroIV, encrypt: true)
        decrypt = AugustFrameCipher(key: sessionKey, mode: .cbcZeroIV, encrypt: false)
    }

    func command(opcode: UInt8) -> [UInt8] {
        encrypt.apply(AugustBLE.operationCommand(opcode: opcode))
    }

    /// Decrypts one notification and classifies it against `opcode`. A frame
    /// of the wrong length is refused before it reaches the decryptor: a
    /// partial block would sit buffered and garble every later frame.
    func receive(_ wire: [UInt8], for opcode: UInt8) throws -> Reply {
        guard wire.count == AugustBLE.frameLength else {
            throw AugustBLEProtocolError.badFrame("\(wire.count) bytes on the plain channel")
        }
        let frame = decrypt.apply(wire)
        guard AugustBLE.isValidPlainReply(frame) else {
            throw AugustBLEProtocolError.badFrame("checksum or flag in \(hex(frame))")
        }
        guard frame[1] == opcode else { return .other }
        return frame[0] == 0xAA ? .ack : .result(frame[AugustBLE.resultByte])
    }
}

/// What the Bluetooth path needs for one lock, read from August's GET
/// /locks/{id} (yalexs `LockDetail.offline_key`, `offline_slot`). August lists
/// a key under `loaded` only once the lock holds it; a key still under
/// `created` is useless until the official app loads it over Bluetooth.
nonisolated struct AugustBLECredentials: Equatable {
    let key: [UInt8]
    let slot: UInt8
    let serial: String

    init?(lockDetail json: [String: Any]) {
        guard let serial = json["SerialNumber"] as? String,
            let offline = json["OfflineKeys"] as? [String: Any],
            let loaded = (offline["loaded"] as? [[String: Any]])?.first,
            let hexKey = loaded["key"] as? String,
            let slot = (loaded["slot"] as? NSNumber)?.intValue
        else { return nil }
        self.init(hexKey: hexKey, slot: slot, serial: serial)
    }

    init?(hexKey: String, slot: Int, serial: String) {
        guard let key = Self.bytes(hex: hexKey), key.count == 16, (0...255).contains(slot) else { return nil }
        self.key = key
        self.slot = UInt8(slot)
        self.serial = serial
    }

    var hexKey: String { hex(key) }

    private static func bytes(hex: String) -> [UInt8]? {
        guard hex.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        return out
    }
}

nonisolated private func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}
