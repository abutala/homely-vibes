import XCTest

@testable import AugustBLEProtocol

/// Expected bytes come from running yalexs-ble 6.1.0's own `Session` and
/// `SecureSession` classes with a test key (00..0f), slot 4, our nonce 10..1f
/// and the lock's half 20..27, by `scripts/gen_ble_vectors.py`. The
/// lock-side ciphertexts come from an independent AES encryptor there.
final class AugustBLEProtocolTests: XCTestCase {
    private let offlineKey = bytes("000102030405060708090a0b0c0d0e0f")
    private let nonce = bytes("101112131415161718191a1b1c1d1e1f")
    private let sessionKey = bytes("10111213141516172021222324252627")

    // MARK: - Checksums and frames

    func testSimpleChecksumZeroesYalexsOpResponse() {
        // A frame from yalexs-ble tests/test_lock.py.
        XCTAssertEqual(AugustBLE.simpleChecksum(bytes("bb0a003b0000000000000000000000000000")), 0)
    }

    func testOperationCommandsMatchYalexs() {
        XCTAssertEqual(AugustBLE.operationCommand(opcode: AugustBLE.unlockOpcode), bytes("ee0a00060000000000000000000000000200"))
        XCTAssertEqual(AugustBLE.operationCommand(opcode: AugustBLE.lockOpcode), bytes("ee0b00050000000000000000000000000200"))
    }

    func testSecureCommandsMatchYalexs() {
        XCTAssertEqual(
            AugustBLE.secureCommand(opcode: 0x01, slot: 4, payload: Array(nonce[0..<8])),
            bytes("010000001011121314151617dbd9d7d50f04"))
        XCTAssertEqual(
            AugustBLE.secureCommand(opcode: 0x03, slot: 4, payload: Array(nonce[8..<16])),
            bytes("0300000018191a1b1c1d1e1fc9c9c7c50f04"))
    }

    func testSecurityChecksumValidatesAndRejects() {
        var reply = bytes("020000002021222324252627bab9b7b50f04")
        XCTAssertTrue(AugustBLE.isValidSecureReply(reply))
        reply[0x05] ^= 0x01
        XCTAssertFalse(AugustBLE.isValidSecureReply(reply))
    }

    func testPlainReplyNeedsFlagAndChecksum() {
        XCTAssertTrue(AugustBLE.isValidPlainReply(bytes("aa0a004a0000000000000000000000000200")))
        XCTAssertFalse(AugustBLE.isValidPlainReply(bytes("aa0a004b0000000000000000000000000200")))
        XCTAssertFalse(AugustBLE.isValidPlainReply(bytes("cc0a00390000000000000000000000000200")))
    }

    func testLocalNameMatchesYalexs() {
        XCTAssertEqual(AugustBLE.localName(serial: "L3ABCDE12345"), "L312345")
    }

    // MARK: - Handshake

    func testHandshakeDerivesSessionKeyAndMatchesYalexsWire() throws {
        let handshake = AugustBLEHandshake(offlineKey: offlineKey, slot: 4, nonce: nonce)
        XCTAssertEqual(handshake.keyExchangeCommand(), bytes("8057b7a941466a2eac73547cf56b366e0f04"))

        let initialization = try handshake.initializationCommand(reply: bytes("2d970bb8635a8bc893a0e8a2cf42b6360f04"))
        XCTAssertEqual(handshake.sessionKey, sessionKey)
        XCTAssertEqual(initialization, bytes("a983bea66fcd0e67d710046275dab5750f04"))
    }

    func testHandshakeRejectsReplyUnderWrongKey() {
        let wrongKey = [UInt8](repeating: 0xAB, count: 16)
        let handshake = AugustBLEHandshake(offlineKey: wrongKey, slot: 4, nonce: nonce)
        XCTAssertThrowsError(try handshake.initializationCommand(reply: bytes("2d970bb8635a8bc893a0e8a2cf42b6360f04"))) {
            XCTAssertEqual($0 as? AugustBLEProtocolError, .keyRejected("security checksum mismatch"))
        }
    }

    func testHandshakeRejectsWrongReplyOpcode() throws {
        // A valid secure frame whose first byte is not the expected 0x02.
        let frame = AugustBLE.secureCommand(opcode: 0x09, slot: 4)
        let wire = AugustFrameCipher(key: offlineKey, mode: .ecb, encrypt: true).apply(frame)
        let handshake = AugustBLEHandshake(offlineKey: offlineKey, slot: 4, nonce: nonce)
        XCTAssertThrowsError(try handshake.initializationCommand(reply: wire))
    }

    // MARK: - Plain channel

    func testPlainChannelChainsAcrossFramesLikeYalexs() {
        let channel = AugustBLEPlainChannel(sessionKey: sessionKey)
        XCTAssertEqual(channel.command(opcode: AugustBLE.unlockOpcode), bytes("da1d4fc8a1a9a700e8dba8233005399a0200"))
        XCTAssertEqual(channel.command(opcode: AugustBLE.lockOpcode), bytes("e948430bf75f67146fb05fc2a447dc910200"))
        // Same plaintext as the first frame, different wire: the chain persisted.
        XCTAssertEqual(channel.command(opcode: AugustBLE.unlockOpcode), bytes("5f6dd36a7830da517cf23e26029556940200"))
    }

    func testPlainChannelDecryptsAckThenResult() throws {
        let channel = AugustBLEPlainChannel(sessionKey: sessionKey)
        XCTAssertEqual(try channel.receive(bytes("5801cbb04dfe6ed1bcf20e1fb278b2040200"), for: AugustBLE.unlockOpcode), .ack)
        XCTAssertEqual(try channel.receive(bytes("27e489aee72fa7f91948b36d9dc226790000"), for: AugustBLE.unlockOpcode), .result(0))
    }

    func testPlainChannelReportsOtherOpcodeAsOther() throws {
        let channel = AugustBLEPlainChannel(sessionKey: sessionKey)
        XCTAssertEqual(try channel.receive(bytes("5801cbb04dfe6ed1bcf20e1fb278b2040200"), for: AugustBLE.lockOpcode), .other)
    }

    func testPlainChannelRefusesShortFrameWithoutPoisoningTheChain() throws {
        let channel = AugustBLEPlainChannel(sessionKey: sessionKey)
        XCTAssertThrowsError(try channel.receive(Array(repeating: 0, count: 10), for: AugustBLE.unlockOpcode))
        XCTAssertEqual(try channel.receive(bytes("5801cbb04dfe6ed1bcf20e1fb278b2040200"), for: AugustBLE.unlockOpcode), .ack)
    }

    func testMotorFaultsAreMechanicalOthersAreNot() {
        // 0x1F is the result byte of yalexs-ble's jammed op-response frame
        // bb0a001c00000000000000000000001f0000 (tests/test_lock.py).
        XCTAssertEqual(AugustBLE.simpleChecksum(bytes("bb0a001c00000000000000000000001f0000")), 0)
        XCTAssertTrue(AugustBLEProtocolError.operationFailed(0x1F).isMechanical)
        XCTAssertTrue(AugustBLEProtocolError.operationFailed(0x1E).isMechanical)
        XCTAssertTrue(AugustBLEProtocolError.operationFailed(0x23).isMechanical)
        XCTAssertFalse(AugustBLEProtocolError.operationFailed(0x3E).isMechanical)  // BUSY
        XCTAssertFalse(AugustBLEProtocolError.keyRejected("x").isMechanical)
    }

    // MARK: - Credentials from GET /locks/{id}

    func testCredentialsReadLoadedKeyOnly() {
        let detail: [String: Any] = [
            "SerialNumber": "L3ABCDE12345",
            "OfflineKeys": ["loaded": [["key": "000102030405060708090a0b0c0d0e0f", "slot": 4]], "created": []],
        ]
        XCTAssertEqual(
            AugustBLECredentials(lockDetail: detail),
            AugustBLECredentials(hexKey: "000102030405060708090a0b0c0d0e0f", slot: 4, serial: "L3ABCDE12345"))
        XCTAssertEqual(AugustBLECredentials(lockDetail: detail)?.key, offlineKey)
    }

    func testCredentialsIgnoreCreatedButNotLoadedKey() {
        let detail: [String: Any] = [
            "SerialNumber": "L3ABCDE12345",
            "OfflineKeys": ["loaded": [], "created": [["key": "000102030405060708090a0b0c0d0e0f", "slot": 4]]],
        ]
        XCTAssertNil(AugustBLECredentials(lockDetail: detail))
    }

    func testCredentialsRejectMalformedKey() {
        XCTAssertNil(AugustBLECredentials(hexKey: "00zz", slot: 4, serial: "L3ABCDE12345"))
        XCTAssertNil(AugustBLECredentials(hexKey: "0001", slot: 4, serial: "L3ABCDE12345"))
        XCTAssertNil(AugustBLECredentials(hexKey: "000102030405060708090a0b0c0d0e0f", slot: 300, serial: "L3ABCDE12345"))
    }
}

private func bytes(_ hex: String) -> [UInt8] {
    var out: [UInt8] = []
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        out.append(UInt8(hex[index..<next], radix: 16)!)
        index = next
    }
    return out
}
