import XCTest

@testable import ClaudeUsageBar

/// Covers only the pure halves of the reader — payload parsing and failure
/// classification. The Keychain and the `security` subprocess stay out of the
/// test target rather than being mocked.
final class KeychainTokenReaderTests: XCTestCase {

    private func data(_ json: String) -> Data { Data(json.utf8) }

    // MARK: - parseToken

    func testParsesNestedClaudeCodeShape() {
        let token = KeychainTokenReader.parseToken(
            from: data(#"{"claudeAiOauth":{"accessToken":"sk-abc","expiresAt":1786970166851}}"#)
        )
        XCTAssertEqual(token?.accessToken, "sk-abc")
        XCTAssertEqual(
            token?.expiresAt?.timeIntervalSince1970 ?? 0, 1_786_970_166.851, accuracy: 0.01
        )
    }

    /// The flat shape is what we write into our own item, so both must parse
    /// through the same function.
    func testParsesFlatShapeWrittenToOwnItem() {
        let token = KeychainTokenReader.parseToken(
            from: data(#"{"accessToken":"sk-flat","expiresAt":1786970166851}"#)
        )
        XCTAssertEqual(token?.accessToken, "sk-flat")
        XCTAssertNotNil(token?.expiresAt)
    }

    func testParsesExpiresAtAsFloatingPoint() {
        let token = KeychainTokenReader.parseToken(
            from: data(#"{"accessToken":"sk-x","expiresAt":1786970166851.0}"#)
        )
        XCTAssertNotNil(token?.expiresAt)
    }

    func testTokenWithoutExpiryIsAccepted() {
        let token = KeychainTokenReader.parseToken(from: data(#"{"accessToken":"sk-x"}"#))
        XCTAssertEqual(token?.accessToken, "sk-x")
        XCTAssertNil(token?.expiresAt)
    }

    /// The `Claude Code-credentials-<hash>` siblings are per-workspace MCP
    /// OAuth caches. They hold no `accessToken` at any level and must never be
    /// mistaken for the API token.
    func testRejectsMCPOAuthSiblingPayload() {
        let payload = #"{"mcpOAuth":{"serverName":"figma","accessToken":"not-anthropic"}}"#
        XCTAssertNil(KeychainTokenReader.parseToken(from: data(payload)))
    }

    func testRejectsPayloadMissingAccessToken() {
        XCTAssertNil(KeychainTokenReader.parseToken(from: data(#"{"refreshToken":"r"}"#)))
    }

    func testRejectsNonJSON() {
        XCTAssertNil(KeychainTokenReader.parseToken(from: data("not json at all")))
    }

    // MARK: - validateCLIPayload

    /// What a signed-out CLI leaves behind (observed 2026-10, CLI 2.1.296): the
    /// item survives with the token blanked and `expiresAt` zeroed. It must not
    /// read as `.expired`, or the app nudges a CLI that has nothing to refresh.
    func testBlankedTokenIsSignedOutNotExpired() {
        let payload = #"{"claudeAiOauth":{"accessToken":"","expiresAt":0,"scopes":["user:inference"]}}"#
        XCTAssertEqual(
            KeychainTokenReader.validateCLIPayload(data(payload)).failure, .signedOut
        )
    }

    func testPastExpiryIsExpired() {
        let payload = #"{"claudeAiOauth":{"accessToken":"sk-x","expiresAt":1000}}"#
        XCTAssertEqual(KeychainTokenReader.validateCLIPayload(data(payload)).failure, .expired)
    }

    func testFutureExpiryIsAccepted() {
        let payload = #"{"claudeAiOauth":{"accessToken":"sk-x","expiresAt":99999999999999}}"#
        XCTAssertEqual(
            try? KeychainTokenReader.validateCLIPayload(data(payload)).get().accessToken, "sk-x"
        )
    }

    func testUnparsablePayloadIsMalformed() {
        XCTAssertEqual(KeychainTokenReader.validateCLIPayload(data("nope")).failure, .malformed)
    }

    // MARK: - classifySecurityFailure

    func testClassifiesItemNotFoundExitCode() {
        XCTAssertEqual(
            KeychainTokenReader.classifySecurityFailure(status: 44, stderr: ""), .notFound
        )
    }

    /// 51 is one of the small curated codes `security` emits; it must never read
    /// as "signed out". The former 25xxx labels were unreachable through a real exit
    /// status (a Unix status is 0-255) and were only ever reached via the message
    /// fallback, so exercising them through the switch gave false confidence.
    func testDeniedExitCodeIsAccessDenied() {
        let result = KeychainTokenReader.classifySecurityFailure(status: 51, stderr: "")
        guard case .accessDenied = result else {
            return XCTFail("status 51 should classify as accessDenied, got \(result)")
        }
    }

    /// `security` does not surface an OSStatus for every failure, so the
    /// message is the fallback signal.
    func testClassifiesNotFoundFromMessage() {
        let stderr = "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."
        XCTAssertEqual(
            KeychainTokenReader.classifySecurityFailure(status: 1, stderr: stderr), .notFound
        )
    }

    func testClassifiesDenialFromMessage() {
        let stderr = "security: SecKeychainItemCopyContent: User interaction is not allowed."
        guard case .accessDenied = KeychainTokenReader.classifySecurityFailure(
            status: 1, stderr: stderr
        ) else {
            return XCTFail("interaction message should classify as accessDenied")
        }
    }

    /// An unrecognised failure must not masquerade as "signed out" — that is
    /// exactly the misclassification this whole change exists to remove.
    func testUnknownFailureIsNotReportedAsNotFound() {
        let result = KeychainTokenReader.classifySecurityFailure(status: 9, stderr: "boom")
        XCTAssertNotEqual(result, .notFound)
        guard case .accessDenied = result else {
            return XCTFail("unknown failure should classify as accessDenied, got \(result)")
        }
    }

    // MARK: - advice routing

    func testOnlyAbsentOrExpiredCredentialsAdviseRunningClaude() {
        XCTAssertTrue(TokenReadError.notFound.isFixedByRunningClaude)
        XCTAssertTrue(TokenReadError.expired.isFixedByRunningClaude)
        XCTAssertTrue(TokenReadError.signedOut.isFixedByRunningClaude)
        XCTAssertFalse(TokenReadError.accessDenied("denied").isFixedByRunningClaude)
        XCTAssertFalse(TokenReadError.malformed.isFixedByRunningClaude)
    }
}

private extension Result {
    var failure: Failure? {
        if case .failure(let error) = self { return error }
        return nil
    }
}
