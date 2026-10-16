import XCTest

@testable import ClaudeUsageBar

/// Covers only the pure steps of the reader — config parsing, decryption,
/// token selection and failure classification. The Keychain and the
/// `security` subprocess stay out of the test target rather than being mocked.
final class DesktopTokenReaderTests: XCTestCase {

    private func data(_ json: String) -> Data { Data(json.utf8) }

    private let account = "11111111-1111-1111-1111-111111111111"
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func key(account: String, base: String = "https://api.anthropic.com", scopes: String = "user:profile") -> String {
        "acct:\(account)|client-id:org-id:\(base):\(scopes)"
    }

    private func entry(_ token: String, expiresAtMillis: Double) -> [String: Any] {
        ["token": token, "refreshToken": "r", "expiresAt": expiresAtMillis]
    }

    private func cache(_ entries: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: entries)
    }

    private var future: Double { (now.timeIntervalSince1970 + 3600) * 1000 }
    private var past: Double { (now.timeIntervalSince1970 - 3600) * 1000 }

    // MARK: - parseConfig

    func testParsesEncryptedCacheAndAccount() throws {
        let config = try DesktopTokenReader.parseConfig(
            data(#"{"oauth:tokenCacheV2":"djEwAA==","lastKnownAccountUuid":"abc"}"#)
        ).get()
        XCTAssertEqual(config.encryptedCache, Data("v10".utf8) + Data([0]))
        XCTAssertEqual(config.account, "abc")
    }

    /// A desktop app that never signed in has a config with no token cache.
    func testConfigWithoutTokenCacheIsSignedOut() {
        XCTAssertEqual(
            DesktopTokenReader.parseConfig(data(#"{"locale":"en-US"}"#)).failure, .signedOut
        )
    }

    func testUnparsableConfigIsMalformed() {
        XCTAssertEqual(DesktopTokenReader.parseConfig(data("nope")).failure, .malformed)
    }

    // MARK: - decrypt

    /// Known-answer vector made outside Swift (Python `hashlib.pbkdf2_hmac` +
    /// `openssl enc -aes-128-cbc`), so a shared bug cannot make it pass.
    func testDecryptsChromiumOSCryptVector() {
        let blob = Data(base64Encoded: "djEwunhmTg7R5O8rZl1RizuL+wqtm7BcxOathv1i3D7c80U=")!
        let plain = DesktopTokenReader.decrypt(blob, password: Data("test-safe-storage-password".utf8))
        XCTAssertEqual(plain.map { String(decoding: $0, as: UTF8.self) }, #"{"hello":"desktop"}"#)
    }

    func testWrongPasswordDoesNotDecrypt() {
        let blob = Data(base64Encoded: "djEwunhmTg7R5O8rZl1RizuL+wqtm7BcxOathv1i3D7c80U=")!
        let plain = DesktopTokenReader.decrypt(blob, password: Data("wrong".utf8))
        XCTAssertNotEqual(plain.map { String(decoding: $0, as: UTF8.self) }, #"{"hello":"desktop"}"#)
    }

    func testBlobWithoutVersionPrefixIsRejected() {
        XCTAssertNil(DesktopTokenReader.decrypt(Data("v11xxxxxxxxxxxxxxxx".utf8), password: Data("p".utf8)))
    }

    // MARK: - selectToken

    func testPicksLiveEntryThatLastsLongest() throws {
        let later = future + 60_000
        let result = DesktopTokenReader.selectToken(
            from: cache([
                key(account: account, scopes: "user:profile"): entry("sk-short", expiresAtMillis: future),
                key(account: account, scopes: "user:inference user:profile"): entry("sk-long", expiresAtMillis: later),
            ]),
            account: account, now: now
        )
        XCTAssertEqual(try result.get().accessToken, "sk-long")
    }

    func testSkipsExpiredEntries() throws {
        let result = DesktopTokenReader.selectToken(
            from: cache([
                key(account: account, scopes: "a"): entry("sk-old", expiresAtMillis: past),
                key(account: account, scopes: "b"): entry("sk-new", expiresAtMillis: future),
            ]),
            account: account, now: now
        )
        XCTAssertEqual(try result.get().accessToken, "sk-new")
    }

    /// The desktop app refreshes only while it runs, so an all-expired cache
    /// means "open the app", not "sign in".
    func testAllEntriesExpiredIsExpired() {
        let result = DesktopTokenReader.selectToken(
            from: cache([key(account: account): entry("sk-old", expiresAtMillis: past)]),
            account: account, now: now
        )
        XCTAssertEqual(result.failure, .expired)
    }

    func testIgnoresOtherAccountsAndOtherAPIBases() {
        let result = DesktopTokenReader.selectToken(
            from: cache([
                key(account: "someone-else"): entry("sk-other", expiresAtMillis: future),
                key(account: account, base: "https://example.com"): entry("sk-base", expiresAtMillis: future),
            ]),
            account: account, now: now
        )
        XCTAssertEqual(result.failure, .signedOut)
    }

    func testWithoutKnownAccountAnyAnthropicEntryCounts() throws {
        let result = DesktopTokenReader.selectToken(
            from: cache([key(account: "any"): entry("sk-any", expiresAtMillis: future)]),
            account: nil, now: now
        )
        XCTAssertEqual(try result.get().accessToken, "sk-any")
    }

    func testBlankTokenIsIgnored() {
        let result = DesktopTokenReader.selectToken(
            from: cache([key(account: account): entry("", expiresAtMillis: future)]),
            account: account, now: now
        )
        XCTAssertEqual(result.failure, .signedOut)
    }

    func testUndecodableCacheIsMalformed() {
        XCTAssertEqual(
            DesktopTokenReader.selectToken(from: data("nope"), account: nil, now: now).failure,
            .malformed
        )
    }

    // MARK: - classifySecurityFailure

    func testClassifiesItemNotFoundExitCode() {
        XCTAssertEqual(
            DesktopTokenReader.classifySecurityFailure(status: 44, stderr: ""), .notFound
        )
    }

    /// 51 is one of the small curated codes `security` emits; it must never read
    /// as "signed out".
    func testDeniedExitCodeIsAccessDenied() {
        let result = DesktopTokenReader.classifySecurityFailure(status: 51, stderr: "")
        guard case .accessDenied = result else {
            return XCTFail("status 51 should classify as accessDenied, got \(result)")
        }
    }

    /// `security` does not surface an OSStatus for every failure, so the
    /// message is the fallback signal.
    func testClassifiesNotFoundFromMessage() {
        let stderr = "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."
        XCTAssertEqual(
            DesktopTokenReader.classifySecurityFailure(status: 1, stderr: stderr), .notFound
        )
    }

    func testClassifiesDenialFromMessage() {
        let stderr = "security: SecKeychainItemCopyContent: User interaction is not allowed."
        guard case .accessDenied = DesktopTokenReader.classifySecurityFailure(
            status: 1, stderr: stderr
        ) else {
            return XCTFail("interaction message should classify as accessDenied")
        }
    }

    /// An unrecognised failure must not masquerade as "signed out".
    func testUnknownFailureIsNotReportedAsNotFound() {
        let result = DesktopTokenReader.classifySecurityFailure(status: 9, stderr: "boom")
        XCTAssertNotEqual(result, .notFound)
        guard case .accessDenied = result else {
            return XCTFail("unknown failure should classify as accessDenied, got \(result)")
        }
    }

    // MARK: - advice routing

    func testOnlyAbsentSignedOutOrExpiredAdviseOpeningClaude() {
        XCTAssertTrue(TokenReadError.notFound.isFixedByOpeningClaude)
        XCTAssertTrue(TokenReadError.signedOut.isFixedByOpeningClaude)
        XCTAssertTrue(TokenReadError.expired.isFixedByOpeningClaude)
        XCTAssertFalse(TokenReadError.accessDenied("denied").isFixedByOpeningClaude)
        XCTAssertFalse(TokenReadError.malformed.isFixedByOpeningClaude)
    }
}

private extension Result {
    var failure: Failure? {
        if case .failure(let error) = self { return error }
        return nil
    }
}
