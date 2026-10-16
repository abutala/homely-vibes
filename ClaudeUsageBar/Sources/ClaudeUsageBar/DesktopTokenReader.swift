import CommonCrypto
import Foundation

struct OAuthToken {
    let accessToken: String
    let expiresAt: Date?
}

/// Why a token read failed. A *blocked* read must stay distinct from a
/// signed-out app, or the UI tells a signed-in user to sign in.
enum TokenReadError: Error, Equatable {
    case notFound
    case signedOut
    case accessDenied(String)
    case expired
    case malformed

    var menuDetail: String {
        switch self {
        case .notFound: return "Claude desktop app not found"
        case .signedOut: return "Claude desktop app is signed out"
        case .accessDenied(let detail): return detail
        case .expired: return "Claude desktop login expired"
        case .malformed: return "credentials unreadable"
        }
    }

    /// Only these are fixed by opening the desktop app: it signs in, or
    /// refreshes its own token while it runs. Saying so for the others is
    /// misleading.
    var isFixedByOpeningClaude: Bool {
        switch self {
        case .notFound, .signedOut, .expired: return true
        case .accessDenied, .malformed: return false
        }
    }
}

/// Reads the OAuth access token the **Claude desktop app** keeps for itself.
///
/// The desktop app stores its tokens in `config.json` under
/// `oauth:tokenCacheV2`, encrypted with Electron `safeStorage` (Chromium
/// OSCrypt). The key is the `Claude Safe Storage` Keychain item, read once
/// through `/usr/bin/security` and kept in memory: the desktop app never
/// rewrites that item, so one "Always Allow" lasts.
///
/// We only read. The desktop app refreshes its own token while it runs, and
/// refresh tokens rotate on use, so a refresh here would sign it out.
enum DesktopTokenReader {
    static let configURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Claude/config.json")
    private static let safeStorageService = "Claude Safe Storage"
    private static let securityTool = "/usr/bin/security"
    private static let anthropicBase = "https://api.anthropic.com"

    private static let lock = NSLock()
    nonisolated(unsafe) private static var cachedPassword: Data?

    static func readValidToken(now: Date = Date()) -> Result<OAuthToken, TokenReadError> {
        guard let configData = try? Data(contentsOf: configURL) else { return .failure(.notFound) }
        let config: DesktopConfig
        switch parseConfig(configData) {
        case .success(let value): config = value
        case .failure(let error): return .failure(error)
        }
        let password: Data
        switch safeStoragePassword() {
        case .success(let value): password = value
        case .failure(let error): return .failure(error)
        }
        guard let cache = decrypt(config.encryptedCache, password: password) else {
            dropCachedPassword()
            return .failure(.malformed)
        }
        return selectToken(from: cache, account: config.account, now: now)
    }

    // MARK: - Pure steps, `internal` for tests

    struct DesktopConfig {
        let encryptedCache: Data
        let account: String?
    }

    static func parseConfig(_ data: Data) -> Result<DesktopConfig, TokenReadError> {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .failure(.malformed)
        }
        guard let encoded = json["oauth:tokenCacheV2"] as? String else { return .failure(.signedOut) }
        guard let blob = Data(base64Encoded: encoded) else { return .failure(.malformed) }
        return .success(
            DesktopConfig(encryptedCache: blob, account: json["lastKnownAccountUuid"] as? String)
        )
    }

    /// Chromium OSCrypt on macOS: `v10` prefix, PBKDF2-HMAC-SHA1 over the
    /// Keychain secret with salt `saltysalt` and 1003 rounds, AES-128-CBC with
    /// an IV of 16 spaces, PKCS7 padding.
    static func decrypt(_ blob: Data, password: Data) -> Data? {
        let prefix = Data("v10".utf8)
        guard blob.starts(with: prefix) else { return nil }
        let ciphertext = Data(blob.dropFirst(prefix.count))
        guard let key = deriveKey(password) else { return nil }

        let iv = [UInt8](repeating: 0x20, count: kCCBlockSizeAES128)
        var plain = [UInt8](repeating: 0, count: ciphertext.count + kCCBlockSizeAES128)
        var plainLength = 0
        let status = ciphertext.withUnsafeBytes { cipherBytes in
            CCCrypt(
                CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionPKCS7Padding),
                key, key.count, iv,
                cipherBytes.baseAddress, ciphertext.count,
                &plain, plain.count, &plainLength
            )
        }
        guard status == kCCSuccess else { return nil }
        return Data(plain.prefix(plainLength))
    }

    /// The cache holds one entry per (OAuth client, scope set), keyed
    /// `acct:<account>|<client>:<org>:<api base>:<scopes>`. Any entry for the
    /// signed-in account on the Anthropic API can read usage, so take the live
    /// one that lasts longest.
    static func selectToken(
        from cache: Data, account: String?, now: Date
    ) -> Result<OAuthToken, TokenReadError> {
        guard let entries = try? JSONSerialization.jsonObject(with: cache) as? [String: Any] else {
            return .failure(.malformed)
        }
        let tokens = entries.compactMap { key, value -> OAuthToken? in
            guard isAnthropicEntry(key, account: account),
                  let entry = value as? [String: Any],
                  let token = entry["token"] as? String, !token.isEmpty
            else { return nil }
            let expiresAt = (entry["expiresAt"] as? Double).map {
                Date(timeIntervalSince1970: $0 / 1000)
            }
            return OAuthToken(accessToken: token, expiresAt: expiresAt)
        }
        guard !tokens.isEmpty else { return .failure(.signedOut) }
        let live = tokens.filter { ($0.expiresAt ?? .distantFuture) > now }
        guard let best = live.max(by: {
            ($0.expiresAt ?? .distantFuture) < ($1.expiresAt ?? .distantFuture)
        }) else { return .failure(.expired) }
        return .success(best)
    }

    static func isAnthropicEntry(_ key: String, account: String?) -> Bool {
        guard key.hasPrefix("acct:"), key.contains(":\(anthropicBase):") else { return false }
        guard let account else { return true }
        return key.hasPrefix("acct:\(account)|")
    }

    /// `security` returns its *own* small exit codes, not the raw `OSStatus`, so
    /// only a few map (observed on-host: 44 = item not found). The stderr message
    /// is authoritative for the rest — a blocked read must land on `.accessDenied`,
    /// never `.notFound`, or the UI tells a signed-in user to sign in.
    static func classifySecurityFailure(status: Int32, stderr: String) -> TokenReadError {
        switch status {
        case 44: return .notFound   // item not found
        case 51: return .accessDenied("authorization denied")   // curated denial code
        default: break
        }

        let message = stderr.lowercased()
        if message.contains("could not be found") {
            return .notFound
        }
        if message.contains("interaction")
            || message.contains("denied")
            || message.contains("cancel")
            || message.contains("authoriz")
        {
            return .accessDenied("Keychain access denied")
        }
        return .accessDenied("security exited \(status)")
    }

    // MARK: - Keychain

    private static func deriveKey(_ password: Data) -> [UInt8]? {
        let salt = Array("saltysalt".utf8)
        var key = [UInt8](repeating: 0, count: kCCKeySizeAES128)
        let status = password.withUnsafeBytes { passwordBytes in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                passwordBytes.baseAddress?.assumingMemoryBound(to: CChar.self), password.count,
                salt, salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1003,
                &key, key.count
            )
        }
        return status == kCCSuccess ? key : nil
    }

    private static func safeStoragePassword() -> Result<Data, TokenReadError> {
        lock.lock()
        defer { lock.unlock() }
        if let cachedPassword { return .success(cachedPassword) }
        let result = runSecurityTool(service: safeStorageService)
        if case .success(let password) = result { cachedPassword = password }
        return result
    }

    private static func dropCachedPassword() {
        lock.lock()
        defer { lock.unlock() }
        cachedPassword = nil
    }

    /// The secret travels back over a pipe — never through `argv`, never to
    /// disk. Both pipes are drained before `waitUntilExit()` so a full buffer
    /// cannot deadlock the child.
    private static func runSecurityTool(service: String) -> Result<Data, TokenReadError> {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: securityTool)
        process.arguments = ["find-generic-password", "-s", service, "-w"]
        let output = Pipe()
        let errors = Pipe()
        process.standardOutput = output
        process.standardError = errors

        do {
            try process.run()
        } catch {
            return .failure(.accessDenied("cannot run \(securityTool)"))
        }

        let outputData = output.fileHandleForReading.readDataToEndOfFile()
        let errorText = String(
            data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8
        ) ?? ""
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            return .failure(
                classifySecurityFailure(status: process.terminationStatus, stderr: errorText)
            )
        }

        // `-w` prints the secret followed by a newline.
        let text = (String(data: outputData, encoding: .utf8) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return .failure(.malformed) }
        return .success(Data(text.utf8))
    }

    /// Reports each step of the read — never any secret value.
    /// `ClaudeUsageBar --probe-token`.
    static func probe() {
        let configPresent = FileManager.default.fileExists(atPath: configURL.path)
        print("config:    \(configURL.path) — \(configPresent ? "present" : "absent")")
        print("key:       \(safeStorageService) — read via \(securityTool)")
        switch readValidToken() {
        case .success(let token):
            print("result:    OK")
            print("expiresAt: \(token.expiresAt.map { ISO8601DateFormatter().string(from: $0) } ?? "none")")
            print("token:     \(token.accessToken.count) chars (value withheld)")
        case .failure(let error):
            print("result:    FAILED — \(error.menuDetail)")
            print("           open the Claude app to fix? \(error.isFixedByOpeningClaude ? "yes" : "no")")
        }
    }
}
