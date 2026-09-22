import Foundation

enum AugustError: LocalizedError {
    case badCredentials
    case requiresVerification
    case invalidCode
    case noLocks
    case notAuthenticated
    case server(Int, String)

    var errorDescription: String? {
        switch self {
        case .badCredentials: return "Incorrect August email or password."
        case .requiresVerification: return "Enter the verification code August emailed you."
        case .invalidCode: return "That verification code didn't work."
        case .noLocks: return "No locks found on this August account."
        case .notAuthenticated: return "Not signed in to August."
        case .server(let code, let body): return "August server error \(code): \(body)"
        }
    }
}

struct AugustLock: Identifiable, Equatable {
    let id: String
    let name: String
}

/// Talks to August's cloud API directly from the device — no home server in
/// the loop. Mirrors the request shapes in August/august_client.py (this
/// repo's Python client, built on the `yalexs` library) since there is no
/// official or third-party Swift SDK for August/Yale locks.
final class AugustClient {
    static let shared = AugustClient()

    private static let baseURL = "https://api-production.august.com"

    // August revoked the API key yalexs ships by default for password-auth
    // calls (session/login return 403 "API key is not valid"). This is the
    // legacy key August still accepts — see the matching comment and
    // `_WORKING_AUGUST_API_KEY` in August/august_client.py, which is the
    // proof this key currently works.
    private static let authAPIKey = "7cab4bbd-2693-4fc1-b99b-dec0fb20f9d4"  // # nosecret: public client key, already committed in August/august_client.py

    // Lock listing/unlock calls use a different key (tied to a different
    // internal "brand" in yalexs) than login/2FA, even though both hit the
    // same host and accept the same access token. Also taken from
    // August/august_client.py's proven-working call path.
    private static let lockAPIKey = "66814fd9-af2c-426c-9710-b37e7eadfb51"  // # nosecret: public client key, from yalexs' YALE_AUGUST brand config

    // August's backend appears to gate on a recognized client User-Agent.
    private static let userAgent = "August/Luna-22.17.0 (Android; SDK 31; gphone64_arm64)"

    private let session = URLSession(configuration: .ephemeral)

    private init() {}

    // MARK: - Persisted state (Keychain)

    private var installID: String {
        if let existing = KeychainStore.get("august_install_id") { return existing }
        let id = UUID().uuidString
        KeychainStore.set(id, forKey: "august_install_id")
        return id
    }

    var isReady: Bool {
        KeychainStore.get("august_access_token") != nil && KeychainStore.get("august_lock_id") != nil
    }

    var lockName: String? { KeychainStore.get("august_lock_name") }

    func signOut() {
        for key in [
            "august_email", "august_password", "august_access_token",
            "august_lock_id", "august_lock_name",
        ] {
            KeychainStore.remove(key)
        }
        // install_id is deliberately kept: reusing it on the next login
        // avoids tripping 2FA again for a device August already trusts.
    }

    // MARK: - Login flow

    /// Logs in with email+password. Returns true once fully authenticated;
    /// false if August still wants a verification code — call
    /// `sendVerificationCode()` next. Lock selection is a separate step
    /// (see `fetchLocks`/`selectLock`) since the caller decides how to
    /// handle a multi-lock account.
    @discardableResult
    func login(email: String, password: String) async throws -> Bool {
        KeychainStore.set(email, forKey: "august_email")
        KeychainStore.set(password, forKey: "august_password")
        return try await requestSession(email: email, password: password)
    }

    func sendVerificationCode() async throws {
        guard let token = KeychainStore.get("august_access_token"),
            let email = KeychainStore.get("august_email")
        else { throw AugustError.notAuthenticated }

        var request = makeRequest(path: "/validation/email", apiKey: Self.authAPIKey, accessToken: token)
        request.httpMethod = "POST"
        request.httpBody = try JSONSerialization.data(withJSONObject: ["value": email])
        let (data, response) = try await send(request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw AugustError.server(code, String(data: data, encoding: .utf8) ?? "")
        }
    }

    /// Validates the emailed code, then re-establishes the session (now
    /// fully authenticated, since this install_id is verified).
    func validateCode(_ code: String) async throws {
        guard let token = KeychainStore.get("august_access_token"),
            let email = KeychainStore.get("august_email"),
            let password = KeychainStore.get("august_password")
        else { throw AugustError.notAuthenticated }

        var request = makeRequest(path: "/validate/email", apiKey: Self.authAPIKey, accessToken: token)
        request.httpMethod = "POST"
        request.httpBody = try JSONSerialization.data(withJSONObject: ["email": email, "code": code])
        let (data, response) = try await send(request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
        guard statusCode == 200 else {
            // August rejects a wrong/expired code with 400; anything else
            // (401/403/5xx) is a real server problem, not a bad code.
            if statusCode == 400 {
                throw AugustError.invalidCode
            }
            throw AugustError.server(statusCode, String(data: data, encoding: .utf8) ?? "")
        }

        guard try await requestSession(email: email, password: password) else {
            throw AugustError.requiresVerification
        }
    }

    /// POSTs /session and stores the resulting access token. Returns true if
    /// fully authenticated, false if August still requires 2FA validation.
    private func requestSession(email: String, password: String) async throws -> Bool {
        var request = makeRequest(path: "/session", apiKey: Self.authAPIKey, accessToken: nil)
        request.httpMethod = "POST"
        // identifier must be "<login method>:<username>" (yalexs:
        // AuthenticatorAsync builds it as self._login_method + ":" +
        // self._username) — the bare email is rejected as a bad identifier,
        // which August's API surfaces identically to a bad password.
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "installId": installID,
            "identifier": "email:\(email)",
            "password": password,
        ])

        let (data, response) = try await send(request)
        guard let http = response as? HTTPURLResponse else { throw AugustError.notAuthenticated }
        if http.statusCode == 400 || http.statusCode == 401 {
            throw AugustError.badCredentials
        }
        guard http.statusCode == 200 else {
            throw AugustError.server(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        guard
            let accessToken = http.value(forHTTPHeaderField: "x-august-access-token")
                ?? http.value(forHTTPHeaderField: "x-access-token")
        else {
            throw AugustError.notAuthenticated
        }
        KeychainStore.set(accessToken, forKey: "august_access_token")

        // vPassword/vInstallId are JSON booleans (confirmed against captured
        // August /session responses), not strings — August/august_client.py
        // doesn't hit this directly (it goes through yalexs'
        // _authentication_from_session_response, which does the same
        // vPassword-then-vInstallId check).
        let json = (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
        guard (json["vPassword"] as? Bool) ?? false else {
            throw AugustError.badCredentials
        }
        return (json["vInstallId"] as? Bool) ?? false
    }

    // MARK: - Locks

    var hasSelectedLock: Bool { KeychainStore.get("august_lock_id") != nil }

    /// Fetches every lock on the account. Doesn't select one — the caller
    /// decides (auto-select when there's exactly one, otherwise prompt).
    func fetchLocks() async throws -> [AugustLock] {
        guard let token = KeychainStore.get("august_access_token") else { throw AugustError.notAuthenticated }
        let request = makeRequest(path: "/users/locks/mine", apiKey: Self.lockAPIKey, accessToken: token)
        let (data, response) = try await send(request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
        guard statusCode == 200 else {
            throw AugustError.server(statusCode, String(data: data, encoding: .utf8) ?? "")
        }

        guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: [String: Any]] else {
            throw AugustError.noLocks
        }
        // Dictionary iteration order is arbitrary (JSONSerialization does not
        // preserve key order, and Swift's is not stable across launches
        // either) — sort by lock ID so the list order is at least stable
        // across launches, even though it's arbitrary relative to the
        // account's real-world lock order.
        return raw.sorted { $0.key < $1.key }.compactMap { id, fields in
            (fields["LockName"] as? String).map { AugustLock(id: id, name: $0) }
        }
    }

    func selectLock(_ lock: AugustLock) {
        KeychainStore.set(lock.id, forKey: "august_lock_id")
        KeychainStore.set(lock.name, forKey: "august_lock_name")
    }

    // MARK: - Lock / unlock

    func unlock() async throws {
        try await operate(action: "unlock", isRetry: false)
    }

    func lock() async throws {
        try await operate(action: "lock", isRetry: false)
    }

    private func operate(action: String, isRetry: Bool) async throws {
        guard let token = KeychainStore.get("august_access_token") else { throw AugustError.notAuthenticated }
        guard let lockID = KeychainStore.get("august_lock_id") else { throw AugustError.noLocks }

        var request = makeRequest(
            path: "/remoteoperate/\(lockID)/\(action)", apiKey: Self.lockAPIKey, accessToken: token)
        request.httpMethod = "PUT"

        let (data, response) = try await send(request)
        guard let http = response as? HTTPURLResponse else {
            throw AugustError.server(-1, "no response")
        }

        if http.statusCode == 401, !isRetry {
            // Access token expired — silently re-authenticate with the
            // stored password (the install_id is already trusted, so this
            // does not trigger 2FA) and retry exactly once.
            guard let email = KeychainStore.get("august_email"),
                let password = KeychainStore.get("august_password"),
                try await requestSession(email: email, password: password)
            else {
                throw AugustError.notAuthenticated
            }
            try await operate(action: action, isRetry: true)
            return
        }

        guard (200...299).contains(http.statusCode) else {
            throw AugustError.server(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
    }

    // MARK: - HTTP plumbing

    private func makeRequest(path: String, apiKey: String, accessToken: String?) -> URLRequest {
        var request = URLRequest(url: URL(string: Self.baseURL + path)!)
        request.setValue(apiKey, forHTTPHeaderField: "x-august-api-key")
        request.setValue("august", forHTTPHeaderField: "x-august-branding")
        request.setValue("0.0.1", forHTTPHeaderField: "Accept-Version")
        request.setValue("application/json; charset=UTF-8", forHTTPHeaderField: "Content-Type")
        request.setValue("US", forHTTPHeaderField: "x-august-country")
        request.setValue(Self.userAgent, forHTTPHeaderField: "User-Agent")
        if let accessToken {
            request.setValue(accessToken, forHTTPHeaderField: "x-august-access-token")
        }
        return request
    }

    private func send(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await session.data(for: request)
    }
}
