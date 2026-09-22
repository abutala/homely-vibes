import SwiftUI

private enum Phase {
    case loading
    case needsLogin
    case needsCode
    case pickLock
    case ready
}

struct ContentView: View {
    @State private var phase: Phase = .loading

    @State private var email = ""
    @State private var password = ""
    @State private var code = ""
    @State private var availableLocks: [AugustLock] = []
    @State private var errorMessage: String?
    @State private var isBusy = false
    @State private var unlockResult: UnlockResult = .idle

    private enum UnlockResult: Equatable {
        case idle
        case unlocking
        case success
        case failure(String)
    }

    var body: some View {
        VStack(spacing: 24) {
            switch phase {
            case .loading:
                ProgressView()
            case .needsLogin:
                loginForm
            case .needsCode:
                codeForm
            case .pickLock:
                pickLockView
            case .ready:
                unlockScreen
            }
        }
        .padding()
        .onAppear {
            phase = AugustClient.shared.isReady ? .ready : .needsLogin
        }
    }

    // MARK: - Login

    private var loginForm: some View {
        VStack(spacing: 16) {
            Text("Sign in to August")
                .font(.title2).bold()
            TextField("Email", text: $email)
                .textContentType(.username)
                .keyboardType(.emailAddress)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
            SecureField("Password", text: $password)
                .textContentType(.password)
                .textFieldStyle(.roundedBorder)
            if let errorMessage {
                Text(errorMessage).foregroundStyle(.red).font(.footnote)
            }
            Button {
                Task { await submitLogin() }
            } label: {
                if isBusy { ProgressView() } else { Text("Sign In").frame(maxWidth: .infinity) }
            }
            .buttonStyle(.borderedProminent)
            .disabled(email.isEmpty || password.isEmpty || isBusy)
        }
        .frame(maxWidth: 320)
    }

    private func submitLogin() async {
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do {
            let authenticated = try await AugustClient.shared.login(email: email, password: password)
            if authenticated {
                await resolveLock()
            } else {
                try await AugustClient.shared.sendVerificationCode()
                phase = .needsCode
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// After a fresh login/verification: keep an already-chosen lock as-is,
    /// auto-select the only lock on a single-lock account (today's
    /// zero-tap behavior), or ask when there's more than one.
    private func resolveLock() async {
        if AugustClient.shared.hasSelectedLock {
            phase = .ready
            return
        }
        do {
            let locks = try await AugustClient.shared.fetchLocks()
            switch locks.count {
            case 0:
                errorMessage = AugustError.noLocks.errorDescription
            case 1:
                AugustClient.shared.selectLock(locks[0])
                phase = .ready
            default:
                availableLocks = locks
                phase = .pickLock
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - 2FA code

    private var codeForm: some View {
        VStack(spacing: 16) {
            Text("Check your email")
                .font(.title2).bold()
            Text("August emailed \(email) a verification code.")
                .font(.footnote)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            TextField("Code", text: $code)
                .keyboardType(.numberPad)
                .textFieldStyle(.roundedBorder)
                .multilineTextAlignment(.center)
            if let errorMessage {
                Text(errorMessage).foregroundStyle(.red).font(.footnote)
            }
            Button {
                Task { await submitCode() }
            } label: {
                if isBusy { ProgressView() } else { Text("Verify").frame(maxWidth: .infinity) }
            }
            .buttonStyle(.borderedProminent)
            .disabled(code.isEmpty || isBusy)
        }
        .frame(maxWidth: 320)
    }

    private func submitCode() async {
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do {
            try await AugustClient.shared.validateCode(code)
            await resolveLock()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Lock picker

    private var pickLockView: some View {
        VStack(spacing: 16) {
            Text("Choose a Lock")
                .font(.title2).bold()
            Text("Your August account has more than one lock.")
                .font(.footnote)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            ForEach(availableLocks) { lock in
                Button(lock.name) {
                    AugustClient.shared.selectLock(lock)
                    phase = .ready
                }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity)
            }
        }
        .frame(maxWidth: 320)
    }

    // MARK: - Unlock

    private var unlockScreen: some View {
        VStack(spacing: 32) {
            if let lockName = AugustClient.shared.lockName {
                Text(lockName)
                    .font(.headline)
                    .foregroundStyle(.secondary)
            }

            Button {
                Task { await performUnlock() }
            } label: {
                ZStack {
                    Circle()
                        .fill(unlockButtonColor)
                        .frame(width: 200, height: 200)
                    if unlockResult == .unlocking {
                        ProgressView().tint(.white).scaleEffect(1.5)
                    } else {
                        Image(systemName: unlockResult == .success ? "lock.open.fill" : "lock.fill")
                            .font(.system(size: 64))
                            .foregroundStyle(.white)
                    }
                }
            }
            .disabled(unlockResult == .unlocking)

            statusText

            HStack(spacing: 24) {
                Button("Change Lock") {
                    Task { await presentLockPicker() }
                }
                Button("Sign Out") {
                    AugustClient.shared.signOut()
                    email = ""
                    password = ""
                    code = ""
                    phase = .needsLogin
                }
            }
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    /// Re-fetches the account's locks and shows the picker again, even if
    /// there's only one — lets a wrong first-time pick be corrected without
    /// signing all the way out.
    private func presentLockPicker() async {
        errorMessage = nil
        do {
            availableLocks = try await AugustClient.shared.fetchLocks()
            phase = availableLocks.isEmpty ? .ready : .pickLock
            if availableLocks.isEmpty {
                errorMessage = AugustError.noLocks.errorDescription
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private var unlockButtonColor: Color {
        switch unlockResult {
        case .idle, .unlocking: return .accentColor
        case .success: return .green
        case .failure: return .red
        }
    }

    @ViewBuilder
    private var statusText: some View {
        switch unlockResult {
        case .idle: Text("Tap to unlock").foregroundStyle(.secondary)
        case .unlocking: Text("Unlocking\u{2026}").foregroundStyle(.secondary)
        case .success: Text("Unlocked").foregroundStyle(.green)
        case .failure(let message): Text(message).foregroundStyle(.red).font(.footnote)
        }
    }

    private func performUnlock() async {
        unlockResult = .unlocking
        let feedback = UINotificationFeedbackGenerator()
        do {
            try await AugustClient.shared.unlock()
            unlockResult = .success
            feedback.notificationOccurred(.success)
        } catch {
            unlockResult = .failure(error.localizedDescription)
            feedback.notificationOccurred(.error)
        }
        try? await Task.sleep(for: .seconds(2))
        if case .unlocking = unlockResult {} else {
            unlockResult = .idle
        }
    }
}

#Preview {
    ContentView()
}
