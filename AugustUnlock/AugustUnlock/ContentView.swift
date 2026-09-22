import SwiftUI

private enum Phase {
    case loading
    case needsLogin
    case needsCode
    case pickLock
    case ready
}

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var phase: Phase = .loading

    @State private var email = ""
    @State private var password = ""
    @State private var code = ""
    @State private var availableLocks: [AugustLock] = []
    @State private var errorMessage: String?
    @State private var isBusy = false
    @State private var operationResult: OperationResult = .idle
    /// Optimistic, session-local belief about the door's current state —
    /// there's no status poll, just the outcome of the last lock/unlock this
    /// app issued. Resets to `false` (locked) on every fresh launch.
    @State private var isUnlocked = false
    /// Set when the scene actually reaches `.background`, consumed on the
    /// next `.active`. A real background resume is `.background ->
    /// .inactive -> .active` (two onChange calls, never one direct
    /// `.background -> .active` pairing), so this can't be a same-call
    /// oldPhase/newPhase check — see the Logbook entry for why.
    @State private var wasBackgrounded = false

    private enum OperationResult: Equatable {
        case idle
        case inProgress
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
            autoUnlockIfReady()
        }
        .onChange(of: scenePhase) { _, newPhase in
            // Covers reopening from the background, not just cold launch —
            // onAppear alone only fires once per view lifetime. A real
            // resume is .background -> .inactive -> .active (two separate
            // onChange calls, so a same-call oldPhase check never matches);
            // a transient interruption (Control Center, Notification
            // Center, the incoming-call banner) is .active -> .inactive ->
            // .active and never touches .background at all. Track having
            // actually seen .background and consume it on .active, instead
            // of pattern-matching a single transition.
            switch newPhase {
            case .background:
                wasBackgrounded = true
            case .active where wasBackgrounded:
                wasBackgrounded = false
                autoUnlockIfReady()
            default:
                break
            }
        }
    }

    /// Fires the unlock the moment the app is opened, with no button tap —
    /// requested explicitly: opening the app is the confirmation. Guarded on
    /// `.idle` so a mid-operation re-open can't double-fire, and on
    /// `!isUnlocked` so re-opening an already-unlocked session doesn't
    /// needlessly resend the command.
    private func autoUnlockIfReady() {
        guard phase == .ready, operationResult == .idle, !isUnlocked else { return }
        Task { await performUnlock() }
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
            enterReady()
            return
        }
        do {
            let locks = try await AugustClient.shared.fetchLocks()
            switch locks.count {
            case 0:
                errorMessage = AugustError.noLocks.errorDescription
            case 1:
                AugustClient.shared.selectLock(locks[0])
                enterReady()
            default:
                availableLocks = locks
                phase = .pickLock
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Enters the ready/unlock screen and fires the auto-unlock — the single
    /// path every "setup just finished" transition (already-signed-in,
    /// single-lock auto-select, or a fresh lock pick) must go through so the
    /// promised "opens unlocked" behavior actually holds the first time,
    /// not just on a later cold launch or background resume.
    private func enterReady() {
        phase = .ready
        autoUnlockIfReady()
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
                    // isUnlocked tracked the *previous* lock (relevant when
                    // reached via "Change Lock"), not this one — reset so
                    // enterReady()'s auto-unlock actually fires for it.
                    isUnlocked = false
                    enterReady()
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
                Task { await performToggle() }
            } label: {
                ZStack {
                    Circle()
                        .fill(buttonColor)
                        .frame(width: 200, height: 200)
                    if operationResult == .inProgress {
                        ProgressView().tint(.white).scaleEffect(1.5)
                    } else {
                        Image(systemName: isUnlocked ? "lock.open.fill" : "lock.fill")
                            .font(.system(size: 64))
                            .foregroundStyle(.white)
                    }
                }
            }
            .disabled(operationResult == .inProgress)

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
                    isUnlocked = false
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

    private var buttonColor: Color {
        switch operationResult {
        case .failure: return .red
        case .inProgress: return .accentColor
        case .idle, .success: return isUnlocked ? .green : .accentColor
        }
    }

    @ViewBuilder
    private var statusText: some View {
        switch operationResult {
        case .idle: Text(isUnlocked ? "Unlocked — tap to lock" : "Tap to unlock").foregroundStyle(.secondary)
        case .inProgress: Text(isUnlocked ? "Locking\u{2026}" : "Unlocking\u{2026}").foregroundStyle(.secondary)
        case .success: Text(isUnlocked ? "Unlocked" : "Locked").foregroundStyle(isUnlocked ? .green : .secondary)
        case .failure(let message): Text(message).foregroundStyle(.red).font(.footnote)
        }
    }

    /// Auto-unlock on app open always unlocks — it never locks on your
    /// behalf without a tap.
    private func performUnlock() async {
        await performOperation(unlocking: true)
    }

    /// Button tap: toggles based on the last known state.
    private func performToggle() async {
        await performOperation(unlocking: !isUnlocked)
    }

    private func performOperation(unlocking: Bool) async {
        operationResult = .inProgress
        let feedback = UINotificationFeedbackGenerator()
        do {
            if unlocking {
                try await AugustClient.shared.unlock()
            } else {
                try await AugustClient.shared.lock()
            }
            isUnlocked = unlocking
            operationResult = .success
            feedback.notificationOccurred(.success)
        } catch {
            operationResult = .failure(error.localizedDescription)
            feedback.notificationOccurred(.error)
        }
        try? await Task.sleep(for: .seconds(2))
        if case .inProgress = operationResult {} else {
            operationResult = .idle
        }
    }
}

#Preview {
    ContentView()
}
