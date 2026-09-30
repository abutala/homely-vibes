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
    /// What August last reported for the selected lock — fetched on every
    /// open and taken from each lock/unlock reply, never inferred from the
    /// command this app sent.
    @State private var lockState: LockState = .unknown
    /// The status check, lock or unlock in flight, kept so a newer one can
    /// cancel it — see `run(_:)`.
    @State private var operationTask: Task<Void, Never>?
    /// Set when the scene actually reaches `.background`, consumed on the
    /// next `.active`. A real background resume is `.background ->
    /// .inactive -> .active` (two onChange calls, never one direct
    /// `.background -> .active` pairing), so this can't be a same-call
    /// oldPhase/newPhase check — see the Logbook entry for why.
    @State private var wasBackgrounded = false

    private enum OperationResult: Equatable {
        case idle
        case checking
        case inProgress(unlocking: Bool)
        case success
        case failure(String)
    }

    private var isOperating: Bool {
        switch operationResult {
        case .checking, .inProgress: return true
        case .idle, .success, .failure: return false
        }
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
            syncThenUnlock()
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
                syncThenUnlock()
            default:
                break
            }
        }
    }

    /// Opening the app — cold launch, finishing setup, or returning from the
    /// background — fetches the lock's real state from August, then unlocks
    /// unless it already is; opening the app is the confirmation (requested
    /// explicitly). Nothing from before is trusted: the door may have
    /// auto-locked or been operated elsewhere meanwhile, and a request iOS
    /// suspended with the app tends to come back as a lost connection — so
    /// whatever is still in flight is cancelled and its result discarded.
    private func syncThenUnlock() {
        guard phase == .ready else { return }
        run {
            operationResult = .checking
            let state = try await AugustClient.shared.fetchLockState()
            try Task.checkCancellation()
            lockState = state
            if state == .unlocked {
                operationResult = .idle
            } else {
                try await performOperation(unlocking: true)
            }
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

    /// Enters the ready/unlock screen and syncs + auto-unlocks — the single
    /// path every "setup just finished" transition (already-signed-in,
    /// single-lock auto-select, or a fresh lock pick) must go through so the
    /// promised "opens unlocked" behavior actually holds the first time,
    /// not just on a later cold launch or background resume.
    private func enterReady() {
        phase = .ready
        syncThenUnlock()
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
                    // lockState described the *previous* lock (relevant when
                    // reached via "Change Lock") — clear it so the screen
                    // doesn't show that lock's state until this one's arrives.
                    lockState = .unknown
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
                performToggle()
            } label: {
                ZStack {
                    Circle()
                        .fill(buttonColor)
                        .frame(width: 200, height: 200)
                    if isOperating {
                        ProgressView().tint(.white).scaleEffect(1.5)
                    } else {
                        Image(systemName: lockState == .unlocked ? "lock.open.fill" : "lock.fill")
                            .font(.system(size: 64))
                            .foregroundStyle(.white)
                    }
                }
            }
            .disabled(isOperating)

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
                    lockState = .unknown
                    phase = .needsLogin
                }
            }
            // Switching lock or signing out mid-operation would drop the
            // lock being acted on off screen with its outcome unknown —
            // the request still reaches August even if the app stops
            // listening. Blocking both while in flight is simpler and safer
            // than reconciling a result for a lock no longer shown.
            .disabled(isOperating)
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
        case .checking, .inProgress: return .accentColor
        case .idle, .success: return lockState == .unlocked ? .green : .accentColor
        }
    }

    private var stateLabel: String {
        switch lockState {
        case .locked: return "Locked"
        case .unlocked: return "Unlocked"
        case .unknown: return "State unknown"
        }
    }

    @ViewBuilder
    private var statusText: some View {
        switch operationResult {
        case .idle:
            Text("\(stateLabel) \u{2014} tap to \(lockState == .unlocked ? "lock" : "unlock")")
                .foregroundStyle(.secondary)
        case .checking: Text("Checking lock\u{2026}").foregroundStyle(.secondary)
        case .inProgress(let unlocking):
            Text(unlocking ? "Unlocking\u{2026}" : "Locking\u{2026}").foregroundStyle(.secondary)
        case .success: Text(stateLabel).foregroundStyle(lockState == .unlocked ? .green : .secondary)
        case .failure(let message): Text(message).foregroundStyle(.red).font(.footnote)
        }
    }

    /// Button tap: locks if August last reported unlocked, otherwise
    /// unlocks — including when the state is unknown, since unlocking is
    /// what this app is for.
    private func performToggle() {
        run { try await performOperation(unlocking: lockState != .unlocked) }
    }

    private func performOperation(unlocking: Bool) async throws {
        operationResult = .inProgress(unlocking: unlocking)
        let state = try await (unlocking ? AugustClient.shared.unlock() : AugustClient.shared.lock())
        try Task.checkCancellation()
        lockState = state
        operationResult = .success
        UINotificationFeedbackGenerator().notificationOccurred(.success)
    }

    /// Runs one operation at a time, cancelling any still in flight. Every
    /// state write in an operation follows a cancellation check, so a
    /// cancelled one's late reply can't overwrite its replacement's.
    private func run(_ operation: @escaping () async throws -> Void) {
        operationTask?.cancel()
        operationTask = Task {
            do {
                try await operation()
            } catch {
                guard !Task.isCancelled else { return }
                operationResult = .failure(error.localizedDescription)
                UINotificationFeedbackGenerator().notificationOccurred(.error)
            }
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            switch operationResult {
            case .success, .failure: operationResult = .idle
            case .idle, .checking, .inProgress: break
            }
        }
    }
}

#Preview {
    ContentView()
}
