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
    /// Every door's state and command, shared with widget taps.
    private let doors = DoorController.shared
    /// Set when the scene actually reaches `.background`, consumed on the
    /// next `.active`. A real background resume is `.background ->
    /// .inactive -> .active` (two onChange calls, never one direct
    /// `.background -> .active` pairing), so this can't be a same-call
    /// oldPhase/newPhase check — see the Logbook entry for why.
    @State private var wasBackgrounded = false
    /// Quits the app after `BackgroundExitPolicy.defaultTimeout` in the
    /// background. Checked on a timer (runs only while iOS keeps the process
    /// awake) and again on return to the foreground (the case that matters,
    /// since a suspended process runs no timers) — see the Logbook.
    @State private var exitPolicy = BackgroundExitPolicy()
    @State private var exitTimer: Task<Void, Never>?
    /// The path icon's side, so it scales with Dynamic Type like the caption.
    @ScaledMetric(relativeTo: .caption) private var captionIconSize: CGFloat = 12

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
            // A widget tap can launch the app in the background (see
            // ToggleDoorIntent). If iOS connects the scene then, it must not
            // unlock the selected door: treat it as backgrounded, so the first
            // real open unlocks instead.
            if UIApplication.shared.applicationState == .background {
                wasBackgrounded = true
                exitPolicy.didBackground(at: Date())
                armExitTimer()
            } else {
                openUnlock()
            }
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
                exitPolicy.didBackground(at: Date())
                armExitTimer()
            case .active where wasBackgrounded:
                wasBackgrounded = false
                exitTimer?.cancel()
                let expired = exitPolicy.shouldExit(at: Date(), operationInFlight: doors.isBusy)
                exitPolicy.didForeground()
                if expired { exit(0) }
                doors.refreshFromStore()
                openUnlock()
            default:
                break
            }
        }
        // A command that outlived the background deadline quits the app once it ends.
        .onChange(of: doors.isBusy) { _, busy in
            if !busy { exitIfExpired() }
        }
    }

    /// Quits once the background deadline passes. A command still in flight
    /// postpones it; the `doors.isBusy` watch calls this again when it ends.
    private func armExitTimer() {
        exitTimer?.cancel()
        guard let remaining = exitPolicy.remaining(at: Date()) else { return }
        exitTimer = Task {
            try? await Task.sleep(for: .seconds(remaining))
            guard !Task.isCancelled else { return }
            exitIfExpired()
        }
    }

    private func exitIfExpired() {
        if exitPolicy.shouldExit(at: Date(), operationInFlight: doors.isBusy) { exit(0) }
    }

    /// See `DoorController.openUnlock()`.
    private func openUnlock() {
        guard phase == .ready else { return }
        doors.openUnlock()
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

    /// Enters the ready/unlock screen and auto-unlocks — the single
    /// path every "setup just finished" transition (already-signed-in,
    /// single-lock auto-select, or a fresh lock pick) must go through so the
    /// promised "opens unlocked" behavior actually holds the first time,
    /// not just on a later cold launch or background resume.
    private func enterReady() {
        phase = .ready
        openUnlock()
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
                    enterReady()
                }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity)
            }
        }
        .frame(maxWidth: 320)
    }

    // MARK: - Doors

    private var unlockScreen: some View {
        VStack(spacing: 32) {
            Button {
                doors.tap()
            } label: {
                DoorCircle(name: pickedDoorName, display: doors.display, diameter: 200)
            }
            .buttonStyle(.plain)

            if let lastError = doors.lastError {
                Text(lastError).foregroundStyle(.red).font(.footnote)
            }

            if let lastTiming = doors.lastTiming {
                HStack(spacing: 4) {
                    lastTiming.icon
                        .resizable()
                        .scaledToFit()
                        .frame(width: captionIconSize, height: captionIconSize)
                        .foregroundStyle(lastTiming.tint)
                        .accessibilityLabel(lastTiming.pathLabel)
                    Text(lastTiming.summary)
                        .foregroundStyle(.tertiary)
                        .monospacedDigit()
                }
                .font(.caption)
                .accessibilityElement(children: .combine)
            }

            HStack(spacing: 24) {
                Button("Change Lock") {
                    Task { await presentLockPicker() }
                }
                Button("Sign Out") {
                    // Door state is keyed by the lock list, so clear it first.
                    doors.signOut()
                    AugustClient.shared.signOut()
                    email = ""
                    password = ""
                    code = ""
                    phase = .needsLogin
                }
            }
            // Both stay live during a command (asked for): switching lock
            // cancels it, and the outcome shows up in the widget's state.
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    /// "Front door" or "Garage" by the lock's place in the account's list;
    /// a lock outside that list keeps its August name.
    private var pickedDoorName: String {
        let locks = AugustClient.shared.cachedLocks ?? []
        if let id = AugustClient.shared.selectedLockID, let slot = locks.firstIndex(where: { $0.id == id }),
            let name = Doors.name(forSlot: slot)
        {
            return name
        }
        return AugustClient.shared.lockName ?? "Door"
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
}

#Preview {
    ContentView()
}
