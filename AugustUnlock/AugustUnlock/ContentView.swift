import SwiftUI

private enum Phase {
    case loading
    case needsLogin
    case needsCode
    case ready
}

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var phase: Phase = .loading
    @State private var model = DoorsModel()

    @State private var email = ""
    @State private var password = ""
    @State private var code = ""
    @State private var errorMessage: String?
    @State private var isBusy = false

    var body: some View {
        VStack(spacing: 24) {
            switch phase {
            case .loading:
                ProgressView()
            case .needsLogin:
                loginForm
            case .needsCode:
                codeForm
            case .ready:
                doorsScreen
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background {
            if phase == .ready { DoorsBackground() }
        }
        // The build's date, time and commit, set by `scripts/build_ipa.sh`
        // (`BUILD_STAMP` into Info.plist); an Xcode build has none.
        .overlay(alignment: .bottom) {
            if let stamp = Bundle.main.object(forInfoDictionaryKey: "BuildStamp") as? String, !stamp.isEmpty {
                Text("Build \(stamp)").font(.caption2).foregroundStyle(.quaternary)
            }
        }
        .task { await start() }
        // A tap on the widget outside its toggles opens the app with this
        // URL: the line tells a missed tap from an open by hand.
        .onOpenURL { url in AppLog.note("opened by the widget body: \(url.host ?? url.absoluteString)") }
        .onChange(of: scenePhase) { _, newPhase in model.scenePhaseChanged(to: newPhase) }
    }

    /// The cached doors show at once and a fresh list follows quietly. With a
    /// session and no list (a first launch of this build, or a sign-in cut off
    /// before its code) the list decides: a session August refuses signs in
    /// again.
    private func start() async {
        guard August.shared.hasSession else {
            phase = .needsLogin
            return
        }
        let cached = August.shared.cachedLocks
        if !cached.isEmpty {
            model.show(cached)
            phase = .ready
            if let locks = try? await August.shared.fetchLocks(), !locks.isEmpty { model.show(locks) }
            return
        }
        await resolveLocks()
        if phase != .ready { phase = .needsLogin }
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
            let authenticated = try await August.shared.login(email: email, password: password)
            if authenticated {
                await resolveLocks()
            } else {
                try await August.shared.sendVerificationCode()
                phase = .needsCode
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// After a fresh login or code: fetch the doors and show them. Nothing is
    /// sent to a door.
    private func resolveLocks() async {
        do {
            let locks = try await August.shared.fetchLocks()
            guard !locks.isEmpty else {
                errorMessage = AugustError.noLocks.errorDescription
                return
            }
            model.show(locks)
            phase = .ready
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
            try await August.shared.validateCode(code)
            await resolveLocks()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Doors

    private var doorsScreen: some View {
        VStack(spacing: 0) {
            Text("The gates of Eden")
                .font(.largeTitle.bold())
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 8)
                .padding(.bottom, 18)
                .accessibilityAddTraits(.isHeader)
            // Large text or many locks scroll, with Sign Out still in reach.
            ViewThatFits(in: .vertical) {
                doorCards
                ScrollView { doorCards }
            }
            .layoutPriority(1)
            Spacer(minLength: 24)
            // Live during a command (asked for, 2026-11-01): the commands are
            // cancelled; a request August already holds may still move a door.
            Button("Sign Out") {
                model.signOut()
                August.shared.signOut()
                email = ""
                password = ""
                code = ""
                phase = .needsLogin
            }
            .buttonStyle(.glass)
            .font(.subheadline)
            .foregroundStyle(.secondary)
            // Clear of the build stamp.
            .padding(.bottom, 24)
        }
    }
}

private extension ContentView {
    /// The cards take the free space, up to a size that still reads as a card
    /// on an account with one lock.
    var doorCards: some View {
        VStack(spacing: 16) {
            ForEach(model.doors) { door in
                DoorRow(door: door).frame(minHeight: 140, maxHeight: 280)
            }
        }
    }
}

#Preview {
    ContentView()
}
