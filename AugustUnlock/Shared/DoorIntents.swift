import AppIntents

/// The widget's two buttons, one intent type per door position and no
/// parameters. Apple: a plain `AppIntent` behind a widget button goes in the
/// widget extension target AND the app target. The system runs it in the
/// widget by default; when it runs in the app instead, the app's own client
/// does the unlock. Names share no word with either module name: the
/// metadata tool compresses repeated words into a mangled form the runtime
/// could not resolve (Logbook, 2026-11-01).
struct OpenFirstDoorIntent: AppIntent {
    static let title: LocalizedStringResource = "Open First Door"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication

    func perform() async throws -> some IntentResult {
        await DoorTap.unlock(position: 0)
        return .result()
    }
}

struct OpenSecondDoorIntent: AppIntent {
    static let title: LocalizedStringResource = "Open Second Door"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication

    func perform() async throws -> some IntentResult {
        await DoorTap.unlock(position: 1)
        return .result()
    }
}

/// Position = index in the account's lock list sorted by lock ID, the order
/// both the widget's labels and the app's lock fetch use.
enum DoorTap {
    static func unlock(position: Int) async {
        #if WIDGET_EXTENSION
            await WidgetDoorAction.unlock(position: position)
        #else
            guard let locks = try? await AugustClient.shared.fetchLocks(), locks.indices.contains(position) else { return }
            _ = try? await AugustClient.shared.unlock(lockID: locks[position].id)
        #endif
    }
}
