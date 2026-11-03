import AppIntents
import WidgetKit

/// The widget's two buttons, one intent type per door position and no
/// parameters. Apple: a plain `AppIntent` behind a widget button goes in the
/// widget extension target AND the app target. `supportedModes` with
/// `.foreground(.dynamic)` makes the system run it in the app's process, in
/// the background (measured, Logbook 2026-11-02): the app's Bluetooth-first
/// client serves the tap, and the app never comes forward because nothing
/// here asks to continue in the foreground. Names share no word with either
/// module name: the metadata tool compresses repeated words into a mangled
/// form the runtime could not resolve (Logbook, 2026-11-01).
struct OpenFirstDoorIntent: AppIntent {
    static let title: LocalizedStringResource = "Open First Door"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication
    static let supportedModes: IntentModes = [.background, .foreground(.dynamic)]

    func perform() async throws -> some IntentResult {
        await DoorTap.unlock(position: 0)
        return .result()
    }
}

struct OpenSecondDoorIntent: AppIntent {
    static let title: LocalizedStringResource = "Open Second Door"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication
    static let supportedModes: IntentModes = [.background, .foreground(.dynamic)]

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
            // Not expected: the modes above put the tap in the app's process.
            WidgetLog.note("tap position=\(position) ran in the extension; nothing sent")
            WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
        #else
            await AppDoorAction.unlock(position: position)
        #endif
    }
}
