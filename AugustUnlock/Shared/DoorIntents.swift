import AppIntents
import WidgetKit

#if !WIDGET_EXTENSION
    import UIKit
#endif

/// The widget's button: one intent, with the door's position (for the
/// widget's own per-door state) and the lock ID it shows, so a tap opens
/// exactly the door under the finger whatever lock list the app holds.
/// Apple: a plain `AppIntent` behind a widget button goes in the widget
/// extension target AND the app target. `supportedModes` with
/// `.foreground(.dynamic)` makes the system run it in the app's process, in
/// the background (measured, Logbook 2026-11-02): the app's Bluetooth-first
/// client serves the tap, and the app never comes forward because nothing
/// here asks to continue in the foreground. The name shares no word with
/// either module name: the metadata tool compresses repeated words into a
/// mangled form the runtime could not resolve (Logbook, 2026-11-01).
struct OpenDoorIntent: AppIntent {
    static let title: LocalizedStringResource = "Open Door"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication
    static let supportedModes: IntentModes = [.background, .foreground(.dynamic)]

    @Parameter(title: "Position")
    var position: Int

    @Parameter(title: "Lock")
    var lockID: String

    init() {}

    init(position: Int, lockID: String) {
        self.position = position
        self.lockID = lockID
    }

    func perform() async throws -> some IntentResult {
        await DoorTap.unlock(position: position, lockID: lockID)
        return .result()
    }
}

enum DoorTap {
    /// The first line of every tap is written from whatever process runs
    /// it, before anything can fail: a tap with no line in either log never
    /// reached the intent (the toggle's hit area, or a locked phone).
    static func unlock(position: Int, lockID: String) async {
        #if WIDGET_EXTENSION
            // Not expected: the modes above put the tap in the app's process.
            WidgetLog.note("tap position=\(position) ran in the extension; nothing sent")
            WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
        #else
            let state = await MainActor.run { UIApplication.shared.applicationState.rawValue }
            AppLog.note("widget intent position=\(position) in the app, state \(state)")
            await AppDoorAction.unlock(position: position, lockID: lockID)
        #endif
    }
}
