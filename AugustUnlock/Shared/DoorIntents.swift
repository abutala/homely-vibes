import AppIntents
import WidgetKit

#if !WIDGET_EXTENSION
    import UIKit
#endif

/// The widget's button: one intent, with the door's position (for the
/// widget's own per-door state), the lock ID it shows, so a tap opens
/// exactly the door under the finger whatever lock list the app holds, and
/// the name it shows, for the tap's Live Activity. A `LiveActivityIntent`,
/// so `perform()` may start that activity with the app in the background
/// (Apple; measured on the phone, Logbook 2026-11-07).
/// The intent type goes in the widget extension target AND the app target
/// (Apple). `supportedModes` with
/// `.foreground(.dynamic)` makes the system run it in the app's process, in
/// the background (measured, Logbook 2026-11-02): the app's Bluetooth-first
/// client serves the tap, and the app never comes forward because nothing
/// here asks to continue in the foreground. The name shares no word with
/// either module name: the metadata tool compresses repeated words into a
/// mangled form the runtime could not resolve (Logbook, 2026-11-01).
struct OpenDoorIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Open Door"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication
    static let supportedModes: IntentModes = [.background, .foreground(.dynamic)]

    @Parameter(title: "Position")
    var position: Int

    @Parameter(title: "Lock")
    var lockID: String

    /// Empty in a button archived before this parameter existed.
    @Parameter(title: "Name", default: "")
    var name: String

    init() {}

    init(position: Int, lockID: String, name: String) {
        self.position = position
        self.lockID = lockID
        self.name = name
    }

    func perform() async throws -> some IntentResult {
        await DoorTap.unlock(position: position, lockID: lockID, name: name)
        return .result()
    }
}

/// The widget's center button: lock both doors, under the same rules as
/// `OpenDoorIntent`. The name shares no word with either module name, for the
/// same reason.
struct SecureDoorsIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Lock Both"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication
    static let supportedModes: IntentModes = [.background, .foreground(.dynamic)]

    /// The locks the widget shows, by position, so a tap locks the doors on
    /// its buttons whatever lock list the app holds.
    @Parameter(title: "Locks")
    var lockIDs: [String]

    init() {}

    init(lockIDs: [String]) {
        self.lockIDs = lockIDs
    }

    func perform() async throws -> some IntentResult {
        await DoorTap.lockBoth(lockIDs: lockIDs)
        return .result()
    }
}

enum DoorTap {
    /// The first line of every tap is written from whatever process runs
    /// it, before anything can fail: a tap with no line in either log never
    /// reached the intent (the toggle's hit area, or a locked phone).
    static func unlock(position: Int, lockID: String, name: String) async {
        #if WIDGET_EXTENSION
            // Not expected: the modes above put the tap in the app's process.
            WidgetLog.note("tap position=\(position) ran in the extension; nothing sent")
            WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
        #else
            let state = await MainActor.run { UIApplication.shared.applicationState.rawValue }
            AppLog.note("widget intent position=\(position) in the app, state \(state)")
            await AppDoorAction.unlock(position: position, lockID: lockID, name: name)
        #endif
    }

    static func lockBoth(lockIDs: [String]) async {
        #if WIDGET_EXTENSION
            WidgetLog.note("lock both ran in the extension; nothing sent")
            WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
        #else
            let state = await MainActor.run { UIApplication.shared.applicationState.rawValue }
            AppLog.note("widget lock both intent in the app, state \(state)")
            await AppDoorAction.lockBoth(lockIDs: lockIDs)
        #endif
    }
}
