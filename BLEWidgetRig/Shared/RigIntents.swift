import AppIntents
import WidgetKit

/// The widget's first button: the probe as AugustUnlock's widget runs its
/// unlock, in the app's process in the background (`supportedModes` with
/// `.foreground(.dynamic)`; the app never comes forward).
struct RigBackgroundProbeIntent: AppIntent {
    static let title: LocalizedStringResource = "Probe in the background"
    static let isDiscoverable = false
    static let supportedModes: IntentModes = [.background, .foreground(.dynamic)]

    func perform() async throws -> some IntentResult {
        await RigTap.probe(label: "widget-background")
        return .result()
    }
}

/// The widget's second button: the trade-off Tesla's widget takes. The
/// system opens the app, then runs the probe in it, in the foreground.
struct RigForegroundProbeIntent: AppIntent {
    static let title: LocalizedStringResource = "Probe in the foreground"
    static let isDiscoverable = false
    static let openAppWhenRun = true

    func perform() async throws -> some IntentResult {
        await RigTap.probe(label: "widget-foreground")
        return .result()
    }
}

enum RigTap {
    static func probe(label: String) async {
        #if WIDGET_EXTENSION
            // Not expected for either intent; logged so a wrong placement shows.
            let url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("rig-extension.log")
            try? "\(Date()) \(label) ran in the widget extension\n".write(to: url, atomically: true, encoding: .utf8)
        #else
            _ = await RigProbe.run(label: label)
        #endif
        WidgetCenter.shared.reloadTimelines(ofKind: "Rig")
    }
}
