import Foundation

/// Switches a UI test sets on the app's launch and a background-launched
/// tap can still read (a widget tap gets no launch environment): a marker
/// file in Caches, written when the app starts with the variable set and
/// removed when it starts without it.
enum TestHooks {
    private static var slowTapMarker: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("slow-widget-tap")
    }

    /// `AUGUST_SLOW_WIDGET_TAP=1`: a widget tap waits 5 s before the
    /// unlock, so the test can see the toggle's optimistic state; `0`
    /// clears it. A launch without the variable (the background launch the
    /// tap itself causes) leaves the marker alone.
    static func applyLaunchEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) {
        switch env["AUGUST_SLOW_WIDGET_TAP"] {
        case "1": try? Data().write(to: slowTapMarker)
        case "0": try? FileManager.default.removeItem(at: slowTapMarker)
        default: break
        }
    }

    static var slowWidgetTap: Bool { FileManager.default.fileExists(atPath: slowTapMarker.path) }
}
