import Foundation

/// Switches a UI test sets on the app's launch and a background-launched
/// tap can still read (a widget tap gets no launch environment): a marker
/// file in Caches, written when the app starts with the variable set and
/// removed when it starts without it.
enum TestHooks {
    private static func marker(_ name: String) -> URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent(name)
    }

    private static let slowTapMarker = marker("slow-widget-tap")
    private static let fakeMarker = marker("fake-august")

    /// `AUGUST_SLOW_WIDGET_TAP=1`: a widget tap waits 5 s before the
    /// unlock, so the test can see the toggle's optimistic state.
    /// `AUGUST_FAKE=1`: a widget tap goes to `FakeAugust` too. `0` clears
    /// either. A launch without the variable (the background launch the tap
    /// itself causes) leaves the markers alone.
    static func applyLaunchEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) {
        for (variable, marker) in [("AUGUST_SLOW_WIDGET_TAP", slowTapMarker), ("AUGUST_FAKE", fakeMarker)] {
            switch env[variable] {
            case "1": try? Data().write(to: marker)
            case "0": try? FileManager.default.removeItem(at: marker)
            default: break
            }
        }
    }

    static var slowWidgetTap: Bool { FileManager.default.fileExists(atPath: slowTapMarker.path) }
    static var fakeAugust: Bool { FileManager.default.fileExists(atPath: fakeMarker.path) }
}
