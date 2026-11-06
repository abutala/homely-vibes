import AppKit

@main
struct MergeQueueBarApp {
    @MainActor
    static func main() {
        if CommandLine.arguments.contains("--probe") {
            probe()
            return
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }

    /// One fetch, printed: `swift run MergeQueueBar --probe`.
    private static func probe() {
        do {
            let s = try GitHubClient.fetch()
            print(SummaryText.title(s))
            print(SummaryText.queueLine(s))
            print("Landed \(SummaryText.historyLine(s.landedByDay))")
            s.queued.forEach { print("  queued: \(SummaryText.row($0))") }
            s.failedToday.forEach { print("  failed: \(SummaryText.row($0))") }
            print(SummaryText.mineLine(s))
            print("Merged \(SummaryText.historyLine(s.mineMergedByDay))")
            s.mineOpen.forEach { print("  mine: \(SummaryText.row($0))") }
        } catch {
            print("fetch failed: \(SummaryText.describe(error))")
            exit(1)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var controller: StatusItemController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let controller = StatusItemController()
        controller.start()
        self.controller = controller
    }
}
