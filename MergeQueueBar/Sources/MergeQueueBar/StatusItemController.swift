import AppKit
import os.log

@MainActor
final class StatusItemController {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let logger = Logger(subsystem: "com.deviationlabs.MergeQueueBar", category: "refresh")
    private var timer: Timer?
    private var state: State = .loading
    /// One fetch at a time: a slow fetch can neither pile up nor overwrite a newer one.
    private var isRefreshing = false

    private static let allPullsURL = URL(string: "https://github.com/pulls")!
    private static let myPullsURL = URL(string: "https://github.com/pulls/authored")!

    /// A failed refresh keeps the last good numbers, marked stale.
    private enum State {
        case loading
        case ok(QueueSnapshot)
        case stale(QueueSnapshot, reason: String)
        case failed(String)

        var snapshot: QueueSnapshot? {
            switch self {
            case .ok(let s), .stale(let s, _): return s
            case .loading, .failed: return nil
            }
        }
    }

    func start() {
        render(.loading)
        refresh()
        scheduleTimer()
    }

    private func scheduleTimer() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: RefreshInterval.current, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    private func refresh() {
        guard !isRefreshing else { return }
        isRefreshing = true
        Task {
            defer { isRefreshing = false }
            let result = await Task.detached { Result { try GitHubClient.fetch() } }.value
            switch result {
            case .success(let snapshot):
                logger.info("refresh OK: \(SummaryText.title(snapshot), privacy: .public)")
                render(.ok(snapshot))
            case .failure(let error):
                let reason = SummaryText.describe(error)
                logger.error("refresh FAILED: \(reason, privacy: .public)")
                render(state.snapshot.map { .stale($0, reason: reason) } ?? .failed(reason))
            }
        }
    }

    private func render(_ newState: State) {
        state = newState
        switch newState {
        case .loading: statusItem.button?.title = "MQ \u{2026}"
        case .ok(let s): statusItem.button?.title = SummaryText.title(s)
        case .stale(let s, _): statusItem.button?.title = "\(SummaryText.title(s)) \(SummaryText.staleMarker)"
        case .failed: statusItem.button?.title = "MQ \u{2014}"
        }
        statusItem.menu = buildMenu()
    }

    private func buildMenu() -> NSMenu {
        let menu = NSMenu()
        // Info rows stay enabled so AppKit does not grey them out.
        menu.autoenablesItems = false
        switch state {
        case .loading:
            menu.addItem(info("Loading\u{2026}"))
        case .failed(let reason):
            menu.addItem(info("\(SummaryText.staleMarker) \(reason)"))
        case .stale(let s, let reason):
            menu.addItem(info("\(SummaryText.staleMarker) Stale: \(reason)"))
            menu.addItem(.separator())
            appendSnapshot(s, to: menu)
        case .ok(let s):
            appendSnapshot(s, to: menu)
        }
        menu.addItem(.separator())
        menu.addItem(link("Open PRs on GitHub", Self.allPullsURL))
        menu.addItem(link("My PRs on GitHub", Self.myPullsURL))
        menu.addItem(.separator())
        if let s = state.snapshot {
            menu.addItem(info("Updated \(s.fetchedAt.formatted(date: .omitted, time: .shortened))"))
        }
        menu.addItem(action("Refresh Now", #selector(refreshNow), key: "r"))
        menu.addItem(intervalMenuItem())
        menu.addItem(action("Quit", #selector(quit), key: "q"))
        return menu
    }

    private func appendSnapshot(_ s: QueueSnapshot, to menu: NSMenu) {
        menu.addItem(info(SummaryText.queueLine(s)))
        appendPRs(s.queued, total: s.queuedCount, to: menu)
        if s.failedTodayCount > 0 {
            menu.addItem(.separator())
            menu.addItem(info("Failed today (\(s.failedTodayCount))"))
            appendPRs(s.failedToday, total: s.failedTodayCount, to: menu)
        }
        menu.addItem(.separator())
        menu.addItem(info(SummaryText.mineLine(s)))
        appendPRs(s.mineOpen, total: s.mineOpenCount, to: menu)
        menu.addItem(.separator())
        menu.addItem(info(SummaryText.weekLine(s)))
    }

    private func appendPRs(_ prs: [PullRequest], total: Int, to menu: NSMenu) {
        for pr in prs {
            let item = link(SummaryText.row(pr), pr.url)
            item.indentationLevel = 1
            menu.addItem(item)
        }
        if let more = SummaryText.moreLine(shown: prs.count, total: total) {
            let item = info(more)
            item.indentationLevel = 1
            menu.addItem(item)
        }
    }

    private func info(_ title: String) -> NSMenuItem {
        NSMenuItem(title: title, action: nil, keyEquivalent: "")
    }

    private func action(_ title: String, _ selector: Selector, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        item.target = self
        return item
    }

    private func link(_ title: String, _ url: URL) -> NSMenuItem {
        let item = action(title, #selector(openLink(_:)))
        item.representedObject = url
        item.toolTip = url.absoluteString
        return item
    }

    private func intervalMenuItem() -> NSMenuItem {
        let current = RefreshInterval.current
        let parent = info("Refresh Every: \(RefreshInterval.label(for: current))")
        let submenu = NSMenu()
        for seconds in RefreshInterval.choices {
            let item = action(RefreshInterval.label(for: seconds), #selector(setInterval(_:)))
            item.representedObject = seconds
            item.state = seconds == current ? .on : .off
            submenu.addItem(item)
        }
        parent.submenu = submenu
        return parent
    }

    @objc private func openLink(_ sender: NSMenuItem) {
        guard let url = sender.representedObject as? URL else { return }
        NSWorkspace.shared.open(url)
    }

    @objc private func refreshNow() { refresh() }

    @objc private func quit() { NSApplication.shared.terminate(nil) }

    @objc private func setInterval(_ sender: NSMenuItem) {
        guard let seconds = sender.representedObject as? TimeInterval else { return }
        RefreshInterval.current = seconds
        scheduleTimer()
        statusItem.menu = buildMenu()
    }
}
