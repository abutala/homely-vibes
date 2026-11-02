import AppIntents
import SwiftUI
import WidgetKit

/// One full-width row: an unlock button per door, named as August names it.
/// No state is shown and nothing locks (Amit, 2026-11-01). Each tap runs in
/// the widget (`DoorIntents.swift`); the app never opens. The widget shares
/// no code or state with the app; it only reads the app's sign-in
/// (`WidgetCloud`).
@main
struct AugustUnlockWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "Doors", provider: DoorsProvider()) { entry in
            DoorsView(entry: entry)
        }
        .configurationDisplayName("Doors")
        .description("Tap a door to unlock it.")
        .supportedFamilies([.systemMedium])
    }
}

struct DoorsEntry: TimelineEntry {
    let date: Date
    /// At most two, in `WidgetStore.locks` order (by lock ID).
    let names: [String]
    let message: String?
}

/// A timeline re-fetches the lock list, capped at `fetchDeadline`. The
/// policy is `.never`: the buttons are stateless, so the only reasons to
/// re-fetch are a tap (`reloadTimelines` after it) and the system's own
/// refreshes; a renamed or added lock shows up on the next of those.
/// "Open the app to sign in" follows `WidgetStore.signedOut`, which a 401
/// sets and any good reply clears; with no cached doors, any other fetch
/// error is shown instead, so the widget never asks for the app's help.
struct DoorsProvider: TimelineProvider {
    static let fetchDeadline: TimeInterval = 4

    func placeholder(in context: Context) -> DoorsEntry {
        DoorsEntry(date: .now, names: ["Door", "Door"], message: nil)
    }

    func getSnapshot(in context: Context, completion: @escaping (DoorsEntry) -> Void) {
        Task { completion(await refresh()) }
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<DoorsEntry>) -> Void) {
        Task { completion(Timeline(entries: [await refresh()], policy: .never)) }
    }

    private func refresh() async -> DoorsEntry {
        do {
            let locks = try await withDeadline(seconds: Self.fetchDeadline) { try await WidgetCloud.fetchLocks() }
            WidgetStore.locks = locks
            WidgetStore.signedOut = false
            WidgetLog.note("timeline locks=\(locks.count)")
        } catch {
            if case WidgetCloud.Failure.signedOut = error { WidgetStore.signedOut = true }
            WidgetLog.note("timeline fetch failed: \(error.localizedDescription); cached=\(WidgetStore.locks.count)")
            if !WidgetStore.signedOut, WidgetStore.locks.isEmpty {
                return DoorsEntry(date: .now, names: DoorNames.names(cached: []), message: error.localizedDescription)
            }
        }
        let names = DoorNames.names(cached: WidgetStore.locks.map(\.name))
        let message = WidgetStore.signedOut ? WidgetCloud.Failure.signedOut.errorDescription : nil
        return DoorsEntry(date: .now, names: names, message: message)
    }
}

/// One full-width row, a door per half. Built up from Apple's sample button
/// (default style, `.tint`), which is the shape that runs under this
/// install; the earlier `.borderedProminent` button with a frame-filling
/// label never ran (Logbook, 2026-11-02).
struct DoorsView: View {
    let entry: DoorsEntry

    var body: some View {
        VStack(spacing: 4) {
            HStack(spacing: 0) {
                ForEach(Array(entry.names.enumerated()), id: \.offset) { position, name in
                    VStack(spacing: 6) {
                        if position == 0 {
                            Button(intent: OpenFirstDoorIntent()) { doorIcon }.accessibilityLabel(name)
                        } else {
                            Button(intent: OpenSecondDoorIntent()) { doorIcon }.accessibilityLabel(name)
                        }
                        Text(name).font(.caption).bold().lineLimit(1).minimumScaleFactor(0.7)
                            .invalidatableContent()
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            .tint(.primary)
            if let message = entry.message {
                Text(message).font(.caption2).foregroundStyle(.red)
            }
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }

    /// Nothing but the image inside the button: `.invalidatableContent()` on
    /// the label made the button inert here (Logbook, 2026-11-02), so the
    /// running-tap cue sits on the name below it instead.
    private var doorIcon: some View {
        Image(systemName: "lock.open.fill").font(.system(size: 34)).padding(8)
    }
}
