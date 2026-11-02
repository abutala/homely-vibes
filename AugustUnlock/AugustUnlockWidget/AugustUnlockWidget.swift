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

/// A timeline re-fetches the lock list, so a renamed or added lock shows up,
/// capped at `fetchDeadline`. "Open the app to sign in" follows
/// `WidgetStore.signedOut`, which a 401 sets and any good reply clears.
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
        }
        let names = DoorNames.names(cached: WidgetStore.locks.map(\.name))
        let message = WidgetStore.signedOut ? WidgetCloud.Failure.signedOut.errorDescription : nil
        return DoorsEntry(date: .now, names: names, message: message)
    }
}

struct DoorsView: View {
    let entry: DoorsEntry

    var body: some View {
        VStack(spacing: 4) {
            HStack(spacing: 0) {
                ForEach(Array(entry.names.enumerated()), id: \.offset) { position, name in
                    button(position: position, name: name)
                }
            }
            if let message = entry.message {
                Text(message).font(.caption2).foregroundStyle(.red)
            }
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }

    /// Bordered is the one button style that stays interactive in this
    /// install (`.plain` taps fall through to "open the app" — see the
    /// Logbook). Each door's half of the widget is its button.
    @ViewBuilder
    private func button(position: Int, name: String) -> some View {
        let label = VStack(spacing: 6) {
            Image(systemName: "lock.open.fill").font(.system(size: 30))
            Text(name).font(.caption).bold().lineLimit(1).minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .invalidatableContent()
        if position == 0 {
            Button(intent: OpenFirstDoorIntent()) { label }.buttonStyle(.borderedProminent)
        } else {
            Button(intent: OpenSecondDoorIntent()) { label }.buttonStyle(.borderedProminent)
        }
    }
}
