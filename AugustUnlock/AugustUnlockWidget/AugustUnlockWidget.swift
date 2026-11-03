import AppIntents
import SwiftUI
import WidgetKit

/// One full-width row: an unlock button per door, named as August names it.
/// No lock state is shown and nothing locks (Amit, 2026-11-01). Each tap
/// runs in the app's process, in the background (`DoorIntents.swift`); the
/// app never comes forward. The widget shares no code with the app's
/// screens; it reads the app's sign-in (`WidgetCloud`) and the per-door tap
/// state (`DoorStateStore`) from the Keychain.
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
    /// The lock ID behind each name, empty for a door with no lock yet: the
    /// button carries it, so a tap opens the door it shows, whatever list
    /// the app holds.
    let locks: [String]
    /// One per name: what the tapped door shows while and just after a tap.
    let marks: [DoorState.Mark]
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
        DoorsEntry(date: .now, names: ["Door", "Door"], locks: ["", ""], marks: [.none, .none], message: nil)
    }

    func getSnapshot(in context: Context, completion: @escaping (DoorsEntry) -> Void) {
        Task { completion(await refresh(at: .now)) }
    }

    /// One entry now; one more at each moment a held result clears. The tap
    /// writes its result and reloads this timeline when it ends
    /// (`AppDoorAction`); a reload asked for while the tap runs is deferred
    /// by WidgetKit until it returns (measured on the phone, Logbook
    /// 2026-11-03), so the only cue during a tap is the system's dimming of
    /// `.invalidatableContent()` views, which is every marked view, not the
    /// tapped door's alone.
    func getTimeline(in context: Context, completion: @escaping (Timeline<DoorsEntry>) -> Void) {
        Task {
            let now = Date()
            let entry = await refresh(at: now)
            let state = DoorStateStore.load()
            let later = state.clearDates(at: now).map { date in
                DoorsEntry(date: date, names: entry.names, locks: entry.locks, marks: state.marks(count: DoorNames.count, at: date), message: entry.message)
            }
            completion(Timeline(entries: [entry] + later, policy: .never))
        }
    }

    private func refresh(at now: Date) async -> DoorsEntry {
        let state = DoorStateStore.load()
        let marks = state.marks(count: DoorNames.count, at: now)
        WidgetLog.note("door state keychain=\(DoorStateStore.lastStatus) running=\(state.running.keys.sorted()) results=\(state.results.count)")
        do {
            let locks = try await withDeadline(seconds: Self.fetchDeadline) { try await WidgetCloud.fetchLocks() }
            WidgetStore.locks = locks
            WidgetStore.signedOut = false
            WidgetLog.note("timeline locks=\(locks.count)")
        } catch {
            if case WidgetCloud.Failure.signedOut = error { WidgetStore.signedOut = true }
            WidgetLog.note("timeline fetch failed: \(error.localizedDescription); cached=\(WidgetStore.locks.count)")
            if !WidgetStore.signedOut, WidgetStore.locks.isEmpty {
                return DoorsEntry(date: now, names: DoorNames.names(cached: []), locks: DoorNames.ids(cached: []), marks: marks, message: error.localizedDescription)
            }
        }
        let names = DoorNames.names(cached: WidgetStore.locks.map(\.name))
        let message = WidgetStore.signedOut ? WidgetCloud.Failure.signedOut.errorDescription : nil
        return DoorsEntry(date: now, names: names, locks: DoorNames.ids(cached: WidgetStore.locks.map(\.id)), marks: marks, message: message)
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
                        Button(intent: OpenDoorIntent(position: position, lockID: entry.locks[position])) { doorIcon }
                            .accessibilityLabel(name)
                        caption(name, entry.marks[position])
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

    /// The door's name, or what its tap did: the result sits here, beside
    /// the button, never inside it (Logbook, 2026-11-02); the dimming while
    /// a tap runs is the system's, on both names.
    private func caption(_ name: String, _ mark: DoorState.Mark) -> some View {
        let (text, color): (String, Color) = switch mark {
        case .none: (name, .primary)
        case .running: ("Unlocking\u{2026}", .secondary)
        case .ok: ("Unlocked", .green)
        case .failed: ("Failed", .red)
        }
        return Text(text).font(.caption).bold().lineLimit(1).minimumScaleFactor(0.7).foregroundStyle(color)
            .invalidatableContent()
    }

    /// Nothing but the image inside the button.
    private var doorIcon: some View {
        Image(systemName: "lock.open.fill").font(.system(size: 34)).padding(8)
    }
}
