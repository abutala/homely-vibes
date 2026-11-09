import SwiftUI

/// One door: the round button, and its name and status to the right.
struct DoorRow: View {
    let door: DoorController

    /// The path icon's side, so it scales with Dynamic Type like the caption.
    @ScaledMetric(relativeTo: .caption) private var captionIconSize: CGFloat = 12

    private var machine: CommandMachine { door.machine }

    var body: some View {
        HStack(spacing: 16) {
            Button(action: door.tap) {
                ZStack {
                    Circle().fill(buttonColor).frame(width: 120, height: 120)
                    if machine.isOperating {
                        ProgressView().tint(.white).scaleEffect(1.2)
                    } else {
                        Image(systemName: lockIcon).font(.system(size: 44)).foregroundStyle(.white)
                    }
                }
            }
            .accessibilityLabel(door.lock.name)

            VStack(alignment: .leading, spacing: 4) {
                Text(door.lock.name).font(.headline).lineLimit(2)
                statusLine
                TimelineView(.periodic(from: .now, by: 5)) { context in
                    if let warning = machine.warning(at: context.date) {
                        Text(warning).font(.footnote).foregroundStyle(.orange)
                    }
                }
                if let note = machine.lateNote {
                    Text(note).font(.footnote).foregroundStyle(.secondary)
                }
                if let timing = door.lastTiming { timingCaption(timing) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var buttonColor: Color {
        switch machine.op {
        case .failure: .red
        case .inProgress: .accentColor
        case .idle, .success: machine.door == .unlocked ? .green : .accentColor
        }
    }

    /// A door no command has answered for reads as a question; a command that
    /// went wrong reads as a warning.
    private var lockIcon: String {
        switch machine.door {
        case .locked: "lock.fill"
        case .unlocked: "lock.open.fill"
        case .unknown: machine.retry == nil ? "questionmark" : "lock.trianglebadge.exclamationmark.fill"
        }
    }

    @ViewBuilder
    private var statusLine: some View {
        switch machine.op {
        case .idle:
            Text(idleStatus).foregroundStyle(.secondary)
        case .inProgress(let unlocking):
            Text(unlocking ? "Unlocking\u{2026} tap to lock" : "Locking\u{2026} tap to unlock").foregroundStyle(.secondary)
            if let note = DoorStage.pathNote(door.seenStages) {
                Text(note).font(.footnote).foregroundStyle(.secondary)
            }
        case .success:
            Text(machine.door.label).foregroundStyle(machine.door == .unlocked ? .green : .secondary)
        case .failure(let message):
            Text(message).foregroundStyle(.red).font(.footnote)
        }
    }

    private var idleStatus: String {
        let action = "tap to \(machine.nextTapUnlocks ? "unlock" : "lock")"
        if machine.door == .unknown, machine.retry == nil { return action.prefix(1).uppercased() + action.dropFirst() }
        return "\(machine.door.label) \u{2014} \(action)"
    }

    /// The Bluetooth rune is a template vector in Assets.xcassets (SF Symbols
    /// has none: it is the Bluetooth SIG's mark); the cloud is a symbol.
    private func timingCaption(_ timing: DoorController.LastTiming) -> some View {
        let bluetooth = timing.path == .bluetooth
        return HStack(spacing: 4) {
            (bluetooth ? Image("bluetooth") : Image(systemName: "cloud"))
                .resizable()
                .scaledToFit()
                .frame(width: captionIconSize, height: captionIconSize)
                .foregroundStyle(bluetooth ? Color.blue : Color.secondary)
                .accessibilityLabel("via \(timing.path.rawValue)")
            Text(timing.summary).foregroundStyle(.tertiary).monospacedDigit()
        }
        .font(.caption)
        .accessibilityElement(children: .combine)
    }
}
