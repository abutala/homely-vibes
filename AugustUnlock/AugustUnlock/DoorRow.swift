import SwiftUI

/// One door as a Liquid Glass card: a status circle, and its name and status to
/// the right. A tap anywhere on the card is the door's button. VoiceOver and
/// the UI tests read the status from the button's value.
struct DoorRow: View {
    let door: DoorController

    /// The path icon's side, so it scales with Dynamic Type like the caption.
    @ScaledMetric(relativeTo: .caption) private var captionIconSize: CGFloat = 12

    private static let cornerRadius: CGFloat = 32

    private var machine: CommandMachine { door.machine }

    private struct Line {
        let text: String
        let font: Font
        let color: Color
    }

    var body: some View {
        // Redraws on its own so the "may still move" line ends on time.
        TimelineView(.periodic(from: .now, by: 5)) { context in
            let lines = statusLines(at: context.date)
            Button(action: door.tap) {
                HStack(spacing: 18) {
                    circle
                    VStack(alignment: .leading, spacing: 3) {
                        Text(door.lock.name).font(.title3.weight(.semibold)).foregroundStyle(.primary).lineLimit(3)
                        ForEach(lines, id: \.text) { line in
                            Text(line.text).font(line.font).foregroundStyle(line.color).fixedSize(horizontal: false, vertical: true)
                        }
                        if let timing = door.lastTiming { timingCaption(timing) }
                    }
                    .multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(20)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .contentShape(.rect(cornerRadius: Self.cornerRadius))
                .glassEffect(.regular, in: .rect(cornerRadius: Self.cornerRadius))
            }
            .buttonStyle(CardPress())
            .accessibilityLabel(door.lock.name)
            .accessibilityValue((lines.map(\.text) + [door.lastTiming?.summary].compactMap { $0 }).joined(separator: ", "))
        }
    }

    private var circle: some View {
        ZStack {
            Circle()
                .fill(fill.gradient)
                .overlay(Circle().strokeBorder(.white.opacity(0.2), lineWidth: 1))
                .shadow(color: isTinted ? fill.opacity(0.25) : .clear, radius: 10, y: 6)
            if machine.isOperating {
                ProgressView().tint(.white).controlSize(.large)
            } else {
                Image(systemName: symbol)
                    .font(.system(size: 50, weight: .semibold))
                    .foregroundStyle(isTinted ? AnyShapeStyle(.white) : AnyShapeStyle(.secondary))
                    .contentTransition(.symbolEffect(.replace))
            }
        }
        .frame(width: 120, height: 120)
        .animation(.snappy(duration: 0.3), value: machine.op)
    }

    /// Green only for a door the lock reported unlocked; a door nobody has
    /// answered for has no color.
    private var fill: Color {
        switch machine.op {
        case .failure: return .red
        case .inProgress: return .accentColor
        case .idle, .success:
            switch machine.door {
            case .unlocked: return .green
            case .locked: return Color(.systemGray)
            case .unknown: return Color(.systemFill)
            }
        }
    }

    private var isTinted: Bool { fill != Color(.systemFill) }

    /// A door no command has answered for reads as a question, never as a lock;
    /// a command that went wrong reads as a warning.
    private var symbol: String {
        if case .failure = machine.op { return "exclamationmark.triangle.fill" }
        switch machine.door {
        case .locked: return "lock.fill"
        case .unlocked: return "lock.open.fill"
        case .unknown: return machine.retry == nil ? "questionmark" : "lock.trianglebadge.exclamationmark.fill"
        }
    }

    private func statusLines(at now: Date) -> [Line] {
        var lines: [Line]
        switch machine.op {
        case .idle:
            lines = [doorLine(idleStatus)]
        case .inProgress(let unlocking):
            lines = [Line(text: unlocking ? "Unlocking\u{2026} tap to lock" : "Locking\u{2026} tap to unlock", font: .subheadline, color: .secondary)]
            if let note = DoorStage.pathNote(door.seenStages) { lines.append(Line(text: note, font: .footnote, color: .secondary)) }
        case .success:
            lines = [doorLine(machine.door.label)]
        case .failure(let message):
            lines = [Line(text: message, font: .footnote, color: .red)]
        }
        if let warning = machine.warning(at: now) { lines.append(Line(text: warning, font: .footnote, color: .orange)) }
        if let note = machine.lateNote { lines.append(Line(text: note, font: .footnote, color: .secondary)) }
        return lines
    }

    private func doorLine(_ text: String) -> Line {
        machine.door == .unlocked
            ? Line(text: text, font: .subheadline.weight(.semibold), color: .green)
            : Line(text: text, font: .subheadline, color: .secondary)
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
            Text(timing.summary).foregroundStyle(.tertiary).monospacedDigit()
        }
        .font(.caption)
    }
}

/// The whole card gives a little under the finger.
private struct CardPress: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(.snappy(duration: 0.15), value: configuration.isPressed)
    }
}

/// Behind the cards: glass needs something to catch, so a soft wash of the
/// tint over the grouped background.
struct DoorsBackground: View {
    var body: some View {
        ZStack {
            Color(.systemGroupedBackground)
            RadialGradient(colors: [Color.accentColor.opacity(0.10), .clear], center: .topLeading, startRadius: 0, endRadius: 500)
        }
        .ignoresSafeArea()
    }
}
