import SwiftUI

/// What one door's circle shows. Compiled into the app and the widget, which
/// read the same shared state (`DoorStateStore`).
enum DoorDisplay: Equatable {
    case unknown
    case locked
    case unlocked
    case locking
    case unlocking

    var color: Color {
        switch self {
        case .unlocked, .unlocking: return .green
        case .locked, .locking: return .red
        case .unknown: return .gray
        }
    }

    var symbol: String {
        switch self {
        case .unlocked, .unlocking: return "lock.open.fill"
        case .locked, .locking: return "lock.fill"
        case .unknown: return "questionmark"
        }
    }

    /// A command is running: the circle pulses in the colour it is heading to.
    var isRunning: Bool { self == .locking || self == .unlocking }

    var caption: String {
        switch self {
        case .unknown: return "Tap to unlock"
        case .locked: return "Locked"
        case .unlocked: return "Unlocked"
        case .locking: return "Locking…"
        case .unlocking: return "Unlocking…"
        }
    }
}

/// A door: a coloured circle with its name under it.
struct DoorCircle: View {
    let name: String
    let display: DoorDisplay
    let diameter: CGFloat

    var body: some View {
        VStack(spacing: 8) {
            ZStack {
                Circle().fill(display.color)
                Image(systemName: display.symbol)
                    .font(.system(size: diameter * 0.32))
                    .foregroundStyle(.white)
            }
            .frame(width: diameter, height: diameter)
            .modifier(Pulse(active: display.isRunning))
            Text(name)
                .font(.headline)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(name), \(accessibilityState)")
    }

    private var accessibilityState: String {
        switch display {
        case .unknown: return "state unknown"
        case .locked: return "locked"
        case .unlocked: return "unlocked"
        case .locking: return "locking"
        case .unlocking: return "unlocking"
        }
    }
}

/// iOS draws a widget without animation, so only the app ever pulses.
private struct Pulse: ViewModifier {
    let active: Bool

    func body(content: Content) -> some View {
        if active {
            content.phaseAnimator([1.0, 0.35]) { view, opacity in
                view.opacity(opacity)
            } animation: { _ in
                .easeInOut(duration: 0.7)
            }
        } else {
            content
        }
    }
}
