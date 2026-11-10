import Foundation

/// One command sent over Bluetooth and the cloud at the same moment (the
/// widget's taps; Amit, 2026-11-09), as a pure value: the adapter
/// (`BothPaths.run`) feeds it each path's end and runs the actions it
/// returns. The first path that moved the door answers the tap. A cloud
/// command cannot be recalled, so after a Bluetooth win the command stays
/// open (the lock's gate held) until August answers: that wait is the
/// "tail". The deadline is the adapter's: it cancels both paths.
nonisolated struct ParallelPaths: Equatable {
    enum BluetoothEnd: Equatable {
        case ok
        /// The lock reported a stalled motor.
        case jammed
        case failed
    }

    enum CloudEnd: Equatable {
        /// August's reply, with the state it reported for the lock.
        case replied(LockState)
        case failed
    }

    enum Verdict: Equatable {
        /// Bluetooth moved the door.
        case bluetooth
        /// August's reply decides, with the state it reported.
        case cloud(LockState)
        case jammed
        case failed
    }

    enum Action: Equatable {
        /// Answer the tap. Exactly one per command.
        case report(Verdict)
        case cancelBluetooth
        /// After a Bluetooth win: August's copy of the command ended.
        /// `confirmed` only if its reply says the door is in the asked state.
        case tailClosed(confirmed: Bool)
        /// The command is over: leave the gate.
        case finish
    }

    let expected: LockState
    private var bluetooth: BluetoothEnd?
    private var cloud: CloudEnd?
    private var reported = false
    private var finished = false

    /// `hasBluetooth` false: the lock has no loaded key, so the cloud decides.
    init(expected: LockState, hasBluetooth: Bool) {
        self.expected = expected
        bluetooth = hasBluetooth ? nil : .failed
    }

    mutating func bluetoothEnded(_ end: BluetoothEnd) -> [Action] {
        guard bluetooth == nil, !finished else { return [] }
        bluetooth = end
        guard end == .ok else { return settle() }
        reported = true
        // August ended first without confirming: its command may still run.
        guard cloud != nil else { return [.report(.bluetooth)] }
        finished = true
        return [.report(.bluetooth), .tailClosed(confirmed: false), .finish]
    }

    mutating func cloudEnded(_ end: CloudEnd) -> [Action] {
        guard cloud == nil, !finished else { return [] }
        cloud = end
        let confirmed = end == .replied(expected)
        if reported {
            finished = true
            return [.tailClosed(confirmed: confirmed), .finish]
        }
        // Only a reply that says the door moved may stop a Bluetooth path
        // that can still confirm it.
        guard confirmed else { return settle() }
        reported = true
        finished = true
        return [.report(.cloud(expected))] + (bluetooth == nil ? [.cancelBluetooth] : []) + [.finish]
    }

    /// Both paths ended and neither moved the door for certain.
    private mutating func settle() -> [Action] {
        guard let bluetooth, let cloud else { return [] }
        reported = true
        finished = true
        let verdict: Verdict
        switch (bluetooth, cloud) {
        case (.jammed, _): verdict = .jammed
        case (_, .replied(let state)): verdict = .cloud(state)
        case (_, .failed): verdict = .failed
        }
        return [.report(verdict), .finish]
    }
}
