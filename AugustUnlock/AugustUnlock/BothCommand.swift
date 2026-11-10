import Foundation

/// One command on both paths, for the real client and for `FakeAugust`:
/// `BothPaths.run` with the two paths the caller supplies, and what the app
/// does with its answer. After a Bluetooth win the wait for August gets
/// background time, the screen's warning and the exit's wait (`OpenTails`),
/// and a state read if August did not confirm. A command August holds with
/// no answer in time fails as `cloudNoReply` and warns on the screen too.
enum BothCommand {
    static func run(
        lockID: String, action: String, gate: CommandGate, success: LockState, deadline: ContinuousClock.Instant?,
        bluetooth: (@Sendable () async throws -> String)?, cloud: @escaping @Sendable () async throws -> LockState,
        isJam: @escaping @Sendable (Error) -> Bool, readDoorLater: @escaping (String) -> Void
    ) async throws -> OperationReply {
        let lock = String(lockID.suffix(4))
        do {
            let answer = try await BothPaths.run(
                gate: gate, expected: success, deadline: deadline, bluetooth: bluetooth, cloud: cloud, isJam: isJam,
                note: { AppLog.note("both \(action) lock \(lock): \($0)") })
            switch answer {
            case .cloud(let state):
                return OperationReply(state: state, path: .cloud)
            case .bluetooth(let tail):
                let openedAt = Date()
                let window = OpenTails.shared.opened(lockID, at: openedAt)
                let keepAlive = BackgroundTask(name: "AugustTail")
                Task {
                    let confirmed = await tail.value
                    OpenTails.shared.ended(window, confirmed: confirmed)
                    if !confirmed { readDoorLater("\(action) over Bluetooth, August's copy not confirmed") }
                    keepAlive.end()
                }
                return OperationReply(state: success, path: .bluetooth, tail: CloudTail(openedAt: openedAt, confirmation: tail))
            }
        } catch is BothPaths.CutOff {
            OpenTails.shared.unanswered(lockID, at: Date())
            readDoorLater("\(action) sent on both paths, no answer in time")
            throw AugustError.cloudNoReply
        } catch where isJam(error) {
            readDoorLater("a jam on \(action), with the cloud command out")
            throw error
        }
    }
}
