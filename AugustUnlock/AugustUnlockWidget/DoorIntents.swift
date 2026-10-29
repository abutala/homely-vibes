import AppIntents
import WidgetKit
import os

/// One intent type per door, with no parameters, run by the widget itself
/// in the background. `.plain` button styles are inert in this install and a
/// parameter was ruled out separately, so the types stay as plain as this.
struct ToggleFrontDoorIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle Front Door"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication

    func perform() async throws -> some IntentResult {
        await WidgetDoorAction.tap(slot: Doors.slot(named: "Front door"))
        return .result()
    }
}

struct ToggleGarageIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle Garage"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication

    func perform() async throws -> some IntentResult {
        await WidgetDoorAction.tap(slot: Doors.slot(named: "Garage"))
        return .result()
    }
}

/// A widget tap: decide from the shared state, record "running", send the
/// cloud command, record the reply. The widget extension has no Bluetooth
/// (see `AugustClient`), so every widget command takes the cloud's 5–9 s. A
/// command the app started for the same door can't be cancelled from here;
/// the last reply wins.
enum WidgetDoorAction {
    /// Under the 20–25 s that widget work is reported to get before iOS
    /// stops it; a stopped command would leave "running" stuck until
    /// `DoorRecord.runningTimeout`.
    static let deadline: TimeInterval = 20

    static func tap(slot: Int) async {
        let door: AugustLock
        do {
            door = try await AugustClient.shared.lock(atSlot: slot)
        } catch {
            log.error("Widget tap for slot \(slot) found no lock: \(error.localizedDescription, privacy: .public)")
            return
        }
        let before = DoorStateStore.record(for: door.id)
        let unlocking = before.nextTapUnlocks(at: Date(), trustUnlockedFor: DoorRecord.widgetUnlockedTrust)
        DoorStateStore.write(DoorRecord(state: before.state, running: unlocking, at: Date()), for: door.id)
        WidgetCenter.shared.reloadAllTimelines()
        log.notice("Widget \(unlocking ? "unlock" : "lock", privacy: .public) of \(door.name, privacy: .public)")

        var state = DoorRecord.State.unknown
        do {
            let reply = try await withDeadline(seconds: deadline) {
                try await unlocking ? AugustClient.shared.unlock(lockID: door.id) : AugustClient.shared.lock(lockID: door.id)
            }
            state = reply.state == .unlocked ? .unlocked : reply.state == .locked ? .locked : .unknown
        } catch {
            log.error("Widget command for \(door.name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
        DoorStateStore.write(DoorRecord(state: state, running: nil, at: Date()), for: door.id)
    }

    private static let log = Logger(subsystem: "AugustUnlock", category: "widget")
}
