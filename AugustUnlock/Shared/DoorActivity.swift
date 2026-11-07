import ActivityKit
import Foundation

/// A widget tap's Live Activity: the door and when the tap started are
/// fixed; the stage moves. The app's process starts, updates and ends it
/// (`DoorLiveActivity`); the widget extension draws it (`DoorActivityView`).
nonisolated struct DoorUnlockAttributes: ActivityAttributes {
    nonisolated struct ContentState: Codable, Hashable, Sendable {
        var stage: DoorStage
        /// The tap's time, set with the final stage.
        var seconds: Double?
    }

    let door: String
    let tap: Date
}
