import AppIntents

/// One widget door button. Compiled into the app and the widget extension.
/// Adopting `LiveActivityIntent` makes iOS run `perform()` in the app's
/// process — launched in the background if needed — not in the extension:
/// the sign-in, the offline key and the command in flight all live there.
/// The extension's copy only names the intent for its buttons and never runs.
struct ToggleDoorIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Toggle Door"
    static let isDiscoverable = false

    /// The door's index in the app's lock list (see `AugustClient.lock(atSlot:)`).
    @Parameter(title: "Door")
    var slot: Int

    init() {}

    init(slot: Int) {
        self.slot = slot
    }

    func perform() async throws -> some IntentResult {
        #if !WIDGET_EXTENSION
            try await DoorToggler.shared.tap(slot: slot)
        #endif
        return .result()
    }
}
