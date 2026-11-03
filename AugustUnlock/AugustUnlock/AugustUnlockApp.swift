import SwiftUI

@main
struct AugustUnlockApp: App {
    init() { TestHooks.applyLaunchEnvironment() }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
