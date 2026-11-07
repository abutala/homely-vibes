import SwiftUI
import WidgetKit

/// The extension's two surfaces: the Home Screen widget, and the Live
/// Activity a widget tap starts.
@main
struct AugustUnlockWidgets: WidgetBundle {
    var body: some Widget {
        AugustUnlockWidget()
        DoorActivityWidget()
    }
}
