import XCTest

/// The rig has no Simulator test: the Simulator has no Bluetooth. This
/// keeps the UI-test target the project template carries buildable.
final class RigUITests: XCTestCase {
    func testTheAppLaunches() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["BLE Widget Rig"].waitForExistence(timeout: 5))
    }
}
