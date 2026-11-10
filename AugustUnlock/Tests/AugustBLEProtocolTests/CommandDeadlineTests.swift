import XCTest

@testable import AugustBLEProtocol

final class CommandDeadlineTests: XCTestCase {
    func testTheScreensBluetoothBudgetsLeaveTheCloudItsWindow() {
        // Cloud unlocks on this account take 1–25 s; a miss on Bluetooth
        // must still leave the cloud a real chance before the deadline.
        XCTAssertGreaterThanOrEqual(CommandDeadline.cloudWindowAfterBluetooth, 12)
        XCTAssertLessThan(CommandDeadline.bluetoothSetup + CommandDeadline.bluetoothOperation, CommandDeadline.limit)
    }

    /// A widget tap uses the screen's Bluetooth budgets inside its own,
    /// shorter limit: the cloud fallback must still get a real window.
    func testAWidgetTapLeavesTheCloudItsWindowToo() {
        let afterBluetooth = DoorState.tapLimit - CommandDeadline.bluetoothSetup - CommandDeadline.bluetoothOperation
        XCTAssertGreaterThanOrEqual(afterBluetooth, 10)
        XCTAssertGreaterThanOrEqual(DoorState.tapLimit - CommandDeadline.bluetoothSetup, 16)
    }

    private let start = Date(timeIntervalSinceReferenceDate: 1000)

    func testLimitIsThirtySeconds() {
        XCTAssertEqual(CommandDeadline.limit, 30)
    }

    func testExpiresAtTheLimitNotBefore() {
        let deadline = CommandDeadline(startedAt: start)
        XCTAssertFalse(deadline.isExpired(at: start.addingTimeInterval(29.9)))
        XCTAssertTrue(deadline.isExpired(at: start.addingTimeInterval(30)))
        XCTAssertTrue(deadline.isExpired(at: start.addingTimeInterval(3600)))
    }
}
