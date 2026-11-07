import XCTest

@testable import AugustBLEProtocol

/// What a widget tap's Live Activity says at each stage, and the stage a
/// tap's outcome ends on.
final class DoorStageTests: XCTestCase {
    func testEachOutcomeEndsOnItsStage() {
        XCTAssertEqual(DoorStage.final(.ok), .unlocked)
        XCTAssertEqual(DoorStage.final(.failed), .failed)
        XCTAssertEqual(DoorStage.final(.noReply), .noReply)
    }

    func testOnlyTheResultsAreFinal() {
        XCTAssertEqual(DoorStage.allCases.filter(\.isFinal), [.unlocked, .failed, .noReply])
    }

    func testCaptions() {
        XCTAssertEqual(DoorStage.unlocking.caption(seconds: nil), "Unlocking\u{2026}")
        XCTAssertEqual(DoorStage.bluetooth.caption(seconds: nil), "Bluetooth\u{2026}")
        XCTAssertEqual(DoorStage.cloud.caption(seconds: nil), "Cloud\u{2026}")
        XCTAssertEqual(DoorStage.unlocked.caption(seconds: 2.14), "Unlocked 2.1 s")
        XCTAssertEqual(DoorStage.unlocked.caption(seconds: nil), "Unlocked")
        XCTAssertEqual(DoorStage.failed.caption(seconds: 6), "Failed")
        XCTAssertEqual(DoorStage.noReply.caption(seconds: 28), "No reply")
    }

    func testAStageSurvivesTheActivityPayload() throws {
        for stage in DoorStage.allCases {
            let data = try JSONEncoder().encode(stage)
            XCTAssertEqual(try JSONDecoder().decode(DoorStage.self, from: data), stage)
        }
    }
}
