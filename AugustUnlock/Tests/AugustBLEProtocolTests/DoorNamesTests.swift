import XCTest

@testable import AugustBLEProtocol

final class DoorNamesTests: XCTestCase {
    func testAlwaysTwoNames() {
        XCTAssertEqual(DoorNames.names(cached: []), ["Door 1", "Door 2"])
        XCTAssertEqual(DoorNames.names(cached: ["Front Door"]), ["Front Door", "Door 2"])
        XCTAssertEqual(DoorNames.names(cached: ["Front Door", "Garage Entrance"]), ["Front Door", "Garage Entrance"])
        XCTAssertEqual(DoorNames.names(cached: ["A", "B", "C"]), ["A", "B"])
    }
}
