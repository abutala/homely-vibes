import XCTest

@testable import AugustBLEProtocol

/// One command sent over Bluetooth and the cloud together (TRIAL 2026-11-09):
/// who answers the tap, and when the command is over.
final class ParallelPathsTests: XCTestCase {
    private typealias Action = ParallelPaths.Action

    func testBluetoothFirstAnswersTheTapAndWaitsForAugust() {
        var paths = ParallelPaths(expected: .unlocked, hasBluetooth: true)
        XCTAssertEqual(paths.bluetoothEnded(.ok), [.report(.bluetooth)])
        XCTAssertEqual(paths.cloudEnded(.replied(.unlocked)), [.tailClosed(confirmed: true), .finish])
    }

    func testAugustsErrorAfterABluetoothWinLeavesTheUnlockUnconfirmed() {
        var paths = ParallelPaths(expected: .unlocked, hasBluetooth: true)
        _ = paths.bluetoothEnded(.ok)
        XCTAssertEqual(paths.cloudEnded(.failed), [.tailClosed(confirmed: false), .finish])
    }

    func testAugustFirstAnswersTheTapAndStopsBluetooth() {
        var paths = ParallelPaths(expected: .locked, hasBluetooth: true)
        XCTAssertEqual(paths.cloudEnded(.replied(.locked)), [.report(.cloud(.locked)), .cancelBluetooth, .finish])
        XCTAssertEqual(paths.bluetoothEnded(.ok), [], "over: a late Bluetooth result reports nothing")
    }

    /// A reply that does not say the door is in the asked state must not
    /// stop the Bluetooth path that can still confirm it.
    func testAnUnknownReplyLetsBluetoothRunOn() {
        var paths = ParallelPaths(expected: .locked, hasBluetooth: true)
        XCTAssertEqual(paths.cloudEnded(.replied(.unknown)), [])
        XCTAssertEqual(paths.bluetoothEnded(.ok), [.report(.bluetooth), .tailClosed(confirmed: false), .finish])
    }

    /// A jam over Bluetooth was final before; with the cloud command already
    /// out, only a reply that says the door moved makes the tap a success.
    func testAJamIsASuccessOnlyIfAugustSaysTheDoorMoved() {
        var moved = ParallelPaths(expected: .unlocked, hasBluetooth: true)
        XCTAssertEqual(moved.bluetoothEnded(.jammed), [])
        XCTAssertEqual(moved.cloudEnded(.replied(.unlocked)), [.report(.cloud(.unlocked)), .finish])

        var unknown = ParallelPaths(expected: .unlocked, hasBluetooth: true)
        _ = unknown.bluetoothEnded(.jammed)
        XCTAssertEqual(unknown.cloudEnded(.replied(.unknown)), [.report(.jammed), .finish])

        var cloudFirst = ParallelPaths(expected: .unlocked, hasBluetooth: true)
        _ = cloudFirst.cloudEnded(.failed)
        XCTAssertEqual(cloudFirst.bluetoothEnded(.jammed), [.report(.jammed), .finish])
    }

    func testBluetoothFailingLeavesTheReplyToAugust() {
        var paths = ParallelPaths(expected: .unlocked, hasBluetooth: true)
        XCTAssertEqual(paths.bluetoothEnded(.failed), [])
        XCTAssertEqual(paths.cloudEnded(.replied(.unknown)), [.report(.cloud(.unknown)), .finish])
    }

    func testBothFailingFailsTheTap() {
        var paths = ParallelPaths(expected: .unlocked, hasBluetooth: true)
        _ = paths.cloudEnded(.failed)
        XCTAssertEqual(paths.bluetoothEnded(.failed), [.report(.failed), .finish])
    }

    func testALockWithNoBluetoothKeyIsCloudOnly() {
        var paths = ParallelPaths(expected: .unlocked, hasBluetooth: false)
        XCTAssertEqual(paths.cloudEnded(.replied(.unlocked)), [.report(.cloud(.unlocked)), .finish])
        var failing = ParallelPaths(expected: .unlocked, hasBluetooth: false)
        XCTAssertEqual(failing.cloudEnded(.failed), [.report(.failed), .finish])
    }

    /// Every order of every pair of ends: the tap is answered once, the
    /// command finishes once and last, and a jam never reads as a success
    /// unless August confirmed the move.
    func testEveryOrderAnswersOnceAndFinishesOnce() {
        let bluetoothEnds: [ParallelPaths.BluetoothEnd] = [.ok, .jammed, .failed]
        let cloudEnds: [ParallelPaths.CloudEnd] = [.replied(.unlocked), .replied(.locked), .replied(.unknown), .failed]
        for bluetooth in bluetoothEnds {
            for cloud in cloudEnds {
                for bluetoothFirst in [true, false] {
                    var paths = ParallelPaths(expected: .unlocked, hasBluetooth: true)
                    let actions = bluetoothFirst
                        ? paths.bluetoothEnded(bluetooth) + paths.cloudEnded(cloud)
                        : paths.cloudEnded(cloud) + paths.bluetoothEnded(bluetooth)
                    let what = "\(bluetooth) \(cloud) bluetoothFirst=\(bluetoothFirst): \(actions)"
                    let reports = actions.compactMap { action -> ParallelPaths.Verdict? in
                        if case .report(let verdict) = action { return verdict }
                        return nil
                    }
                    XCTAssertEqual(reports.count, 1, what)
                    XCTAssertEqual(actions.filter { $0 == .finish }.count, 1, what)
                    XCTAssertEqual(actions.last, .finish, what)
                    if bluetooth == .jammed, cloud != .replied(.unlocked) { XCTAssertEqual(reports, [.jammed], what) }
                    if bluetooth == .ok, bluetoothFirst { XCTAssertEqual(reports, [.bluetooth], what) }
                    if reports == [.bluetooth] {
                        let confirmed = cloud == .replied(.unlocked)
                        XCTAssertTrue(actions.contains(.tailClosed(confirmed: confirmed)), what)
                    }
                }
            }
        }
    }
}
