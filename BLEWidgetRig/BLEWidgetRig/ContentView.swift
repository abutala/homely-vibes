import SwiftUI

/// Pair once (a foreground scan for the Mac's echo peripheral), then read
/// what each probe logged. The app's own button probes from the foreground
/// for the baseline.
struct ContentView: View {
    @State private var log = RigLog.tail()
    @State private var busy = false
    @State private var known = RigProbe.knownPeripheral

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("BLE Widget Rig").font(.title2).bold()
            Text(known.map { "Paired with …\($0.suffix(6))" } ?? "Not paired: run the Mac peripheral, then Pair.")
                .font(.footnote).foregroundStyle(.secondary)
            HStack {
                Button(known == nil ? "Pair" : "Probe now") { Task { await probe(label: known == nil ? "app-pair" : "app-foreground") } }
                    .buttonStyle(.borderedProminent).disabled(busy)
                Button("Forget") { RigProbe.forget(); known = nil }.disabled(known == nil || busy)
                Button("Refresh") { log = RigLog.tail() }
            }
            ScrollView {
                Text(log).font(.system(.caption2, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding()
        .onAppear {
            log = RigLog.tail()
            // First launch pairs by itself: the one foreground step the rig needs.
            if known == nil { Task { await probe(label: "app-pair") } }
        }
    }

    private func probe(label: String) async {
        busy = true
        _ = await RigProbe.run(label: label)
        known = RigProbe.knownPeripheral
        log = RigLog.tail()
        busy = false
    }
}
