import Foundation
import Vision

// usage: feature_prints <dir-of-jpgs> <out.json>
// Writes {"names": [...], "dist": [[...]]}: pairwise Vision feature-print distances
// (0 = identical; ~0.5 = same scene; >0.8 = unrelated). Driven by dedup_photos.py.
let args = CommandLine.arguments
guard args.count == 3 else {
    FileHandle.standardError.write("usage: feature_prints <dir> <out.json>\n".data(using: .utf8)!)
    exit(2)
}
let dir = URL(fileURLWithPath: args[1])
let names = try FileManager.default.contentsOfDirectory(atPath: args[1])
    .filter { $0.lowercased().hasSuffix(".jpg") }
    .sorted()

var prints: [VNFeaturePrintObservation] = []
for name in names {
    let handler = VNImageRequestHandler(url: dir.appendingPathComponent(name), options: [:])
    let request = VNGenerateImageFeaturePrintRequest()
    try handler.perform([request])
    prints.append(request.results!.first!)
}

var dist = [[Float]](repeating: [Float](repeating: 0, count: names.count), count: names.count)
for i in 0..<names.count {
    for j in (i + 1)..<names.count {
        var d: Float = 0
        try prints[i].computeDistance(&d, to: prints[j])
        dist[i][j] = d
        dist[j][i] = d
    }
}
let out: [String: Any] = ["names": names, "dist": dist]
try JSONSerialization.data(withJSONObject: out).write(to: URL(fileURLWithPath: args[2]))
