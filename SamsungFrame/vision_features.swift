import Foundation
import Vision

// usage: vision_features <dir-of-jpgs> <out.json>
// Writes {"names": [...], "dist": [[...]], "scores": [...], "utility": [...]} for every .jpg:
//   dist     pairwise feature-print distance (0 = identical; ~0.5 = same scene; >0.8 = unrelated)
//   scores   Apple's overall aesthetics score, about -1...1 (higher is better composed)
//   utility  true for reference shots (signs, plates, receipts, screenshots), not "nice photos"
// Driven by dedup_photos.py.
let args = CommandLine.arguments
guard args.count == 3 else {
    FileHandle.standardError.write("usage: vision_features <dir> <out.json>\n".data(using: .utf8)!)
    exit(2)
}
let dir = URL(fileURLWithPath: args[1])
let names = try FileManager.default.contentsOfDirectory(atPath: args[1])
    .filter { $0.lowercased().hasSuffix(".jpg") }
    .sorted()

struct NoResult: Error {}

// A JPG Vision cannot read is reported on stderr and treated as a unique, unscored, non-utility
// photo (unrelated to every other), so one bad file never aborts the run or silently vanishes.
var prints: [VNFeaturePrintObservation?] = []
var scores: [Float] = []
var utility: [Bool] = []
for name in names {
    let handler = VNImageRequestHandler(url: dir.appendingPathComponent(name), options: [:])
    let printRequest = VNGenerateImageFeaturePrintRequest()
    let aestheticsRequest = VNCalculateImageAestheticsScoresRequest()
    do {
        try handler.perform([printRequest, aestheticsRequest])
        guard let print = printRequest.results?.first, let aesthetics = aestheticsRequest.results?.first else {
            throw NoResult()
        }
        prints.append(print)
        scores.append(aesthetics.overallScore)
        utility.append(aesthetics.isUtility)
    } catch {
        FileHandle.standardError.write("vision_features: \(name) unreadable (\(error)); treating as unique\n".data(using: .utf8)!)
        prints.append(nil)
        scores.append(0)
        utility.append(false)
    }
}

var dist = [[Float]](repeating: [Float](repeating: 0, count: names.count), count: names.count)
for i in 0..<names.count {
    for j in (i + 1)..<names.count {
        var d: Float = 1.0
        if let a = prints[i], let b = prints[j] {
            try a.computeDistance(&d, to: b)
        }
        dist[i][j] = d
        dist[j][i] = d
    }
}
let out: [String: Any] = ["names": names, "dist": dist, "scores": scores, "utility": utility]
try JSONSerialization.data(withJSONObject: out).write(to: URL(fileURLWithPath: args[2]))
