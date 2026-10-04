#!/usr/bin/env python3
"""Stage 2: drop near-duplicates and reference shots from an ingested job (macOS).

Reads only the local JPGs and the manifest written by ingest.py. Apple Vision supplies a feature
print per photo (similarity), an aesthetics score (which frame is best) and a utility flag
(signs, plates, receipts). Time-windowed average-linkage clustering groups near-duplicates; the
best-scored frame of each cluster is kept. Survivors are recorded in the manifest, with a reason
for every photo dropped, and hard-linked into the job's `deduped/` dir.
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np
import numpy.typing as npt

from lib.logger import get_logger
from SamsungFrame.frame_job import Job, PhotoRecord, drop_kind, reason_counts

logger = get_logger(__name__)

SWIFT_HELPER = Path(__file__).with_name("vision_features.swift")
# Added to the aesthetics score (about -1..1, typically 0.4-0.75) of a landscape frame: the TV is
# landscape, so a landscape frame beats a portrait one of the same scene unless the portrait
# scores clearly higher.
LANDSCAPE_BONUS = 0.15
DEFAULT_WINDOW = 600.0
DEFAULT_MAX_DISTANCE = 0.4  # ~0 identical, ~0.4 near-identical frames, ~0.5 same scene
OVER_LIMIT = "over the limit"  # drop reason for a unique photo cut by --max-photos

Matrix = npt.NDArray[np.float64]


@dataclass(frozen=True)
class VisionFeatures:
    names: list[str]
    dist: Matrix
    scores: list[float]
    utility: list[bool]


def vision_features(jpg_dir: Path, build_dir: Path) -> VisionFeatures:
    """Compile and run the Swift helper over every JPG in `jpg_dir`."""
    helper = build_dir / "vision_features"
    if not helper.exists() or helper.stat().st_mtime < SWIFT_HELPER.stat().st_mtime:
        subprocess.run(["swiftc", "-O", str(SWIFT_HELPER), "-o", str(helper)], check=True)
    out = build_dir / "vision_features.json"
    subprocess.run([str(helper), str(jpg_dir), str(out)], check=True)
    data = json.loads(out.read_text())
    return VisionFeatures(
        names=data["names"],
        dist=np.array(data["dist"], dtype=np.float64),
        scores=data["scores"],
        utility=data["utility"],
    )


def cluster(
    dist: Matrix, times: npt.NDArray[np.float64], window: float, cap: float
) -> list[list[int]]:
    """Average-linkage clustering: merge the closest pair until none is within `cap`.

    Photos more than `window` seconds apart never share a cluster.
    """
    cost = np.where(np.abs(times[:, None] - times[None, :]) <= window, dist, np.inf)
    np.fill_diagonal(cost, np.inf)
    sizes = np.ones(len(times))
    members = [[i] for i in range(len(times))]
    live = len(members)
    while live > 1:
        a, b = (int(i) for i in np.unravel_index(np.argmin(cost), cost.shape))
        if cost[a, b] > cap:  # also catches inf: nothing left within the window
            break
        merged = (cost[a] * sizes[a] + cost[b] * sizes[b]) / (sizes[a] + sizes[b])
        cost[a, :] = merged
        cost[:, a] = merged
        cost[a, a] = np.inf
        cost[b, :] = np.inf
        cost[:, b] = np.inf
        sizes[a] += sizes[b]
        members[a] += members[b]
        members[b] = []
        live -= 1
    return [m for m in members if m]


def rank(score: float, photo: PhotoRecord) -> tuple[float, float]:
    """Aesthetics score (plus the landscape bonus); sharpness only breaks ties."""
    return score + (LANDSCAPE_BONUS if photo.landscape else 0.0), photo.sharpness


def pick_best(members: list[int], scores: list[float], photos: list[PhotoRecord]) -> int:
    return max(members, key=lambda i: rank(scores[i], photos[i]))


def best_spread(
    members: list[int], scores: list[float], photos: list[PhotoRecord], limit: int
) -> list[int]:
    """At most `limit` of `members`: in capture order they are cut into `limit` runs and the
    best-ranked photo of each run is kept, so the selection still spans the whole album."""
    if limit <= 0 or len(members) <= limit:
        return members
    in_order = sorted(members, key=lambda i: photos[i].time)
    runs = np.array_split(np.array(in_order), limit)
    return [pick_best([int(i) for i in run], scores, photos) for run in runs]


def link_kept(job: Job, kept: list[str]) -> None:
    """Rebuild `deduped/` from the kept names; hard links, so no extra disk."""
    shutil.rmtree(job.deduped_dir, ignore_errors=True)
    job.deduped_dir.mkdir(parents=True)
    for name in kept:
        try:
            os.link(job.jpg_dir / name, job.deduped_dir / name)
        except OSError:
            shutil.copy2(job.jpg_dir / name, job.deduped_dir / name)


def dedup(
    job: Job,
    window: float = DEFAULT_WINDOW,
    cap: float = DEFAULT_MAX_DISTANCE,
    features_of: Callable[[Path, Path], VisionFeatures] = vision_features,
    max_photos: int = 0,
) -> list[str]:
    manifest = job.load()
    if not manifest.photos:
        raise ValueError(f"Nothing ingested in {job.root}; run ingest.py first")
    features = features_of(job.jpg_dir, job.root)
    rows = [i for i, name in enumerate(features.names) if name in manifest.photos]
    dropped = {features.names[i]: "utility" for i in rows if features.utility[i]}
    rows = [i for i in rows if not features.utility[i]]
    photos = [manifest.photos[features.names[i]] for i in rows]
    scores = [features.scores[i] for i in rows]
    groups = cluster(
        features.dist[np.ix_(rows, rows)], np.array([p.time for p in photos]), window, cap
    )
    winners = []
    for group in groups:
        best = pick_best(group, scores, photos)
        winners.append(best)
        for i in group:
            if i != best:
                dropped[photos[i].name] = f"duplicate of {photos[best].name}"
    chosen = best_spread(winners, scores, photos, max_photos)
    for i in set(winners) - set(chosen):
        dropped[photos[i].name] = OVER_LIMIT
    manifest.kept = sorted(photos[i].name for i in chosen)
    manifest.dropped = dropped
    job.save(manifest)
    link_kept(job, manifest.kept)
    return manifest.kept


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("job_dir", type=Path, help="Job dir produced by ingest.py")
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_WINDOW,
        help="Only photos taken within this many seconds can be duplicates (default: %(default)s)",
    )
    parser.add_argument(
        "--max-distance",
        type=float,
        default=DEFAULT_MAX_DISTANCE,
        help="Frames closer than this are duplicates; raise to drop more, lower to keep more "
        "(default: %(default)s; ~0.5 is the same scene, >0.8 unrelated)",
    )
    parser.add_argument(
        "--max-photos",
        type=int,
        default=0,
        help="Keep at most this many, the best of each stretch of the album (default: no limit)",
    )
    args = parser.parse_args()

    if platform.system() != "Darwin" or shutil.which("swiftc") is None:
        logger.error("Needs macOS with swiftc (Xcode command line tools) for Vision")
        return 1
    job = Job(args.job_dir)
    try:
        kept = dedup(job, args.window, args.max_distance, max_photos=args.max_photos)
    except ValueError as e:
        logger.error(str(e))
        return 1
    dropped = job.load().dropped
    counts = reason_counts(drop_kind(reason) for reason in dropped.values())
    summary = ", ".join(f"{n} {kind}" for kind, n in sorted(counts.items())) or "nothing"
    logger.info(f"Kept {len(kept)} photos in {job.deduped_dir}; dropped: {summary}")
    return 0 if kept else 1


if __name__ == "__main__":
    sys.exit(main())
