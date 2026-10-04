#!/usr/bin/env python3
"""Thin a photo folder to a fraction of its size by dropping near-duplicates (macOS only).

Pipeline: downsize everything to <=4K JPG -> Apple Vision feature prints -> time-windowed
average-linkage clustering -> keep the sharpest frame per cluster -> copy into a new folder.
Upload the result with batch_upload.py.
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from pathlib import Path

import numpy as np
import numpy.typing as npt
import pillow_heif
from PIL import Image, ImageOps
from pydantic import BaseModel

from lib.logger import get_logger

pillow_heif.register_heif_opener()

logger = get_logger(__name__)

SWIFT_HELPER = Path(__file__).with_name("feature_prints.swift")
IMAGE_EXTENSIONS = {".heic", ".jpg", ".jpeg", ".png"}
MAX_BOX = (3840, 2160)
JPEG_QUALITY = 90
# The TV is landscape and batch_upload skips portraits by default, so a landscape frame
# beats a portrait one of the same scene unless the portrait is twice as sharp.
LANDSCAPE_BONUS = 2.0
EXIF_DATETIME_ORIGINAL = 0x9003
EXIF_DATETIME = 0x0132
EXIF_IFD = 0x8769

Matrix = npt.NDArray[np.float64]


class Photo(BaseModel):
    name: str  # JPG file name inside the work dir
    time: float  # capture time, epoch seconds
    width: int
    height: int
    sharpness: float

    @property
    def landscape(self) -> bool:
        return self.width >= self.height


def capture_time(img: Image.Image, fallback: float) -> float:
    exif = img.getexif()
    raw = exif.get_ifd(EXIF_IFD).get(EXIF_DATETIME_ORIGINAL) or exif.get(EXIF_DATETIME)
    if raw:
        try:
            return datetime.strptime(str(raw)[:19], "%Y:%m:%d %H:%M:%S").timestamp()
        except ValueError:
            pass
    return fallback


def sharpness(gray: Image.Image) -> float:
    """Variance of the Laplacian on a 1024px copy; only comparable between similar frames."""
    small = gray.copy()
    small.thumbnail((1024, 1024))
    a = np.asarray(small, dtype=np.float32)
    lap = a[1:-1, 1:-1] * 4 - a[:-2, 1:-1] - a[2:, 1:-1] - a[1:-1, :-2] - a[1:-1, 2:]
    return float(lap.var())


def prepare_one(job: tuple[Path, Path]) -> Photo:
    """Write an EXIF-rotated <=4K JPG of `source` to `target`; top-level so it pickles."""
    source, target = job
    with Image.open(source) as raw:
        taken = capture_time(raw, source.stat().st_mtime)
        img = ImageOps.exif_transpose(raw).convert("RGB")
    img.thumbnail(MAX_BOX, Image.Resampling.LANCZOS)
    img.save(target, "JPEG", quality=JPEG_QUALITY)
    return Photo(
        name=target.name,
        time=taken,
        width=img.width,
        height=img.height,
        sharpness=sharpness(img.convert("L")),
    )


def jpg_names(sources: list[Path]) -> list[str]:
    """`IMG_1.HEIC` -> `IMG_1.jpg`; a stem shared by several files gets its extension appended."""
    stems = [p.stem for p in sources]
    return [
        f"{p.stem}.jpg" if stems.count(p.stem) == 1 else f"{p.stem}_{p.suffix[1:].lower()}.jpg"
        for p in sources
    ]


def find_images(src: Path) -> list[Path]:
    return sorted(p for p in src.iterdir() if p.suffix.lower() in IMAGE_EXTENSIONS)


def prepare(src: Path, jpg_dir: Path) -> list[Photo]:
    sources = find_images(src)
    jobs = [(s, jpg_dir / n) for s, n in zip(sources, jpg_names(sources))]
    with ProcessPoolExecutor() as pool:
        return list(pool.map(prepare_one, jobs, chunksize=4))


def feature_distances(jpg_dir: Path, build_dir: Path) -> tuple[list[str], Matrix]:
    """Pairwise Vision feature-print distances, rows ordered like the returned names."""
    helper = build_dir / "feature_prints"
    subprocess.run(["swiftc", "-O", str(SWIFT_HELPER), "-o", str(helper)], check=True)
    out = build_dir / "distances.json"
    subprocess.run([str(helper), str(jpg_dir), str(out)], check=True)
    data = json.loads(out.read_text())
    return data["names"], np.array(data["dist"], dtype=np.float64)


def cluster(
    dist: Matrix, times: npt.NDArray[np.float64], goal: int, window: float, cap: float
) -> list[list[int]]:
    """Average-linkage clustering that merges closest pairs until `goal` clusters remain.

    Photos more than `window` seconds apart never share a cluster; stops early rather than
    merge clusters whose average distance exceeds `cap`.
    """
    cost = np.where(np.abs(times[:, None] - times[None, :]) <= window, dist, np.inf)
    np.fill_diagonal(cost, np.inf)
    sizes = np.ones(len(times))
    members = [[i] for i in range(len(times))]
    live = len(members)
    while live > goal:
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


def pick_best(members: list[int], photos: list[Photo]) -> int:
    def score(i: int) -> float:
        return photos[i].sharpness * (LANDSCAPE_BONUS if photos[i].landscape else 1.0)

    return max(members, key=score)


def dedup(
    src: Path, out: Path, keep_fraction: float, window: float, cap: float, work: Path
) -> list[str]:
    """Copy the best photo of each cluster from `src` (as <=4K JPG) into `out`."""
    jpgs = work / "jpgs"
    shutil.rmtree(jpgs, ignore_errors=True)
    jpgs.mkdir(parents=True)
    prepared = prepare(src, jpgs)
    logger.info(f"Prepared {len(prepared)} images; computing Vision feature prints...")
    names, dist = feature_distances(jpgs, work)
    by_name = {p.name: p for p in prepared}
    photos = [by_name[n] for n in names]
    times = np.array([p.time for p in photos])
    goal = max(1, round(len(photos) * keep_fraction))
    groups = cluster(dist, times, goal, window, cap)
    kept = sorted(photos[pick_best(g, photos)].name for g in groups)
    out.mkdir(parents=True, exist_ok=True)
    for name in kept:
        shutil.copy2(jpgs / name, out / name)
    return kept


def default_out_dir(src: Path) -> Path:
    return src.with_name(f"{src.name} - dedup")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source_dir", type=Path, help="Folder of photos (HEIC/JPG/PNG, top level)")
    parser.add_argument("--out", type=Path, help="Output folder (default: '<source> - dedup')")
    parser.add_argument(
        "--keep", type=float, default=0.5, help="Fraction to keep, 0-1 (default: %(default)s)"
    )
    parser.add_argument(
        "--window",
        type=float,
        default=600,
        help="Only photos taken within this many seconds can be duplicates (default: %(default)s)",
    )
    parser.add_argument(
        "--max-distance",
        type=float,
        default=0.85,
        help="Never merge clusters farther apart than this, even if --keep is not reached "
        "(default: %(default)s; ~0.5 same scene, >0.8 unrelated)",
    )
    parser.add_argument("--work-dir", type=Path, help="Keep the 4K JPG cache here (default: temp)")
    args = parser.parse_args()

    if sys.platform != "darwin" or shutil.which("swiftc") is None:
        logger.error("Needs macOS with swiftc (Xcode command line tools) for Vision")
        return 1
    if not args.source_dir.is_dir():
        logger.error(f"Source directory not found: {args.source_dir}")
        return 1
    if not find_images(args.source_dir):
        logger.error(f"No HEIC/JPG/PNG images in {args.source_dir} (top level only)")
        return 1
    if not 0 < args.keep <= 1:
        logger.error("--keep must be in (0, 1]")
        return 1
    out = args.out or default_out_dir(args.source_dir)
    if out.exists() and any(out.iterdir()):
        logger.error(f"Output folder is not empty: {out}")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        work = args.work_dir or Path(tmp)
        work.mkdir(parents=True, exist_ok=True)
        kept = dedup(args.source_dir, out, args.keep, args.window, args.max_distance, work)

    logger.info(f"Kept {len(kept)} photos in {out}")
    logger.info(f'Upload: python -m SamsungFrame.batch_upload "{out}" --no-purge')
    return 0


if __name__ == "__main__":
    sys.exit(main())
