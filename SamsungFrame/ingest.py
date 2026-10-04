#!/usr/bin/env python3
"""Stage 1: turn a (possibly network) photo folder into local <=4K JPGs, checkpointed.

Files are filtered by name and size before any bytes are read, so videos, sidecars, thumbnails
and tiny files cost no network traffic. Each remaining original is read once, into memory, and
decoded from there; originals are never copied. Portraits are dropped after that read.
Rerunning resumes: anything already recorded in the manifest is not read again.
"""

import argparse
import hashlib
import io
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from datetime import datetime
from pathlib import Path
from typing import Callable

import numpy as np
import pillow_heif
from PIL import Image, ImageOps

from lib.config import get_config
from lib.logger import get_logger
from SamsungFrame.frame_job import Job, Manifest, PhotoRecord, default_job_dir

pillow_heif.register_heif_opener()

logger = get_logger(__name__)

IMAGE_EXTENSIONS = {".heic", ".jpg", ".jpeg", ".png"}
VIDEO_EXTENSIONS = {".mov", ".mp4", ".m4v", ".avi"}
SIDECAR_EXTENSIONS = {".aae"}
THUMBNAIL_PATTERNS = re.compile(r"_(thumb|thumbnail|small)(@\d+x)?\.[\w]+$", re.IGNORECASE)
MAX_BOX = (3840, 2160)
JPEG_QUALITY = 90
EXIF_IFD = 0x8769
EXIF_DATETIME_ORIGINAL = 0x9003
EXIF_DATETIME = 0x0132
EXIF_ORIENTATION = 0x0112
TRANSPOSING_ORIENTATIONS = {5, 6, 7, 8}  # EXIF values that rotate the image a quarter turn
NAME_SIZE_REASONS = {"video", "sidecar", "not an image", "thumbnail", "small"}  # recomputed
REREAD_REASONS = {"unreadable"}  # content skips retried on every run; "portrait" is cached
BATCH_PER_WORKER = (
    4  # files in flight per worker; bounds lost work on interrupt, one save per batch
)

IngestJob = tuple[Path, str, Path, bool]
IngestResult = tuple[str, PhotoRecord | None, str | None]


def skip_reason(name: str, size: int, min_bytes: int) -> str | None:
    """Why a file is not a candidate, from its name and size alone; None = candidate."""
    ext = Path(name).suffix.lower()
    if ext in VIDEO_EXTENSIONS:
        return "video"
    if ext in SIDECAR_EXTENSIONS:
        return "sidecar"
    if ext not in IMAGE_EXTENSIONS:
        return "not an image"
    if THUMBNAIL_PATTERNS.search(name):
        return "thumbnail"
    if size < min_bytes:
        return "small"
    return None


def list_source(source: Path, min_bytes: int) -> tuple[list[str], dict[str, str]]:
    """(candidate relative paths, relpath -> skip reason). Metadata only; no file is read."""
    candidates: list[str] = []
    skipped: dict[str, str] = {}
    for path in sorted(source.rglob("*")):
        if path.name.startswith(".") or not path.is_file():
            continue
        rel = str(path.relative_to(source))
        reason = skip_reason(path.name, path.stat().st_size, min_bytes)
        if reason:
            skipped[rel] = reason
        else:
            candidates.append(rel)
    return candidates, skipped


def jpg_name(rel: str, taken: set[str]) -> str:
    """`dir/IMG_1.HEIC` -> `IMG_1.jpg`; a name already taken gets a short hash of its path."""
    stem = Path(rel).stem
    name = f"{stem}.jpg"
    if name.lower() in taken:
        name = f"{stem}_{hashlib.sha256(rel.encode()).hexdigest()[:6]}.jpg"
    taken.add(name.lower())
    return name


def capture_time(img: Image.Image, fallback: float) -> float:
    exif = img.getexif()
    raw = exif.get_ifd(EXIF_IFD).get(EXIF_DATETIME_ORIGINAL) or exif.get(EXIF_DATETIME)
    if raw:
        try:
            return datetime.strptime(str(raw)[:19], "%Y:%m:%d %H:%M:%S").timestamp()
        except ValueError:
            pass
    return fallback


def is_portrait(img: Image.Image) -> bool:
    """Orientation-aware, from header data only (no pixel decode)."""
    width, height = img.size
    if img.getexif().get(EXIF_ORIENTATION) in TRANSPOSING_ORIENTATIONS:
        width, height = height, width
    return height > width


def sharpness(gray: Image.Image) -> float:
    """Variance of the Laplacian on a 1024px copy; only comparable between similar frames."""
    small = gray.copy()
    small.thumbnail((1024, 1024))
    a = np.asarray(small, dtype=np.float32)
    lap = a[1:-1, 1:-1] * 4 - a[:-2, 1:-1] - a[2:, 1:-1] - a[1:-1, :-2] - a[1:-1, 2:]
    return float(lap.var())


def ingest_one(job: IngestJob) -> IngestResult:
    """(relpath, record, skip reason) for one original; top-level so it pickles."""
    source, rel, target, include_portraits = job
    try:
        data = (source / rel).read_bytes()
        mtime = (source / rel).stat().st_mtime
        with Image.open(io.BytesIO(data)) as raw:
            if not include_portraits and is_portrait(raw):
                return rel, None, "portrait"
            taken = capture_time(raw, mtime)
            img = ImageOps.exif_transpose(raw).convert("RGB")
        img.thumbnail(MAX_BOX, Image.Resampling.LANCZOS)
        img.save(target, "JPEG", quality=JPEG_QUALITY)
        record = PhotoRecord(
            name=target.name,
            source=rel,
            time=taken,
            width=img.width,
            height=img.height,
            sharpness=sharpness(img.convert("L")),
        )
    except Exception as e:
        return rel, None, f"unreadable: {e}"
    return rel, record, None


def ingest_isolated(job: IngestJob, fn: Callable[[IngestJob], IngestResult]) -> IngestResult:
    """Run one file in its own pool, so a worker that dies is reported for that file alone."""
    try:
        with ProcessPoolExecutor(max_workers=1) as pool:
            return pool.submit(fn, job).result()
    except BrokenProcessPool:
        return job[1], None, "unreadable: worker crashed"


def ingest_batch(
    jobs: list[IngestJob], workers: int, fn: Callable[[IngestJob], IngestResult] = ingest_one
) -> list[IngestResult]:
    """Results for every job, in order. A crashing file (corrupt HEIC killing libheif) breaks the
    pool, so the files it took down are rerun one by one and only the culprit is reported."""
    done: dict[int, IngestResult] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for i, job in enumerate(jobs):
            try:
                futures[pool.submit(fn, job)] = i
            except BrokenProcessPool:
                break  # jobs never submitted are rerun in isolation below
        for future in as_completed(futures):
            try:
                done[futures[future]] = future.result()
            except BrokenProcessPool:
                pass
    for i, job in enumerate(jobs):
        if i not in done:
            done[i] = ingest_isolated(job, fn)
    return [done[i] for i in range(len(jobs))]


def pending(manifest: Manifest, candidates: list[str], include_portraits: bool) -> list[str]:
    """Candidates not yet recorded; unreadable files, and portraits once they are wanted, retry.

    Name/size skips are not consulted here: `run_ingest` recomputes them from the folder.
    """
    retry = REREAD_REASONS | ({"portrait"} if include_portraits else set())
    done = {p.source for p in manifest.photos.values()}
    done |= {rel for rel, reason in manifest.skipped.items() if reason.split(":")[0] not in retry}
    return [rel for rel in candidates if rel not in done]


def run_ingest(
    source: Path, job: Job, include_portraits: bool, min_size_mb: float, workers: int
) -> Manifest:
    job.create()
    manifest = job.load()
    if manifest.source and manifest.source != str(source.resolve()):
        raise ValueError(f"Job {job.root} belongs to {manifest.source}, not {source}")
    manifest.source = str(source.resolve())
    if not include_portraits:
        for name in [n for n, p in manifest.photos.items() if not p.landscape]:
            manifest.skipped[manifest.photos.pop(name).source] = "portrait"

    candidates, skipped = list_source(source, int(min_size_mb * 1024 * 1024))
    manifest.skipped = {
        rel: reason
        for rel, reason in manifest.skipped.items()
        if reason.split(":")[0] not in NAME_SIZE_REASONS
    } | skipped
    todo = pending(manifest, candidates, include_portraits)
    logger.info(
        f"{len(candidates)} candidates, {len(manifest.photos)} already ingested, "
        f"{len(todo)} to read, {len(skipped)} skipped by name/size"
    )

    job.save(manifest)  # the prune and the refreshed skips must survive a run with nothing to read
    taken = {name.lower() for name in manifest.photos}
    jobs = [(source, rel, job.jpg_dir / jpg_name(rel, taken), include_portraits) for rel in todo]
    step = max(1, workers * BATCH_PER_WORKER)
    for start in range(0, len(jobs), step):
        for rel, record, reason in ingest_batch(jobs[start : start + step], workers):
            if record:
                manifest.photos[record.name] = record
                manifest.skipped.pop(rel, None)
            else:
                manifest.skipped[rel] = reason or "unreadable"
        job.save(manifest)  # checkpoint per batch: a killed run loses at most one batch
        logger.info(f"Ingested {min(start + step, len(jobs))}/{len(jobs)}")
    return manifest


def summarize(manifest: Manifest) -> str:
    reasons: dict[str, int] = {}
    for reason in manifest.skipped.values():
        key = reason.split(":")[0]
        reasons[key] = reasons.get(key, 0) + 1
    skips = ", ".join(f"{n} {r}" for r, n in sorted(reasons.items())) or "none"
    return f"{len(manifest.photos)} photos ready; skipped: {skips}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source_dir", type=Path, help="Photo folder (local or network mount)")
    parser.add_argument("--job", type=Path, help="Job dir (default: /tmp/frame-jobs/<name>-<hash>)")
    parser.add_argument("--include-portraits", action="store_true", help="Keep portrait photos")
    parser.add_argument("--workers", type=int, default=8, help="Parallel reads (default: 8)")
    args = parser.parse_args()

    if not args.source_dir.is_dir():
        logger.error(f"Source directory not found: {args.source_dir}")
        return 1
    job = Job(args.job or default_job_dir(args.source_dir))
    cfg = get_config()
    try:
        manifest = run_ingest(
            args.source_dir,
            job,
            args.include_portraits,
            cfg.samsung_frame.min_size_mb,
            args.workers,
        )
    except ValueError as e:
        logger.error(str(e))
        return 1
    logger.info(summarize(manifest))
    logger.info(f"Job: {job.root}")
    return 0 if manifest.photos else 1


if __name__ == "__main__":
    sys.exit(main())
