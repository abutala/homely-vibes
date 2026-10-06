#!/usr/bin/env python3
"""Put this week's album from the photo library on the Frame TV.

Picks the next album from the queue (album_queue.py), works out which of its pictures to show,
and hands them to the pipeline (frame_run.py). Which pictures:

- an album whose files already carry typed captions: exactly those files, no dedup;
- else an album with a picks CSV from an earlier visit: the files it lists, no dedup;
- else: ingest and dedup the album, and write the picks CSV (the kept files and a recommended
  name for each) into the album folder. Nothing is renamed.

An album with too few usable pictures is marked and the next one is tried; one with too many
plays in consecutive weeks. Once an album is chosen for the week, a rerun after a failure
resumes that album and part.
"""

import argparse
import csv
import json
import os
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable

from lib.config import FrameAlbumsConfig, get_config
from lib.logger import get_logger
from SamsungFrame import album_queue as queue
from SamsungFrame.album_queue import Album
from SamsungFrame.dedup_photos import dedup
from SamsungFrame.frame_job import JOBS_ROOT, Job, Manifest
from SamsungFrame.frame_run import pushover_sender
from SamsungFrame.ingest import run_ingest

logger = get_logger(__name__)

EXIT_OK, EXIT_FAILED, EXIT_NOT_MOUNTED, EXIT_NEEDS_KIND = 0, 1, 2, 3
PICKS_HEADER = ["file", "recommended_name"]
INGEST_WORKERS = 8


@dataclass(frozen=True)
class Steps:
    """The work this command delegates; tests pass fakes."""

    ingest: Callable[[Path, Job], Manifest]
    dedup: Callable[[Job], object]
    pipeline: Callable[[Path, Path], int]  # (source dir, job dir) -> exit code
    notify: Callable[[str, bool], None]  # (one line, is it an error?)


def read_picks(picks: Path, album_dir: Path) -> list[str]:
    """Files a picks CSV lists that still exist, relative to the album; [] without a CSV."""
    if not picks.is_file():
        return []
    with picks.open(newline="") as f:
        return [row["file"] for row in csv.DictReader(f) if (album_dir / row["file"]).is_file()]


def recommended_name(source: str, words: str) -> str:
    """`sub/IMG_1.HEIC` + `Mountain sky` -> `IMG_1-Mountain sky.HEIC`; unchanged without words."""
    path = Path(source)
    return f"{path.stem}-{words}{path.suffix}" if words else path.name


def write_picks(picks: Path, manifest: Manifest) -> None:
    """One row per kept photo, in capture order: its file and a recommended file name."""
    kept = sorted(manifest.upload_targets(), key=lambda n: (manifest.photos[n].time, n))
    tmp = picks.with_name(f".{picks.name}.tmp")  # renamed into place: never a half-written CSV
    with tmp.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(PICKS_HEADER)
        for name in kept:
            source = manifest.photos[name].source
            writer.writerow([source, recommended_name(source, manifest.captions.get(name, ""))])
    os.replace(tmp, picks)


def link_farm(album_dir: Path, rels: list[str], dest: Path) -> Path:
    """`dest` holding symlinks to the chosen originals, so the pipeline reads only those."""
    shutil.rmtree(dest, ignore_errors=True)
    for rel in rels:
        link = dest / rel
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(album_dir / rel)
    return dest


def measure(
    album_dir: Path, job: Job, cfg: FrameAlbumsConfig, steps: Steps
) -> tuple[Path, list[str]]:
    """(the folder the pipeline reads, the usable JPG names in capture order) for an album.

    Recorded in the job dir, so a rerun reuses the same choice instead of making it again.
    """
    state = job.root / "album.json"
    if state.exists():
        saved = json.loads(state.read_text())
        return Path(saved["source"]), saved["usable"]

    picks = album_dir / cfg.picks_csv
    files = queue.image_files(album_dir)
    labelled = [f for f in files if queue.is_labelled_file(f)]
    job.create()
    if len(labelled) >= cfg.labelled_album_min:
        source = link_farm(album_dir, labelled, job.root / "src")
    elif picked := read_picks(picks, album_dir):
        source = link_farm(album_dir, picked, job.root / "src")
    else:
        source = album_dir

    manifest = steps.ingest(source, job)
    if source == album_dir and manifest.photos:
        steps.dedup(job)
        manifest = job.load()
        try:
            write_picks(picks, manifest)
        except OSError as e:
            logger.warning(f"Could not write {picks}: {e}; the album will be deduplicated again")
    usable = sorted(manifest.upload_targets(), key=lambda n: (manifest.photos[n].time, n))
    state.write_text(json.dumps({"source": str(source), "usable": usable}))
    return source, usable


def job_for(album: Album, week: str, jobs_root: Path) -> Job:
    return Job(jobs_root / f"album-{queue.slug(album.path)}-{week}")


def choose_album(
    albums: list[Album],
    cfg: FrameAlbumsConfig,
    steps: Steps,
    week: str,
    jobs_root: Path,
    save: Callable[[], None],
) -> tuple[Album, Job, Path, list[str]] | None:
    """The first album in queue order with enough usable pictures; smaller ones are marked."""
    while album := queue.pick(albums, cfg, week):
        job = job_for(album, week, jobs_root)
        source, usable = measure(Path(cfg.root) / album.path, job, cfg, steps)
        enough = queue.record_measure(album, len(usable), cfg)
        if enough:
            album.status = "playing"  # the week's choice: a rerun returns to it, whatever is new
        save()
        if enough:
            return album, job, source, usable
        logger.info(f"{album.path}: {len(usable)} usable pictures, under the minimum; skipped")
    return None


def success_line(album: Album, manifest: Manifest, next_name: str) -> str:
    part = f", part {album.part} of {album.parts}" if album.parts > 1 else ""
    removed = manifest.cleanup.deleted if manifest.cleanup else 0
    return (
        f"{album.name} ({album.shot}){part}: {len(manifest.uploaded)} up, "
        f"{removed} old removed. Next: {next_name}"
    )


def run_week(
    cfg: FrameAlbumsConfig,
    steps: Steps,
    today: date,
    rng: random.Random,
    jobs_root: Path = JOBS_ROOT,
) -> int:
    root, data_dir = Path(cfg.root), Path(cfg.data_dir).expanduser()
    if not cfg.root or not root.is_dir():
        steps.notify(f"photo library not mounted: {cfg.root}", True)
        return EXIT_NOT_MOUNTED
    index = data_dir / "index.tsv"
    albums = queue.load_index(index)
    week = queue.week_key(today)

    def save() -> None:
        queue.save_index(index, albums)
        (data_dir / "upcoming.md").write_text(queue.table_markdown(albums, cfg, today))

    queue.scan(albums, root, today)
    if unknown := queue.needs_kind(albums, cfg):
        save()
        print("\n".join(f"{a.path}\t{a.pictures}" for a in unknown))
        logger.error(f"{len(unknown)} albums need a kind; classify them and run again")
        return EXIT_NEEDS_KIND
    queue.place(albums, cfg, rng)

    try:
        chosen = choose_album(albums, cfg, steps, week, jobs_root, save)
    except Exception as e:
        logger.exception("Could not work out which pictures to show")
        save()
        steps.notify(f"choosing pictures failed: {e}"[:200], True)
        return EXIT_FAILED
    if chosen is None:
        steps.notify("no eligible album left in the queue", True)
        return EXIT_FAILED
    album, job, source, usable = chosen
    part = min(queue.part_for(album, week), album.parts)
    manifest = job.load()
    manifest.kept = sorted(queue.split(usable, album.parts)[part - 1])
    job.save(manifest)
    logger.info(f"{album.path}: part {part} of {album.parts}, {len(manifest.kept)} pictures")

    code = steps.pipeline(source, job.root)
    if code != 0:
        save()
        steps.notify(f"{album.name}: upload stopped (exit {code}); run again to resume", True)
        return EXIT_FAILED
    queue.mark_shown(album, week)
    save()
    rows = queue.upcoming(albums, cfg, today)
    later = [row[1] for row in rows if queue.week_key(date.fromisoformat(row[0])) > week]
    steps.notify(success_line(album, job.load(), later[0] if later else "nothing"), False)
    return EXIT_OK


def real_steps() -> Steps:
    cfg = get_config().samsung_frame
    send = pushover_sender()

    def pipeline(source: Path, job_dir: Path) -> int:
        command = [sys.executable, "-m", "SamsungFrame.frame_run", str(source)]
        return subprocess.run(
            command + ["--job", str(job_dir), "--no-dedup", "--no-notify"]
        ).returncode

    def notify(line: str, error: bool) -> None:
        send(line, "Frame album - FAILED" if error else "Frame album", 0 if error else -1)

    return Steps(
        ingest=lambda source, job: run_ingest(
            source, job, False, cfg.min_size_mb, INGEST_WORKERS, cfg.max_image_size_mb
        ),
        dedup=dedup,
        pipeline=pipeline,
        notify=notify,
    )


def classify(albums: list[Album], lines: list[str]) -> None:
    """Apply `path<TAB>kind<TAB>region` lines; raises ValueError on a bad one."""
    known = {a.path: a for a in albums}
    for line in filter(str.strip, lines):
        path, kind, region = line.split("\t")
        if path not in known or kind not in queue.KINDS:
            raise ValueError(f"bad line: {line}")
        known[path].kind, known[path].region = kind, region


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="put this week's album on the TV")
    run.add_argument("--scheduled", action="store_true", help="do nothing unless today is a Monday")
    scan = sub.add_parser("scan", help="index new albums; print those that need a kind")
    scan.add_argument("--full", action="store_true", help="also recount albums already indexed")
    sub.add_parser("classify", help="set kind and region from `path<TAB>kind<TAB>region` on stdin")
    sub.add_parser("shuffle", help="re-deal the eligible queue")
    sub.add_parser("table", help="rewrite upcoming.md and print it")
    args = parser.parse_args()

    cfg = get_config().samsung_frame.albums
    today = date.today()
    if not cfg.root or not cfg.data_dir:
        logger.error("Set samsung_frame.albums.root and .data_dir in config/local.yaml")
        return EXIT_FAILED
    if args.command == "run":
        if args.scheduled and today.weekday() != 0:
            logger.info("Not a Monday; nothing to do")
            return EXIT_OK
        return run_week(cfg, real_steps(), today, random.Random())

    data_dir = Path(cfg.data_dir).expanduser()
    index = data_dir / "index.tsv"
    albums = queue.load_index(index)
    if args.command == "scan":
        if not Path(cfg.root).is_dir():
            logger.error(f"photo library not mounted: {cfg.root}")
            return EXIT_NOT_MOUNTED
        added = queue.scan(albums, Path(cfg.root), today, full=args.full)
        unknown = queue.needs_kind(albums, cfg)
        print("\n".join(f"{a.path}\t{a.pictures}" for a in unknown))
        logger.info(f"{len(albums)} albums indexed, {added} new, {len(unknown)} to classify")
    elif args.command == "classify":
        try:
            classify(albums, sys.stdin.read().splitlines())
        except ValueError as e:
            logger.error(str(e))
            return EXIT_FAILED
    elif args.command == "shuffle":
        albums = queue.shuffle(albums, cfg, random.Random(), today.year)
    queue.save_index(index, albums)
    text = queue.table_markdown(albums, cfg, today)
    (data_dir / "upcoming.md").write_text(text)
    if args.command == "table":
        print(text)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
