"""Tests for the monthly album command: which pictures it chooses, the picks CSV, skips, parts
and reruns. Ingest, dedup, the pipeline and the notifier are hand-written fakes."""

import csv
import random
from datetime import date
from pathlib import Path

import pytest

from lib.config import FrameAlbumsConfig
from SamsungFrame import album_queue as queue
from SamsungFrame.frame_album import (
    EXIT_FAILED,
    EXIT_NEEDS_KIND,
    EXIT_NOT_MOUNTED,
    EXIT_OK,
    Steps,
    classify,
    recommended_name,
    run_month,
)
from SamsungFrame.frame_job import Job, Manifest, PhotoRecord
from SamsungFrame.test_album_queue import config

OCTOBER, NOVEMBER = date(2026, 10, 5), date(2026, 11, 2)


class World:
    """A photo library on disk, an index, and fakes that record what the command asked of them."""

    def __init__(self, tmp_path: Path, **limits: object):
        self.root = tmp_path / "library"
        self.root.mkdir()
        self.data = tmp_path / "data"
        self.jobs = tmp_path / "jobs"
        values: dict[str, object] = dict(
            root=str(self.root),
            data_dir=str(self.data),
            min_pictures=2,
            min_on_tv=3,
            max_on_tv=6,
            labelled_album_min=2,
        )
        self.cfg: FrameAlbumsConfig = config(**(values | limits))
        self.ingested: list[Path] = []
        self.deduped = 0
        self.played: list[list[str]] = []  # the originals each pipeline run was given
        self.notes: list[tuple[str, bool]] = []
        self.pipeline_exit = 0
        self.dedup_error: Exception | None = None

    def album(self, name: str, files: list[str], kind: str = "park") -> Path:
        folder = self.root / "2020" / "05-May" / name
        folder.mkdir(parents=True)
        for file in files:
            (folder / file).write_bytes(b"x")
        albums = queue.load_index(self.data / "index.tsv")
        queue.scan(albums, self.root, OCTOBER)
        classify(albums, [f"2020/05-May/{name}\t{kind}\taway"])
        queue.save_index(self.data / "index.tsv", albums)
        return folder

    def ingest(self, source: Path, job: Job) -> Manifest:
        self.ingested.append(source)
        job.create()
        manifest = job.load()
        for i, rel in enumerate(queue.image_files(source)):
            name = f"{Path(rel).stem}.jpg"
            manifest.photos[name] = PhotoRecord(
                name=name, source=rel, time=float(i), width=4, height=3, sharpness=1.0
            )
        job.save(manifest)
        return manifest

    def dedup(self, job: Job) -> None:
        """Drops every photo whose name ends in `dup`; captions the rest."""
        if self.dedup_error:
            raise self.dedup_error
        self.deduped += 1
        manifest = job.load()
        manifest.kept = sorted(n for n in manifest.photos if not Path(n).stem.endswith("dup"))
        manifest.captions = {n: "Blue sky" for n in manifest.kept}
        job.save(manifest)

    def pipeline(self, _source: Path, job_dir: Path) -> int:
        manifest = Job(job_dir).load()
        self.played.append([manifest.photos[n].source for n in manifest.upload_targets()])
        return self.pipeline_exit

    def run(self, today: date = OCTOBER) -> int:
        steps = Steps(
            self.ingest,
            self.dedup,
            self.pipeline,
            lambda line, error: self.notes.append((line, error)),
        )
        return run_month(self.cfg, steps, today, random.Random(0), self.jobs)

    def row(self, name: str) -> queue.Album:
        albums = queue.load_index(self.data / "index.tsv")
        return next(a for a in albums if a.name == name)


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def camera(count: int, start: int = 1) -> list[str]:
    return [f"IMG_{i:04}.jpg" for i in range(start, start + count)]


class TestWhichPictures:
    def test_an_unlabelled_album_is_deduplicated_and_gets_a_picks_csv(self, world: World) -> None:
        folder = world.album("Trip", camera(4) + ["IMG_0009dup.jpg"])
        assert world.run() == EXIT_OK
        assert world.deduped == 1
        assert world.played == [camera(4)]
        rows = list(csv.reader((folder / "frame_picks.csv").open()))
        assert rows[0] == ["file", "recommended_name"]
        assert rows[1] == ["IMG_0001.jpg", "IMG_0001-Blue sky.jpg"]
        assert len(rows) == 5
        assert sorted(p.name for p in folder.iterdir() if p.suffix == ".jpg") == sorted(
            camera(4) + ["IMG_0009dup.jpg"]
        )  # nothing renamed

    def test_a_picks_csv_from_an_earlier_visit_replaces_dedup(self, world: World) -> None:
        folder = world.album("Trip", camera(6))
        (folder / "frame_picks.csv").write_text(
            "file,recommended_name\nIMG_0002.jpg,a\nIMG_0004.jpg,b\nIMG_0005.jpg,c\ngone.jpg,d\n"
        )
        assert world.run() == EXIT_OK
        assert world.deduped == 0
        assert world.played == [["IMG_0002.jpg", "IMG_0004.jpg", "IMG_0005.jpg"]]

    def test_a_labelled_album_plays_exactly_its_labelled_files(self, world: World) -> None:
        labelled = ["IMG_0001-Sunset.jpg", "IMG_0002-Harbour.jpg", "IMG_0003-Old town.jpg"]
        folder = world.album("Trip", camera(5, start=10) + labelled)
        assert world.run() == EXIT_OK
        assert world.deduped == 0
        assert world.played == [labelled]
        assert not (folder / "frame_picks.csv").exists()

    def test_stray_captions_do_not_make_an_album_labelled(self, world: World) -> None:
        world.album("Trip", camera(4) + ["IMG_0099-Sunset.jpg"])
        assert world.run() == EXIT_OK
        assert world.deduped == 1 and len(world.played[0]) == 5

    def test_recommended_name_keeps_the_camera_name_and_extension(self) -> None:
        assert recommended_name("day 2/IMG_1.HEIC", "Mountain sky") == "IMG_1-Mountain sky.HEIC"
        assert recommended_name("IMG_1.HEIC", "") == "IMG_1.HEIC"


class TestSkipsAndParts:
    def test_a_small_album_is_marked_and_the_next_one_plays_in_the_same_run(
        self, world: World
    ) -> None:
        world.album("Small", camera(2) + ["IMG_0008dup.jpg"])
        world.album("Next", camera(4), kind="city")
        assert world.run() == EXIT_OK
        assert (world.row("Small").status, world.row("Small").on_tv) == ("small", 2)
        assert world.row("Next").status == "shown"
        assert world.played == [camera(4)]

    def test_a_small_labelled_album_is_skipped_not_topped_up(self, world: World) -> None:
        world.album("Few", camera(9, start=10) + ["IMG_0001-Sunset.jpg", "IMG_0002-Pier.jpg"])
        world.album("Next", camera(4), kind="city")
        assert world.run() == EXIT_OK
        assert world.row("Few").status == "small"
        assert world.played == [camera(4)]

    def test_a_big_album_plays_in_equal_parts_over_consecutive_months(self, world: World) -> None:
        world.album("Big", camera(10))
        world.album("Town", camera(4), kind="city")
        assert world.run(OCTOBER) == EXIT_OK
        assert (world.row("Big").status, world.row("Big").part, world.row("Big").parts) == (
            "playing",
            1,
            2,
        )
        assert world.run(NOVEMBER) == EXIT_OK  # alternation is suspended: Town waits
        assert world.played == [camera(5), camera(5, start=6)]
        assert world.row("Big").status == "shown" and world.row("Town").status == "queued"
        assert world.deduped == 1  # November was cut from the picks CSV

    def test_a_rerun_in_the_same_month_repeats_the_same_part(self, world: World) -> None:
        world.album("Big", camera(10))
        world.run(OCTOBER)
        world.run(OCTOBER)
        assert world.played == [camera(5), camera(5)]
        assert world.row("Big").part == 1
        assert len(world.ingested) == 1  # the choice was recorded, not made again


class TestFailures:
    def test_an_unmounted_library_is_one_error_notification(self, world: World) -> None:
        world.cfg.root = str(world.root / "missing")
        assert world.run() == EXIT_NOT_MOUNTED
        assert world.notes == [(f"photo library not mounted: {world.cfg.root}", True)]

    def test_new_albums_without_a_kind_stop_the_run_without_notifying(self, world: World) -> None:
        (world.root / "2021" / "01-Jan" / "New").mkdir(parents=True)
        for name in camera(3):
            (world.root / "2021" / "01-Jan" / "New" / name).write_bytes(b"x")
        assert world.run() == EXIT_NEEDS_KIND
        assert world.notes == [] and world.played == []
        assert world.row("New").kind == "?"

    def test_a_failed_pipeline_is_not_marked_shown_and_resumes(self, world: World) -> None:
        world.album("Trip", camera(4))
        world.pipeline_exit = 1
        assert world.run() == EXIT_FAILED
        assert world.row("Trip").status == "playing" and world.row("Trip").part == 0
        assert world.notes == [("Trip: upload stopped (exit 1); run again to resume", True)]
        world.pipeline_exit = 0
        assert world.run() == EXIT_OK
        assert world.row("Trip").status == "shown"
        assert len(world.ingested) == 1 and world.deduped == 1

    def test_a_new_album_cannot_take_over_a_month_already_chosen(self, world: World) -> None:
        world.album("Trip", camera(4))
        world.pipeline_exit = 1
        world.run()
        world.pipeline_exit = 0
        for seed in range(5):  # wherever the newcomer lands in the queue
            world.album(f"New{seed}", camera(4), kind="city")
        assert world.run() == EXIT_OK
        assert world.row("Trip").status == "shown" and len(world.played) == 2
        assert world.played[1] == camera(4)

    def test_an_album_with_nothing_ingestable_is_small_not_a_crash(self, world: World) -> None:
        world.album("Empty", camera(3))
        world.album("Next", camera(4), kind="city")
        for file in (world.root / "2020" / "05-May" / "Empty").iterdir():
            file.unlink()  # the folder emptied after it was indexed
        assert world.run() == EXIT_OK
        assert world.row("Empty").status == "small"
        assert world.row("Next").status == "shown"

    def test_a_failure_while_choosing_pictures_is_reported_and_retried(self, world: World) -> None:
        world.album("Trip", camera(4))
        world.dedup_error = RuntimeError("swiftc")
        assert world.run() == EXIT_FAILED
        assert world.notes == [("choosing pictures failed: swiftc", True)]
        world.dedup_error = None
        assert world.run() == EXIT_OK and world.row("Trip").status == "shown"

    def test_a_header_only_picks_csv_is_ignored(self, world: World) -> None:
        folder = world.album("Trip", camera(4))
        (folder / "frame_picks.csv").write_text("file,recommended_name\n")
        assert world.run() == EXIT_OK
        assert world.deduped == 1 and world.played == [camera(4)]

    def test_next_names_the_following_month_on_a_catch_up_run(self, world: World) -> None:
        world.album("Trip", camera(4))
        world.album("Town", camera(4), kind="city")
        world.album("Hill", camera(4))
        world.run(date(2026, 10, 20))
        assert world.notes[-1][0].endswith("Next: Town")

    def test_nothing_eligible_is_an_error(self, world: World) -> None:
        world.album("Party", camera(4), kind="other")
        assert world.run() == EXIT_FAILED
        assert world.notes == [("no eligible album left in the queue", True)]

    def test_success_is_one_terse_line_and_a_published_table(self, world: World) -> None:
        world.album("Trip", camera(4))
        world.album("Town", camera(4), kind="city")
        world.run()
        assert world.notes == [("Trip (May 2020): 0 up, 0 old removed. Next: Town", False)]
        assert "| 2026-11-02 | Town |" in (world.data / "upcoming.md").read_text()


class TestClassify:
    def test_bad_kind_or_unknown_album_is_refused(self) -> None:
        albums = [queue.Album(path="2020/05-May/Trip", pictures=5)]
        with pytest.raises(ValueError):
            classify(albums, ["2020/05-May/Trip\tbeach\taway"])
        with pytest.raises(ValueError):
            classify(albums, ["2020/05-May/Nope\tpark\taway"])
