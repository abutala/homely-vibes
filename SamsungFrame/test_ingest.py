"""Tests for ingest: name/size filtering, single-read conversion, portraits, checkpoint and resume."""

import os
from pathlib import Path

import numpy as np
import pytest
from PIL import Image, ImageDraw

from SamsungFrame.frame_job import Job, Manifest, PhotoRecord
from SamsungFrame.ingest import (
    IngestJob,
    IngestResult,
    capture_time,
    save_within_limit,
    ingest_batch,
    ingest_one,
    is_portrait,
    jpg_name,
    list_source,
    pending,
    run_ingest,
    skip_reason,
    summarize,
)

MIN = 1000  # bytes
NO_LIMIT = 10 * 1024 * 1024


def pattern(seed: int, size: tuple[int, int] = (800, 600)) -> Image.Image:
    rng = np.random.default_rng(seed)
    img = Image.new("RGB", size, tuple(int(c) for c in rng.integers(0, 255, 3)))
    draw = ImageDraw.Draw(img)
    for _ in range(12):
        x, y = (int(v) for v in rng.integers(0, 600, 2))
        w, h = (int(v) for v in rng.integers(40, 300, 2))
        color = tuple(int(c) for c in rng.integers(0, 255, 3))
        draw.ellipse([x, y, x + w, y + h], fill=color)
    return img


def exif_with_orientation(orientation: int) -> Image.Exif:
    exif = Image.Exif()
    exif[0x0112] = orientation
    return exif


def crash_on_boom(job: IngestJob) -> IngestResult:
    """Stands in for a corrupt file that kills its worker process outright."""
    if job[1].startswith("boom"):
        os._exit(1)
    return ingest_one(job)


class TestSkipReason:
    @pytest.mark.parametrize(
        ("name", "size", "reason"),
        [
            ("IMG_1.HEIC", MIN, None),
            ("IMG_1.jpeg", MIN, None),
            ("IMG_1.MOV", MIN, "video"),
            ("clip.mp4", MIN, "video"),
            ("IMG_1.AAE", 10, "sidecar"),
            ("notes.txt", MIN, "not an image"),
            ("pic_thumb.jpg", MIN, "thumbnail"),
            ("pic_small@2x.png", MIN, "thumbnail"),
            ("tiny.jpg", MIN - 1, "small"),
        ],
    )
    def test_by_name_and_size(self, name: str, size: int, reason: str | None) -> None:
        assert skip_reason(name, size, MIN) == reason


class TestListSource:
    def test_recursive_with_reasons_and_hidden_files_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "a.jpg").write_bytes(b"x" * MIN)
        (tmp_path / "sub" / "b.HEIC").write_bytes(b"x" * MIN)
        (tmp_path / "clip.MOV").write_bytes(b"x" * MIN)
        (tmp_path / "tiny.jpg").write_bytes(b"x")
        (tmp_path / ".DS_Store").write_bytes(b"x")
        (tmp_path / "._a.jpg").write_bytes(b"x" * MIN)
        candidates, skipped = list_source(tmp_path, MIN)
        assert candidates == ["a.jpg", "sub/b.HEIC"]
        assert skipped == {"clip.MOV": "video", "tiny.jpg": "small"}


class TestJpgName:
    def test_extension_swapped(self) -> None:
        assert jpg_name("d/IMG_1.HEIC", set()) == "IMG_1.jpg"

    def test_collision_gets_path_hash_and_is_deterministic(self) -> None:
        taken: set[str] = set()
        first = jpg_name("a/IMG_1.HEIC", taken)
        second = jpg_name("b/IMG_1.HEIC", taken)
        assert first == "IMG_1.jpg"
        assert second != first and second.startswith("IMG_1_")
        assert jpg_name("b/IMG_1.HEIC", {"img_1.jpg"}) == second

    def test_long_names_are_capped_to_fifty_characters_with_the_extension(self) -> None:
        name = jpg_name("d/" + "x" * 120 + ".HEIC", set())
        assert len(name) == 50 and name.endswith(".jpg")

    def test_long_names_sharing_a_prefix_still_get_distinct_jpgs(self) -> None:
        taken: set[str] = set()
        first = jpg_name("a/" + "x" * 120 + "_one.jpg", taken)
        second = jpg_name("b/" + "x" * 120 + "_two.jpg", taken)
        assert first != second and len(second) <= 50

    def test_collision_is_case_insensitive(self) -> None:
        taken = {"img_1.jpg"}
        assert jpg_name("x/IMG_1.png", taken) != "IMG_1.jpg"


class TestImageFacts:
    def test_orientation_turns_a_landscape_file_into_a_portrait(self, tmp_path: Path) -> None:
        path = tmp_path / "p.jpg"
        pattern(1, (400, 300)).save(path, exif=exif_with_orientation(6))
        with Image.open(path) as img:
            assert is_portrait(img)

    def test_plain_landscape_and_square_are_not_portraits(self, tmp_path: Path) -> None:
        for size in ((400, 300), (300, 300)):
            path = tmp_path / f"{size[0]}x{size[1]}.jpg"
            pattern(1, size).save(path)
            with Image.open(path) as img:
                assert not is_portrait(img)

    def test_capture_time_from_exif_and_fallback(self, tmp_path: Path) -> None:
        exif = Image.Exif()
        exif[0x0132] = "2024:10:01 12:30:00"
        path = tmp_path / "t.jpg"
        pattern(1).save(path, exif=exif)
        with Image.open(path) as img:
            assert capture_time(img, 7.0) == pytest.approx(1727800200.0, abs=14 * 3600)
        plain = tmp_path / "n.jpg"
        pattern(1).save(plain)
        with Image.open(plain) as img:
            assert capture_time(img, 7.0) == 7.0


class TestIngestOne:
    def run(
        self, tmp_path: Path, rel: str, include_portraits: bool = False
    ) -> tuple[tuple[str, PhotoRecord | None, str | None], Path]:
        target = tmp_path / "out" / "x.jpg"
        target.parent.mkdir(exist_ok=True)
        return ingest_one((tmp_path, rel, target, include_portraits, NO_LIMIT)), target

    def test_big_png_becomes_4k_jpg_with_record(self, tmp_path: Path) -> None:
        Image.new("RGB", (5000, 3000), "red").save(tmp_path / "big.png")
        (rel, record, reason), target = self.run(tmp_path, "big.png")
        assert reason is None and record is not None
        assert (record.width, record.height) == (3600, 2160)
        assert record.source == "big.png" and record.name == "x.jpg"
        with Image.open(target) as out:
            assert out.format == "JPEG"

    def test_heic_is_read_and_converted(self, tmp_path: Path) -> None:
        pattern(3).save(tmp_path / "h.heic", format="HEIF")
        (_, record, reason), target = self.run(tmp_path, "h.heic")
        assert reason is None and record is not None and target.exists()

    def test_heic_portrait_is_detected(self, tmp_path: Path) -> None:
        pattern(3, (300, 400)).save(tmp_path / "p.heic", format="HEIF")
        (_, record, reason), target = self.run(tmp_path, "p.heic")
        assert (record, reason) == (None, "portrait") and not target.exists()

    def test_portrait_is_skipped_without_writing(self, tmp_path: Path) -> None:
        pattern(1, (300, 400)).save(tmp_path / "p.jpg")
        (_, record, reason), target = self.run(tmp_path, "p.jpg")
        assert (record, reason) == (None, "portrait")
        assert not target.exists()

    def test_portrait_kept_when_wanted(self, tmp_path: Path) -> None:
        pattern(1, (300, 400)).save(tmp_path / "p.jpg")
        (_, record, reason), _ = self.run(tmp_path, "p.jpg", include_portraits=True)
        assert reason is None and record is not None and not record.landscape

    def test_unreadable_file_is_reported(self, tmp_path: Path) -> None:
        (tmp_path / "bad.jpg").write_bytes(b"not an image")
        (_, record, reason), _ = self.run(tmp_path, "bad.jpg")
        assert record is None and reason is not None and reason.startswith("unreadable")


class TestIngestBatch:
    def jobs(self, tmp_path: Path, names: list[str]) -> list[IngestJob]:
        (tmp_path / "out").mkdir()
        for i, name in enumerate(names):
            pattern(i).save(tmp_path / name)
        return [
            (tmp_path, n, tmp_path / "out" / f"{Path(n).stem}.jpg", False, NO_LIMIT) for n in names
        ]

    def test_results_come_back_in_job_order(self, tmp_path: Path) -> None:
        results = ingest_batch(self.jobs(tmp_path, ["a.jpg", "b.jpg", "c.jpg"]), workers=2)
        assert [r[0] for r in results] == ["a.jpg", "b.jpg", "c.jpg"]
        assert all(r[1] is not None for r in results)

    def test_a_crashing_file_is_isolated_and_the_rest_still_ingest(self, tmp_path: Path) -> None:
        jobs = self.jobs(tmp_path, ["ok1.jpg", "boom.jpg", "ok2.jpg", "ok3.jpg"])
        results = ingest_batch(jobs, workers=2, fn=crash_on_boom)
        assert results[1] == ("boom.jpg", None, "unreadable: worker crashed")
        assert [r[1] is not None for r in results] == [True, False, True, True]


class TestSaveWithinLimit:
    def noisy(self) -> Image.Image:
        rng = np.random.default_rng(0)
        return Image.fromarray(rng.integers(0, 255, (900, 1200, 3), dtype=np.uint8))

    def size_at(self, img: Image.Image, tmp_path: Path, quality: int) -> int:
        path = tmp_path / f"q{quality}.jpg"
        img.save(path, "JPEG", quality=quality)
        return path.stat().st_size

    def test_a_file_that_fits_keeps_the_highest_quality(self, tmp_path: Path) -> None:
        img, target = self.noisy(), tmp_path / "out.jpg"
        save_within_limit(img, target, NO_LIMIT)
        assert target.stat().st_size == self.size_at(img, tmp_path, 90)

    def test_quality_drops_until_the_file_fits(self, tmp_path: Path) -> None:
        img, target = self.noisy(), tmp_path / "out.jpg"
        limit = (self.size_at(img, tmp_path, 90) + self.size_at(img, tmp_path, 70)) // 2
        save_within_limit(img, target, limit)
        assert target.stat().st_size <= limit
        assert target.stat().st_size < self.size_at(img, tmp_path, 90)

    def test_an_impossible_limit_still_writes_the_lowest_quality(self, tmp_path: Path) -> None:
        img, target = self.noisy(), tmp_path / "out.jpg"
        save_within_limit(img, target, 1)
        assert target.stat().st_size == self.size_at(img, tmp_path, 70)


class TestPending:
    def photo(self, name: str, source: str) -> PhotoRecord:
        return PhotoRecord(name=name, source=source, time=0, width=2, height=1, sharpness=1.0)

    def manifest(self) -> Manifest:
        return Manifest(
            photos={"a.jpg": self.photo("a.jpg", "a.jpg")},
            skipped={"p.jpg": "portrait", "bad.jpg": "unreadable: boom"},
        )

    def test_recorded_photos_and_cached_portraits_are_not_reread(self) -> None:
        todo = pending(self.manifest(), ["a.jpg", "p.jpg", "new.jpg"], include_portraits=False)
        assert todo == ["new.jpg"]

    def test_unreadable_always_retries(self) -> None:
        todo = pending(self.manifest(), ["a.jpg", "bad.jpg"], include_portraits=False)
        assert todo == ["bad.jpg"]

    def test_portraits_retry_once_wanted(self) -> None:
        todo = pending(self.manifest(), ["a.jpg", "p.jpg"], include_portraits=True)
        assert todo == ["p.jpg"]


class TestRunIngest:
    def source(self, tmp_path: Path) -> Path:
        src = tmp_path / "src"
        src.mkdir()
        pattern(1).save(src / "land.jpg")
        pattern(2, (300, 400)).save(src / "port.jpg")
        (src / "clip.MOV").write_bytes(b"x" * 5000)
        (src / "IMG.AAE").write_text("x")
        return src

    def ingest(self, src: Path, job: Job, include_portraits: bool = False) -> Manifest:
        return run_ingest(src, job, include_portraits, min_size_mb=0.0, workers=2)

    def test_end_to_end_filters_and_records_reasons(self, tmp_path: Path) -> None:
        job = Job(tmp_path / "job")
        manifest = self.ingest(self.source(tmp_path), job)
        assert list(manifest.photos) == ["land.jpg"]
        assert manifest.skipped == {
            "clip.MOV": "video",
            "IMG.AAE": "sidecar",
            "port.jpg": "portrait",
        }
        assert sorted(p.name for p in job.jpg_dir.iterdir()) == ["land.jpg"]
        assert job.load() == manifest
        assert summarize(manifest) == "1 photos ready; skipped: 1 portrait, 1 sidecar, 1 video"

    def test_resume_does_not_reread_originals(self, tmp_path: Path) -> None:
        src = self.source(tmp_path)
        job = Job(tmp_path / "job")
        self.ingest(src, job)
        (src / "land.jpg").unlink()  # a reread would now record it as unreadable
        manifest = self.ingest(src, job)
        assert list(manifest.photos) == ["land.jpg"]
        assert "land.jpg" not in manifest.skipped

    def test_new_files_are_picked_up_on_rerun(self, tmp_path: Path) -> None:
        src = self.source(tmp_path)
        job = Job(tmp_path / "job")
        self.ingest(src, job)
        pattern(5).save(src / "later.jpg")
        assert sorted(self.ingest(src, job).photos) == ["land.jpg", "later.jpg"]

    def test_file_that_grows_past_the_size_floor_is_ingested(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        pattern(1, (40, 30)).save(src / "pic.jpg")
        job = Job(tmp_path / "job")
        floor = (src / "pic.jpg").stat().st_size / (1024 * 1024) + 0.001
        assert run_ingest(src, job, False, floor, 1).skipped == {"pic.jpg": "small"}
        manifest = run_ingest(src, job, False, 0.0, 1)
        assert list(manifest.photos) == ["pic.jpg"] and manifest.skipped == {}

    def test_including_portraits_later_ingests_them(self, tmp_path: Path) -> None:
        src = self.source(tmp_path)
        job = Job(tmp_path / "job")
        self.ingest(src, job)
        manifest = self.ingest(src, job, include_portraits=True)
        assert sorted(manifest.photos) == ["land.jpg", "port.jpg"]
        assert "port.jpg" not in manifest.skipped

    def test_unreadable_file_is_retried_not_cached(self, tmp_path: Path) -> None:
        src = self.source(tmp_path)
        (src / "bad.jpg").write_bytes(b"not an image")
        job = Job(tmp_path / "job")
        assert self.ingest(src, job).skipped["bad.jpg"].startswith("unreadable")
        pattern(9).save(src / "bad.jpg")
        assert "bad.jpg" in self.ingest(src, job).photos

    def test_same_stem_in_two_folders_gets_two_jpgs(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        for sub_dir in ("a", "b"):
            (src / sub_dir).mkdir(parents=True)
        pattern(1).save(src / "a" / "IMG_1.jpg")
        pattern(2).save(src / "b" / "IMG_1.jpg")
        manifest = self.ingest(src, Job(tmp_path / "job"))
        assert len(manifest.photos) == 2
        assert sorted(p.source for p in manifest.photos.values()) == ["a/IMG_1.jpg", "b/IMG_1.jpg"]

    def test_portraits_ingested_earlier_are_dropped_when_no_longer_wanted(
        self, tmp_path: Path
    ) -> None:
        src = self.source(tmp_path)
        job = Job(tmp_path / "job")
        self.ingest(src, job, include_portraits=True)
        manifest = self.ingest(src, job, include_portraits=False)
        assert list(manifest.photos) == ["land.jpg"]
        assert manifest.skipped["port.jpg"] == "portrait"
        assert job.load() == manifest  # persisted even though there was nothing to read

    def test_a_video_removed_from_the_source_is_forgotten_on_disk(self, tmp_path: Path) -> None:
        src = self.source(tmp_path)
        job = Job(tmp_path / "job")
        self.ingest(src, job)
        (src / "clip.MOV").unlink()
        self.ingest(src, job)
        assert "clip.MOV" not in job.load().skipped

    def test_oversized_photos_are_recompressed_to_the_limit(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        rng = np.random.default_rng(1)
        img = Image.fromarray(rng.integers(0, 255, (1200, 1600, 3), dtype=np.uint8))
        img.save(src / "noisy.jpg", quality=95)
        sizes = {}
        for quality in (90, 70):
            img.save(tmp_path / f"q{quality}.jpg", "JPEG", quality=quality)
            sizes[quality] = (tmp_path / f"q{quality}.jpg").stat().st_size
        limit = (sizes[90] + sizes[70]) // 2
        job = Job(tmp_path / "job")
        run_ingest(src, job, False, 0.0, 1, max_image_mb=limit / (1024 * 1024))
        written = (job.jpg_dir / "noisy.jpg").stat().st_size
        assert written <= limit and written < sizes[90]

    def test_job_for_another_source_is_refused(self, tmp_path: Path) -> None:
        job = Job(tmp_path / "job")
        self.ingest(self.source(tmp_path), job)
        other = tmp_path / "other"
        other.mkdir()
        with pytest.raises(ValueError, match="belongs to"):
            self.ingest(other, job)
