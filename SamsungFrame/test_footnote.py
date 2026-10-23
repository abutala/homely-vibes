"""Tests for the footnote: its lines, its contrast on any background, and the upload copies."""

from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from SamsungFrame.footnote import (
    footnote_job,
    footnote_lines,
    offline_places,
    shutter,
    stamp,
)
from SamsungFrame.frame_job import Job, Manifest, PhotoRecord, Shot

NO_LIMIT = 10 * 1024 * 1024
BANFF = Shot(
    taken="2022:08:08 17:22:43",
    lat=51.26,
    lon=-115.83,
    camera="iPhone 13 Pro",
    f_number=2.2,
    exposure=0.008547,
    iso=100,
)


class TestFootnoteLines:
    def test_every_field(self) -> None:
        assert footnote_lines("trip/IMG_0802.HEIC", BANFF, "Banff, Alberta") == [
            "IMG_0802",
            "8 Aug 2022, 5:22 PM · Banff, Alberta",
            "iPhone 13 Pro · ƒ/2.2 · 1/117 s · ISO 100",
        ]

    def test_a_typed_caption_is_part_of_the_name(self) -> None:
        assert footnote_lines("IMG_2092-Valley view vista.JPG", Shot(), None) == [
            "IMG_2092-Valley view vista"
        ]

    def test_missing_fields_are_left_out_and_empty_lines_dropped(self) -> None:
        shot = Shot(taken="2022:08:08 07:05:00", iso=400)
        assert footnote_lines("a.jpg", shot, None) == ["a", "8 Aug 2022, 7:05 AM", "ISO 400"]

    def test_a_place_without_a_date_still_shows(self) -> None:
        assert footnote_lines("a.jpg", Shot(taken="garbage"), "Banff, Alberta") == [
            "a",
            "Banff, Alberta",
        ]

    @pytest.mark.parametrize(
        ("seconds", "text"), [(1 / 250, "1/250 s"), (0.5, "1/2 s"), (1.0, "1 s"), (2.5, "2.5 s")]
    )
    def test_shutter(self, seconds: float, text: str) -> None:
        assert shutter(seconds) == text


class TestStamp:
    LINES = ["IMG_0802", "8 Aug 2022, 5:22 PM", "iPhone 13 Pro · ISO 100"]

    def corner(self, img: Image.Image) -> np.ndarray:
        w, h = img.size
        return np.asarray(img.convert("L").crop((0, int(h * 0.85), w // 3, h)))

    @pytest.mark.parametrize("background", ["white", "black", (250, 180, 190)])
    def test_reads_on_any_background(self, background: object) -> None:
        out = stamp(Image.new("RGB", (1600, 900), background), self.LINES)  # type: ignore[arg-type]
        corner = self.corner(out)
        assert corner.max() >= 250, "white text is drawn"
        assert corner.min() <= 120, "a dark halo separates it from the background"

    def test_only_the_bottom_left_corner_changes(self) -> None:
        img = Image.new("RGB", (1600, 900), (90, 120, 150))
        out = np.asarray(stamp(img, self.LINES))
        assert (out[: int(900 * 0.8)] == np.asarray(img)[: int(900 * 0.8)]).all()
        assert (out[:, 1100:] == np.asarray(img)[:, 1100:]).all()

    def test_the_original_is_left_untouched(self) -> None:
        img = Image.new("RGB", (800, 450), "white")
        stamp(img, self.LINES)
        assert np.asarray(img).min() == 255


def make_job(tmp_path: Path, shots: dict[str, Shot]) -> tuple[Job, Manifest]:
    job = Job(tmp_path / "job")
    job.create()
    photos = {}
    for name, shot in shots.items():
        Image.new("RGB", (1600, 900), "white").save(job.jpg_dir / name)
        photos[name] = PhotoRecord(
            name=name, source=f"dir/{name}", time=0, width=1600, height=900, sharpness=1, shot=shot
        )
    manifest = Manifest(photos=photos)
    job.save(manifest)
    return job, manifest


class Places:
    def __init__(self, fail: bool = False):
        self.calls: list[list[tuple[float, float]]] = []
        self.fail = fail

    def __call__(self, coords: list[tuple[float, float]]) -> list[str | None]:
        self.calls.append(coords)
        if self.fail:
            raise RuntimeError("no table")
        return ["Banff, Alberta"] * len(coords)


class TestFootnoteJob:
    def test_copies_are_footnoted_and_the_jpgs_untouched(self, tmp_path: Path) -> None:
        job, manifest = make_job(tmp_path, {"a.jpg": BANFF, "b.jpg": Shot()})
        places = Places()
        files = footnote_job(job, manifest, ["a.jpg", "b.jpg"], places, NO_LIMIT)
        assert files == [job.footnoted_dir / "a.jpg", job.footnoted_dir / "b.jpg"]
        assert places.calls == [[(51.26, -115.83)]], "one lookup, only for photos with GPS"
        for f in files:
            with Image.open(f) as out:
                assert np.asarray(out.convert("L")).min() < 200
        with Image.open(job.jpg_dir / "a.jpg") as jpg:
            assert np.asarray(jpg.convert("L")).min() == 255

    def test_a_rerun_reuses_the_copies(self, tmp_path: Path) -> None:
        job, manifest = make_job(tmp_path, {"a.jpg": BANFF})
        footnote_job(job, manifest, ["a.jpg"], Places(), NO_LIMIT)
        again = Places()
        footnote_job(job, manifest, ["a.jpg"], again, NO_LIMIT)
        assert again.calls == [[]]

    def test_an_unreadable_jpg_is_sent_plain(self, tmp_path: Path) -> None:
        job, manifest = make_job(tmp_path, {"a.jpg": BANFF, "b.jpg": BANFF})
        (job.jpg_dir / "b.jpg").write_bytes(b"not a jpg")
        files = footnote_job(job, manifest, ["a.jpg", "b.jpg"], Places(), NO_LIMIT)
        assert files == [job.footnoted_dir / "a.jpg", job.jpg_dir / "b.jpg"]
        assert not (job.footnoted_dir / "b.jpg").exists()

    def test_a_copy_over_the_size_limit_is_sent_plain(self, tmp_path: Path) -> None:
        job, manifest = make_job(tmp_path, {"a.jpg": BANFF})
        files = footnote_job(job, manifest, ["a.jpg"], Places(), max_bytes=100)
        assert files == [job.jpg_dir / "a.jpg"]
        assert list(job.footnoted_dir.iterdir()) == [], "no copy and no temp file is left"

    def test_a_failed_place_lookup_still_footnotes(self, tmp_path: Path) -> None:
        job, manifest = make_job(tmp_path, {"a.jpg": BANFF})
        files = footnote_job(job, manifest, ["a.jpg"], Places(fail=True), NO_LIMIT)
        assert files == [job.footnoted_dir / "a.jpg"]


def test_offline_places_names_the_nearest_town() -> None:
    assert offline_places([(51.1784, -115.5708), (37.7749, -122.4194)]) == [
        "Banff, Alberta",
        "San Francisco, California",
    ]
    assert offline_places([]) == []
