"""Tests for dedup_photos: pure clustering logic, image prep, and a real-Vision smoke test."""

import shutil
import sys
from pathlib import Path

import numpy as np
import pytest
from PIL import Image, ImageDraw

from SamsungFrame.dedup_photos import (
    Photo,
    cluster,
    dedup,
    find_images,
    jpg_names,
    pick_best,
    prepare,
)


def matrix(rows: list[list[float]]) -> np.ndarray:
    return np.array(rows, dtype=np.float64)


def photo(name: str, sharp: float, width: int = 400, height: int = 300) -> Photo:
    return Photo(name=name, time=0.0, width=width, height=height, sharpness=sharp)


class TestCluster:
    # 0 and 1 are twins, 2 is close to the pair, 3 is unrelated
    DIST = matrix(
        [
            [0.0, 0.1, 0.5, 0.9],
            [0.1, 0.0, 0.6, 0.9],
            [0.5, 0.6, 0.0, 0.9],
            [0.9, 0.9, 0.9, 0.0],
        ]
    )
    TIMES = np.zeros(4)

    def test_merges_closest_pair_first(self) -> None:
        assert sorted(map(sorted, cluster(self.DIST, self.TIMES, 3, 600, 1.0))) == [
            [0, 1],
            [2],
            [3],
        ]

    def test_stops_at_goal(self) -> None:
        assert len(cluster(self.DIST, self.TIMES, 2, 600, 1.0)) == 2

    def test_average_linkage_not_single(self) -> None:
        groups = cluster(self.DIST, self.TIMES, 2, 600, 1.0)
        assert sorted(map(sorted, groups)) == [[0, 1, 2], [3]]

    def test_cap_stops_merging_before_goal(self) -> None:
        groups = cluster(self.DIST, self.TIMES, 1, 600, 0.2)
        assert sorted(map(sorted, groups)) == [[0, 1], [2], [3]]

    def test_window_keeps_distant_twins_apart(self) -> None:
        times = np.array([0.0, 5000.0, 10.0, 20.0])
        groups = cluster(self.DIST, times, 1, 600, 1.0)
        assert not any({0, 1} <= set(g) for g in groups)

    def test_goal_larger_than_photos_is_a_noop(self) -> None:
        assert len(cluster(self.DIST, self.TIMES, 10, 600, 1.0)) == 4


class TestPickBest:
    def test_sharpest_wins(self) -> None:
        photos = [photo("a", 10), photo("b", 30), photo("c", 20)]
        assert pick_best([0, 1, 2], photos) == 1

    def test_landscape_beats_slightly_sharper_portrait(self) -> None:
        photos = [photo("land", 10), photo("port", 15, width=300, height=400)]
        assert pick_best([0, 1], photos) == 0

    def test_much_sharper_portrait_still_wins(self) -> None:
        photos = [photo("land", 10), photo("port", 25, width=300, height=400)]
        assert pick_best([0, 1], photos) == 1


class TestJpgNames:
    def test_extension_swapped(self) -> None:
        assert jpg_names([Path("IMG_1.HEIC"), Path("IMG_2.png")]) == ["IMG_1.jpg", "IMG_2.jpg"]

    def test_shared_stem_keeps_both(self) -> None:
        names = jpg_names([Path("IMG_1.HEIC"), Path("IMG_1.PNG")])
        assert names == ["IMG_1_heic.jpg", "IMG_1_png.jpg"]


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


class TestFindImages:
    def test_top_level_images_only(self, tmp_path: Path) -> None:
        Image.new("RGB", (10, 10)).save(tmp_path / "a.PNG")
        (tmp_path / "clip.MOV").write_bytes(b"x")
        (tmp_path / "sub").mkdir()
        Image.new("RGB", (10, 10)).save(tmp_path / "sub" / "b.jpg")
        assert [p.name for p in find_images(tmp_path)] == ["a.PNG"]

    def test_empty_folder(self, tmp_path: Path) -> None:
        assert find_images(tmp_path) == []


class TestPrepare:
    def test_downsizes_to_4k_and_converts_to_jpg(self, tmp_path: Path) -> None:
        src, work = tmp_path / "src", tmp_path / "work"
        src.mkdir()
        work.mkdir()
        Image.new("RGB", (5000, 3000), "red").save(src / "big.png")
        Image.new("RGB", (300, 400), "blue").save(src / "small.JPG")
        photos = {p.name: p for p in prepare(src, work)}
        assert set(photos) == {"big.jpg", "small.jpg"}
        assert (photos["big.jpg"].width, photos["big.jpg"].height) == (3600, 2160)
        assert not photos["small.jpg"].landscape
        with Image.open(work / "big.jpg") as out:
            assert out.format == "JPEG"

    def test_ignores_non_images(self, tmp_path: Path) -> None:
        src, work = tmp_path / "src", tmp_path / "work"
        src.mkdir()
        work.mkdir()
        Image.new("RGB", (100, 100)).save(src / "a.jpg")
        (src / "clip.MOV").write_bytes(b"x")
        (src / "IMG_1.AAE").write_text("x")
        assert [p.name for p in prepare(src, work)] == ["a.jpg"]


@pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("swiftc") is None,
    reason="Apple Vision needs macOS + swiftc",
)
class TestDedupWithVision:
    def test_near_identical_pair_collapses(self, tmp_path: Path) -> None:
        src, out, work = tmp_path / "src", tmp_path / "out", tmp_path / "work"
        for d in (src, work):
            d.mkdir()
        pattern(1).save(src / "twin_a.jpg", quality=95)
        pattern(1).save(src / "twin_b.jpg", quality=80)
        pattern(2).save(src / "other_1.jpg")
        pattern(3).save(src / "other_2.jpg")
        kept = dedup(src, out, keep_fraction=0.75, window=600, cap=0.85, work=work)
        assert len(kept) == 3
        assert {"twin_a.jpg", "twin_b.jpg"} - set(kept) != set()  # one twin dropped
        assert sorted(p.name for p in out.iterdir()) == kept

    def test_leftovers_in_reused_work_dir_are_ignored(self, tmp_path: Path) -> None:
        src, out, work = tmp_path / "src", tmp_path / "out", tmp_path / "work"
        (work / "jpgs").mkdir(parents=True)
        src.mkdir()
        pattern(9).save(work / "jpgs" / "stale.jpg")
        pattern(1).save(src / "a.jpg")
        pattern(2).save(src / "b.jpg")
        kept = dedup(src, out, keep_fraction=1.0, window=600, cap=0.85, work=work)
        assert kept == ["a.jpg", "b.jpg"]
