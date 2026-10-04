"""Tests for dedup_photos: clustering, best-pick, the full flow on fake Vision output, and a
real-Vision smoke test."""

import platform
import shutil
from pathlib import Path

import numpy as np
import pytest

from SamsungFrame.dedup_photos import (
    DEFAULT_MAX_DISTANCE,
    OVER_LIMIT,
    VisionFeatures,
    cluster,
    dedup,
    link_kept,
    pick_best,
    vision_features,
)
from SamsungFrame.frame_job import Job, Manifest, PhotoRecord
from SamsungFrame.ingest import run_ingest
from SamsungFrame.test_ingest import pattern


def matrix(rows: list[list[float]]) -> np.ndarray:
    return np.array(rows, dtype=np.float64)


def photo(
    name: str, sharp: float = 1.0, width: int = 400, height: int = 300, time: float = 0.0
) -> PhotoRecord:
    return PhotoRecord(
        name=name, source=name, time=time, width=width, height=height, sharpness=sharp
    )


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

    def groups(self, times: np.ndarray, window: float, cap: float) -> list[list[int]]:
        return sorted(map(sorted, cluster(self.DIST, times, window, cap)))

    def test_cap_alone_decides_how_much_merges(self) -> None:
        assert self.groups(self.TIMES, 600, 0.2) == [[0, 1], [2], [3]]
        assert self.groups(self.TIMES, 600, 0.6) == [[0, 1, 2], [3]]
        assert self.groups(self.TIMES, 600, 1.0) == [[0, 1, 2, 3]]

    def test_nothing_within_the_cap_means_nothing_merges(self) -> None:
        assert self.groups(self.TIMES, 600, 0.05) == [[0], [1], [2], [3]]

    def test_average_linkage_not_single(self) -> None:
        # 2 is 0.5 from 0 but 0.6 from 1: the pair's average (0.55) must pass the cap, not 0.5
        assert self.groups(self.TIMES, 600, 0.52) == [[0, 1], [2], [3]]

    def test_window_keeps_distant_twins_apart(self) -> None:
        times = np.array([0.0, 5000.0, 10.0, 20.0])
        assert not any({0, 1} <= set(g) for g in cluster(self.DIST, times, 600, 1.0))

    def test_empty_and_single_inputs(self) -> None:
        assert cluster(matrix([]).reshape(0, 0), np.zeros(0), 600, 0.4) == []
        assert cluster(matrix([[0.0]]), np.zeros(1), 600, 0.4) == [[0]]


class TestPickBest:
    def test_highest_score_wins_over_sharpness(self) -> None:
        photos = [photo("a", sharp=99), photo("b", sharp=1)]
        assert pick_best([0, 1], [0.4, 0.6], photos) == 1

    def test_sharpness_breaks_a_tie(self) -> None:
        photos = [photo("a", sharp=1), photo("b", sharp=5)]
        assert pick_best([0, 1], [0.5, 0.5], photos) == 1

    def test_landscape_beats_a_slightly_better_portrait(self) -> None:
        photos = [photo("land"), photo("port", width=300, height=400)]
        assert pick_best([0, 1], [0.50, 0.55], photos) == 0

    def test_clearly_better_portrait_still_wins(self) -> None:
        photos = [photo("land"), photo("port", width=300, height=400)]
        assert pick_best([0, 1], [0.40, 0.70], photos) == 1


class TestLinkKept:
    def make_job(self, tmp_path: Path) -> Job:
        job = Job(tmp_path / "job")
        job.create()
        for name in ("a.jpg", "b.jpg"):
            (job.jpg_dir / name).write_bytes(name.encode())
        return job

    def test_links_only_kept_names_without_copying(self, tmp_path: Path) -> None:
        job = self.make_job(tmp_path)
        link_kept(job, ["a.jpg"])
        assert [p.name for p in job.deduped_dir.iterdir()] == ["a.jpg"]
        assert (job.deduped_dir / "a.jpg").stat().st_ino == (job.jpg_dir / "a.jpg").stat().st_ino

    def test_rerun_drops_previously_kept_names(self, tmp_path: Path) -> None:
        job = self.make_job(tmp_path)
        link_kept(job, ["a.jpg", "b.jpg"])
        link_kept(job, ["b.jpg"])
        assert [p.name for p in job.deduped_dir.iterdir()] == ["b.jpg"]


class TestDedupFlow:
    """The whole stage on fake Vision output, so it runs on any platform."""

    NAMES = ["a.jpg", "b.jpg", "c.jpg", "d.jpg"]

    def job(self, tmp_path: Path, times: dict[str, float] | None = None) -> Job:
        job = Job(tmp_path / "job")
        job.create()
        times = times or {}
        manifest = Manifest(photos={n: photo(n, time=times.get(n, 0.0)) for n in self.NAMES})
        for name in self.NAMES:
            (job.jpg_dir / name).write_bytes(name.encode())
        job.save(manifest)
        return job

    def features(
        self, utility: list[bool] | None = None, extra: list[str] | None = None
    ) -> "VisionFeatures":
        names = self.NAMES + (extra or [])
        n = len(names)
        dist = np.full((n, n), 0.9)
        np.fill_diagonal(dist, 0.0)
        dist[0, 1] = dist[1, 0] = 0.1  # a and b are twins
        return VisionFeatures(
            names=names,
            dist=dist,
            scores=[0.5, 0.7, 0.6, 0.55] + [0.5] * len(extra or []),
            utility=(utility or [False] * 4) + [False] * len(extra or []),
        )

    def run(self, job: Job, features: VisionFeatures, cap: float = 0.4) -> list[str]:
        return dedup(job, cap=cap, features_of=lambda _jpgs, _build: features)

    def test_keeps_best_of_each_cluster_and_records_why_the_rest_went(self, tmp_path: Path) -> None:
        job = self.job(tmp_path)
        kept = self.run(job, self.features(utility=[False, False, True, False]))
        assert kept == ["b.jpg", "d.jpg"]
        manifest = job.load()
        assert manifest.kept == kept
        assert manifest.dropped == {"a.jpg": "duplicate of b.jpg", "c.jpg": "utility"}
        assert sorted(p.name for p in job.deduped_dir.iterdir()) == kept

    def test_utility_photos_never_pull_a_duplicate_into_their_cluster(self, tmp_path: Path) -> None:
        job = self.job(tmp_path)
        features = self.features(utility=[False, True, False, False])
        kept = self.run(job, features)
        assert "a.jpg" in kept and job.load().dropped["b.jpg"] == "utility"

    def test_window_applies(self, tmp_path: Path) -> None:
        job = self.job(tmp_path, times={"a.jpg": 0.0, "b.jpg": 5000.0})
        kept = self.run(job, self.features())
        assert "a.jpg" in kept and "b.jpg" in kept

    def test_max_distance_is_the_only_control(self, tmp_path: Path) -> None:
        job = self.job(tmp_path)
        assert len(self.run(job, self.features(), cap=0.05)) == 4
        assert len(self.run(job, self.features(), cap=0.4)) == 3

    def test_max_photos_keeps_the_best_of_each_stretch_of_the_album(self, tmp_path: Path) -> None:
        job = self.job(tmp_path, times={"a.jpg": 0, "b.jpg": 9000, "c.jpg": 18000, "d.jpg": 27000})
        kept = dedup(job, features_of=lambda _jpgs, _build: self.features(), max_photos=2)
        assert kept == ["b.jpg", "c.jpg"]  # scores: a .5, b .7 | c .6, d .55
        assert job.load().dropped == {"a.jpg": OVER_LIMIT, "d.jpg": OVER_LIMIT}

    def test_max_photos_above_the_count_changes_nothing(self, tmp_path: Path) -> None:
        job = self.job(tmp_path)
        assert len(dedup(job, features_of=lambda _j, _b: self.features(), max_photos=10)) == 3

    def test_everything_utility_keeps_nothing(self, tmp_path: Path) -> None:
        job = self.job(tmp_path)
        assert self.run(job, self.features(utility=[True] * 4)) == []

    def test_photos_not_in_the_manifest_are_ignored(self, tmp_path: Path) -> None:
        job = self.job(tmp_path)
        kept = self.run(job, self.features(extra=["stale.jpg"]))
        assert "stale.jpg" not in kept and "stale.jpg" not in job.load().dropped

    def test_empty_job_is_refused(self, tmp_path: Path) -> None:
        job = Job(tmp_path / "job")
        job.create()
        with pytest.raises(ValueError, match="run ingest.py first"):
            dedup(job)


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("swiftc") is None,
    reason="Apple Vision needs macOS + swiftc",
)
class TestRealVision:
    def test_features_for_real_images(self, tmp_path: Path) -> None:
        pattern(1).save(tmp_path / "a.jpg")
        pattern(1).save(tmp_path / "b.jpg", quality=80)
        pattern(2).save(tmp_path / "c.jpg")
        features = vision_features(tmp_path, tmp_path)
        assert features.names == ["a.jpg", "b.jpg", "c.jpg"]
        assert features.dist[0, 1] < DEFAULT_MAX_DISTANCE
        assert features.dist[0, 1] < features.dist[0, 2]
        assert len(features.scores) == 3 and all(isinstance(s, float) for s in features.scores)
        assert len(features.utility) == 3

    def test_an_unreadable_jpg_is_unique_and_does_not_abort_the_run(self, tmp_path: Path) -> None:
        pattern(1).save(tmp_path / "a.jpg")
        (tmp_path / "bad.jpg").write_bytes(b"not a jpeg")
        features = vision_features(tmp_path, tmp_path)
        bad = features.names.index("bad.jpg")
        assert features.scores[bad] == 0 and not features.utility[bad]
        assert features.dist[bad, features.names.index("a.jpg")] == 1.0

    def test_twins_collapse_end_to_end(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        pattern(1).save(src / "twin_a.jpg", quality=95)
        pattern(1).save(src / "twin_b.jpg", quality=80)
        pattern(2).save(src / "other_1.jpg")
        pattern(3).save(src / "other_2.jpg")
        job = Job(tmp_path / "job")
        run_ingest(src, job, False, 0.0, 2)
        kept = dedup(job)
        assert len(kept) == 3 and len({"twin_a.jpg", "twin_b.jpg"} - set(kept)) == 1
