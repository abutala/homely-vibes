"""Tests for the cleanup stage: the minimum-photo floor, the safety guards, dry run, idempotence."""

from pathlib import Path
from typing import Any, Optional

import pytest

from SamsungFrame.frame_cleanup import check_ready, choose_deletions, run_cleanup
from SamsungFrame.frame_job import ArtRecord, CleanupRecord, Job, Manifest, PhotoRecord


def old(*items: tuple[str, str]) -> list[ArtRecord]:
    return [ArtRecord(id=i, image_date=d) for i, d in items]


def photo(name: str) -> PhotoRecord:
    return PhotoRecord(name=name, source=name, time=0, width=4, height=3, sharpness=1.0)


class TestChooseDeletions:
    SNAPSHOT = old(
        ("MY_F1", "2024:01:01 00:00:00"),
        ("MY_F2", "2024:03:01 00:00:00"),
        ("MY_F3", "2024:02:01 00:00:00"),
        ("MY_F4", ""),
    )
    ALL = {"MY_F1", "MY_F2", "MY_F3", "MY_F4"}

    def test_floor_not_binding_deletes_every_old_photo(self) -> None:
        plan = choose_deletions(self.SNAPSHOT, self.ALL, new_on_tv=10, min_images=5)
        assert sorted(plan.delete) == ["MY_F1", "MY_F2", "MY_F3", "MY_F4"] and plan.retain == []

    def test_floor_retains_the_newest_old_photos(self) -> None:
        plan = choose_deletions(self.SNAPSHOT, self.ALL, new_on_tv=3, min_images=5)
        assert plan.retain == ["MY_F3", "MY_F2"]  # the two newest by date
        assert sorted(plan.delete) == ["MY_F1", "MY_F4"]

    def test_an_undated_photo_counts_as_the_oldest(self) -> None:
        plan = choose_deletions(self.SNAPSHOT, self.ALL, new_on_tv=0, min_images=3)
        assert plan.delete == ["MY_F4"]

    def test_floor_larger_than_everything_keeps_it_all(self) -> None:
        plan = choose_deletions(self.SNAPSHOT, self.ALL, new_on_tv=0, min_images=100)
        assert plan.delete == [] and len(plan.retain) == 4

    def test_old_photos_already_gone_are_not_planned(self) -> None:
        plan = choose_deletions(self.SNAPSHOT, {"MY_F1"}, new_on_tv=10, min_images=5)
        assert plan.delete == ["MY_F1"]

    def test_a_duplicated_snapshot_entry_is_planned_once(self) -> None:
        snapshot = old(("MY_F1", "2024:01:01 00:00:00"), ("MY_F1", "2024:01:01 00:00:00"))
        plan = choose_deletions(snapshot, {"MY_F1"}, new_on_tv=10, min_images=5)
        assert plan.delete == ["MY_F1"] and plan.retain == []

    def test_floor_counts_the_new_photos_exactly(self) -> None:
        plan = choose_deletions(self.SNAPSHOT, self.ALL, new_on_tv=5, min_images=5)
        assert plan.retain == [] and len(plan.delete) == 4
        plan = choose_deletions(self.SNAPSHOT, self.ALL, new_on_tv=4, min_images=5)
        assert plan.retain == ["MY_F2"]


class FakeTv:
    def __init__(self, ids: list[str]):
        self.ids = ids

    def get_available_art_strict(self) -> list[dict[str, Any]]:
        return [{"content_id": i} for i in self.ids] + [{"content_id": "SAM-S1"}]


class Deleter:
    def __init__(self, tv: FakeTv, fail: Optional[set[str]] = None):
        self.tv = tv
        self.fail = fail or set()
        self.calls: list[list[str]] = []

    def __call__(self, _client: Any, ids: list[str]) -> dict[str, int]:
        self.calls.append(list(ids))
        failed = [i for i in ids if i in self.fail]
        self.tv.ids = [i for i in self.tv.ids if i not in ids or i in failed]
        return {"total": len(ids), "deleted": len(ids) - len(failed), "failed": len(failed)}


def finished_job(tmp_path: Path, **overrides: Any) -> Job:
    """Old catalog MY_F1..3, new batch a/b on the TV as MY_F10/11, everything uploaded."""
    job = Job(tmp_path / "job")
    job.create()
    manifest = Manifest(
        photos={n: photo(n) for n in ("a.jpg", "b.jpg")},
        snapshot=old(
            ("MY_F1", "2024:01:01 00:00:00"), ("MY_F2", "2024:02:01 00:00:00"), ("MY_F3", "")
        ),
        uploaded={"a.jpg": "MY_F10", "b.jpg": "MY_F11"},
    )
    job.save(manifest.model_copy(update=overrides))
    return job


ON_TV = ["MY_F1", "MY_F2", "MY_F3", "MY_F10", "MY_F11"]


class TestCheckReady:
    def test_ready_returns_how_many_new_photos_are_on_the_tv(self, tmp_path: Path) -> None:
        manifest = finished_job(tmp_path).load()
        assert check_ready(manifest, set(ON_TV)) == 2

    def test_no_snapshot_means_the_upload_never_ran(self, tmp_path: Path) -> None:
        manifest = finished_job(tmp_path, snapshot=None).load()
        with pytest.raises(ValueError, match="No snapshot"):
            check_ready(manifest, set(ON_TV))

    def test_unfinished_upload_is_refused(self, tmp_path: Path) -> None:
        manifest = finished_job(tmp_path, uploaded={"a.jpg": "MY_F10"}).load()
        with pytest.raises(ValueError, match="1 photos are not uploaded"):
            check_ready(manifest, set(ON_TV))

    def test_none_of_the_batch_on_the_tv_is_refused(self, tmp_path: Path) -> None:
        manifest = finished_job(tmp_path, kept=[], uploaded={}).load()
        with pytest.raises(ValueError, match="None of this batch"):
            check_ready(manifest, {"MY_F1", "MY_F2"})

    def test_a_recorded_photo_missing_from_the_tv_is_refused(self, tmp_path: Path) -> None:
        manifest = finished_job(tmp_path).load()
        with pytest.raises(ValueError, match="1 uploaded photos are not on the TV"):
            check_ready(manifest, {"MY_F1", "MY_F2", "MY_F3", "MY_F10"})

    def test_overlap_between_old_and_new_is_refused(self, tmp_path: Path) -> None:
        manifest = finished_job(tmp_path, uploaded={"a.jpg": "MY_F1", "b.jpg": "MY_F11"}).load()
        with pytest.raises(ValueError, match="both old catalog and new batch"):
            check_ready(manifest, set(ON_TV))


class TestRunCleanup:
    def test_deletes_exactly_the_old_catalog_and_records_it(self, tmp_path: Path) -> None:
        job, tv = finished_job(tmp_path), FakeTv(list(ON_TV))
        deleter = Deleter(tv)
        run_cleanup(job, tv, min_images=1, delete=deleter)
        assert deleter.calls == [["MY_F3", "MY_F1", "MY_F2"]]  # undated first, then by date
        assert job.load().cleanup == CleanupRecord(deleted=3, failed=0, retained=0)
        assert tv.ids == ["MY_F10", "MY_F11"]

    def test_the_floor_keeps_the_newest_old_photos(self, tmp_path: Path) -> None:
        job, tv = finished_job(tmp_path), FakeTv(list(ON_TV))
        run_cleanup(job, tv, min_images=3, delete=(deleter := Deleter(tv)))
        assert deleter.calls == [["MY_F3", "MY_F1"]]
        assert job.load().cleanup == CleanupRecord(deleted=2, failed=0, retained=1)
        assert "MY_F2" in tv.ids

    def test_dry_run_deletes_nothing_and_leaves_the_manifest_alone(self, tmp_path: Path) -> None:
        job, tv = finished_job(tmp_path), FakeTv(list(ON_TV))
        deleter = Deleter(tv)
        plan = run_cleanup(job, tv, min_images=1, dry_run=True, delete=deleter)
        assert len(plan.delete) == 3 and deleter.calls == []
        assert job.load().cleanup is None and tv.ids == ON_TV

    def test_rerun_after_success_has_nothing_left_to_delete(self, tmp_path: Path) -> None:
        job, tv = finished_job(tmp_path), FakeTv(list(ON_TV))
        deleter = Deleter(tv)
        run_cleanup(job, tv, min_images=1, delete=deleter)
        run_cleanup(job, tv, min_images=1, delete=deleter)
        assert deleter.calls[1] == []

    def test_failed_deletes_are_retried_by_the_next_run(self, tmp_path: Path) -> None:
        job, tv = finished_job(tmp_path), FakeTv(list(ON_TV))
        deleter = Deleter(tv, fail={"MY_F1"})
        run_cleanup(job, tv, min_images=1, delete=deleter)
        assert job.load().cleanup == CleanupRecord(deleted=2, failed=1, retained=0)
        deleter.fail = set()
        run_cleanup(job, tv, min_images=1, delete=deleter)
        assert deleter.calls[1] == ["MY_F1"] and tv.ids == ["MY_F10", "MY_F11"]

    def test_never_deletes_a_photo_of_this_batch(self, tmp_path: Path) -> None:
        job, tv = finished_job(tmp_path, unattributed=["MY_F12"]), FakeTv(ON_TV + ["MY_F12"])
        run_cleanup(job, tv, min_images=1, delete=(deleter := Deleter(tv)))
        assert not {"MY_F10", "MY_F11", "MY_F12"} & {i for call in deleter.calls for i in call}

    def test_unfinished_upload_deletes_nothing(self, tmp_path: Path) -> None:
        job, tv = finished_job(tmp_path, uploaded={"a.jpg": "MY_F10"}), FakeTv(list(ON_TV))
        deleter = Deleter(tv)
        with pytest.raises(ValueError):
            run_cleanup(job, tv, min_images=1, delete=deleter)
        assert deleter.calls == [] and tv.ids == ON_TV
