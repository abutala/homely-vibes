"""Tests for the upload stage: snapshot-before-upload, per-image checkpoint, resume, failures."""

from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from SamsungFrame.frame_job import ArtRecord, Job, Manifest, PhotoRecord
from SamsungFrame.frame_upload import run_upload, unattributed_ids
from SamsungFrame.samsung_client import ImageUploadSummary


def photo(name: str) -> PhotoRecord:
    return PhotoRecord(name=name, source=name, time=0, width=4, height=3, sharpness=1.0)


class FakeTv:
    """Stands in for the TV client: tracks its art list and which uploads fail."""

    def __init__(
        self, existing: Optional[list[dict[str, Any]]] = None, fail: Optional[set[str]] = None
    ):
        self.art = list(existing or [])
        self.fail = fail or set()
        self.calls: list[list[str]] = []
        self.next_id = 100
        self.art_list_error: Optional[Exception] = None
        self.ghost_uploads: set[str] = set()  # reported failed but actually arrive

    def get_available_art_strict(self) -> list[dict[str, Any]]:
        if self.art_list_error:
            raise self.art_list_error
        return list(self.art)

    def upload_images(
        self,
        image_files: list[str],
        *,
        matte: Optional[str] = None,
        on_uploaded: Optional[Callable[[str, str], None]] = None,
    ) -> ImageUploadSummary:
        self.calls.append([Path(f).name for f in image_files])
        ids, errors = [], []
        for path in image_files:
            name = Path(path).name
            if name in self.fail:
                if name in self.ghost_uploads:
                    self.art.append({"content_id": f"MY_F{self.next_id}"})
                    self.next_id += 1
                errors.append({"file": name, "error": "Upload returned None"})
                continue
            content_id = f"MY_F{self.next_id}"
            self.next_id += 1
            self.art.append({"content_id": content_id})
            ids.append(content_id)
            if on_uploaded:
                on_uploaded(path, content_id)
        return ImageUploadSummary(
            total_images=len(image_files),
            successful_uploads=len(ids),
            failed_uploads=len(errors),
            uploaded_image_ids=ids,
            errors=errors,
        )


def make_job(tmp_path: Path, names: list[str], kept: Optional[list[str]] = None) -> Job:
    job = Job(tmp_path / "job")
    job.create()
    for name in names:
        (job.jpg_dir / name).write_bytes(name.encode())
    job.save(Manifest(photos={n: photo(n) for n in names}, kept=kept))
    return job


OLD_ART = [
    {"content_id": "MY_F1", "image_date": "2024:01:01 00:00:00"},
    {"content_id": "MY_F2", "image_date": ""},
    {"content_id": "SAM-S1"},
]


class TestRunUpload:
    def test_snapshot_records_only_user_photos_before_any_upload(self, tmp_path: Path) -> None:
        job = make_job(tmp_path, ["a.jpg", "b.jpg"])
        run_upload(job, FakeTv(existing=OLD_ART))
        assert job.load().snapshot == [
            ArtRecord(id="MY_F1", image_date="2024:01:01 00:00:00"),
            ArtRecord(id="MY_F2", image_date=""),
        ]

    def test_a_photo_the_tv_lists_twice_is_in_the_snapshot_once(self, tmp_path: Path) -> None:
        job = make_job(tmp_path, ["a.jpg"])
        run_upload(job, FakeTv(existing=OLD_ART + [OLD_ART[0]]))
        assert [a.id for a in job.load().snapshot or []] == ["MY_F1", "MY_F2"]

    def test_uploads_the_deduped_set_not_every_photo(self, tmp_path: Path) -> None:
        job = make_job(tmp_path, ["a.jpg", "b.jpg", "c.jpg"], kept=["a.jpg", "c.jpg"])
        tv = FakeTv()
        assert run_upload(job, tv) == []
        assert tv.calls == [["a.jpg", "c.jpg"]]
        assert sorted(job.load().uploaded) == ["a.jpg", "c.jpg"]

    def test_without_dedup_every_photo_is_uploaded(self, tmp_path: Path) -> None:
        job = make_job(tmp_path, ["a.jpg", "b.jpg"])
        tv = FakeTv()
        run_upload(job, tv)
        assert tv.calls == [["a.jpg", "b.jpg"]]

    def test_each_image_is_checkpointed_as_it_lands(self, tmp_path: Path) -> None:
        job = make_job(tmp_path, ["a.jpg", "b.jpg", "c.jpg"])
        seen: list[int] = []

        class RecordingTv(FakeTv):
            def upload_images(self, image_files, *, matte=None, on_uploaded=None):  # type: ignore[no-untyped-def]
                def checkpoint(path: str, content_id: str) -> None:
                    assert on_uploaded is not None
                    on_uploaded(path, content_id)
                    seen.append(len(job.load().uploaded))  # already on disk when the call returns

                return super().upload_images(image_files, matte=matte, on_uploaded=checkpoint)

        run_upload(job, RecordingTv())
        assert seen == [1, 2, 3]

    def test_resume_uploads_only_what_is_missing_and_keeps_the_first_snapshot(
        self, tmp_path: Path
    ) -> None:
        job = make_job(tmp_path, ["a.jpg", "b.jpg", "c.jpg"])
        tv = FakeTv(existing=OLD_ART, fail={"b.jpg"})
        assert run_upload(job, tv) == ["b.jpg"]
        assert job.load().failed == {"b.jpg": "Upload returned None"}
        first_snapshot = job.load().snapshot

        tv.fail = set()
        assert run_upload(job, tv) == []
        assert tv.calls == [["a.jpg", "b.jpg", "c.jpg"], ["b.jpg"]]
        manifest = job.load()
        assert manifest.failed == {} and sorted(manifest.uploaded) == ["a.jpg", "b.jpg", "c.jpg"]
        assert manifest.snapshot == first_snapshot  # the batch's own uploads never join it

    def test_a_photo_the_tv_lost_is_uploaded_again(self, tmp_path: Path) -> None:
        job = make_job(tmp_path, ["a.jpg", "b.jpg"])
        tv = FakeTv(existing=OLD_ART)
        run_upload(job, tv)
        lost = job.load().uploaded["b.jpg"]
        tv.art = [a for a in tv.art if a["content_id"] != lost]  # e.g. gone after a reboot
        assert run_upload(job, tv) == []
        assert tv.calls[1] == ["b.jpg"]
        assert job.load().uploaded["b.jpg"] != lost

    def test_an_unreadable_art_list_at_the_start_aborts_the_stage(self, tmp_path: Path) -> None:
        job = make_job(tmp_path, ["a.jpg"])
        tv = FakeTv()
        tv.art_list_error = TimeoutError("art list timed out")
        with pytest.raises(TimeoutError):
            run_upload(job, tv)
        assert tv.calls == [] and job.load().snapshot is None

    def test_a_complete_job_uploads_nothing_more(self, tmp_path: Path) -> None:
        job = make_job(tmp_path, ["a.jpg"])
        tv = FakeTv()
        run_upload(job, tv)
        run_upload(job, tv)
        assert len(tv.calls) == 1

    def test_upload_that_arrived_despite_a_reported_failure_is_unattributed(
        self, tmp_path: Path
    ) -> None:
        job = make_job(tmp_path, ["a.jpg", "b.jpg"])
        tv = FakeTv(existing=OLD_ART, fail={"b.jpg"})
        tv.ghost_uploads = {"b.jpg"}
        assert run_upload(job, tv) == ["b.jpg"]
        manifest = job.load()
        assert len(manifest.unattributed) == 1
        assert manifest.unattributed[0] not in set(manifest.uploaded.values())

    def test_unreadable_art_list_keeps_the_stage_result(self, tmp_path: Path) -> None:
        job = make_job(tmp_path, ["a.jpg"])

        class FlakyTv(FakeTv):
            def get_available_art_strict(self) -> list[dict[str, Any]]:
                if self.calls:  # fine for the snapshot, times out after the upload
                    raise TimeoutError("art list timed out")
                return super().get_available_art_strict()

        run_upload(job, FlakyTv())
        assert job.load().uploaded

    def test_nothing_to_upload_is_refused(self, tmp_path: Path) -> None:
        job = Job(tmp_path / "job")
        job.create()
        with pytest.raises(ValueError, match="Nothing to upload"):
            run_upload(job, FakeTv())


class TestUnattributedIds:
    def test_ids_in_neither_snapshot_nor_uploaded(self) -> None:
        manifest = Manifest(snapshot=[ArtRecord(id="MY_F1")], uploaded={"a.jpg": "MY_F2"})
        art = [{"content_id": i} for i in ("MY_F1", "MY_F2", "MY_F3", "SAM-S1")]
        assert unattributed_ids(art, manifest) == ["MY_F3"]
