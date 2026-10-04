"""Tests for the pipeline job dir and manifest."""

from pathlib import Path

from SamsungFrame.frame_job import JOBS_ROOT, Job, Manifest, PhotoRecord, default_job_dir


def record(name: str = "a.jpg", width: int = 400, height: int = 300) -> PhotoRecord:
    return PhotoRecord(
        name=name, source=f"d/{name}", time=1.0, width=width, height=height, sharpness=2.0
    )


class TestJob:
    def test_missing_manifest_loads_empty(self, tmp_path: Path) -> None:
        assert Job(tmp_path).load() == Manifest()

    def test_roundtrip(self, tmp_path: Path) -> None:
        job = Job(tmp_path / "j")
        job.create()
        manifest = Manifest(
            source="/s",
            photos={"a.jpg": record()},
            skipped={"x.MOV": "video"},
            kept=["a.jpg"],
            dropped={"b.jpg": "utility"},
        )
        job.save(manifest)
        assert job.load() == manifest

    def test_save_leaves_no_temp_files(self, tmp_path: Path) -> None:
        job = Job(tmp_path / "j")
        job.create()
        job.save(Manifest(source="/s"))
        job.save(Manifest(source="/t"))
        assert sorted(p.name for p in job.root.iterdir()) == ["jpg", "manifest.json"]
        assert job.load().source == "/t"

    def test_create_is_idempotent(self, tmp_path: Path) -> None:
        job = Job(tmp_path / "j")
        job.create()
        job.create()
        assert job.jpg_dir.is_dir()


class TestPhotoRecord:
    def test_landscape_includes_square(self) -> None:
        assert record(width=300, height=300).landscape
        assert record(width=400, height=300).landscape
        assert not record(width=300, height=400).landscape


class TestDefaultJobDir:
    def test_under_tmp_and_stable(self, tmp_path: Path) -> None:
        src = tmp_path / "Trip 2026"
        src.mkdir()
        assert default_job_dir(src) == default_job_dir(src)
        assert default_job_dir(src).parent == JOBS_ROOT
        assert default_job_dir(src).name.startswith("Trip-2026-")

    def test_same_name_different_parent_differs(self, tmp_path: Path) -> None:
        a, b = tmp_path / "x" / "Trip", tmp_path / "y" / "Trip"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        assert default_job_dir(a) != default_job_dir(b)
