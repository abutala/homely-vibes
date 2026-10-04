"""Tests for the slideshow stage."""

from pathlib import Path

from SamsungFrame.frame_job import Job, Manifest
from SamsungFrame.frame_slideshow import run_slideshow


class FakeTv:
    def __init__(self, accepts: bool = True, problems: list[str] | None = None):
        self.accepts = accepts
        self.problems = problems or []
        self.started: list[tuple[int, bool]] = []
        self.verified: list[tuple[int, bool]] = []

    def start_slideshow(self, duration: int, shuffle: bool) -> bool:
        self.started.append((duration, shuffle))
        return self.accepts

    def verify_slideshow(self, duration: int, shuffle: bool) -> list[str]:
        self.verified.append((duration, shuffle))
        return self.problems


def job(tmp_path: Path) -> Job:
    j = Job(tmp_path / "job")
    j.create()
    j.save(Manifest(source="/s"))
    return j


class TestRunSlideshow:
    def test_verified_slideshow_is_recorded_as_no_problems(self, tmp_path: Path) -> None:
        j, tv = job(tmp_path), FakeTv()
        assert run_slideshow(j, tv, 3, True) == []
        assert j.load().slideshow_problems == []
        assert tv.started == tv.verified == [(3, True)]

    def test_problems_found_on_the_tv_are_recorded(self, tmp_path: Path) -> None:
        j = job(tmp_path)
        problems = run_slideshow(j, FakeTv(problems=["playlist is stale"]), 5, False)
        assert problems == ["playlist is stale"]
        assert j.load().slideshow_problems == problems

    def test_a_rejected_start_is_a_problem_and_is_not_verified(self, tmp_path: Path) -> None:
        j, tv = job(tmp_path), FakeTv(accepts=False)
        assert run_slideshow(j, tv, 3, True) == ["the TV did not accept the slideshow command"]
        assert tv.verified == []

    def test_other_manifest_state_is_preserved(self, tmp_path: Path) -> None:
        j = job(tmp_path)
        run_slideshow(j, FakeTv(), 3, True)
        assert j.load().source == "/s"
