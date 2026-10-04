"""Tests for the pipeline driver: stage commands, stop-at-first-failure, retries, one notification."""

import argparse
from pathlib import Path
from typing import Optional

from SamsungFrame.frame_job import CleanupRecord, Job, Manifest, PhotoRecord
from SamsungFrame.frame_run import (
    INTERRUPTED,
    PRIORITY_HIGH,
    PRIORITY_QUIET,
    Stage,
    build_report,
    build_stages,
    notify,
    run_pipeline,
    run_stages,
)


def args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "source_dir": Path("/src/Trip"),
        "include_portraits": False,
        "no_dedup": False,
        "window": 600.0,
        "max_distance": 0.4,
        "upload_attempts": 3,
        "no_cleanup": False,
        "duration": 3,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def photo(name: str) -> PhotoRecord:
    return PhotoRecord(name=name, source=name, time=0, width=4, height=3, sharpness=1.0)


def finished_manifest(**overrides: object) -> Manifest:
    manifest = Manifest(
        photos={n: photo(n) for n in ("a.jpg", "b.jpg", "c.jpg")},
        skipped={"p.jpg": "portrait", "q.jpg": "portrait", "v.MOV": "video"},
        kept=["a.jpg", "b.jpg"],
        dropped={"c.jpg": "duplicate of a.jpg", "r.jpg": "utility"},
        uploaded={"a.jpg": "MY_F1", "b.jpg": "MY_F2"},
        cleanup=CleanupRecord(deleted=7, failed=0, retained=2),
        slideshow_problems=[],
    )
    return manifest.model_copy(update=overrides)


class TestBuildStages:
    def names(self, stages: list[Stage]) -> list[str]:
        return [s.name for s in stages]

    def test_default_pipeline_in_order(self) -> None:
        stages = build_stages(args(), Path("/tmp/j"), python="py")
        assert self.names(stages) == ["ingest", "dedup", "upload", "cleanup", "slideshow"]
        assert stages[0].command == [
            "py", "-m", "SamsungFrame.ingest", "/src/Trip", "--job", "/tmp/j",
        ]  # fmt: skip
        assert stages[1].command == [
            "py", "-m", "SamsungFrame.dedup_photos", "/tmp/j",
            "--window", "600.0", "--max-distance", "0.4",
        ]  # fmt: skip

    def test_upload_is_the_only_stage_that_retries(self) -> None:
        stages = {s.name: s.attempts for s in build_stages(args(upload_attempts=4), Path("/j"))}
        assert stages == {"ingest": 1, "dedup": 1, "upload": 4, "cleanup": 1, "slideshow": 1}

    def test_flags_change_the_stages(self) -> None:
        stages = build_stages(
            args(include_portraits=True, no_dedup=True, no_cleanup=True, duration=5), Path("/j")
        )
        assert self.names(stages) == ["ingest", "upload", "slideshow"]
        assert "--include-portraits" in stages[0].command
        assert stages[-1].command[-2:] == ["--duration", "5"]


class TestRunStages:
    def stages(self) -> list[Stage]:
        return [Stage("one", ["1"]), Stage("two", ["2"], attempts=3), Stage("three", ["3"])]

    def runner(self, codes: dict[str, list[int]]):  # type: ignore[no-untyped-def]
        ran: list[str] = []

        def run(command: list[str]) -> int:
            ran.append(command[0])
            return codes.get(command[0], [0]).pop(0)

        return run, ran

    def test_all_green_runs_every_stage_once(self) -> None:
        run, ran = self.runner({})
        assert run_stages(self.stages(), run) is None
        assert ran == ["1", "2", "3"]

    def test_first_failure_stops_the_run_and_is_named(self) -> None:
        run, ran = self.runner({"1": [1]})
        assert run_stages(self.stages(), run) == "one"
        assert ran == ["1"]

    def test_a_retrying_stage_is_retried_until_it_passes(self) -> None:
        run, ran = self.runner({"2": [1, 1, 0]})
        assert run_stages(self.stages(), run) is None
        assert ran == ["1", "2", "2", "2", "3"]

    def test_exhausted_attempts_fail_the_stage_and_skip_the_rest(self) -> None:
        run, ran = self.runner({"2": [1, 1, 1]})
        assert run_stages(self.stages(), run) == "two"
        assert ran == ["1", "2", "2", "2"]


class TestBuildReport:
    def test_all_green_is_quiet(self) -> None:
        report = build_report(finished_manifest(), None)
        assert (report.title, report.priority) == ("Samsung Frame - Complete", PRIORITY_QUIET)
        assert "Uploaded: 2/2" in report.message
        assert "Skipped: 2 portrait, 1 video" in report.message
        assert "Dropped: 1 duplicate, 1 utility" in report.message
        assert "Old removed: 7 (2 kept for the minimum, 0 failed)" in report.message
        assert "Slideshow verified on the TV" in report.message

    def test_a_failed_stage_is_named_and_loud(self) -> None:
        report = build_report(finished_manifest(uploaded={"a.jpg": "MY_F1"}), "upload")
        assert report.title == "Samsung Frame - Failed at upload"
        assert report.priority == PRIORITY_HIGH
        assert report.message.startswith("🛑 Stopped at: upload (rerun to resume)")
        assert "Uploaded: 1/2" in report.message

    def test_interrupted_has_its_own_title(self) -> None:
        report = build_report(finished_manifest(), INTERRUPTED)
        assert report.title == "Samsung Frame - Interrupted" and report.priority == PRIORITY_HIGH

    def test_unverified_slideshow_needs_attention_even_if_every_stage_exited_zero(self) -> None:
        report = build_report(finished_manifest(slideshow_problems=["playlist is stale"]), None)
        assert report.title == "Samsung Frame - Needs attention"
        assert "Slideshow NOT verified: playlist is stale" in report.message

    def test_upload_failures_need_attention(self) -> None:
        report = build_report(finished_manifest(failed={"b.jpg": "timeout"}), None)
        assert report.priority == PRIORITY_HIGH and "Upload failures: 1" in report.message

    def test_totals_are_the_manifests_so_a_retry_is_not_undercounted(self) -> None:
        manifest = finished_manifest(uploaded={f"{i}.jpg": f"MY_F{i}" for i in range(174)})
        manifest.kept = [f"{i}.jpg" for i in range(174)]
        assert "Uploaded: 174/174" in build_report(manifest, None).message

    def test_photos_uploaded_outside_the_current_targets_are_not_counted(self) -> None:
        manifest = finished_manifest(
            uploaded={"a.jpg": "MY_F1", "b.jpg": "MY_F2", "z.jpg": "MY_F9"}
        )
        assert "Uploaded: 2/2" in build_report(manifest, None).message

    def test_cleanup_and_slideshow_not_run_are_stated(self) -> None:
        report = build_report(finished_manifest(cleanup=None, slideshow_problems=None), "upload")
        assert "Old catalog: not cleaned up" in report.message
        assert "Slideshow: not run" in report.message

    def test_unnamed_uploads_are_reported(self) -> None:
        report = build_report(finished_manifest(unattributed=["MY_F9"]), None)
        assert "On the TV but unnamed: 1" in report.message


class TestNotify:
    def test_send_receives_message_title_priority(self) -> None:
        sent: list[tuple[str, str, int]] = []
        notify(build_report(finished_manifest(), None), lambda m, t, p: sent.append((m, t, p)))
        assert len(sent) == 1 and sent[0][1:] == ("Samsung Frame - Complete", PRIORITY_QUIET)

    def test_a_failing_sender_never_raises(self) -> None:
        def boom(_m: str, _t: str, _p: int) -> None:
            raise RuntimeError("pushover down")

        notify(build_report(finished_manifest(), None), boom)


class TestRunPipeline:
    def job(self, tmp_path: Path, manifest: Optional[Manifest] = None) -> Job:
        job = Job(tmp_path / "job")
        job.create()
        job.save(manifest or finished_manifest())
        return job

    def test_success_sends_one_quiet_notification_and_returns_zero(self, tmp_path: Path) -> None:
        sent: list[str] = []
        code = run_pipeline(
            args(), self.job(tmp_path), lambda _c: 0, lambda m, t, p: sent.append(t)
        )
        assert code == 0 and sent == ["Samsung Frame - Complete"]

    def test_failure_sends_one_notification_naming_the_stage(self, tmp_path: Path) -> None:
        sent: list[str] = []
        code = run_pipeline(
            args(upload_attempts=1),
            self.job(tmp_path),
            lambda c: 1 if "frame_upload" in c[2] else 0,
            lambda m, t, p: sent.append(t),
        )
        assert code == 1 and sent == ["Samsung Frame - Failed at upload"]

    def test_an_unreadable_manifest_still_sends_one_notification(self, tmp_path: Path) -> None:
        job = self.job(tmp_path)
        job.manifest_path.write_text("{not json")
        sent: list[tuple[str, str]] = []
        code = run_pipeline(args(), job, lambda _c: 0, lambda m, t, p: sent.append((t, m)))
        assert code == 0 and len(sent) == 1
        assert sent[0][1].startswith("🛑 Manifest unreadable")

    def test_an_unexpected_error_is_not_reported_as_an_interrupt(self, tmp_path: Path) -> None:
        sent: list[str] = []

        def run(_command: list[str]) -> int:
            raise OSError("no such interpreter")

        code = run_pipeline(args(), self.job(tmp_path), run, lambda m, t, p: sent.append(t))
        assert code == 1 and sent == ["Samsung Frame - Failed at the driver"]

    def test_interrupt_still_sends_exactly_one_notification(self, tmp_path: Path) -> None:
        sent: list[str] = []

        def run(_command: list[str]) -> int:
            raise KeyboardInterrupt

        code = run_pipeline(args(), self.job(tmp_path), run, lambda m, t, p: sent.append(t))
        assert code == 1 and sent == ["Samsung Frame - Interrupted"]
