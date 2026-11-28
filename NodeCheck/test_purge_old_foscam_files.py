"""Tests for purge_old_foscam_files: the purge result and the alert it sends."""

import os
import time
from pathlib import Path

import pytest

from NodeCheck.purge_old_foscam_files import purge_old_foscam_files


class Notes:
    """Collects the alert texts the purge sends."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    def __call__(self, text: str) -> None:
        self.sent.append(text)


def _old_file(path: Path, days: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("clip")
    stamp = time.time() - days * 24 * 60 * 60
    os.utime(path, (stamp, stamp))


def test_deletes_only_old_files_two_levels_down(tmp_path: Path) -> None:
    _old_file(tmp_path / "CamA" / "day1" / "old.mp4", days=100)
    _old_file(tmp_path / "CamA" / "day2" / "new.mp4", days=1)
    _old_file(tmp_path / "top.mp4", days=100)
    notes = Notes()

    success, _ = purge_old_foscam_files(str(tmp_path), purge_after_days=90, notify=notes)

    assert success
    assert not (tmp_path / "CamA" / "day1" / "old.mp4").exists()
    assert (tmp_path / "CamA" / "day2" / "new.mp4").exists()
    assert (tmp_path / "top.mp4").exists()
    assert notes.sent == ["✓ Foscam cleanup: Successfully removed 1 old files"]


def test_missing_dir_fails_and_alerts(tmp_path: Path) -> None:
    notes = Notes()

    success, report = purge_old_foscam_files(
        str(tmp_path / "absent"), purge_after_days=90, notify=notes
    )

    assert not success
    assert "not accessible" in report
    assert len(notes.sent) == 1 and "not accessible" in notes.sent[0]


@pytest.mark.skipif(os.geteuid() == 0, reason="root can enter a mode-000 directory")
def test_unenterable_dir_reports_the_real_error(tmp_path: Path) -> None:
    """The 2026-11-27 failure: chdir raised and the error path crashed on an unset message."""
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o000)
    notes = Notes()
    cwd = os.getcwd()
    try:
        success, report = purge_old_foscam_files(str(locked), purge_after_days=90, notify=notes)
    finally:
        locked.chmod(0o755)

    assert not success
    assert "Permission denied" in report
    assert len(notes.sent) == 1 and "Permission denied" in notes.sent[0]
    assert os.getcwd() == cwd


def test_failed_alert_does_not_hide_the_result(tmp_path: Path) -> None:
    def offline(_: str) -> None:
        raise OSError("Temporary failure in name resolution")

    success, report = purge_old_foscam_files(str(tmp_path), purge_after_days=90, notify=offline)

    assert success
    assert "No old files" in report
