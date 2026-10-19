"""Tests for RingBeams/beams_manager.py — no patch() on production code.

Sidecar subprocess is not spawned in unit tests; classify() and notify() are
exercised directly with DeviceRecord fixtures. Auth-error path tested via
missing-token file.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from lib.config import RingBeamsConfig
from lib.file_lock import LockTimeoutError, acquire_lock
from lib.MyPushover import Pushover
from RingBeams.beams_manager import (
    SIDECAR_PACKAGE,
    BeamsAuthError,
    DeviceRecord,
    Findings,
    _alert_text,
    _require_sidecar_deps,
    classify,
    notify,
    run_sidecar,
)


class RecordingPushover(Pushover):
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def send_message(self, message: str, title: str | None = None, priority: int = 0) -> bool:
        self.calls.append({"message": message, "title": title, "priority": priority})
        return True


@pytest.fixture
def logger() -> logging.Logger:
    return logging.getLogger("test-beams")


NOW_MS = 1_800_000_000_000
HOUR_MS = 3_600_000


def _rec(
    name: str,
    battery: int | str | None = None,
    battery_status: str | None = None,
    tamper: str | None = "ok",
    comm_status: str | None = "ok",
    last_comm_ms: int | None = NOW_MS,
    ac_status: str | None = None,
) -> DeviceRecord:
    return DeviceRecord(
        name=name,
        device_type="sensor.motion",
        location="Home",
        battery=battery,  # type: ignore[arg-type]
        battery_status=battery_status,
        tamper=tamper,
        comm_status=comm_status,
        last_comm_ms=last_comm_ms,
        ac_status=ac_status,
    )


def _classify(devs: list[DeviceRecord], threshold_pct: int = 25) -> Findings:
    return classify(devs, threshold_pct, offline_after_hours=36, now_ms=NOW_MS)


def test_low_battery_threshold_only() -> None:
    devs = [
        _rec("Mailbox", battery=12, battery_status="warn"),
        _rec("Motion Kitchen", battery=0, battery_status="warn"),
        _rec("Motion Corridor", battery=25, battery_status="ok"),  # at threshold, skip
        _rec("Motion Entrance", battery=65, battery_status="ok"),
    ]
    found = _classify(devs)
    assert found.low == ["Mailbox: 12%", "Motion Kitchen: 0%"]
    assert found.tamper == []
    assert found.offline == []


def test_ring_warn_status_triggers_even_if_above_threshold() -> None:
    # Ring says "warn" — trust it even if numeric value contradicts.
    found = _classify([_rec("Weird", battery=80, battery_status="warn")])
    assert found.low == ["Weird: 80%"]


def test_wired_devices_skipped() -> None:
    devs = [
        _rec("Base Station", battery=None, battery_status="charged", last_comm_ms=None),
        _rec("Keypad", battery=100, battery_status="charging"),
        _rec("Adapter", battery=None, battery_status="none", last_comm_ms=None),
        _rec("Motion Kitchen", battery=0, battery_status="warn"),
    ]
    found = _classify(devs)
    assert found.low == ["Motion Kitchen: 0%"]  # only the real one
    assert found.offline == []


def test_tamper_detected() -> None:
    devs = [
        _rec("Door", battery=99, battery_status="full", tamper="tamper"),
        _rec("Motion", battery=80, battery_status="ok", tamper="ok"),
    ]
    found = _classify(devs)
    assert found.low == []
    assert found.tamper == ["Door (tampered)"]


def test_tamper_on_wired_device_still_alerts() -> None:
    """The battery skip must not hide tamper on a keypad or base station."""
    devs = [
        _rec("Base Station", battery=None, battery_status="charged", tamper="tamper"),
        _rec("Keypad", battery=100, battery_status="charging", tamper="tamper"),
    ]
    assert _classify(devs).tamper == ["Base Station (tampered)", "Keypad (tampered)"]


def test_comm_error_alerts_offline_despite_ok_battery() -> None:
    """2026-10-19: a Beams sensor read 58% "ok" with commStatus "error" for 15 days."""
    dead = _rec(
        "MS 55",
        battery=58,
        battery_status="ok",
        comm_status="error",
        last_comm_ms=NOW_MS - 356 * HOUR_MS,
    )
    found = _classify([dead])
    assert found.offline == ["MS 55: comm error, last seen 15d ago"]
    assert found.low == []


def test_comm_error_on_wired_device_alerts() -> None:
    hub = _rec(
        "Adapter", battery=None, battery_status="none", comm_status="error", last_comm_ms=None
    )
    assert _classify([hub]).offline == ["Adapter: comm error"]


def test_stale_last_comm_alerts_even_when_comm_ok() -> None:
    stale = _rec("Door", battery=99, battery_status="full", last_comm_ms=NOW_MS - 37 * HOUR_MS)
    assert _classify([stale]).offline == ["Door: last seen 37h ago"]


def test_last_comm_within_window_is_healthy() -> None:
    # Contact sensors poll every 12 h; 35 h is two missed polls, still inside.
    recent = _rec("Door", battery=99, battery_status="full", last_comm_ms=NOW_MS - 35 * HOUR_MS)
    assert _classify([recent]).offline == []


def test_missing_comm_fields_are_not_offline() -> None:
    """Hubs and adapters report no lastCommTime; an absent field is not a fault."""
    hub = _rec("Hub", battery=None, battery_status="none", comm_status=None, last_comm_ms=None)
    assert _classify([hub]).offline == []


def test_string_battery_coerced_and_unparseable_ignored() -> None:
    devs = [
        _rec("Str", battery="15.5", battery_status="ok"),
        _rec("Junk", battery="abc", battery_status="ok"),
    ]
    assert _classify(devs).low == ["Str: 15%"]


def test_ring_low_status_alerts_above_threshold_and_without_level() -> None:
    """ring-client-api's type says "low", not "warn"; a level may be absent."""
    devs = [
        _rec("High But Low", battery=40, battery_status="low"),
        _rec("No Level", battery=None, battery_status="low"),
        _rec("Keypad Backup", battery=100, battery_status="low"),
    ]
    assert _classify(devs).low == [
        "High But Low: 40%",
        "No Level: battery low",
        "Keypad Backup: 100%",
    ]


def test_base_station_on_backup_battery_alerts() -> None:
    hub = _rec(
        "Base Station", battery=None, battery_status="charged", ac_status="error", last_comm_ms=None
    )
    assert _classify([hub]).offline == ["Base Station: mains power lost"]


def test_notify_priorities(logger: logging.Logger) -> None:
    p = RecordingPushover()
    found = Findings(low=["A: 10%"], tamper=["B (tampered)"], offline=["C: comm error"])
    notify(p, found, [], logger)
    by_title = {c["title"]: c["priority"] for c in p.calls}
    assert by_title == {
        "Ring: Low Battery": 1,
        "Ring: Tamper": 1,
        "Ring: Sensor Offline": 1,
    }


def test_notify_partial_failure_alerts_p1(logger: logging.Logger) -> None:
    """Sidecar partial-location failure MUST alert even when devices returned
    look healthy — otherwise the user sees false 'all healthy' with missing
    devices."""
    p = RecordingPushover()
    notify(p, Findings([], [], []), ["getDevices(Home): connection reset"], logger)
    assert len(p.calls) == 1
    assert "Partial" in (p.calls[0]["title"] or "")
    assert p.calls[0]["priority"] == 1
    assert "connection reset" in p.calls[0]["message"]


def test_notify_no_alerts_silent(logger: logging.Logger) -> None:
    p = RecordingPushover()
    notify(p, Findings([], [], []), [], logger)
    assert p.calls == []


def test_missing_token_raises_auth_error(tmp_path: Path, logger: logging.Logger) -> None:
    cfg = RingBeamsConfig(
        token_file=str(tmp_path / "missing.json"),
        battery_threshold_pct=25,
        sidecar_timeout_seconds=5,
        offline_after_hours=36,
    )
    with pytest.raises(BeamsAuthError, match="No Ring token"):
        run_sidecar(cfg, logger)


def test_sidecar_auth_failure_exit5_treated_as_auth(tmp_path: Path, logger: logging.Logger) -> None:
    """Sidecar exit=5 with JSON error is the auth/list-locations failure class."""
    tok = tmp_path / "tok.json"
    tok.write_text('{"refresh_token": "fake"}')
    script = tmp_path / "fake_sidecar.js"
    # Not a real node file — we pass /bin/sh and pretend it's node.
    fake = tmp_path / "fake.sh"
    fake.write_text('#!/bin/sh\necho \'{"error":"bad token"}\' >&2\nexit 5\n')
    fake.chmod(0o755)
    cfg = RingBeamsConfig(
        token_file=str(tok),
        battery_threshold_pct=25,
        sidecar_timeout_seconds=5,
        offline_after_hours=36,
    )
    with pytest.raises(BeamsAuthError, match="bad token"):
        run_sidecar(cfg, logger, node_path=str(fake), script_path=str(script))


def test_sidecar_exit1_node_crash_not_auth(tmp_path: Path, logger: logging.Logger) -> None:
    """Node crash-at-load (exit=1 with raw stack, no JSON envelope) MUST route
    to RuntimeError, not BeamsAuthError. This is the prod-host 2026-07-04 case:
    undici + Node 18 ReferenceError got misclassified as "Auth Required"."""
    tok = tmp_path / "tok.json"
    tok.write_text('{"refresh_token": "fake"}')
    fake = tmp_path / "fake.sh"
    # Raw stack trace on stderr, no {"error": "..."} envelope, exit 1.
    fake.write_text(
        "#!/bin/sh\n"
        "echo 'ReferenceError: File is not defined' >&2\n"
        "echo '    at Object.<anonymous>' >&2\n"
        "exit 1\n"
    )
    fake.chmod(0o755)
    cfg = RingBeamsConfig(
        token_file=str(tok),
        battery_threshold_pct=25,
        sidecar_timeout_seconds=5,
        offline_after_hours=36,
    )
    with pytest.raises(RuntimeError, match="sidecar exit=1") as exc:
        run_sidecar(cfg, logger, node_path=str(fake), script_path=str(tmp_path / "x.js"))
    assert not isinstance(exc.value, BeamsAuthError)


def test_sidecar_generic_error_not_misclassified_as_auth(
    tmp_path: Path, logger: logging.Logger
) -> None:
    """rc=4 (post-auth unhandled) MUST NOT map to BeamsAuthError — otherwise a
    parsing bug in the sidecar would tell the user to re-auth."""
    tok = tmp_path / "tok.json"
    tok.write_text('{"refresh_token": "fake"}')
    fake = tmp_path / "fake.sh"
    fake.write_text('#!/bin/sh\necho \'{"error":"unhandled: bad device"}\' >&2\nexit 4\n')
    fake.chmod(0o755)
    cfg = RingBeamsConfig(
        token_file=str(tok),
        battery_threshold_pct=25,
        sidecar_timeout_seconds=5,
        offline_after_hours=36,
    )
    with pytest.raises(RuntimeError, match="sidecar exit=4") as exc:
        run_sidecar(cfg, logger, node_path=str(fake), script_path=str(tmp_path / "x.js"))
    # Explicitly assert it's NOT the auth subclass.
    assert not isinstance(exc.value, BeamsAuthError)


def test_sidecar_happy_path(tmp_path: Path, logger: logging.Logger) -> None:
    """Fake sidecar prints a valid device list; run_sidecar parses it."""
    tok = tmp_path / "tok.json"
    tok.write_text('{"refresh_token": "fake"}')
    fake = tmp_path / "fake.sh"
    fake.write_text(
        "#!/bin/sh\ncat <<EOF\n"
        '{"devices":[{"name":"Mailbox","deviceType":"motion-sensor.beams",'
        '"batteryLevel":12,"batteryStatus":"warn","tamperStatus":"ok",'
        '"commStatus":"ok","lastCommTime":1800000000000,"acStatus":null,'
        '"locationName":"Home"}]}\nEOF\n'
    )
    fake.chmod(0o755)
    cfg = RingBeamsConfig(
        token_file=str(tok),
        battery_threshold_pct=25,
        sidecar_timeout_seconds=5,
        offline_after_hours=36,
    )
    devs, errs = run_sidecar(cfg, logger, node_path=str(fake), script_path=str(tmp_path / "x.js"))
    assert len(devs) == 1
    assert devs[0].name == "Mailbox"
    assert devs[0].battery == 12
    assert devs[0].battery_status == "warn"
    assert devs[0].comm_status == "ok"
    assert devs[0].last_comm_ms == 1800000000000
    assert errs == []


def test_sidecar_empty_payload_is_an_error(tmp_path: Path, logger: logging.Logger) -> None:
    """Zero devices and zero errors must not read as "all healthy"."""
    tok = tmp_path / "tok.json"
    tok.write_text('{"refresh_token": "fake"}')
    fake = tmp_path / "fake.sh"
    fake.write_text('#!/bin/sh\necho \'{"devices":[],"errors":[]}\'\n')
    fake.chmod(0o755)
    cfg = RingBeamsConfig(
        token_file=str(tok),
        battery_threshold_pct=25,
        sidecar_timeout_seconds=5,
        offline_after_hours=36,
    )
    with pytest.raises(RuntimeError, match="no devices"):
        run_sidecar(cfg, logger, node_path=str(fake), script_path=str(tmp_path / "x.js"))


def test_sidecar_surfaces_partial_errors(tmp_path: Path, logger: logging.Logger) -> None:
    """Sidecar returned devices AND per-location errors — both surface."""
    tok = tmp_path / "tok.json"
    tok.write_text('{"refresh_token": "fake"}')
    fake = tmp_path / "fake.sh"
    fake.write_text(
        "#!/bin/sh\ncat <<EOF\n"
        '{"devices":[{"name":"Mailbox","batteryLevel":90,"batteryStatus":"ok",'
        '"tamperStatus":"ok"}],'
        '"errors":["getDevices(Second Home): oops"]}\nEOF\n'
    )
    fake.chmod(0o755)
    cfg = RingBeamsConfig(
        token_file=str(tok),
        battery_threshold_pct=25,
        sidecar_timeout_seconds=5,
        offline_after_hours=36,
    )
    devs, errs = run_sidecar(cfg, logger, node_path=str(fake), script_path=str(tmp_path / "x.js"))
    assert len(devs) == 1
    assert errs == ["getDevices(Second Home): oops"]


def test_sidecar_token_write_warn_on_stderr_is_logged_not_raised(
    tmp_path: Path, logger: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:
    """Sidecar exit=0 with a TOKEN_WRITE_FAILED warn on stderr: parse normally
    and log the warning. Regression guard for the 2026-07-05 invalid_grant
    scenario — the ring-client-api rotates refresh_token; if our write fails
    silently, the next RingSecurity run gets invalid_grant. Surfacing the
    warn line lets us diagnose the chain."""
    tok = tmp_path / "tok.json"
    tok.write_text('{"refresh_token": "fake"}')
    fake = tmp_path / "fake.sh"
    fake.write_text(
        "#!/bin/sh\n"
        'echo \'{"warn":"TOKEN_WRITE_FAILED: EACCES","path":"/tmp/tok"}\' >&2\n'
        "cat <<EOF\n"
        '{"devices":[{"name":"Mailbox","batteryLevel":90,"batteryStatus":"ok",'
        '"tamperStatus":"ok"}]}\nEOF\n'
    )
    fake.chmod(0o755)
    cfg = RingBeamsConfig(
        token_file=str(tok),
        battery_threshold_pct=25,
        sidecar_timeout_seconds=5,
        offline_after_hours=36,
    )
    with caplog.at_level(logging.WARNING):
        devs, errs = run_sidecar(
            cfg, logger, node_path=str(fake), script_path=str(tmp_path / "x.js")
        )
    assert len(devs) == 1
    assert errs == []
    assert any("TOKEN_WRITE_FAILED" in r.message for r in caplog.records)


def test_missing_sidecar_deps_raises_actionable(tmp_path: Path) -> None:
    """The 2026-08-30 prod case: a re-clone drops the gitignored node_modules.
    Node would die at module load with a 20-line ERR_MODULE_NOT_FOUND stack that
    then lands in a Pushover body. Fail early with a one-line remedy instead."""
    script = tmp_path / "fetch_status.js"
    script.write_text("// no deps installed next to me\n")
    with pytest.raises(RuntimeError, match=SIDECAR_PACKAGE) as exc:
        _require_sidecar_deps(str(script))
    assert "make node-deps" in str(exc.value)
    assert not isinstance(exc.value, BeamsAuthError)


def test_sidecar_deps_in_script_dir_ok(tmp_path: Path) -> None:
    """Normal install: node_modules sits beside the sidecar."""
    script = tmp_path / "fetch_status.js"
    script.write_text("// deps live next to me\n")
    (tmp_path / "node_modules" / SIDECAR_PACKAGE).mkdir(parents=True)
    _require_sidecar_deps(str(script))


def test_sidecar_deps_in_ancestor_dir_ok(tmp_path: Path) -> None:
    """Node resolves bare specifiers by walking node_modules upward, so a
    hoisted install in a parent directory is valid and must not false-alarm."""
    module_dir = tmp_path / "RingBeams"
    module_dir.mkdir()
    script = module_dir / "fetch_status.js"
    script.write_text("// deps are hoisted to the repo root\n")
    (tmp_path / "node_modules" / SIDECAR_PACKAGE).mkdir(parents=True)
    _require_sidecar_deps(str(script))


def test_alert_text_keeps_first_line_only() -> None:
    """Pushover bodies must not carry a Node stack trace; logs keep the rest."""
    exc = RuntimeError(
        "sidecar exit=1: ERR_MODULE_NOT_FOUND\n  at packageResolve\n  at moduleResolve"
    )
    assert _alert_text(exc) == "sidecar exit=1: ERR_MODULE_NOT_FOUND"


def test_alert_text_caps_length() -> None:
    body = _alert_text(RuntimeError("x" * 500))
    assert len(body) == 200


def test_alert_text_falls_back_to_class_name() -> None:
    """An exception with an empty message still needs an identifiable alert."""
    assert _alert_text(RuntimeError("")) == "RuntimeError"


def test_orphaned_sidecar_keeps_token_lock_after_parent_is_killed(
    tmp_path: Path,
) -> None:
    """End to end through run_sidecar: SIGKILL the parent mid-sidecar and the
    token lock must stay held while the orphan runs, so RingSecurity cannot
    refresh concurrently. Guards the lock_fd -> pass_fds wiring."""
    tok = tmp_path / "tok.json"
    tok.write_text('{"refresh_token": "fake"}')
    pidfile = tmp_path / "sidecar.pid"
    fake = tmp_path / "fake.sh"
    fake.write_text(f"#!/bin/sh\necho $$ > {pidfile}\nexec sleep 60\n")
    fake.chmod(0o755)
    repo = Path(__file__).resolve().parent.parent
    parent_script = tmp_path / "parent.py"
    parent_script.write_text(
        f"import logging, sys\nsys.path.insert(0, {str(repo)!r})\n"
        "from lib.config import RingBeamsConfig\n"
        "from lib.file_lock import acquire_lock\n"
        "from RingBeams.beams_manager import run_sidecar\n"
        f"cfg = RingBeamsConfig(token_file={str(tok)!r}, battery_threshold_pct=25,"
        " sidecar_timeout_seconds=60, offline_after_hours=36)\n"
        f"with acquire_lock(cfg.token_file) as fd:\n"
        f"    run_sidecar(cfg, logging.getLogger('t'), node_path={str(fake)!r},"
        f" script_path={str(tmp_path / 'x.js')!r}, lock_fd=fd)\n"
    )
    parent = subprocess.Popen([sys.executable, str(parent_script)])
    sidecar_pid = None
    try:
        deadline = time.monotonic() + 10
        while not pidfile.exists() or not pidfile.read_text().strip():
            assert time.monotonic() < deadline, "sidecar never started"
            time.sleep(0.05)
        sidecar_pid = int(pidfile.read_text())
        parent.kill()
        parent.wait(timeout=5)

        with pytest.raises(LockTimeoutError):
            with acquire_lock(tok, timeout_s=0.5, poll_interval_s=0.05):
                pass

        os.kill(sidecar_pid, signal.SIGKILL)
        with acquire_lock(tok, timeout_s=5.0, poll_interval_s=0.05):
            pass
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if sidecar_pid is not None:
            try:
                os.kill(sidecar_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node")
def test_watchdog_exits_hung_sidecar_with_code_4(tmp_path: Path) -> None:
    """An orphan holds the token lock with no parent to time it out, so the
    sidecar must bound itself. A live event loop stands in for a hung socket."""
    watchdog = Path(__file__).resolve().parent / "watchdog.js"
    harness = tmp_path / "hang.mjs"
    harness.write_text(
        f"import {{ armWatchdog }} from {watchdog.as_uri()!r};\n"
        "armWatchdog();\nsetInterval(() => {}, 1000);\n"
    )
    env = {**os.environ, "RING_BEAMS_TIMEOUT_S": "1"}
    proc = subprocess.run(
        [shutil.which("node") or "node", str(harness)],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc.returncode == 4
    assert "watchdog" in proc.stderr
