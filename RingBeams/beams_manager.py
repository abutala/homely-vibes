#!/usr/bin/env python3
"""Ring Beams / Alarm daily health check.

Spawns a Node.js sidecar (fetch_status.js) that uses ring-client-api to
pull device state via Ring's socket.io channel — the only way to get
battery for Beams motion sensors and Alarm contact/motion sensors.

P1 alert: battery below the threshold, OR batteryStatus "low" / "warn".
P1 alert: offline -- commStatus not "ok", lastCommTime too old, or acStatus
          "error" (base station lost mains power).
P1 alert: tamperStatus == "tamper", on any device, wired ones included.
P1 alert: zero devices returned, or a partial sidecar failure.
P0 alert: sidecar auth failure (needs re-auth).

The battery threshold skips wired devices (batteryLevel null, or a wired
batteryStatus). `faulted: true` on contact sensors just means "door open
now" -- ignored.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from lib.config import RingBeamsConfig, get_config
from lib.file_lock import LockTimeoutError, acquire_lock
from lib.logger import get_logger
from lib.MyPushover import Pushover
from lib.secure_io import ensure_secret_perms
from lib.notifications import Notifier

PUSHOVER_KEY = "Ring Security"
WIRED_BATTERY_STATUSES = {"none", "charging", "charged"}
# ring-client-api types batteryStatus as full|charged|ok|low|none|charging;
# "warn" is kept because earlier payloads sent it.
LOW_BATTERY_STATUSES = {"low", "warn"}
SIDECAR_PACKAGE = "ring-client-api"
ALERT_MAX_CHARS = 200


class BeamsAuthError(RuntimeError):
    """Sidecar refresh token missing / expired / rejected."""


@dataclass
class DeviceRecord:
    name: str
    device_type: str
    location: str
    battery: Optional[int]
    battery_status: Optional[str]
    tamper: Optional[str]
    comm_status: Optional[str]
    last_comm_ms: Optional[int]
    ac_status: Optional[str]


@dataclass
class Findings:
    low: list[str]
    tamper: list[str]
    offline: list[str]


def _resolve_node() -> str:
    node = shutil.which("node")
    if not node:
        raise RuntimeError(
            "`node` not found on PATH. Install Node.js (e.g. `brew install node`) "
            "and ensure PATH is set correctly in cron."
        )
    return node


def _require_sidecar_deps(script: str) -> None:
    """Fail early when the sidecar's node_modules is absent.

    node_modules/ is gitignored, so any fresh clone or re-clone of the repo has
    a working Python side and no sidecar deps at all. Without this check Node
    dies at module load and its ERR_MODULE_NOT_FOUND stack becomes the Pushover
    body. Walk parents the way Node resolves bare specifiers, so a hoisted
    install does not false-alarm.
    """
    start = Path(script).resolve().parent
    for parent in (start, *start.parents):
        if (parent / "node_modules" / SIDECAR_PACKAGE).is_dir():
            return
    raise RuntimeError(
        f"Sidecar dependency `{SIDECAR_PACKAGE}` is not installed under {start}. "
        "Run `make node-deps` from the repo root."
    )


def _alert_text(exc: Exception) -> str:
    """First line of an exception, capped -- notification bodies are not logs."""
    message = str(exc).strip()
    if not message:
        return exc.__class__.__name__
    return message.splitlines()[0][:ALERT_MAX_CHARS]


def run_sidecar(
    cfg: RingBeamsConfig,
    logger: logging.Logger,
    *,
    node_path: Optional[str] = None,
    script_path: Optional[str] = None,
    lock_fd: Optional[int] = None,
) -> tuple[list[DeviceRecord], list[str]]:
    """Invoke fetch_status.js. Returns (devices, per-location errors).

    ``lock_fd`` is the token flock's fd from ``acquire_lock``. The sidecar
    inherits it, so a hard-killed parent leaves the lock held until the orphan
    exits rather than letting it rotate the refresh token unserialized.

    Per-location errors are surfaced (not raised) so a partial failure never
    masks itself as "all healthy" — the caller pushes them to Pushover at P1.
    """
    node = node_path or _resolve_node()
    script = script_path or str(Path(__file__).resolve().parent / "fetch_status.js")
    token_file = cfg.token_file
    if not Path(token_file).exists():
        raise BeamsAuthError(
            f"No Ring token at {token_file}. Run "
            "`uv run python RingSecurity/ring_manager.py auth` first "
            "(RingBeams reuses the RingSecurity token)."
        )
    # After the token check: a missing token is the more specific diagnosis and
    # must still surface as "Auth Required", not as a dep error. Skipped when a
    # script is injected, matching _resolve_node()'s handling of node_path.
    if not script_path:
        _require_sidecar_deps(script)

    env = os.environ.copy()
    env["RING_BEAMS_TOKEN_FILE"] = token_file
    env["RING_BEAMS_TIMEOUT_S"] = str(cfg.sidecar_timeout_seconds)

    logger.info(f"Spawning node sidecar: {node} {script}")
    proc = subprocess.run(
        [node, script],
        env=env,
        capture_output=True,
        text=True,
        timeout=cfg.sidecar_timeout_seconds,
        pass_fds=() if lock_fd is None else (lock_fd,),
    )
    if proc.returncode != 0:
        # Exits 2..5 carry a JSON {"error": ...} envelope on stderr; exit 1 is
        # a raw Node stack trace with none.
        try:
            err = json.loads(proc.stderr.strip().splitlines()[-1])
            msg = err.get("error", proc.stderr)
        except Exception:
            msg = proc.stderr.strip() or "sidecar failed with no stderr"
        # Sidecar exit-code contract (see fetch_status.js):
        #   1  uncaught Node crash / module-load (reserved for Node itself)
        #   2  missing env var
        #   3  token file unreadable          → auth class
        #   4  any other failure, or watchdog timeout
        #   5  Ring rejected the token / 2FA  → auth class
        # Only 3 and 5 are auth. Exit 1 is a Node crash (e.g. undici requiring
        # global `File` on Node <20) and MUST NOT route to "Auth Required".
        if proc.returncode in (3, 5):
            raise BeamsAuthError(msg)
        raise RuntimeError(f"sidecar exit={proc.returncode}: {msg}")

    # The sidecar rewrites token_file whenever Ring rotates the refresh token.
    # It writes 0600 itself, but per CLAUDE.md any third-party writer gets an
    # explicit re-assert -- the sidecar is not the only thing that touches this.
    ensure_secret_perms(token_file)

    # Sidecar succeeded but may have emitted structured warnings on stderr
    # (e.g. TOKEN_WRITE_FAILED — server rotated refresh_token but our write
    # threw, leaving the file with an already-consumed token). Log them so
    # the next RingSecurity invalid_grant is traceable.
    if proc.stderr.strip():
        logger.warning(f"sidecar stderr on success: {proc.stderr.strip()}")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"sidecar produced non-JSON stdout: {e}") from e

    out: list[DeviceRecord] = []
    for d in payload.get("devices", []):
        out.append(
            DeviceRecord(
                name=d.get("name", "<unnamed>"),
                device_type=d.get("deviceType", ""),
                location=d.get("locationName", ""),
                battery=d.get("batteryLevel"),
                battery_status=d.get("batteryStatus"),
                tamper=d.get("tamperStatus"),
                comm_status=d.get("commStatus"),
                last_comm_ms=d.get("lastCommTime"),
                ac_status=d.get("acStatus"),
            )
        )
    errors = list(payload.get("errors", []) or [])
    if not out and not errors:
        # Zero devices is never a healthy house -- it is a broken fetch.
        raise RuntimeError("sidecar returned no devices and no errors")
    return out, errors


def _offline_reason(d: DeviceRecord, offline_after_hours: int, now_ms: int) -> Optional[str]:
    """Why a device is not talking to its hub, or None when it is.

    A sensor that lost its link keeps its last battery reading, so battery and
    tamper alone call it healthy. Hubs and adapters report lastCommTime 0.
    """
    reasons = []
    if d.ac_status == "error":
        reasons.append("mains power lost")
    if d.comm_status is not None and d.comm_status != "ok":
        reasons.append(f"comm {d.comm_status}")
    # lastCommTime is epoch ms but untyped in ring-client-api; a value that
    # does not parse must not crash the run and hide every other finding.
    # Hubs and adapters send 0, which means "no time", not 1970.
    if isinstance(d.last_comm_ms, (int, float)) and d.last_comm_ms > 0:
        silent_h = (now_ms - d.last_comm_ms) / 3_600_000
        if silent_h > offline_after_hours:
            age = f"{silent_h:.0f}h" if silent_h < 48 else f"{silent_h / 24:.0f}d"
            reasons.append(f"last seen {age} ago")
    return f"{d.name}: {', '.join(reasons)}" if reasons else None


def _low_battery(d: DeviceRecord, threshold_pct: int) -> Optional[str]:
    try:
        batt_int: Optional[int] = int(float(d.battery)) if d.battery is not None else None
    except (TypeError, ValueError):
        batt_int = None
    level = f"{batt_int}%" if batt_int is not None else "battery low"
    # Ring's own low signal wins, even with no level or a wired status.
    if d.battery_status in LOW_BATTERY_STATUSES:
        return f"{d.name}: {level}"
    if batt_int is None or d.battery_status in WIRED_BATTERY_STATUSES:
        return None
    return f"{d.name}: {level}" if batt_int < threshold_pct else None


def classify(
    devices: list[DeviceRecord], threshold_pct: int, offline_after_hours: int, now_ms: int
) -> Findings:
    """Sort devices into low-battery, tamper and offline alert lines.

    Tamper and offline apply to wired devices too, so neither may sit behind
    the battery skip.
    """
    found = Findings(low=[], tamper=[], offline=[])
    for d in devices:
        if d.tamper == "tamper":
            found.tamper.append(f"{d.name} (tampered)")
        offline = _offline_reason(d, offline_after_hours, now_ms)
        if offline:
            found.offline.append(offline)
        low = _low_battery(d, threshold_pct)
        if low:
            found.low.append(low)
    return found


def notify(
    pushover: Notifier,
    found: Findings,
    errors: list[str],
    logger: logging.Logger,
) -> None:
    if found.offline:
        body = "\n".join(found.offline)
        logger.info(f"Offline alert: {body}")
        pushover.send_message(body, title="Ring: Device Offline", priority=1)
    if found.low:
        body = "\n".join(found.low)
        logger.info(f"Low battery alert: {body}")
        pushover.send_message(body, title="Ring: Low Battery", priority=1)
    if found.tamper:
        body = "\n".join(found.tamper)
        logger.info(f"Tamper alert: {body}")
        pushover.send_message(body, title="Ring: Tamper", priority=1)
    if errors:
        # Partial-location failure — coverage was incomplete, mustn't look healthy.
        body = "\n".join(errors)
        logger.error(f"Sidecar partial failure: {body}")
        pushover.send_message(body, title="Ring: Partial Sidecar Failure", priority=1)
    if not (found.offline or found.low or found.tamper or errors):
        logger.info("All Ring Beams/Alarm sensors healthy.")


def main() -> None:
    logger = get_logger(__name__)
    parser = argparse.ArgumentParser(
        description="Ring Beams + Alarm daily health check via Node sidecar"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="Run daily health check (for cron)")
    parser.parse_args()

    cfg = get_config()
    pushover = Pushover(cfg.pushover.user, cfg.pushover.tokens[PUSHOVER_KEY])
    try:
        # Serialize against RingSecurity — both share cfg.ring_beams.token_file
        # (== cfg.ring.token_file); Ring OAuth rotates the refresh_token on
        # every use. Parent Python holds the flock across the Node sidecar
        # spawn and passes its fd to the child, so the lock outlives the parent
        # for as long as the sidecar runs.
        with acquire_lock(cfg.ring_beams.token_file) as lock_fd:
            devices, errors = run_sidecar(cfg.ring_beams, logger, lock_fd=lock_fd)
        logger.info(f"Fetched {len(devices)} devices from sidecar ({len(errors)} location errors)")
        found = classify(
            devices,
            cfg.ring_beams.battery_threshold_pct,
            cfg.ring_beams.offline_after_hours,
            now_ms=int(time.time() * 1000),
        )
        notify(pushover, found, errors, logger)
    except LockTimeoutError as e:
        logger.error(f"Ring token lock timeout: {e}")
        pushover.send_message(str(e), title="Ring: Token Lock Timeout", priority=1)
        sys.exit(1)
    except BeamsAuthError as e:
        logger.error(f"Ring Beams auth failure: {e}")
        pushover.send_message(str(e), title="Ring: Auth Required", priority=0)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Ring Beams check failed: {e}")
        pushover.send_message(_alert_text(e), title="Ring: Error", priority=1)
        sys.exit(1)


if __name__ == "__main__":
    main()
