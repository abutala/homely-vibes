#!/usr/bin/env python3
"""Dump a Ring account's device config for a backup. It changes no device setting.

Combines the two ways this repo reads Ring: REST for cameras, doorbells, chimes
and modes (as RingSecurity does), and the Node sidecar for alarm sensors, keypads
and Beams (as beams_manager does). The dump's own REST calls are all GETs. Login
and ring-client-api still write to Ring's record of this client (session, push
token), as the daily checks do. The token rotates, so the run holds the token flock.

Writes ``ring_dump.json`` and ``devices.md`` to --out, both 0600. It writes nothing
if a Ring call needed for coverage fails, or if the dump looks like it holds a secret.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Coroutine

import aiohttp
from ring_doorbell import AuthenticationError, Auth, Requires2FAError, RingError

from RingBeams.beams_manager import run_raw_sidecar
from RingSecurity.ring_manager import USER_AGENT, RingAuthError, _load_token, _save_token
from lib.config import get_config
from lib.file_lock import acquire_lock
from lib.logger import get_logger
from lib.secure_io import write_secret_atomic

API = "https://api.ring.com"
APP = "https://app.ring.com"
CAMERA_FAMILIES = {"doorbots", "authorized_doorbots", "stickup_cams"}

SECRET_KEY = re.compile(
    r"token|secret|passw|passcode|pin_?code|access_?code|user_?code|credential|api_?key"
    r"|private_?key|^(codes?|pins?)$",
    re.IGNORECASE,
)
TOKEN_VALUE = re.compile(r"^eyJ[\w+/=-]{10,}|^bearer\s", re.IGNORECASE)
ACCESS_CODE_TYPE = "access-code"

Query = Callable[[str], Awaitable[Any]]
RestCollector = Callable[[], Coroutine[Any, Any, dict[str, Any]]]
Sidecar = Callable[[int], tuple[list[dict[str, Any]], list[str]]]


class DumpRefusedError(RuntimeError):
    """The dump looks like it holds a secret. The message names paths, never values."""


async def _get(query: Query, base: str, path: str, log: dict[str, str]) -> Any:
    """GET one path. A failed endpoint is logged, so one 404 does not lose the dump."""
    try:
        result = await query(base + path)
    except (AuthenticationError, Requires2FAError):
        raise
    except (RingError, ValueError) as e:
        log[path] = f"{type(e).__name__}: {e}"[:140]
        return None
    log[path] = "ok"
    return result


async def _collect_location(query: Query, location: str, log: dict[str, str]) -> dict[str, Any]:
    mode = f"/api/v1/mode/location/{location}"
    return {
        "groups": await _get(query, API, f"/groups/v1/locations/{location}/groups", log),
        "mode": await _get(query, APP, mode, log),
        "mode_settings": await _get(query, APP, f"{mode}/settings", log),
        "mode_sharing": await _get(query, APP, f"{mode}/sharing", log),
    }


async def _collect_device(
    query: Query, family: str, device: dict[str, Any], log: dict[str, str]
) -> dict[str, Any]:
    device_id = device.get("id")
    entry: dict[str, Any] = {"family": family, "name": device.get("description")}
    if family in CAMERA_FAMILIES:
        entry["health"] = await _get(query, API, f"/clients_api/doorbots/{device_id}/health", log)
        entry["settings_v1"] = await _get(
            query, API, f"/devices/v1/devices/{device_id}/settings", log
        )
    elif family == "chimes":
        chime = f"/clients_api/chimes/{device_id}"
        entry["health"] = await _get(query, API, f"{chime}/health", log)
        entry["linked_doorbells"] = await _get(query, API, f"{chime}/linked_doorbells", log)
    return entry


def _account_devices(account: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        (family, device)
        for family, devices in account.items()
        if isinstance(devices, list)
        for device in devices
    ]


async def collect_rest(query: Query, taken_at: str) -> dict[str, Any]:
    """Collect everything REST exposes, keyed the way ring_dump.json is read."""
    log: dict[str, str] = {}
    account = await _get(query, API, "/clients_api/ring_devices", log)
    devices = _account_devices(account or {})
    if not devices:
        raise RuntimeError(f"no account device list: {log}")
    locations = sorted({d["location_id"] for _, d in devices if d.get("location_id")})
    dump = {
        "taken_at": taken_at,
        "account_devices": account,
        "locations": await _get(query, API, "/devices/v1/locations", log),
        "per_location": {loc: await _collect_location(query, loc, log) for loc in locations},
        "per_device": {
            str(device.get("id")): await _collect_device(query, family, device, log)
            for family, device in devices
        },
    }
    dump["_fetch_log"] = log
    return dump


def _embedded_json(text: str) -> Any:
    """Ring nests JSON in some strings. Returns None when the text is not JSON."""
    if not text.startswith(("{", "[")):
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _is_secret_field(key: str, item: Any) -> bool:
    if isinstance(item, bool) or item in (None, "", [], {}):
        return False
    is_code_device = key == "deviceType" and str(item).startswith(ACCESS_CODE_TYPE)
    return is_code_device or bool(SECRET_KEY.search(key))


def find_secret_paths(value: Any, path: str = "") -> list[str]:
    """Paths whose key name or value looks like a secret. Never returns a value."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}/{key}" if path else str(key)
            if _is_secret_field(str(key), item):
                found.add(child)
            found.update(find_secret_paths(item, child))
    elif isinstance(value, list):
        for item in value:
            found.update(find_secret_paths(item, f"{path}[]"))
    elif isinstance(value, str):
        if TOKEN_VALUE.search(value):
            found.add(path)
        found.update(find_secret_paths(_embedded_json(value), path))
    return sorted(found)


def _cell(value: Any) -> str:
    return "" if value is None else str(value).strip().replace("|", "/")


def _row(*cells: Any) -> str:
    return "| " + " | ".join(_cell(c) for c in cells) + " |"


def _comm_date(last_comm_ms: Any) -> str:
    """A hub sends 0, which means no time, not 1970."""
    if not last_comm_ms:
        return ""
    return datetime.fromtimestamp(last_comm_ms / 1000, UTC).date().isoformat()


def render_devices_md(dump: dict[str, Any]) -> str:
    """The readable index beside ring_dump.json."""
    account_rows = sorted(
        _row(
            family,
            d.get("description"),
            d.get("kind"),
            d.get("device_id") or d.get("hardware_id"),
            d.get("firmware_version"),
        )
        for family, d in _account_devices(dump["account_devices"])
    )
    alarm_rows = sorted(
        _row(
            d.get("name"),
            d.get("deviceType"),
            d.get("zid"),
            d.get("batteryLevel"),
            d.get("commStatus"),
            _comm_date(d.get("lastCommTime")),
        )
        for d in dump["alarm_devices"]
    )
    return "\n".join(
        [
            f"# Ring devices, {dump['taken_at'][:10]}",
            "",
            "Pulled from Ring, with no device setting changed. Full data: `ring_dump.json`. "
            "It holds the home address "
            "and location. It holds no credentials: the script refuses to write a dump where a "
            "check finds one.",
            "",
            "Not included: alarm access codes, rooms and recordings. Nothing here restores by "
            "itself: use it as a reference to set a device up again. Motion flags show the mode "
            "at the time of the dump, so use the mode rules as the baseline.",
            "",
            "## Account devices",
            "",
            "Firmware is Ring's status text. Ring does not return a version here.",
            "",
            "| Family | Name | Kind | Device or hardware id | Firmware |",
            "|---|---|---|---|---|",
            *account_rows,
            "",
            "## Alarm and Beams devices",
            "",
            "| Name | Type | zid | Battery | Comm | Last comm (UTC) |",
            "|---|---|---|---|---|---|",
            *alarm_rows,
            "",
        ]
    )


def write_dump(out_dir: Path, dump: dict[str, Any]) -> None:
    """Write both files 0600, or nothing if the dump looks like it holds a secret."""
    secrets = find_secret_paths(dump)
    if secrets:
        raise DumpRefusedError(f"dump not written, secret-like paths: {secrets}")
    index = render_devices_md(dump)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_secret_atomic(out_dir / "ring_dump.json", json.dumps(dump, indent=1, sort_keys=True))
    write_secret_atomic(out_dir / "devices.md", index)


def take_dump(token_file: str, rest: RestCollector, sidecar: Sidecar) -> dict[str, Any]:
    """Run REST, then the sidecar, under one token flock. They rotate the same token."""
    with acquire_lock(token_file) as lock_fd:
        dump = asyncio.run(rest())
        alarm_devices, errors = sidecar(lock_fd)
    if errors:
        raise RuntimeError(f"sidecar errors: {errors}")
    if not alarm_devices:
        raise RuntimeError("sidecar returned no alarm devices")
    dump["alarm_devices"] = alarm_devices
    return dump


async def _collect_live(token_file: str, taken_at: str) -> dict[str, Any]:
    token = _load_token(token_file)
    if not token:
        raise RingAuthError(
            f"No Ring token at {token_file}. Run: uv run python RingSecurity/ring_manager.py auth"
        )
    async with aiohttp.ClientSession() as session:
        auth = Auth(
            USER_AGENT, token, lambda t: _save_token(token_file, t), http_client_session=session
        )

        async def query(url: str) -> Any:
            return (await auth.async_query(url)).json()

        return await collect_rest(query, taken_at)


def main() -> None:
    parser = argparse.ArgumentParser(description="Dump Ring device config for a backup.")
    parser.add_argument("--out", type=Path, required=True, help="Directory for the two files")
    args = parser.parse_args()

    logger: logging.Logger = get_logger(__name__)
    cfg = get_config().ring_beams
    taken_at = datetime.now(UTC).isoformat()
    try:
        dump = take_dump(
            cfg.token_file,
            lambda: _collect_live(cfg.token_file, taken_at),
            lambda fd: run_raw_sidecar(cfg, logger, lock_fd=fd),
        )
        write_dump(args.out, dump)
    except Exception as e:
        logger.error(f"Ring config dump failed: {e}")
        sys.exit(1)
    logger.info(f"Ring config dump written to {args.out}")


if __name__ == "__main__":
    main()
