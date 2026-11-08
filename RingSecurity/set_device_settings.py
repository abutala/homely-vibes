#!/usr/bin/env python3
"""Change one Ring device's settings, and show everything that changed.

A dry run by default: it reads the device and prints the planned change. With
--apply it sends a partial PATCH, reads the device again, and prints every field
that moved, because Ring can move linked fields too. It fails if a requested value
did not take effect. The run holds the token flock, because a call can rotate the token.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any, Awaitable, Callable

from RingSecurity.ring_manager import open_auth
from lib.config import get_config
from lib.file_lock import acquire_lock
from lib.logger import get_logger

SETTINGS_URL = "https://api.ring.com/devices/v1/devices/{device_id}/settings"
SETTLE_S = 3.0

Path = tuple[str, ...]
Read = Callable[[], Awaitable[dict[str, Any]]]
Write = Callable[[dict[str, Any]], Awaitable[None]]


class SettingNotAppliedError(RuntimeError):
    """Ring accepted the write, but a requested value did not change."""


def _leaves(value: Any, path: Path = ()) -> dict[Path, Any]:
    """Flatten nested dicts to key paths. A list or an empty dict is one value."""
    if not isinstance(value, dict) or not value:
        return {path: value}
    leaves: dict[Path, Any] = {}
    for key, item in value.items():
        leaves.update(_leaves(item, (*path, str(key))))
    return leaves


def _name(path: Path) -> str:
    return ".".join(path)


def _holds(leaves: dict[Path, Any], path: Path, value: Any) -> bool:
    """Strict: a missing key is not null, and Python's True == 1 is not a match."""
    return path in leaves and json.dumps(leaves[path], sort_keys=True) == json.dumps(
        value, sort_keys=True
    )


def _diff(before: dict[Path, Any], after: dict[Path, Any]) -> dict[str, list[Any]]:
    return {
        _name(path): [before.get(path), after.get(path)]
        for path in sorted(before.keys() | after.keys())
        if not (path in before and _holds(after, path, before[path]))
    }


async def change_settings(
    read: Read, write: Write, patch: dict[str, Any], *, apply: bool, settle_s: float = SETTLE_S
) -> dict[str, list[Any]]:
    """Return {setting: [old, new]}. A dry run returns the plan and writes nothing."""
    before = _leaves(await read())
    requested = _leaves(patch)
    unknown = sorted(_name(path) for path in requested.keys() - before.keys())
    if unknown:
        raise ValueError(f"unknown settings, nothing written: {unknown}")
    if not apply:
        return _diff(before, {**before, **requested})

    await write(patch)
    await asyncio.sleep(settle_s)
    after = _leaves(await read())
    changes = _diff(before, after)
    not_applied = sorted(_name(p) for p, v in requested.items() if not _holds(after, p, v))
    if not_applied:
        raise SettingNotAppliedError(f"not applied: {not_applied}; changed: {changes}")
    return changes


async def _change_live(
    token_file: str, device_id: str, patch: dict[str, Any], apply: bool
) -> dict[str, list[Any]]:
    url = SETTINGS_URL.format(device_id=device_id)
    async with open_auth(token_file) as auth:

        async def read() -> dict[str, Any]:
            return (await auth.async_query(url)).json()  # type: ignore[no-any-return]

        async def write(body: dict[str, Any]) -> None:
            await auth.async_query(url, method="PATCH", json=body)

        return await change_settings(read, write, patch, apply=apply)


def _patch_arg(text: str) -> dict[str, Any]:
    patch = json.loads(text)
    if not isinstance(patch, dict) or not patch:
        raise ValueError("patch must be a non-empty JSON object")
    return patch


def _device_id_arg(text: str) -> str:
    if not text.isdecimal():
        raise ValueError("device id must be digits")
    return text


def parse_args(argv: list[str] | None = None) -> tuple[str, dict[str, Any], bool]:
    parser = argparse.ArgumentParser(description="Change one Ring device's settings.")
    parser.add_argument("device_id", type=_device_id_arg, help="A per_device key in ring_dump.json")
    parser.add_argument("patch", type=_patch_arg, help="Partial settings, as JSON")
    parser.add_argument("--apply", action="store_true", help="Write. Without it, a dry run")
    args = parser.parse_args(argv)
    return args.device_id, args.patch, args.apply


def main() -> None:
    device_id, patch, apply = parse_args()
    logger = get_logger(__name__)
    token_file = get_config().ring.token_file
    try:
        with acquire_lock(token_file):
            changes = asyncio.run(_change_live(token_file, device_id, patch, apply))
    except Exception as e:
        logger.error(f"Ring settings change failed: {e}")
        sys.exit(1)
    print(json.dumps({"device": device_id, "applied": apply, "changes": changes}, indent=1))


if __name__ == "__main__":
    main()
