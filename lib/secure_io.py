"""Atomic 0o600 file writes for secret material and state (OAuth tokens, monitor state).

Two entry points cover the two patterns in this repo:

- ``write_secret_atomic(path, content)`` — we own the write: create the file with
  ``0o600`` from birth (no TOCTOU window under a 0o022 umask) and swap it in
  with a rename, so a crash mid-write leaves the previous file, never a torn one.
- ``ensure_secret_perms(path)`` — a third-party library owns the write (e.g. yalexs
  writing the August token cache, SamsungTVWS writing the pairing token). Call
  this immediately after the library returns to tighten perms.

Both are safe to call on files that already exist with looser modes — they always
end at 0o600.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Union

_SecretContent = Union[str, bytes, dict[str, Any]]


def _to_bytes(content: _SecretContent) -> bytes:
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, dict):
        return json.dumps(content).encode("utf-8")
    raise TypeError(
        f"write_secret_atomic content must be str, bytes, or dict; got {type(content).__name__}"
    )


def write_secret_atomic(path: Union[str, Path], content: _SecretContent) -> None:
    """Write ``content`` to ``path`` with mode ``0o600``, atomically.

    The bytes go to a temp file in the same directory (``mkstemp`` creates it
    ``0o600`` whatever the umask), are fsynced, then renamed over ``path``.
    A reader or a crash sees the old file or the new one, never a partial
    write, and the new content is never readable at a wider mode.

    ``content`` may be ``str``, ``bytes``, or ``dict`` (serialized as JSON).

    A symlinked ``path`` is resolved first, so the link survives and its
    target is what gets replaced.
    """
    p = Path(os.path.realpath(path))
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = _to_bytes(content)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def ensure_secret_perms(path: Union[str, Path]) -> None:
    """Tighten ``path`` to ``0o600`` if it exists. No-op if missing.

    For token/cache files written by third-party libraries where we can't
    control the open flags. Call immediately after the library returns.
    """
    p = Path(path)
    if p.exists():
        os.chmod(p, 0o600)
