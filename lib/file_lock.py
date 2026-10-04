"""POSIX advisory file lock for cross-process critical sections.

Used to serialize Ring token refresh across RingSecurity (Python, ring-doorbell)
and RingBeams (Node sidecar spawned by Python parent) — both read/write the
same token file at config/tokens/ring_auth_token.json. Ring OAuth rotates the
refresh_token on every use, so overlapping refreshes race the server and one
side gets `invalid_grant`.

Design notes:

- ``fcntl.flock`` (POSIX BSD flock, LOCK_EX) is auto-released on process exit
  including crash — no staleness detection or PID sentinels needed. Works on
  both dev macOS and prod Linux.
- Locks a sibling ``<path>.lock`` file, NOT the resource itself. The resource
  gets rewritten via tmp+rename (secure_io); an fd on the pre-rename inode
  would point to a deleted file and the lock would silently dangle. The
  sidecar ``.lock`` file is never renamed, so its inode stays stable.
- The lock belongs to the open file description, not the process. Yielding
  the fd lets a caller hand it to a child via ``subprocess(pass_fds=...)``;
  the child then keeps the lock after a hard-killed parent, until it exits.
  Release is therefore a plain ``close()``: an explicit ``LOCK_UN`` would drop
  the lock for every inheritor at once.
- Blocking acquire with a wall-clock timeout (default 60s). The daily cron
  cadence is 5 min apart, so anything longer than 60s means something is
  genuinely stuck — surface as ``TimeoutError`` rather than paging silently.
"""

from __future__ import annotations

import fcntl
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Union


class LockTimeoutError(TimeoutError):
    """Advisory lock was not acquired within the timeout window."""


@contextmanager
def acquire_lock(
    resource_path: Union[str, Path],
    *,
    timeout_s: float = 60.0,
    poll_interval_s: float = 0.5,
) -> Iterator[int]:
    """Acquire an exclusive advisory flock on ``<resource_path>.lock``.

    Held for the ``with`` block; auto-released on exit (including exceptions
    and process crash). Blocking acquire; raises ``LockTimeoutError`` if the
    lock isn't obtained within ``timeout_s``. Yields the lock's fd: pass it to
    a child via ``pass_fds`` so the child holds the lock for as long as it runs.
    """
    lock_path = Path(str(resource_path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_s
    fd = None
    try:
        fd = lock_path.open("w")
        while True:
            try:
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockTimeoutError(
                        f"Could not acquire {lock_path} within {timeout_s}s"
                    ) from None
                time.sleep(poll_interval_s)
        yield fd.fileno()
    finally:
        if fd is not None:
            fd.close()
