#!/usr/bin/env python3
"""Shared wiring for the NetworkCheck scripts.

Every entry point in this module needs the same two things: a Pushover client
bound to the NetworkCheck app token, and a start-of-run banner in the log. Both
were copy-pasted into each script, which meant three places to keep in sync and
three chances to bind the wrong token.
"""

import logging
import os
import sys
from contextlib import AbstractContextManager

from lib.config import get_config
from lib.file_lock import acquire_lock
from lib.MyPushover import Pushover

BANNER = "=" * 50

# Every NetworkCheck script that logs into the Deco takes this one lock. The
# admin account is single-session: a second login evicts the first, and an
# evicted watchdog census reads as zero clients and starts the outage clock.
DECO_ADMIN_LOCK = "deco_admin"


def network_notifier() -> Pushover:
    """Pushover client bound to the NetworkCheck app token."""
    cfg = get_config()
    return Pushover(cfg.pushover.user, cfg.pushover.tokens["NetworkCheck"])


def log_invocation(logger: logging.Logger) -> None:
    """Record how the script was invoked.

    Cron redirects stdout+stderr to a file, but that only catches crashes; this
    is what tells you *which* invocation produced the lines that follow.
    """
    logger.info(BANNER)
    logger.info("Invoked: %s", " ".join(sys.argv))


def deco_admin_lock(timeout_s: float = 60.0) -> AbstractContextManager[int]:
    """Hold the Deco admin session against our own other scripts.

    It cannot stop a human signing in through the Deco app; `DecoClient` logs in
    again once on a read for that case.
    """
    path = os.path.join(get_config().paths.logging_dir, DECO_ADMIN_LOCK)
    return acquire_lock(path, timeout_s=timeout_s)
