#!/usr/bin/env python3
import argparse
import sys
import time
from collections.abc import Callable
from pathlib import Path
from lib.config import get_config
from lib.logger import SystemLogger
from lib import Mailer
from lib.MyPushover import Pushover

cfg = get_config()
logger = SystemLogger.get_logger(__name__)

# Initialize Pushover client for Foscam notifications
pushover = Pushover(cfg.pushover.user, cfg.pushover.tokens["NodeCheck"])


def purge_old_foscam_files(
    foscam_dir: str, purge_after_days: int, notify: Callable[[str], object]
) -> tuple[bool, str]:
    """Delete clips older than purge_after_days, two or more levels under foscam_dir.

    Every path sends exactly one alert through notify, and a failure to send it is
    logged, never raised, so it cannot hide the purge result.
    """
    messages = ["Starting foscam file purge process..."]
    success, alert = _purge(Path(foscam_dir), purge_after_days, messages)
    try:
        notify(alert)
    except Exception as e:
        logger.error(f"Foscam cleanup alert not sent: {e}")
    return success, "\n".join(messages)


def _purge(foscam_path: Path, purge_after_days: int, messages: list[str]) -> tuple[bool, str]:
    """Return (success, alert text); append report lines to messages."""
    if not foscam_path.is_dir():
        alert = f"Error: Foscam directory {foscam_path} is not accessible"
        messages.append(alert)
        logger.error(alert)
        return False, alert
    try:
        # rglob skips unreadable directories silently, so probe the root first:
        # a stale or dead mount must fail loudly, not report "no old files"
        next(foscam_path.iterdir(), None)
    except OSError as e:
        alert = f"Error: Foscam directory {foscam_path} is not readable: {e}"
        messages.append(alert)
        logger.error(alert)
        return False, alert
    messages.append(f"Foscam directory {foscam_path} is accessible")
    messages.append(f"Deleting all IPCam data older than {purge_after_days} days...")

    cutoff_time = time.time() - purge_after_days * 24 * 60 * 60
    deleted_count = 0
    error_count = 0
    try:
        for file_path in foscam_path.rglob("*"):
            # Only files two or more directories below the root (find -mindepth 3)
            if len(file_path.relative_to(foscam_path).parts) < 3 or not file_path.is_file():
                continue
            try:
                if file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    deleted_count += 1
            except OSError as e:
                error_count += 1
                logger.warning(f"Could not delete {file_path}: {e}")
    except OSError as e:
        alert = f"Error during file deletion: {e}"
        messages.append(alert)
        logger.error(alert)
        return False, alert

    if deleted_count == 0 and error_count == 0:
        messages.append("No old files found to clean")
        return True, f"Foscam cleanup: No old files to clean (older than {purge_after_days} days)"
    if error_count == 0:
        messages.append(f"✓ Successfully cleaned {deleted_count} old files")
        logger.info(f"Foscam cleanup: {deleted_count} files removed, 0 errors")
        return True, f"✓ Foscam cleanup: Successfully removed {deleted_count} old files"
    messages.append(f"⚠ Cleaned {deleted_count} old files with {error_count} errors")
    logger.warning(f"Foscam cleanup: {deleted_count} files removed, {error_count} errors")
    # Errors above 10% of deletions count as a failure
    return (
        error_count <= deleted_count * 0.1,
        f"⚠ Foscam cleanup: Removed {deleted_count} files with {error_count} errors",
    )


#### Main Routine ####
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Purge Foscam videos from NAS")
    parser.add_argument(
        "--always_email",
        help="Send email report",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()

    logger.info("============")
    logger.info("Invoked command: %s" % " ".join(sys.argv))

    # Run the integrated purge functionality
    alert = False
    try:
        success, msg = purge_old_foscam_files(
            cfg.node_check.foscam.foscam_dir,
            cfg.node_check.foscam.purge_after_days,
            lambda text: pushover.send_message(text, title="Foscam Cleanup", priority=-2),
        )
        alert = not success
    except Exception as e:
        msg = f"Fatal error in foscam purge: {str(e)}"
        alert = True
        logger.error(msg)
    finally:
        logger.info(msg)

    Mailer.sendmail(
        topic="[PurgeFoscam]",
        alert=alert,
        message=msg,
        always_email=args.always_email,
    )
    print("Done!")
