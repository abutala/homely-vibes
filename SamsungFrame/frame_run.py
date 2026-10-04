#!/usr/bin/env python3
"""Run the whole frame pipeline on a photo folder, then send one notification.

Stages run as separate processes, in order, and the run stops at the first one that fails:
ingest, dedup, upload (retried from its checkpoint), cleanup of the old catalog, slideshow.
Every stage is resumable, so after any failure rerun the same command. The single Pushover
message is built from the job's manifest, so its totals cover every attempt.
"""

import argparse
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Callable, Optional

from lib.config import get_config
from lib.logger import get_logger
from lib.MyPushover import Pushover
from SamsungFrame.frame_job import (
    Job,
    Manifest,
    default_job_dir,
    drop_kind,
    reason_counts,
)

logger = get_logger(__name__)

MODULES = {
    "ingest": "SamsungFrame.ingest",
    "dedup": "SamsungFrame.dedup_photos",
    "upload": "SamsungFrame.frame_upload",
    "cleanup": "SamsungFrame.frame_cleanup",
    "slideshow": "SamsungFrame.frame_slideshow",
}
INTERRUPTED = "interrupted"
DRIVER_ERROR = "the driver"
PRIORITY_QUIET = -1
PRIORITY_HIGH = 1


@dataclass(frozen=True)
class Stage:
    name: str
    command: list[str]
    attempts: int = 1


@dataclass(frozen=True)
class Report:
    title: str
    message: str
    priority: int


def build_stages(
    args: argparse.Namespace, job_dir: Path, python: str = sys.executable
) -> list[Stage]:
    def cmd(name: str, *args_: str) -> list[str]:
        return [python, "-m", MODULES[name], *args_]

    job = str(job_dir)
    ingest = cmd("ingest", str(args.source_dir), "--job", job)
    if args.include_portraits:
        ingest.append("--include-portraits")
    stages = [Stage("ingest", ingest)]
    if not args.no_dedup:
        dedup = cmd(
            "dedup",
            job,
            "--window",
            str(args.window),
            "--max-distance",
            str(args.max_distance),
            "--max-photos",
            str(args.max_photos),
        )
        stages.append(Stage("dedup", dedup))
    stages.append(Stage("upload", cmd("upload", job), attempts=args.upload_attempts))
    if not args.no_cleanup:
        stages.append(Stage("cleanup", cmd("cleanup", job)))
    stages.append(Stage("slideshow", cmd("slideshow", job, "--duration", str(args.duration))))
    return stages


def run_stages(stages: list[Stage], run: Callable[[list[str]], int]) -> Optional[str]:
    """Run stages in order; returns the name of the first that fails, or None."""
    for stage in stages:
        for attempt in range(1, stage.attempts + 1):
            logger.info(f"=== {stage.name} (attempt {attempt}/{stage.attempts}) ===")
            if run(stage.command) == 0:
                break
        else:
            logger.error(f"Stage {stage.name} failed; rerun the same command to resume")
            return stage.name
    return None


def _counts(reasons: dict[str, int]) -> str:
    return ", ".join(f"{n} {reason}" for reason, n in sorted(reasons.items())) or "none"


def build_report(manifest: Manifest, failed_stage: Optional[str]) -> Report:
    targets = manifest.upload_targets()
    dropped = reason_counts(drop_kind(why) for why in manifest.dropped.values())
    lines = [
        f"✅ Uploaded: {sum(1 for name in targets if name in manifest.uploaded)}/{len(targets)}",
        f"⏭ Skipped: {_counts(reason_counts(manifest.skipped.values()))}",
        f"🧹 Dropped: {_counts(dropped)}",
    ]
    if manifest.failed:
        lines.append(f"❌ Upload failures: {len(manifest.failed)}")
    if manifest.unattributed:
        lines.append(f"❔ On the TV but unnamed: {len(manifest.unattributed)}")
    if manifest.cleanup:
        c = manifest.cleanup
        lines.append(
            f"🗑 Old removed: {c.deleted} ({c.retained} kept for the minimum, {c.failed} failed)"
        )
    else:
        lines.append("🗑 Old catalog: not cleaned up")
    problems = manifest.slideshow_problems
    if problems is None:
        lines.append("🖼 Slideshow: not run")
    elif problems:
        lines.append("🖼 Slideshow NOT verified: " + "; ".join(problems))
    else:
        lines.append("🖼 Slideshow verified on the TV")
    if failed_stage == INTERRUPTED:
        lines.insert(0, "🛑 Interrupted (rerun to resume)")
        return Report("Samsung Frame - Interrupted", "\n".join(lines), PRIORITY_HIGH)
    if failed_stage:
        lines.insert(0, f"🛑 Stopped at: {failed_stage} (rerun to resume)")
        return Report(f"Samsung Frame - Failed at {failed_stage}", "\n".join(lines), PRIORITY_HIGH)
    if problems != [] or manifest.failed:
        return Report("Samsung Frame - Needs attention", "\n".join(lines), PRIORITY_HIGH)
    return Report("Samsung Frame - Complete", "\n".join(lines), PRIORITY_QUIET)


def safe_report(job: Job, failed_stage: Optional[str]) -> Report:
    """The report, or a bare one when the manifest cannot be read: a notification always goes."""
    try:
        return build_report(job.load(), failed_stage)
    except Exception as e:
        stage = failed_stage or "the manifest"
        return Report(
            f"Samsung Frame - Failed at {stage}", f"🛑 Manifest unreadable: {e}", PRIORITY_HIGH
        )


def notify(report: Report, send: Callable[[str, str, int], object]) -> None:
    try:
        send(report.message, report.title, report.priority)
        logger.info(f"Notification sent: {report.title}")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")


def run_pipeline(
    args: argparse.Namespace,
    job: Job,
    run: Callable[[list[str]], int],
    send: Callable[[str, str, int], object],
) -> int:
    """Run every stage, then send exactly one notification whatever happened. 0 = all green."""
    failed_stage: Optional[str] = INTERRUPTED
    try:
        failed_stage = run_stages(build_stages(args, job.root), run)
    except KeyboardInterrupt:
        logger.error("Interrupted; rerun the same command to resume")
    except Exception as e:
        failed_stage = DRIVER_ERROR
        logger.error(f"Driver error: {e}")
    finally:
        notify(safe_report(job, failed_stage), send)
    return 1 if failed_stage else 0


def _raise_interrupt(_signum: int, _frame: Optional[FrameType]) -> None:
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source_dir", type=Path, help="Photo folder (local or network mount)")
    parser.add_argument("--job", type=Path, help="Job dir (default: /tmp/frame-jobs/<name>-<hash>)")
    parser.add_argument("--include-portraits", action="store_true", help="Keep portrait photos")
    parser.add_argument("--no-dedup", action="store_true", help="Upload every ingested photo")
    parser.add_argument("--window", type=float, default=600, help="Dedup time window, seconds")
    parser.add_argument("--max-distance", type=float, default=0.4, help="Dedup similarity limit")
    parser.add_argument(
        "--max-photos", type=int, default=0, help="Keep at most this many after dedup (0 = all)"
    )
    parser.add_argument("--upload-attempts", type=int, default=3, help="Upload stage tries")
    parser.add_argument("--no-cleanup", action="store_true", help="Keep the old catalog")
    parser.add_argument("--duration", type=int, default=3, help="Slideshow minutes per photo")
    args = parser.parse_args()

    if not args.source_dir.is_dir():
        logger.error(f"Source directory not found: {args.source_dir}")
        return 1
    job = Job(args.job or default_job_dir(args.source_dir))
    job.create()
    cfg = get_config()
    token = cfg.pushover.tokens.get("SamsungFrame", cfg.pushover.default_token)
    pushover = Pushover(cfg.pushover.user, token)
    signal.signal(signal.SIGTERM, _raise_interrupt)
    return run_pipeline(
        args,
        job,
        lambda command: subprocess.run(command).returncode,
        lambda message, title, priority: pushover.send_message(
            message, title=title, priority=priority
        ),
    )


if __name__ == "__main__":
    sys.exit(main())
