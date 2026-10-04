#!/usr/bin/env python3
"""Stage 5: start the slideshow and verify on the TV that it is really playing.

The TV is read back after the start: art mode on, My Pictures, interval and shuffle as
requested, and the playlist exactly the photos on the TV. Exits non-zero unless all of that
holds, because a started slideshow is not a playing slideshow (deleting art after the start
leaves a stale playlist and no autoplay).
"""

import argparse
import sys
import time
from pathlib import Path
from typing import Protocol

from lib.config import get_config
from lib.logger import get_logger
from SamsungFrame.frame_job import Job
from SamsungFrame.samsung_client import SamsungFrameClient

logger = get_logger(__name__)


class SlideshowClient(Protocol):
    def start_slideshow(self, duration: int, shuffle: bool) -> bool: ...

    def verify_slideshow(self, duration: int, shuffle: bool) -> list[str]: ...


def run_slideshow(job: Job, client: SlideshowClient, duration: int, shuffle: bool) -> list[str]:
    """Problems found after starting the slideshow; empty = verified. Recorded in the manifest."""
    if client.start_slideshow(duration, shuffle):
        problems = client.verify_slideshow(duration, shuffle)
    else:
        problems = ["the TV did not accept the slideshow command"]
    manifest = job.load()
    manifest.slideshow_problems = problems
    job.save(manifest)
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("job_dir", type=Path, help="Job dir produced by ingest.py")
    parser.add_argument("--duration", type=int, default=3, help="Minutes per photo (default: 3)")
    parser.add_argument("--no-shuffle", action="store_true", help="Play in order")
    parser.add_argument("--timeout", type=int, default=60, help="WebSocket timeout in seconds")
    args = parser.parse_args()

    client = SamsungFrameClient(timeout=args.timeout)
    if not client.connect_ready():
        logger.error("Failed to connect to the TV")
        return 1
    try:
        time.sleep(get_config().samsung_frame.slideshow_delay_seconds)
        problems = run_slideshow(Job(args.job_dir), client, args.duration, not args.no_shuffle)
    finally:
        client.close()
    for problem in problems:
        logger.error(f"Slideshow not verified: {problem}")
    if not problems:
        logger.info("Slideshow started and verified on the TV")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
