#!/usr/bin/env python3
"""Stage 4: delete the old catalog from the TV, once the whole new batch is on it.

"Old" means exactly the photos the upload stage recorded as already on the TV before it began,
not "older than 24h", so a retry on another day cannot delete the batch itself. A minimum
photo count is kept: if fewer than that many would remain, the newest old photos are retained.
Nothing is deleted unless every target photo is uploaded and on the TV.
"""

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from lib.config import get_config
from lib.logger import get_logger
from SamsungFrame.frame_job import ArtRecord, CleanupRecord, Job, Manifest
from SamsungFrame.samsung_client import SamsungFrameClient, delete_art_by_ids, user_art

logger = get_logger(__name__)


class CleanupClient(Protocol):
    def get_available_art_strict(self) -> list[dict[str, Any]]: ...


Deleter = Callable[[Any, list[str]], dict[str, int]]


@dataclass(frozen=True)
class CleanupPlan:
    delete: list[str]
    retain: list[str]


def choose_deletions(
    snapshot: list[ArtRecord], on_tv: set[str], new_on_tv: int, min_images: int
) -> CleanupPlan:
    """Old photos still on the TV are deleted, except the newest ones needed to keep the TV at
    `min_images` photos in total (an undated photo counts as oldest)."""
    still_there = {a.id: a for a in snapshot if a.id in on_tv}  # one entry per id
    old = sorted(still_there.values(), key=lambda a: a.image_date)
    retain_count = min(len(old), max(0, min_images - new_on_tv))
    split = len(old) - retain_count
    return CleanupPlan(delete=[a.id for a in old[:split]], retain=[a.id for a in old[split:]])


def check_ready(manifest: Manifest, on_tv: set[str]) -> int:
    """Photos of this batch that are on the TV; raises if deleting the old catalog is unsafe."""
    if manifest.snapshot is None:
        raise ValueError("No snapshot of the old catalog: the upload stage has not run")
    if pending := manifest.pending_uploads():
        raise ValueError(f"{len(pending)} photos are not uploaded yet; finish the upload first")
    if missing := [n for n in manifest.upload_targets() if manifest.uploaded.get(n) not in on_tv]:
        raise ValueError(f"{len(missing)} uploaded photos are not on the TV; rerun the upload")
    new_ids = set(manifest.uploaded.values()) | set(manifest.unattributed)
    if not new_ids & on_tv:
        raise ValueError("None of this batch's photos are on the TV; refusing to delete")
    if overlap := new_ids & {a.id for a in manifest.snapshot}:
        raise ValueError(f"{len(overlap)} ids are both old catalog and new batch; refusing")
    return len(new_ids & on_tv)


def run_cleanup(
    job: Job,
    client: CleanupClient,
    min_images: int,
    dry_run: bool = False,
    delete: Deleter = delete_art_by_ids,
) -> CleanupPlan:
    manifest = job.load()
    on_tv = {a["content_id"] for a in user_art(client.get_available_art_strict())}
    new_on_tv = check_ready(manifest, on_tv)
    plan = choose_deletions(manifest.snapshot or [], on_tv, new_on_tv, min_images)
    logger.info(
        f"{len(plan.delete)} old photos to delete, {len(plan.retain)} retained "
        f"(minimum {min_images}, {new_on_tv} new photos on the TV)"
    )
    if dry_run:
        return plan
    result = delete(client, plan.delete)
    manifest.cleanup = CleanupRecord(
        deleted=result["deleted"], failed=result["failed"], retained=len(plan.retain)
    )
    job.save(manifest)
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("job_dir", type=Path, help="Job dir produced by ingest.py")
    parser.add_argument("--dry-run", action="store_true", help="Show the plan, delete nothing")
    parser.add_argument(
        "--min-images", type=int, help="Photos to keep (default: config min_images)"
    )
    parser.add_argument("--timeout", type=int, default=60, help="WebSocket timeout in seconds")
    args = parser.parse_args()

    min_images = (
        args.min_images if args.min_images is not None else get_config().samsung_frame.min_images
    )
    job = Job(args.job_dir)
    client = SamsungFrameClient(timeout=args.timeout)
    if not client.connect_ready():
        logger.error("Failed to connect to the TV")
        return 1
    try:
        run_cleanup(job, client, min_images, args.dry_run)
    except ValueError as e:
        logger.error(str(e))
        return 1
    finally:
        client.close()
    record = job.load().cleanup
    if args.dry_run or record is None:
        return 0
    logger.info(f"Deleted {record.deleted}, failed {record.failed}, retained {record.retained}")
    return 1 if record.failed else 0


if __name__ == "__main__":
    sys.exit(main())
