#!/usr/bin/env python3
"""Stage 3: upload a job's photos to the TV, checkpointing every image.

Before the first upload it records which user photos are already on the TV (the old catalog
that stage 4 may later remove). Each image is recorded in the manifest the moment the TV has
it, so rerunning after any failure uploads only what is still missing.
"""

import argparse
import sys
from pathlib import Path
from typing import Any, Callable, Optional, Protocol

from lib.logger import get_logger
from SamsungFrame.frame_job import ArtRecord, Job, Manifest
from SamsungFrame.samsung_client import ImageUploadSummary, SamsungFrameClient, user_art

logger = get_logger(__name__)


class UploadClient(Protocol):
    def get_available_art_strict(self) -> list[dict[str, Any]]: ...

    def upload_images(
        self,
        image_files: list[str],
        *,
        matte: Optional[str] = None,
        on_uploaded: Optional[Callable[[str, str], None]] = None,
    ) -> ImageUploadSummary: ...


def unattributed_ids(art_list: list[dict[str, Any]], manifest: Manifest) -> list[str]:
    """User photos on the TV that this batch added but cannot name (a timed-out upload that
    arrived anyway): on the TV now, in neither the old catalog nor the uploaded record."""
    known = {a.id for a in manifest.snapshot or []} | set(manifest.uploaded.values())
    return sorted(a["content_id"] for a in user_art(art_list) if a["content_id"] not in known)


def run_upload(job: Job, client: UploadClient, matte: Optional[str] = None) -> list[str]:
    """Upload what is missing; returns the names still not on the TV (empty = stage complete)."""
    manifest = job.load()
    if not manifest.upload_targets():
        raise ValueError(
            f"Nothing to upload in {job.root}; run ingest.py and dedup_photos.py first"
        )
    on_tv = user_art(client.get_available_art_strict())  # raises if unreadable: retried by rerun
    if manifest.snapshot is None:
        # keyed by id: the TV's art list can return the same photo twice
        old_catalog = {
            a["content_id"]: ArtRecord(id=a["content_id"], image_date=a.get("image_date", ""))
            for a in on_tv
        }
        manifest.snapshot = list(old_catalog.values())
        job.save(manifest)  # before any upload, so it never includes this batch
    else:
        gone = [
            n for n, i in manifest.uploaded.items() if i not in {a["content_id"] for a in on_tv}
        ]
        for name in gone:  # the TV wins over the checkpoint: upload them again
            del manifest.uploaded[name]
        if gone:
            logger.warning(f"{len(gone)} recorded photos are no longer on the TV; re-uploading")
            job.save(manifest)

    def checkpoint(path: str, content_id: str) -> None:
        name = Path(path).name
        manifest.uploaded[name] = content_id
        manifest.failed.pop(name, None)
        job.save(manifest)

    pending = manifest.pending_uploads()
    if pending:
        logger.info(
            f"Uploading {len(pending)} of {len(manifest.upload_targets())} photos "
            f"({len(manifest.uploaded)} already on the TV)"
        )
        summary = client.upload_images(
            [str(job.jpg_dir / name) for name in pending], matte=matte, on_uploaded=checkpoint
        )
        for error in summary.errors:
            manifest.failed[error["file"]] = error["error"]
    try:
        manifest.unattributed = unattributed_ids(client.get_available_art_strict(), manifest)
    except Exception as e:
        logger.warning(f"Could not read the TV's art list to check for unnamed uploads: {e}")
    job.save(manifest)
    return manifest.pending_uploads()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("job_dir", type=Path, help="Job dir produced by ingest.py")
    parser.add_argument("--matte", help="Matte style (default: samsung_frame.default_matte)")
    parser.add_argument("--timeout", type=int, default=60, help="WebSocket timeout in seconds")
    args = parser.parse_args()

    job = Job(args.job_dir)
    client = SamsungFrameClient(timeout=args.timeout)
    if not client.connect_ready():
        logger.error("Failed to connect to the TV")
        return 1
    try:
        pending = run_upload(job, client, args.matte)
    except ValueError as e:
        logger.error(str(e))
        return 1
    finally:
        client.close()
    manifest = job.load()
    logger.info(
        f"Uploaded {len(manifest.uploaded)}/{len(manifest.upload_targets())}; "
        f"{len(manifest.failed)} failed; {len(manifest.unattributed)} unnamed on the TV"
    )
    if pending:
        logger.error(f"{len(pending)} photos are not on the TV; rerun the same command to resume")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
