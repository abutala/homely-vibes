"""Checkpointed state shared by the frame pipeline stages.

A job is a local directory holding the downsized JPGs, the deduped hard links and one
manifest. Stages (ingest, dedup, upload, cleanup, slideshow) are separate scripts that read and
write only this manifest, so any stage can be rerun and resumes from what is already recorded.
"""

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, Field

JOBS_ROOT = Path("/tmp/frame-jobs")  # scratch: a lost job just redoes its stages


class PhotoRecord(BaseModel):
    name: str  # JPG file name inside the job's jpg dir
    source: str  # original's path relative to the source folder
    time: float  # capture time, epoch seconds
    width: int
    height: int
    sharpness: float

    @property
    def landscape(self) -> bool:
        return self.width >= self.height


class ArtRecord(BaseModel):
    """A user photo that was already on the TV before the batch started."""

    id: str
    image_date: str = ""  # the TV's upload timestamp, "%Y:%m:%d %H:%M:%S"; empty when unknown


class CleanupRecord(BaseModel):
    deleted: int
    failed: int
    retained: int  # old photos kept so the TV never falls below the minimum photo count


class Manifest(BaseModel):
    source: str = ""
    photos: dict[str, PhotoRecord] = Field(default_factory=dict)  # ingested, by JPG name
    skipped: dict[str, str] = Field(default_factory=dict)  # source relpath -> reason
    kept: list[str] | None = None  # JPG names that survived dedup; None until dedup has run
    dropped: dict[str, str] = Field(default_factory=dict)  # JPG name -> why dedup dropped it
    snapshot: list[ArtRecord] | None = None  # the TV's user photos before the first upload
    uploaded: dict[str, str] = Field(default_factory=dict)  # JPG name -> TV content id
    failed: dict[str, str] = Field(default_factory=dict)  # JPG name -> last upload error
    unattributed: list[str] = Field(default_factory=list)  # TV ids this batch added, name unknown
    cleanup: CleanupRecord | None = None
    slideshow_problems: list[str] | None = None  # None = not run, [] = verified on the TV

    def upload_targets(self) -> list[str]:
        """What stage 3 must get onto the TV: the deduped set, or everything if dedup was skipped."""
        return list(self.kept) if self.kept is not None else sorted(self.photos)

    def pending_uploads(self) -> list[str]:
        return [name for name in self.upload_targets() if name not in self.uploaded]


class Job:
    def __init__(self, root: Path):
        self.root = root
        self.jpg_dir = root / "jpg"
        self.deduped_dir = root / "deduped"
        self.manifest_path = root / "manifest.json"

    def create(self) -> None:
        self.jpg_dir.mkdir(parents=True, exist_ok=True)

    def load(self) -> Manifest:
        if not self.manifest_path.exists():
            return Manifest()
        return Manifest.model_validate_json(self.manifest_path.read_text())

    def save(self, manifest: Manifest) -> None:
        """Atomic: a crash mid-write leaves the previous manifest, never a torn one."""
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".manifest-", suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            f.write(manifest.model_dump_json(indent=1))
        os.replace(tmp, self.manifest_path)


def reason_counts(reasons: Iterable[str]) -> dict[str, int]:
    """Counts by reason, ignoring any detail after a colon ("unreadable: boom" -> "unreadable")."""
    counts: dict[str, int] = {}
    for reason in reasons:
        key = reason.split(":")[0]
        counts[key] = counts.get(key, 0) + 1
    return counts


def drop_kind(reason: str) -> str:
    """A dedup drop reason without the photo it names ("duplicate of a.jpg" -> "duplicate")."""
    return "duplicate" if reason.startswith("duplicate of ") else reason


def default_job_dir(source: Path) -> Path:
    """`/tmp/frame-jobs/<folder name>-<hash of full path>`: stable across runs, unique per source."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", source.name).strip("-") or "photos"
    digest = hashlib.sha256(str(source.resolve()).encode()).hexdigest()[:6]
    return JOBS_ROOT / f"{slug}-{digest}"
