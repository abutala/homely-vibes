"""Checkpointed state shared by the frame pipeline stages.

A job is a local directory holding the downsized JPGs, the deduped hard links and one
manifest. Stages are separate scripts that read and write only this manifest, so any stage can
be rerun and resumes from what is already recorded.
"""

import hashlib
import os
import re
import tempfile
from pathlib import Path

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


class Manifest(BaseModel):
    source: str = ""
    photos: dict[str, PhotoRecord] = Field(default_factory=dict)  # ingested, by JPG name
    skipped: dict[str, str] = Field(default_factory=dict)  # source relpath -> reason
    kept: list[str] | None = None  # JPG names that survived dedup; None until dedup has run
    dropped: dict[str, str] = Field(default_factory=dict)  # JPG name -> why dedup dropped it


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


def default_job_dir(source: Path) -> Path:
    """`/tmp/frame-jobs/<folder name>-<hash of full path>`: stable across runs, unique per source."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", source.name).strip("-") or "photos"
    digest = hashlib.sha256(str(source.resolve()).encode()).hexdigest()[:6]
    return JOBS_ROOT / f"{slug}-{digest}"
