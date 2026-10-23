"""Burn a three-line caption into the bottom-left corner of each photo the upload stage sends.

No background box: white text with a soft dark halo, so it reads on bright sky and dark rock
alike. Line 1 is the original's file name, line 2 the capture time and place, line 3 the camera
and exposure. A line with nothing to say is left out. Place names come from an offline table of
towns (GeoNames, via `reverse_geocoder`), so no coordinate leaves the machine.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Callable

from PIL import Image, ImageDraw, ImageFilter, ImageFont

from lib.logger import get_logger
from SamsungFrame.frame_job import Job, Manifest, Shot
from SamsungFrame.ingest import save_within_limit

logger = get_logger(__name__)

FONT_PATHS = ("/System/Library/Fonts/HelveticaNeue.ttc", "/System/Library/Fonts/Helvetica.ttc")
SCREEN_ASPECT = 16 / 9  # the Frame fills its screen by cropping the photo to this, centred
NAME_SCALE = 0.024  # name line height as a share of the visible height
DETAIL_SCALE = 0.018
MARGIN_SCALE = 0.025
GAP_SCALE = 0.006
HALO_ALPHA = 170

Places = Callable[[list[tuple[float, float]]], list[str | None]]  # coords -> "Banff, Alberta"


def offline_places(coords: list[tuple[float, float]]) -> list[str | None]:
    """Nearest town and its state or province, for each (lat, lon)."""
    import reverse_geocoder  # loads a 10MB table on first use; imported only when needed

    if not coords:
        return []
    found = reverse_geocoder.search(coords, mode=1, verbose=False)
    return [", ".join(p for p in (r["name"], r["admin1"]) if p) or None for r in found]


def font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONT_PATHS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default(size)


def shutter(seconds: float) -> str:
    return f"1/{round(1 / seconds)} s" if seconds < 1 else f"{seconds:g} s"


def when(taken: str | None) -> str | None:
    try:
        return datetime.strptime(taken or "", "%Y:%m:%d %H:%M:%S").strftime("%-d %b %Y, %-I:%M %p")
    except ValueError:
        return None


def footnote_lines(source: str, shot: Shot, place: str | None) -> list[str]:
    """[name, "date · place", "camera · f/ · shutter · ISO"]; missing fields are left out."""
    camera = [
        shot.camera,
        f"ƒ/{shot.f_number:g}" if shot.f_number else None,
        shutter(shot.exposure) if shot.exposure else None,
        f"ISO {shot.iso}" if shot.iso else None,
    ]
    rows = [
        Path(source).stem,
        " · ".join(p for p in (when(shot.taken), place) if p),
        " · ".join(p for p in camera if p),
    ]
    return [r for r in rows if r]


def screen_box(width: int, height: int) -> tuple[int, int, int, int]:
    """(left, top, right, bottom) of the part of a photo the TV shows once it fills the screen:
    a 4:3 photo loses its top and bottom, a panorama its sides."""
    if width / height > SCREEN_ASPECT:
        shown = round(height * SCREEN_ASPECT)
        return (width - shown) // 2, 0, (width - shown) // 2 + shown, height
    shown = round(width / SCREEN_ASPECT)
    return 0, (height - shown) // 2, width, (height - shown) // 2 + shown


def stamp(img: Image.Image, lines: list[str]) -> Image.Image:
    """A copy of `img` with `lines` in the bottom-left corner of what the TV shows of it,
    sized to that visible height."""
    left, top, _, bottom = screen_box(*img.size)
    h = bottom - top
    fonts = [font(round(h * NAME_SCALE))] + [font(round(h * DETAIL_SCALE))] * (len(lines) - 1)
    margin, gap = round(h * MARGIN_SCALE), round(h * GAP_SCALE)
    heights = [f.getbbox("Ag")[3] for f in fonts]
    y = bottom - margin - sum(heights) - gap * (len(lines) - 1)

    text = Image.new("L", img.size, 0)
    draw = ImageDraw.Draw(text)
    for line, f, line_height in zip(lines, fonts, heights):
        draw.text((left + margin, y), line, font=f, fill=255)
        y += line_height + gap

    halo = text.filter(ImageFilter.MaxFilter(5)).filter(ImageFilter.GaussianBlur(h * 0.003))
    out = img.convert("RGB")
    out.paste((0, 0, 0), mask=halo.point(lambda v: min(v, HALO_ALPHA)))
    out.paste((255, 255, 255), mask=text)
    return out


def name_places(manifest: Manifest, names: list[str], places: Places) -> dict[str, str | None]:
    """Place of each named photo that has GPS, in one lookup; none if the lookup fails."""
    located = {n: w for n in names if (w := manifest.photos[n].shot.where)}
    if not located:
        return {}  # never load the town table for a batch with no GPS
    try:
        return dict(zip(located, places(list(located.values())), strict=True))
    except Exception as e:
        logger.warning(f"Footnotes without places: the place lookup failed: {e}")
        return {}


def footnote_job(
    job: Job, manifest: Manifest, names: list[str], places: Places, max_bytes: int
) -> list[Path]:
    """The file to upload for each name: its footnoted copy, made once and reused on a rerun.

    A photo that cannot be footnoted is uploaded plain, with a warning: the footnote is
    decoration, never a reason to leave a photo off the TV.
    """
    job.footnoted_dir.mkdir(parents=True, exist_ok=True)
    todo = [n for n in names if not (job.footnoted_dir / n).exists()]
    place_of = name_places(manifest, todo, places)
    for name in todo:
        record = manifest.photos[name]
        lines = footnote_lines(record.source, record.shot, place_of.get(name))
        target = job.footnoted_dir / name
        tmp = job.footnoted_dir / f".{name}.tmp"  # the copy appears whole or not at all
        try:
            with Image.open(job.jpg_dir / name) as img:
                save_within_limit(stamp(img, lines), tmp, max_bytes)
            if tmp.stat().st_size > max_bytes:
                raise ValueError(f"footnoted copy is over {max_bytes} bytes")
            os.replace(tmp, target)
        except Exception as e:
            logger.warning(f"Uploading {name} without a footnote: {e}")
        finally:
            tmp.unlink(missing_ok=True)
    return [
        job.footnoted_dir / n if (job.footnoted_dir / n).exists() else job.jpg_dir / n
        for n in names
    ]
