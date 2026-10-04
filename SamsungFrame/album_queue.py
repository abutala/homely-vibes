"""The queue of photo albums for the monthly Frame routine: one TSV row per album, in play order.

The file's line order IS the queue. `pick` takes the first eligible row whose kind differs from
the last album shown, so the two kinds alternate; an album with more usable pictures than the TV
should hold plays in consecutive months, one part each. Nothing here touches the TV.
"""

import copy
import csv
import math
import os
import random
import re
from dataclasses import asdict, dataclass, fields
from datetime import date, timedelta
from pathlib import Path

from lib.config import FrameAlbumsConfig

IMAGE_EXTENSIONS = {".heic", ".jpg", ".jpeg", ".png"}
PLAYABLE_KINDS = {"park", "city"}
KINDS = PLAYABLE_KINDS | {"other", "?"}
UNKNOWN = "?"
# Words a camera or an export tool puts in a file name; anything else is a caption a person typed.
CAMERA_WORDS = {
    "img", "dsc", "dscn", "dscf", "cimg", "pxl", "mvimg", "dji", "gopr", "vid", "mov", "pano",
    "hdr", "burst", "edited", "copy", "orig", "jpg", "jpeg", "png", "heic", "photo", "image",
    "picture", "whatsapp", "screenshot", "fullsizerender", "sam", "pict", "imgp", "kimg",
    "original", "received",
}  # fmt: skip
CAMERA_WORD_PATTERNS = re.compile(r"st[a-z]|[a-f]+")  # Canon stitch (STA_, STB_), hex fragments


@dataclass
class Album:
    path: str  # relative to the library root: <year>/<month>/<album>
    pictures: int  # image files in the folder
    labelled: int = -1  # of those, files a person captioned; -1 = not counted yet
    kind: str = UNKNOWN  # park | city | other | ?
    region: str = UNKNOWN  # free text, compared with the configured home region
    status: str = "new"  # new | queued | playing (mid-split) | shown | small | skip
    shown: str = ""  # YYYY-MM it was last put on the TV
    added: str = ""  # date the row was first indexed
    on_tv: int = -1  # usable pictures (portraits dropped, deduplicated); -1 = unmeasured
    parts: int = 0  # months it takes to play; 0 = unmeasured
    part: int = 0  # parts played so far

    @property
    def year(self) -> int:
        return int(self.path.split("/")[0])

    @property
    def name(self) -> str:
        return self.path.split("/")[-1]

    @property
    def shot(self) -> str:
        year, month = self.path.split("/")[:2]
        return f"{month.split('-')[-1][:3]} {year}"


INT_FIELDS = {f.name for f in fields(Album) if f.type is int}


def load_index(path: Path) -> list[Album]:
    if not path.exists():
        return []
    with path.open(newline="") as f:
        return [
            Album(**{k: int(v) if k in INT_FIELDS else v for k, v in row.items()})  # type: ignore[arg-type]
            for row in csv.DictReader(f, delimiter="\t")
        ]


def save_index(path: Path, albums: list[Album]) -> None:
    """Atomic: a crash mid-write leaves the previous index."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", newline="") as f:
        writer = csv.DictWriter(
            f, [x.name for x in fields(Album)], delimiter="\t", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(asdict(a) for a in albums)
    os.replace(tmp, path)


def slug(path: str) -> str:
    """An album path as a file-name-safe token."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", path).strip("-")


def is_labelled_file(name: str) -> bool:
    """True when the file name carries a caption a person typed (`IMG_1234-Sunset.jpg`)."""
    words = re.findall(r"[a-z]{3,}", Path(name).stem.lower())
    return any(w not in CAMERA_WORDS and not CAMERA_WORD_PATTERNS.fullmatch(w) for w in words)


def image_files(album_dir: Path) -> list[str]:
    """Relative paths of the album's image files, sorted."""
    return sorted(
        str(Path(folder, name).relative_to(album_dir))
        for folder, _, names in os.walk(album_dir)
        for name in names
        if not name.startswith(".") and Path(name).suffix.lower() in IMAGE_EXTENSIONS
    )


def album_dirs(root: Path) -> list[str]:
    """`<year>/<month>/<album>` for every album dir; roots that are not a year are ignored."""
    found = []
    for year in sorted(p for p in root.iterdir() if p.is_dir() and re.fullmatch(r"\d{4}", p.name)):
        for month in sorted(p for p in year.iterdir() if p.is_dir()):
            found += [
                f"{year.name}/{month.name}/{a.name}"
                for a in sorted(month.iterdir())
                if a.is_dir() and not a.name.startswith(".")
            ]
    return found


def scan(albums: list[Album], root: Path, today: date, full: bool = False) -> int:
    """Index albums not seen before (and recount the rest when `full`); returns how many are new."""
    known = {a.path: a for a in albums}
    added = 0
    for rel in album_dirs(root):
        album = known.get(rel)
        if album is None:
            album = Album(path=rel, pictures=0, added=today.isoformat())
            albums.append(album)
            added += 1
        elif not full and album.labelled >= 0:
            continue
        files = image_files(root / rel)
        album.pictures = len(files)
        album.labelled = sum(1 for f in files if is_labelled_file(f))
    return added


def needs_kind(albums: list[Album], cfg: FrameAlbumsConfig) -> list[Album]:
    """Albums big enough to play that nobody has classified yet."""
    return [
        a
        for a in albums
        if a.kind == UNKNOWN and a.status != "skip" and a.pictures > cfg.min_pictures
    ]


def is_labelled(album: Album, cfg: FrameAlbumsConfig) -> bool:
    return album.labelled >= cfg.labelled_album_min


def eligible(album: Album, cfg: FrameAlbumsConfig) -> bool:
    return (
        album.status == "queued"
        and album.pictures > cfg.min_pictures
        and album.kind in PLAYABLE_KINDS
    )


def place(albums: list[Album], cfg: FrameAlbumsConfig, rng: random.Random) -> list[Album]:
    """Queue every `new` row; an eligible one is shuffled in among the first top_k eligible.

    Returns the albums placed near the top.
    """
    placed = []
    for album in [a for a in albums if a.status == "new"]:
        album.status = "queued"
        if not eligible(album, cfg):
            continue
        albums.remove(album)
        head = [i for i, a in enumerate(albums) if eligible(a, cfg)][: cfg.top_k]
        albums.insert(rng.choice(head + [head[-1] + 1]) if head else 0, album)
        placed.append(album)
    return placed


def weight(album: Album, cfg: FrameAlbumsConfig, this_year: int) -> float:
    away = cfg.away_weight if album.region not in (cfg.home_region, UNKNOWN) else 1.0
    return float(away * 0.5 ** (max(0, this_year - album.year) / cfg.recency_half_life_years))


def shuffle(
    albums: list[Album], cfg: FrameAlbumsConfig, rng: random.Random, this_year: int
) -> list[Album]:
    """The index with its eligible rows re-dealt first: weighted random, favouring albums from
    away and newer ones."""
    playable = [a for a in albums if eligible(a, cfg)]
    rest = [a for a in albums if not eligible(a, cfg)]
    playable.sort(key=lambda a: rng.random() ** (1 / weight(a, cfg, this_year)), reverse=True)
    return playable + rest


def pick(albums: list[Album], cfg: FrameAlbumsConfig, month: str) -> Album | None:
    """This month's album: the one already marked for the month, else the album mid-split,
    else the first eligible row whose kind differs from the last one shown."""
    for album in albums:
        if album.shown == month and album.status in ("shown", "playing"):
            return album
    for album in albums:
        if album.status == "playing":
            return album
    last = max((a for a in albums if a.status == "shown"), key=lambda a: a.shown, default=None)
    queue = [a for a in albums if eligible(a, cfg)]
    alternate = [a for a in queue if last is None or a.kind != last.kind]
    return next(iter(alternate or queue), None)


def record_measure(album: Album, count: int, cfg: FrameAlbumsConfig) -> bool:
    """Record an album's usable picture count; False (and status `small`) when it is too few."""
    album.on_tv = count
    if count < cfg.min_on_tv:
        album.status = "small"
        return False
    album.parts = math.ceil(count / cfg.max_on_tv)
    return True


def part_for(album: Album, month: str) -> int:
    """The part (1-based) to play in `month`: the same one again on a rerun within the month."""
    return album.part if album.shown == month else album.part + 1


def mark_shown(album: Album, month: str) -> None:
    album.part = part_for(album, month)
    album.shown = month
    album.status = "shown" if album.part >= max(album.parts, 1) else "playing"


def split(items: list[str], parts: int) -> list[list[str]]:
    """`parts` consecutive chunks whose sizes differ by at most one."""
    size, extra = divmod(len(items), parts)
    chunks, start = [], 0
    for i in range(parts):
        end = start + size + (1 if i < extra else 0)
        chunks.append(items[start:end])
        start = end
    return chunks


def first_monday(year: int, month: int) -> date:
    first = date(year, month, 1)
    return first + timedelta(days=(7 - first.weekday()) % 7)


def run_dates(today: date, count: int) -> list[date]:
    """The next `count` first-Mondays, today included."""
    dates: list[date] = []
    year, month = today.year, today.month
    while len(dates) < count:
        run = first_monday(year, month)
        if run >= today:
            dates.append(run)
        year, month = (year + 1, 1) if month == 12 else (year, month + 1)
    return dates


def forecast(album: Album, cfg: FrameAlbumsConfig) -> tuple[int, int, bool]:
    """(usable pictures, parts, measured?) for an album, guessed when it is not measured."""
    if album.on_tv >= 0 and album.parts:
        return album.on_tv, album.parts, True
    guess = album.labelled if is_labelled(album, cfg) else round(album.pictures * cfg.keep_ratio)
    return guess, max(1, math.ceil(guess / cfg.max_on_tv)), False


def upcoming(albums: list[Album], cfg: FrameAlbumsConfig, today: date) -> list[list[str]]:
    """Table rows for the coming months, by playing the queue forward on a copy."""
    albums = copy.deepcopy(albums)
    rows = []
    for run in run_dates(today, cfg.table_months):
        month = run.strftime("%Y-%m")
        album = pick(albums, cfg, month)
        while album and is_labelled(album, cfg) and album.labelled < cfg.min_on_tv:
            album.status = "small"  # will be skipped on the day
            album = pick(albums, cfg, month)
        if album is None:
            break
        count, parts, measured = forecast(album, cfg)
        album.parts = parts
        mark_shown(album, month)
        per_part = math.ceil(count / parts)
        rows.append(
            [
                run.isoformat(),
                album.name + (f" (part {album.part} of {parts})" if parts > 1 else ""),
                album.shot,
                album.kind,
                album.region,
                str(album.pictures),
                str(per_part) if measured else f"~{per_part}",
                str(album.labelled) if album.labelled > 0 else "",
            ]
        )
    return rows


def pool_stats(albums: list[Album], cfg: FrameAlbumsConfig) -> list[str]:
    queue = [a for a in albums if eligible(a, cfg)]
    kinds = ", ".join(f"{sum(a.kind == k for a in queue)} {k}" for k in sorted(PLAYABLE_KINDS))
    regions = sorted({a.region for a in queue})
    by_region = ", ".join(f"{sum(a.region == r for a in queue)} {r}" for r in regions)
    months = sum(forecast(a, cfg)[1] for a in queue)
    count = {s: sum(a.status == s for a in albums) for s in ("shown", "playing", "small", "skip")}
    return [
        f"- Queue: {len(queue)} albums ({kinds}; {by_region}), about {months} months of albums",
        f"- Labelled albums in the queue: {sum(is_labelled(a, cfg) for a in queue)}",
        f"- Shown: {count['shown']} · playing in parts: {count['playing']} · "
        f"skipped as too small: {count['small']} · vetoed: {count['skip']}",
        f"- Limits: folder > {cfg.min_pictures} pictures; on the TV {cfg.min_on_tv} to "
        f"{cfg.max_on_tv} per month",
    ]


TABLE_HEADER = ["Run date", "Album", "Shot", "Kind", "Region", "In folder", "On TV", "Labelled"]


def table_markdown(albums: list[Album], cfg: FrameAlbumsConfig, today: date) -> str:
    """The next-months table and the pool stats, as the Markdown published beside the index."""
    return "\n".join(
        [
            "# Frame TV: next months",
            "",
            f"Rewritten by every run of the monthly album routine; last on {today.isoformat()}. "
            "`~` marks a guess for an album not measured yet; a guess under the minimum may be "
            "skipped on the day and the next album plays instead.",
            "",
            "| " + " | ".join(TABLE_HEADER) + " |",
            "|" + "---|" * len(TABLE_HEADER),
            *("| " + " | ".join(row) + " |" for row in upcoming(albums, cfg, today)),
            "",
            "## Pool",
            "",
            *pool_stats(albums, cfg),
            "",
        ]
    )
