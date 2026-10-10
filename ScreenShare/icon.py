"""App icon for a launcher: a monitor showing the host's initials on a rounded blue tile."""

import re
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

SIZE = 1024
TILE_INSET = 100  # macOS icon grid: 824 px tile on a 1024 px canvas
TILE_RADIUS = 185
TOP_COLOR = (64, 156, 255)
BOTTOM_COLOR = (20, 60, 170)
FONT_PATHS = (
    "/System/Library/Fonts/SFNS.ttf",
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
)
ICONSET_SIZES = (16, 32, 128, 256, 512)


def initials(label: str) -> str:
    """'Studio Mac' -> 'SM'; '192.0.2.10' -> '10'."""
    if re.fullmatch(r"[0-9.]+", label):
        return label.rsplit(".", 1)[-1]
    return "".join(word[0] for word in label.split()[:2]).upper()


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONT_PATHS:
        if Path(path).exists():
            font = ImageFont.truetype(path, size)
            try:
                font.set_variation_by_name("Bold")
            except (OSError, ValueError):
                pass  # not a variable font
            return font
    return ImageFont.load_default(size)


def _tile() -> Image.Image:
    gradient = Image.new("RGBA", (SIZE, SIZE))
    draw = ImageDraw.Draw(gradient)
    for y in range(SIZE):
        t = y / (SIZE - 1)
        color = tuple(round(a + (b - a) * t) for a, b in zip(TOP_COLOR, BOTTOM_COLOR))
        draw.line([(0, y), (SIZE, y)], fill=(*color, 255))
    mask = Image.new("L", (SIZE, SIZE), 0)
    box = (TILE_INSET, TILE_INSET, SIZE - TILE_INSET, SIZE - TILE_INSET)
    ImageDraw.Draw(mask).rounded_rectangle(box, TILE_RADIUS, fill=255)
    shadow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    shadow_box = (box[0], box[1] + 12, box[2], box[3] + 12)
    ImageDraw.Draw(shadow).rounded_rectangle(shadow_box, TILE_RADIUS, fill=(0, 0, 0, 90))
    canvas = shadow.filter(ImageFilter.GaussianBlur(18))
    canvas.paste(gradient, (0, 0), mask)
    return canvas


def _monitor(canvas: Image.Image, text: str) -> None:
    draw = ImageDraw.Draw(canvas)
    white = (255, 255, 255, 255)
    screen = (230, 300, 794, 660)
    draw.rounded_rectangle(screen, 44, outline=white, width=34)
    draw.polygon([(462, 660), (562, 660), (590, 742), (434, 742)], fill=white)
    draw.rounded_rectangle((372, 734, 652, 768), 17, fill=white)
    font = _font(230 if len(text) <= 2 else 170)
    cx, cy = (screen[0] + screen[2]) / 2, (screen[1] + screen[3]) / 2
    draw.text((cx, cy), text, font=font, fill=white, anchor="mm")


def make_icon(label: str) -> Image.Image:
    canvas = _tile()
    _monitor(canvas, initials(label))
    return canvas


def write_icns(image: Image.Image, icns: Path) -> None:
    """iconutil needs an .iconset folder with 1x and 2x PNGs per size."""
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "icon.iconset"
        iconset.mkdir()
        for size in ICONSET_SIZES:
            for scale in (1, 2):
                suffix = "" if scale == 1 else "@2x"
                png = image.resize((size * scale, size * scale), Image.Resampling.LANCZOS)
                png.save(iconset / f"icon_{size}x{size}{suffix}.png")
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(icns)], check=True)
