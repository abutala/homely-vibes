"""Focus and grain of a photo, measured so that one threshold works across scenes and cameras.

Both are calibrated on ingested JPGs (<=4K); see the Logbook entry "Out-of-focus and grainy
photos" for the sample, the synthetic blur and grain, and why simpler measures failed.
"""

import numpy as np
import numpy.typing as npt
from PIL import Image
from scipy.ndimage import convolve, sobel, uniform_filter

Gray = npt.NDArray[np.float32]

LAPLACIAN = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
NOISE_MASK = np.array([[1, -2, 1], [-2, 4, -2], [1, -2, 1]], dtype=np.float32)  # Immerkaer 1996
FOCUS_WIDTH = 1920  # measured at TV-viewing scale
FOCUS_GRID = 6  # tiles per side; the sharpest tile speaks for the photo
MIN_EDGE = 8.0  # a tile whose strongest gradient is below this has nothing to judge
FLAT_SHARE = 10  # percent of the photo, the smoothest, where grain is measured
FLAT_WINDOW = 9


def gray(img: Image.Image, width: int | None = None) -> Gray:
    g = img.convert("L")
    if width and g.width > width:
        g = g.resize((width, round(g.height * width / g.width)), Image.Resampling.LANCZOS)
    return np.asarray(g, dtype=np.float32)


def focus(img: Image.Image) -> float | None:
    """Edge sharpness of the photo's sharpest tile: curvature per unit slope on its strongest
    edges, about 1 / edge width, so contrast and texture cancel out. A sharp subject on a
    blurred background still scores high. None when no tile has an edge (fog, plain sky)."""
    a = gray(img, FOCUS_WIDTH)
    slope = np.hypot(sobel(a, 0), sobel(a, 1)) / 8
    curve = np.abs(convolve(a, LAPLACIAN))
    h, w = a.shape
    best = None
    for i in range(FOCUS_GRID):
        for j in range(FOCUS_GRID):
            tile = (
                slice(i * h // FOCUS_GRID, (i + 1) * h // FOCUS_GRID),
                slice(j * w // FOCUS_GRID, (j + 1) * w // FOCUS_GRID),
            )
            edge = float(np.percentile(slope[tile], 99))
            if edge >= MIN_EDGE:
                ratio = float(np.percentile(curve[tile], 99)) / edge
                best = ratio if best is None else max(best, ratio)
    return best


def grain(img: Image.Image) -> float:
    """Noise level (0-255 scale) in the smoothest tenth of the photo, at full ingested size:
    texture (foliage, rock) is excluded, so only grain and halftone dots are left."""
    a = gray(img)
    mean = uniform_filter(a, FLAT_WINDOW)
    local = uniform_filter(a * a, FLAT_WINDOW) - mean * mean
    flat = local <= np.percentile(local, FLAT_SHARE)
    residual = np.abs(convolve(a, NOISE_MASK)) * float(np.sqrt(np.pi / 2) / 6)
    return float(np.median(residual[flat]))
