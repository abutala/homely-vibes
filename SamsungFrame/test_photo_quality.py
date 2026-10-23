"""Tests for photo_quality: blur and grain land on the far side of dedup's thresholds."""

import numpy as np
from PIL import Image, ImageFilter

from SamsungFrame.dedup_photos import DEFAULT_MAX_GRAIN, DEFAULT_MIN_FOCUS
from SamsungFrame.photo_quality import focus, grain
from SamsungFrame.test_ingest import pattern


def scene() -> Image.Image:
    return pattern(5, (800, 600)).resize((1600, 1200), Image.Resampling.NEAREST)


def noisy(img: Image.Image, sigma: float) -> Image.Image:
    a = np.asarray(img, dtype=np.float32)
    lum = np.random.default_rng(0).normal(0, sigma, a.shape[:2])[..., None]
    return Image.fromarray(np.clip(a + lum, 0, 255).astype(np.uint8))


class TestFocus:
    def test_a_sharp_scene_passes(self) -> None:
        assert (focus(scene()) or 0) > DEFAULT_MIN_FOCUS

    def test_a_defocused_scene_fails(self) -> None:
        assert (focus(scene().filter(ImageFilter.GaussianBlur(3))) or 0) < DEFAULT_MIN_FOCUS

    def test_a_sharp_corner_on_a_blurred_photo_passes(self) -> None:
        img = scene().filter(ImageFilter.GaussianBlur(3))
        sharp = (500, 350, 1100, 850)  # a subject in focus, the background not
        img.paste(scene().crop(sharp), sharp[:2])
        assert (focus(img) or 0) > DEFAULT_MIN_FOCUS

    def test_nothing_to_judge_in_a_plain_frame(self) -> None:
        assert focus(Image.new("RGB", (1600, 1200), (120, 160, 200))) is None


class TestGrain:
    def test_a_clean_scene_passes(self) -> None:
        assert grain(scene()) < DEFAULT_MAX_GRAIN

    def test_a_grainy_scene_fails(self) -> None:
        assert grain(noisy(scene(), 10)) > DEFAULT_MAX_GRAIN

    def test_texture_is_not_grain(self) -> None:
        stripes = np.zeros((1200, 1600, 3), dtype=np.uint8)
        stripes[:, ::4] = 255  # fine, regular detail over half the frame
        stripes[:, 800:] = 128
        assert grain(Image.fromarray(stripes)) < DEFAULT_MAX_GRAIN
