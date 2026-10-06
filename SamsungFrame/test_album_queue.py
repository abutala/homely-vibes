"""Tests for the album queue: labelled detection, picking, parts and the published table."""

import random
from datetime import date
from pathlib import Path

import pytest

from lib.config import FrameAlbumsConfig
from SamsungFrame import album_queue as queue
from SamsungFrame.album_queue import Album

TODAY = date(2026, 10, 4)


def config(**overrides: object) -> FrameAlbumsConfig:
    values: dict[str, object] = dict(
        root="",
        data_dir="",
        picks_csv="frame_picks.csv",
        min_pictures=150,
        min_on_tv=100,
        max_on_tv=900,
        labelled_album_min=20,
        keep_ratio=0.5,
        top_k=3,
        home_region="home",
        away_weight=3.0,
        recency_half_life_years=8.0,
        table_weeks=4,
    )
    return FrameAlbumsConfig(**(values | overrides))  # type: ignore[arg-type]


def album(name: str, kind: str = "park", pictures: int = 200, **fields: object) -> Album:
    values: dict[str, object] = dict(labelled=0, region="away", status="queued")
    return Album(path=f"2020/05-May/{name}", pictures=pictures, kind=kind, **(values | fields))  # type: ignore[arg-type]


class TestLabelledFile:
    @pytest.mark.parametrize(
        "name",
        [
            "IMG_5213-It's a small world.jpg",
            "P1000090-Lots of fish.JPG",
            "Lake 20070807 148.jpg",
            "IMG_1453-Mom n me.jpg",
        ],
    )
    def test_a_typed_caption_is_a_label(self, name: str) -> None:
        assert queue.is_labelled_file(name)

    @pytest.mark.parametrize(
        "name",
        [
            "IMG_5097.HEIC",
            "DSC03025.JPG",
            "STA_7794.JPG",
            "PXL_20230405_123456789.jpg",
            "IMG-20230405-WA0001.jpg",
            "34b50195-7b29-4f9b-b00b-7a6d277de30e.jpg",
            "fc8ba19d.jpg.orig.jpg",
        ],
    )
    def test_camera_and_export_names_are_not(self, name: str) -> None:
        assert not queue.is_labelled_file(name)


class TestScan:
    def library(self, tmp_path: Path) -> Path:
        trip = tmp_path / "2020" / "05-May" / "01-Trip"
        (trip / "day 2").mkdir(parents=True)
        for name in ("IMG_1.jpg", "IMG_2-Sunset.jpg", "clip.mov", ".hidden.jpg"):
            (trip / name).write_bytes(b"x")
        (trip / "day 2" / "IMG_3.HEIC").write_bytes(b"x")
        (tmp_path / "Wallpapers" / "x" / "y").mkdir(parents=True)
        return tmp_path

    def test_counts_pictures_and_labels_and_ignores_non_year_roots(self, tmp_path: Path) -> None:
        albums: list[Album] = []
        assert queue.scan(albums, self.library(tmp_path), TODAY) == 1
        (found,) = albums
        assert (found.path, found.pictures, found.labelled) == ("2020/05-May/01-Trip", 3, 1)
        assert (found.status, found.added) == ("new", "2026-10-04")

    def test_known_albums_are_recounted_only_on_a_full_scan(self, tmp_path: Path) -> None:
        root = self.library(tmp_path)
        albums: list[Album] = []
        queue.scan(albums, root, TODAY)
        (root / "2020" / "05-May" / "01-Trip" / "IMG_9.jpg").write_bytes(b"x")
        assert queue.scan(albums, root, TODAY) == 0 and albums[0].pictures == 3
        queue.scan(albums, root, TODAY, full=True)
        assert albums[0].pictures == 4

    def test_index_round_trip(self, tmp_path: Path) -> None:
        albums = [album("A", on_tv=120, parts=1), album("B", kind="city", shown="2026-09")]
        queue.save_index(tmp_path / "data" / "index.tsv", albums)
        assert queue.load_index(tmp_path / "data" / "index.tsv") == albums

    def test_needs_kind_lists_only_big_unclassified_albums(self) -> None:
        albums = [album("big", kind="?"), album("tiny", kind="?", pictures=10), album("done")]
        assert [a.name for a in queue.needs_kind(albums, config())] == ["big"]


class TestPick:
    def test_kinds_alternate(self) -> None:
        albums = [
            album("P1", shown="2026-09", status="shown"),
            album("P2"),
            album("C1", kind="city"),
        ]
        assert queue.pick(albums, config(), "2026-10").name == "C1"  # type: ignore[union-attr]

    def test_queue_order_wins_when_only_one_kind_is_left(self) -> None:
        albums = [album("P1", shown="2026-09", status="shown"), album("P2"), album("P3")]
        assert queue.pick(albums, config(), "2026-10").name == "P2"  # type: ignore[union-attr]

    def test_an_album_mid_split_plays_before_anything_else(self) -> None:
        albums = [album("C1", kind="city"), album("Big", status="playing", shown="2026-09", part=1)]
        assert queue.pick(albums, config(), "2026-10").name == "Big"  # type: ignore[union-attr]

    def test_the_week_already_marked_is_stable(self) -> None:
        albums = [album("C1", kind="city"), album("P1", shown="2026-10", status="shown")]
        assert queue.pick(albums, config(), "2026-10").name == "P1"  # type: ignore[union-attr]

    def test_small_skipped_other_and_undersized_folders_never_play(self) -> None:
        albums = [
            album("a", status="small"),
            album("b", status="skip"),
            album("c", kind="other"),
            album("d", pictures=150),
        ]
        assert queue.pick(albums, config(), "2026-10") is None


class TestPlaceAndShuffle:
    def test_a_new_eligible_album_lands_within_the_top_k(self) -> None:
        for seed in range(20):
            albums = [album(f"old{i}") for i in range(10)] + [album("fresh", status="new")]
            (placed,) = queue.place(albums, config(), random.Random(seed))
            assert placed.status == "queued"
            assert [a.name for a in albums].index("fresh") <= 3

    def test_a_new_ineligible_album_is_queued_where_it_is(self) -> None:
        albums = [album("old"), album("party", kind="other", status="new")]
        assert queue.place(albums, config(), random.Random(0)) == []
        assert [(a.name, a.status) for a in albums] == [("old", "queued"), ("party", "queued")]

    def test_shuffle_keeps_eligible_rows_first_and_loses_none(self) -> None:
        albums = [album("x", kind="other")] + [album(f"p{i}") for i in range(5)]
        dealt = queue.shuffle(albums, config(), random.Random(1), 2026)
        assert dealt[-1].name == "x"
        assert sorted(a.name for a in dealt) == sorted(a.name for a in albums)

    def test_away_and_recent_albums_weigh_more(self) -> None:
        cfg = config()
        old_home = Album(path="2010/05-May/a", pictures=200, region="home")
        new_away = Album(path="2026/05-May/b", pictures=200, region="away")
        assert queue.weight(new_away, cfg, 2026) == 3.0
        assert queue.weight(old_home, cfg, 2026) == pytest.approx(0.25)


class TestParts:
    def test_split_is_consecutive_and_even(self) -> None:
        assert queue.split(list("abcdefg"), 3) == [["a", "b", "c"], ["d", "e"], ["f", "g"]]

    def test_too_few_pictures_marks_the_album_small(self) -> None:
        small = album("s")
        assert queue.record_measure(small, 99, config()) is False
        assert (small.status, small.on_tv) == ("small", 99)

    def test_parts_follow_the_tv_limit(self) -> None:
        one, three = album("one"), album("three")
        assert queue.record_measure(one, 900, config()) and one.parts == 1
        assert queue.record_measure(three, 1801, config()) and three.parts == 3

    def test_a_split_album_plays_through_and_a_rerun_repeats_the_part(self) -> None:
        big = album("big", parts=2)
        assert queue.part_for(big, "2026-10") == 1
        queue.mark_shown(big, "2026-10")
        assert (big.status, big.part) == ("playing", 1)
        assert queue.part_for(big, "2026-10") == 1  # same week: same part
        queue.mark_shown(big, "2026-11")
        assert (big.status, big.part) == ("shown", 2)


class TestTable:
    def test_run_dates_are_the_coming_mondays(self) -> None:
        assert queue.run_dates(TODAY, 3) == [
            date(2026, 10, 5),
            date(2026, 10, 12),
            date(2026, 10, 19),
        ]
        assert queue.run_dates(date(2026, 10, 6), 1) == [date(2026, 10, 12)]

    def test_week_key_follows_the_iso_year_at_the_boundary(self) -> None:
        assert queue.week_key(date(2026, 10, 5)) == "2026-W41"
        assert queue.week_key(date(2027, 1, 1)) == "2026-W53"

    def test_forecast_uses_the_measurement_else_a_guess(self) -> None:
        cfg = config()
        assert queue.forecast(album("m", on_tv=950, parts=2), cfg) == (950, 2, True)
        assert queue.forecast(album("guess", pictures=400), cfg) == (200, 1, False)
        assert queue.forecast(album("lab", pictures=3000, labelled=1000), cfg) == (1000, 2, False)

    def test_upcoming_plays_the_queue_forward_without_touching_it(self) -> None:
        albums = [
            album("Big", pictures=3000, labelled=1000),
            album("Town", kind="city"),
            album("Few", kind="city", pictures=500, labelled=30),
            album("Hill"),
        ]
        rows = queue.upcoming(albums, config(), TODAY)
        assert [r[1] for r in rows] == ["Big (part 1 of 2)", "Big (part 2 of 2)", "Town", "Hill"]
        assert rows[0][6] == "~500" and rows[0][7] == "1000"
        assert all(a.status == "queued" for a in albums)

    def test_table_has_the_header_and_the_pool(self) -> None:
        text = queue.table_markdown([album("Hill")], config(), TODAY)
        assert "| Run date | Album | Shot |" in text
        assert "| 2026-10-05 | Hill | May 2020 | park | away | 200 | ~100 |  |" in text
        assert "- Queue: 1 albums (0 city, 1 park; 1 away)" in text
