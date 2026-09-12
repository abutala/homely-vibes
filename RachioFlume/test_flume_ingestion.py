"""Flume readings are upserted so re-fetched minutes replace values that read short at poll time.

Replays 2026-09-08: each poll stored the in-progress minute as 0.0 and the minute before it
short; Flume's API later reported the full values (Logbook.md).
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from RachioFlume.collector import FETCH_OVERLAP, WaterTrackingCollector
from RachioFlume.data_storage import WaterTrackingDB
from RachioFlume.flume_client import FlumeClient, WaterReading
from RachioFlume.rachio_client import RachioClient

FIRST_MINUTE = datetime(2026, 9, 8, 6, 52)


def reading(offset_minutes: int, gpm: float) -> WaterReading:
    return WaterReading(timestamp=FIRST_MINUTE + timedelta(minutes=offset_minutes), value=gpm)


def stored(db: WaterTrackingDB) -> list[tuple[str, float]]:
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT timestamp, value FROM water_readings ORDER BY timestamp"
        ).fetchall()
    return [(row[0][11:16], row[1]) for row in rows]


@pytest.fixture
def db(tmp_path: Path) -> WaterTrackingDB:
    return WaterTrackingDB(str(tmp_path / "water.db"))


class TestReadingUpsert:
    def test_refetched_minute_replaces_short_value(self, db: WaterTrackingDB) -> None:
        db.save_water_readings([reading(0, 1.26), reading(1, 0.0)])
        db.save_water_readings([reading(0, 2.52), reading(1, 2.32), reading(2, 2.25)])

        assert stored(db) == [("06:52", 2.52), ("06:53", 2.32), ("06:54", 2.25)]

    def test_reopening_a_legacy_db_collapses_duplicates_and_adds_unique_key(
        self, tmp_path: Path
    ) -> None:
        path = str(tmp_path / "legacy.db")
        WaterTrackingDB(path)
        conn = sqlite3.connect(path)
        conn.execute("DROP INDEX IF EXISTS idx_water_readings_unique")
        conn.executemany(
            "INSERT INTO water_readings (timestamp, value) VALUES ('2026-09-08 06:53:00', ?)",
            [(0.0,), (2.32,)],
        )
        conn.commit()
        conn.close()

        db = WaterTrackingDB(path)
        db.save_water_readings([reading(1, 2.4)])

        assert stored(db) == [("06:53", 2.4)]


class FakeFlume:
    """Serves one scripted batch of readings per poll and records each requested window."""

    def __init__(self, *batches: list[WaterReading]) -> None:
        self.batches = list(batches)
        self.windows: list[tuple[datetime, datetime]] = []

    def get_usage(
        self, start_time: datetime, end_time: datetime, bucket: str = "MIN"
    ) -> list[WaterReading]:
        self.windows.append((start_time, end_time))
        return self.batches.pop(0)


class TestCollectorReadingWindow:
    @pytest.mark.asyncio
    async def test_poll_refetches_recent_minutes_and_corrects_them(self, tmp_path: Path) -> None:
        flume = FakeFlume(
            [reading(0, 1.26), reading(1, 0.0)],
            [reading(0, 2.52), reading(1, 2.32), reading(2, 2.25)],
        )
        collector = WaterTrackingCollector(
            str(tmp_path / "water.db"),
            rachio_client=cast(RachioClient, object()),
            flume_client=cast(FlumeClient, flume),
        )
        collector.last_flume_collection = datetime.now() - timedelta(minutes=5)

        await collector.collect_flume_data()
        await collector.collect_flume_data()

        assert stored(collector.db) == [("06:52", 2.52), ("06:53", 2.32), ("06:54", 2.25)]
        first_end, second_start = flume.windows[0][1], flume.windows[1][0]
        assert first_end - second_start >= FETCH_OVERLAP - timedelta(seconds=5)
