"""Zone-session pairing and event ingestion when Rachio publishes events late or loses them.

Scenarios replay the prod incidents of 2026-08-12, 2026-09-05 and 2026-09-08 (Logbook.md).
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from RachioFlume.alert_rules import ZoneThreshold
from RachioFlume.collector import FETCH_OVERLAP, WaterTrackingCollector
from RachioFlume.data_storage import WaterTrackingDB, estimate_run_end
from RachioFlume.flume_client import FlumeClient, WaterReading
from RachioFlume.rachio_client import RachioClient, WateringEvent, Zone
from RachioFlume.reporter import WeeklyReporter
from RachioFlume.simulate_alerts import DBReplayDataset

DAY = datetime(2026, 9, 8)


def at(clock: str, days: int = 0) -> datetime:
    hour, minute, second = (int(part) for part in clock.split(":"))
    return DAY.replace(hour=hour, minute=minute, second=second) + timedelta(days=days)


def event(clock: str, zone: int, kind: str, days: int = 0) -> WateringEvent:
    return WateringEvent(
        event_date=at(clock, days), zone_name=f"Z{zone}", zone_number=zone, event_type=kind
    )


def flow(db: WaterTrackingDB, clock: str, minutes: int, gpm: float) -> None:
    first = at(f"{clock}:00")
    db.save_water_readings(
        [WaterReading(timestamp=first + timedelta(minutes=i), value=gpm) for i in range(minutes)]
    )


def sessions(db: WaterTrackingDB, zone: int) -> list[dict[str, Any]]:
    everything = db.get_zone_sessions(DAY - timedelta(days=1), DAY + timedelta(days=30))
    return [s for s in everything if s["zone_number"] == zone]


def event_count(db: WaterTrackingDB) -> int:
    with db.get_connection() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM watering_events").fetchone()[0])


@pytest.fixture
def db(tmp_path: Path) -> WaterTrackingDB:
    return WaterTrackingDB(str(tmp_path / "water.db"))


class TestSessionPairing:
    def test_lost_end_is_estimated_from_flume_instead_of_pairing_days_later(
        self, db: WaterTrackingDB
    ) -> None:
        # 2026-09-08: Z9's COMPLETED was never ingested; Z12 started the same second.
        db.save_watering_events(
            [
                event("06:55:02", 9, "ZONE_STARTED"),
                event("07:03:02", 12, "ZONE_STARTED"),
                event("07:33:43", 12, "ZONE_COMPLETED"),
                event("06:55:02", 9, "ZONE_STARTED", days=3),
                event("07:03:02", 9, "ZONE_COMPLETED", days=3),
            ]
        )
        flow(db, "06:55", 8, 1.8)
        flow(db, "07:03", 30, 1.1)

        assert db.compute_zone_sessions() == 1

        lost, intact = sessions(db, 9)
        assert lost["duration_seconds"] == 480
        assert lost["total_water_used"] == pytest.approx(7 * 1.8 + 1.1)
        assert intact["duration_seconds"] == 480

    def test_end_sharing_a_second_with_next_start_still_pairs(self, db: WaterTrackingDB) -> None:
        # Rachio lists the next zone's START before this zone's COMPLETED when they tie.
        db.save_watering_events(
            [
                event("06:55:02", 9, "ZONE_STARTED"),
                event("07:03:02", 12, "ZONE_STARTED"),
                event("07:03:02", 9, "ZONE_COMPLETED"),
                event("07:33:43", 12, "ZONE_COMPLETED"),
            ]
        )

        assert db.compute_zone_sessions() == 0
        assert [s["duration_seconds"] for s in sessions(db, 9)] == [480]
        assert [s["duration_seconds"] for s in sessions(db, 12)] == [1841]

    def test_orphan_ends_where_flow_stops_not_at_next_start(self, db: WaterTrackingDB) -> None:
        # 2026-08-12: Z11's end is missing even from Rachio's API; its next event is a week later.
        db.save_watering_events(
            [
                event("06:55:02", 11, "ZONE_STARTED"),
                event("06:55:02", 11, "ZONE_STARTED", days=7),
                event("07:25:02", 11, "ZONE_COMPLETED", days=7),
            ]
        )
        flow(db, "06:55", 30, 6.0)
        flow(db, "09:00", 5, 2.0)  # household use later that morning

        assert db.compute_zone_sessions() == 1

        orphan = sessions(db, 11)[0]
        assert orphan["duration_seconds"] == 1798
        assert orphan["total_water_used"] == pytest.approx(29 * 6.0)

    def test_orphan_is_bounded_by_controller_reboot(self, db: WaterTrackingDB) -> None:
        # 2026-09-05: the controller cold-rebooted mid-run, then the zone was restarted.
        db.save_watering_events(
            [
                event("13:04:23", 10, "ZONE_STARTED"),
                event("13:10:08", -1, "COLD_REBOOT"),
                event("13:10:31", 10, "ZONE_STARTED"),
                event("13:12:27", 10, "ZONE_STOPPED"),
            ]
        )
        flow(db, "13:04", 9, 5.0)

        assert db.compute_zone_sessions() == 1
        assert [s["duration_seconds"] for s in sessions(db, 10)] == [345, 116]

    def test_orphan_without_flow_is_a_zero_length_session(self, db: WaterTrackingDB) -> None:
        # Kept rather than dropped: the stale-zone monitor reads MAX(start_time) from sessions.
        db.save_watering_events(
            [event("06:55:02", 9, "ZONE_STARTED"), event("07:03:02", 12, "ZONE_STARTED")]
        )

        assert db.compute_zone_sessions() == 1
        assert [(s["duration_seconds"], s["total_water_used"]) for s in sessions(db, 9)] == [
            (0, 0.0)
        ]

    def test_start_with_no_later_event_is_still_running(self, db: WaterTrackingDB) -> None:
        db.save_watering_events([event("06:55:02", 9, "ZONE_STARTED")])

        assert db.compute_zone_sessions() == 0
        assert sessions(db, 9) == []


class TestEstimateRunEnd:
    def test_single_dry_minute_does_not_end_the_run(self) -> None:
        readings = [(at("06:56:00"), 1.8), (at("06:57:00"), 0.0), (at("06:58:00"), 1.8)]
        assert estimate_run_end(at("06:55:02"), at("07:30:00"), readings) == at("06:59:00")

    def test_two_dry_minutes_end_the_run(self) -> None:
        readings = [(at("06:56:00"), 1.8), (at("06:59:00"), 1.8)]
        assert estimate_run_end(at("06:55:02"), at("07:30:00"), readings) == at("06:57:00")

    def test_end_is_clamped_to_bound(self) -> None:
        readings = [(at("06:56:00"), 1.8), (at("06:57:00"), 1.8)]
        assert estimate_run_end(at("06:55:02"), at("06:57:30"), readings) == at("06:57:30")

    def test_single_missing_minute_does_not_end_the_run(self) -> None:
        # A minute Flume never stored reads the same as a dry one: one is tolerated.
        readings = [(at("06:56:00"), 1.8), (at("06:58:00"), 1.8)]
        assert estimate_run_end(at("06:55:02"), at("07:30:00"), readings) == at("06:59:00")


class TestEventIngestion:
    def test_refetched_events_are_not_duplicated(self, db: WaterTrackingDB) -> None:
        first = [event("06:55:02", 9, "ZONE_STARTED")]

        assert db.save_watering_events(first) == 1
        assert db.save_watering_events(first + [event("07:03:02", 9, "ZONE_COMPLETED")]) == 1
        assert event_count(db) == 2

    def test_reopening_a_legacy_db_drops_duplicates_and_adds_unique_key(
        self, tmp_path: Path
    ) -> None:
        path = str(tmp_path / "legacy.db")
        WaterTrackingDB(path)
        conn = sqlite3.connect(path)
        conn.execute("DROP INDEX IF EXISTS idx_watering_events_unique")
        conn.executemany(
            "INSERT INTO watering_events (event_date, zone_name, zone_number, event_type) "
            "VALUES ('2026-09-08 06:55:02', 'Z9', 9, 'ZONE_STARTED')",
            [(), ()],
        )
        conn.commit()
        conn.close()

        db = WaterTrackingDB(path)

        assert event_count(db) == 1
        assert db.save_watering_events([event("06:55:02", 9, "ZONE_STARTED")]) == 0


class TestReplayActiveZone:
    def test_lost_end_does_not_leave_zone_irrigating(self, db: WaterTrackingDB) -> None:
        # A START with no later end used to read as irrigating for the rest of the DB,
        # suppressing every flow rule in `alerts replay` and hiding that zone's run ends.
        db.save_watering_events(
            [
                event("06:55:02", 11, "ZONE_STARTED"),
                event("06:55:02", 9, "ZONE_STARTED", days=1),
                event("07:03:02", 12, "ZONE_STARTED", days=1),
                event("07:03:02", 9, "ZONE_COMPLETED", days=1),
                event("07:33:43", 12, "ZONE_COMPLETED", days=1),
            ]
        )
        replay = DBReplayDataset(db, start=DAY, end=DAY + timedelta(days=2))

        def active(clock: str, days: int = 1) -> int | None:
            zone = replay.rachio_active_at(at(clock, days))
            return zone.zone_number if zone else None

        assert active("07:00:00", days=0) == 11
        assert active("12:00:00", days=0) is None
        assert active("06:58:00") == 9
        assert active("07:03:02") == 12
        assert active("08:00:00") is None

    def test_long_run_with_a_recorded_end_stays_active_past_the_cap(
        self, db: WaterTrackingDB
    ) -> None:
        # The cap is for STARTs whose end was lost, not for runs that are simply long.
        db.save_watering_events(
            [event("06:00:00", 4, "ZONE_STARTED"), event("10:00:00", 4, "ZONE_COMPLETED")]
        )
        replay = DBReplayDataset(db, start=DAY, end=DAY + timedelta(days=1))

        zone = replay.rachio_active_at(at("09:30:00"))

        assert zone is not None
        assert zone.zone_number == 4


class TestWeeklyReportAlerts:
    # Anomaly parameters are pinned to config/default.yaml in every report call below, so
    # a local.yaml override cannot move the thresholds these tests assert.

    def test_controller_sessions_over_threshold_are_counted(self, db: WaterTrackingDB) -> None:
        # The report read "avg_flow_rate" off per-session rows, a key only the aggregate
        # query produces, so the Alrt column was blank for every controller zone.
        db.save_watering_events(
            [
                event("06:00:00", 1, "ZONE_STARTED"),
                event("06:10:00", 1, "ZONE_COMPLETED"),
                event("06:00:00", 1, "ZONE_STARTED", days=1),
                event("06:10:00", 1, "ZONE_COMPLETED", days=1),
            ]
        )
        flow(db, "06:00", 10, 3.0)  # first run only; the second shows no flow
        db.compute_zone_sessions()

        report = WeeklyReporter(str(db.db_path)).generate_period_report_with_dates(
            DAY - timedelta(days=1),
            DAY + timedelta(days=7),
            zone_thresholds={"Controller": {"1": ZoneThreshold(zone_key="1", avg_gpm=1.0)}},
            absolute_gpm=0.5,
            percent_above=10.0,
            min_runtime_minutes=5,
        )

        (zone,) = report.zones
        assert zone.sessions == 2
        assert zone.alert_sessions == 1

    def test_hose_valve_threshold_matches_despite_a_different_prefix(
        self, db: WaterTrackingDB
    ) -> None:
        # The report looked hose baselines up by exact valve name, so a config key with a
        # different prefix left the row with no threshold and no alert count.
        db.save_hose_zone_session(
            {
                "valve_id": "v1",
                "base_station_id": "bs1",
                "valve_name": "Z13 BUD - Upper Deck Planters",
                "base_station_label": "Hoses",
                "start_time": at("09:00:00"),
                "end_time": at("09:10:00"),
                "duration_seconds": 600,
                "flow_detected": True,
                "total_water_used": 12.0,
                "average_flow_rate": 1.2,
            }
        )
        key = "Z13 FS - Upper Deck Planters"

        report = WeeklyReporter(str(db.db_path)).generate_period_report_with_dates(
            DAY - timedelta(days=1),
            DAY + timedelta(days=1),
            zone_thresholds={"Hoses": {key: ZoneThreshold(zone_key=key, avg_gpm=0.5)}},
            absolute_gpm=0.5,
            percent_above=10.0,
            min_runtime_minutes=5,
        )

        (zone,) = report.zones
        assert zone.threshold_gpm == 1.0
        assert zone.alert_sessions == 1

    def test_runs_shorter_than_min_runtime_are_not_counted_as_alerts(
        self, db: WaterTrackingDB
    ) -> None:
        # A seconds-long manual stop divides a whole Flume minute by a few seconds and reads
        # as 50+ GPM. The alert engine ignores runs under min_runtime_minutes; so must the report.
        db.save_watering_events(
            [
                event("06:00:00", 1, "ZONE_STARTED"),
                event("06:10:00", 1, "ZONE_COMPLETED"),
                event("07:00:00", 1, "ZONE_STARTED"),
                event("07:00:30", 1, "ZONE_STOPPED"),
            ]
        )
        flow(db, "06:00", 10, 3.0)
        flow(db, "07:00", 1, 3.0)
        db.compute_zone_sessions()

        report = WeeklyReporter(str(db.db_path)).generate_period_report_with_dates(
            DAY - timedelta(days=1),
            DAY + timedelta(days=1),
            zone_thresholds={"Controller": {"1": ZoneThreshold(zone_key="1", avg_gpm=1.0)}},
            absolute_gpm=0.5,
            percent_above=10.0,
            min_runtime_minutes=5,
        )

        (zone,) = report.zones
        assert zone.sessions == 2
        assert zone.alert_sessions == 1


class FakeRachio:
    """Serves one scripted batch of events per poll and records each requested window."""

    last_device_status = None

    def __init__(self, *batches: list[WateringEvent]) -> None:
        self.batches = list(batches)
        self.windows: list[tuple[datetime, datetime]] = []

    def get_zones(self) -> list[Zone]:
        return [Zone(id="z9", zone_number=9, name="Z9 FD", enabled=True)]

    def get_events(self, start: datetime, end: datetime) -> list[WateringEvent]:
        self.windows.append((start, end))
        return self.batches.pop(0)


class TestCollectorEventWindow:
    @pytest.mark.asyncio
    async def test_late_event_older_than_newest_stored_event_is_saved(self, tmp_path: Path) -> None:
        # 2026-09-08: Z12's START became visible a poll before Z9's earlier COMPLETED.
        rachio = FakeRachio(
            [event("07:03:02", 12, "ZONE_STARTED")],
            [event("07:03:01", 9, "ZONE_COMPLETED"), event("07:03:02", 12, "ZONE_STARTED")],
        )
        collector = WaterTrackingCollector(
            str(tmp_path / "water.db"),
            rachio_client=cast(RachioClient, rachio),
            flume_client=cast(FlumeClient, object()),
        )
        collector.last_rachio_collection = datetime.now() - timedelta(minutes=5)

        await collector.collect_rachio_data()
        await collector.collect_rachio_data()

        with collector.db.get_connection() as conn:
            stored = conn.execute(
                "SELECT zone_number, event_type FROM watering_events ORDER BY event_date"
            ).fetchall()
        assert [tuple(row) for row in stored] == [(9, "ZONE_COMPLETED"), (12, "ZONE_STARTED")]
        first_end, second_start = rachio.windows[0][1], rachio.windows[1][0]
        assert first_end - second_start >= FETCH_OVERLAP - timedelta(seconds=5)
