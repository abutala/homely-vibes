"""The period report lists every zone, and says why a zone did not run.

Replays the prod week of 2026-10-18: Z6/Z10/Z11 ("Back Trees") were skipped by
Weather Intelligence on 10/21 and vanished from the email with no explanation.
"""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from RachioFlume.data_storage import WaterTrackingDB
from RachioFlume.rachio_client import WateringEvent, Zone, schedule_zones_from_device
from RachioFlume.reporter import WeeklyReporter, WaterUsageReport, _skipped_run, skip_reason

START = datetime(2026, 10, 18)
END = START + timedelta(days=7)
SCHEDULES = {
    "Lawn": [1, 2],
    "Back Trees": [6, 10, 11],
    "Front Beds Summer": [3, 4, 7, 12, 15],
}


@pytest.fixture
def db(tmp_path: Path) -> WaterTrackingDB:
    db = WaterTrackingDB(str(tmp_path / "water.db"))
    db.save_zones(
        [
            Zone(id="z1", zone_number=1, name="Z1 FS - Lawn A", enabled=True),
            Zone(id="z3", zone_number=3, name="Z3 FB - Bed", enabled=True),
            Zone(id="z6", zone_number=6, name="Z6 BB - Trees", enabled=True),
            Zone(id="z9", zone_number=9, name="Z9 FD - Side", enabled=True),
            Zone(id="z13", zone_number=13, name="Zone 13", enabled=False),
            Zone(id="z14", zone_number=14, name="Z14 FB - Pots", enabled=False),  # ran, then off
        ]
    )
    db.save_watering_events(
        [
            WateringEvent(
                event_date=START + timedelta(days=3, hours=6),
                zone_name="Back Trees was scheduled for 10/21 at 06:05 AM",
                zone_number=-1,
                event_type="WEATHER_INTELLIGENCE_SKIP",
            ),
            WateringEvent(
                event_date=START + timedelta(days=5, hours=6),
                zone_name="Front Beds Sum... was scheduled for 10/23 at 06:05 AM",
                zone_number=-1,
                event_type="WEATHER_INTELLIGENCE_CLIMATE_SKIP",
            ),
            WateringEvent(
                event_date=START + timedelta(days=1),
                zone_name="The season is changing",
                zone_number=-1,
                event_type="SCHEDULE_RULE_SKIP_ADDED",
            ),
        ]
    )
    with db.get_connection() as conn:
        conn.executemany(
            "INSERT INTO zone_sessions (zone_name, zone_number, start_time, duration_seconds,"
            " total_water_used) VALUES (?, ?, ?, 600, 75.0)",
            [("Z1 FS", 1, START + timedelta(hours=6)), ("Z14 FB", 14, START + timedelta(hours=7))],
        )
        conn.commit()
    db.save_hose_valves(
        [
            {
                "id": "v1",
                "base_station_id": "bs1",
                "base_station_label": "Hoses",
                "name": "Z13 BUD - Upper Deck Planters",
                "connected": False,
            },
            {"id": "v2", "base_station_id": "bs1", "base_station_label": "Hoses", "name": "Pots"},
        ]
    )
    db.save_hose_zone_session(
        {
            "valve_id": "v2",
            "base_station_id": "bs1",
            "valve_name": "Pots",
            "base_station_label": "Hoses",
            "start_time": START + timedelta(hours=8),
            "end_time": START + timedelta(hours=8, minutes=10),
            "duration_seconds": 600,
            "flow_detected": False,
            "total_water_used": 5.0,
            "average_flow_rate": 0.5,
        }
    )
    return db


def _report(db: WaterTrackingDB, schedules: dict[str, list[int]] | None) -> WaterUsageReport:
    return WeeklyReporter(str(db.db_path)).generate_period_report_with_dates(
        START,
        END,
        zone_thresholds={},
        absolute_gpm=0.5,
        percent_above=10.0,
        min_runtime_minutes=5,
        schedule_zones=schedules,
    )


def _notes(report: WaterUsageReport) -> dict[str, str]:
    return {z.zone_name: z.note for z in report.zones}


def test_every_enabled_zone_and_valve_gets_a_row_with_a_reason(db: WaterTrackingDB) -> None:
    report = _report(db, SCHEDULES)
    assert _notes(report) == {
        "Z1 FS": "",
        "Z3 FB": "skipped: climate 10/23",
        "Z6 BB": "skipped: weather 10/21",
        "Z9 FD": "in no active schedule",
        "Z14 FB": "",  # disabled now, but it ran: a data row
        "Pots": "",  # ran, so no idle row beside its data row
        "Z13 BUD": "offline, no run recorded",
    }
    assert [z.zone_name for z in report.zones if z.problem] == ["Z13 BUD"]
    assert "Zone 13" not in _notes(report)  # disabled and idle: no row
    assert report.summary.zones_watered == 3


def test_a_scheduled_zone_with_no_run_or_skip_is_a_problem(db: WaterTrackingDB) -> None:
    report = _report(db, {**SCHEDULES, "Side": [9]})
    (z9,) = [z for z in report.zones if z.zone_name == "Z9 FD"]
    assert (z9.note, z9.problem) == ("scheduled, but no run or skip recorded", True)


def test_without_schedules_the_reason_falls_back_but_skips_still_show(
    db: WaterTrackingDB,
) -> None:
    report = _report(db, None)
    notes = _notes(report)
    assert notes["Z6 BB"] == "no run recorded"
    assert notes["Z9 FD"] == "no run recorded"
    # Rachio unreachable must not turn the whole roster into problems.
    assert [z.zone_name for z in report.zones if z.problem] == ["Z13 BUD"]


@pytest.mark.parametrize(
    ("event_type", "label"),
    [
        ("WEATHER_INTELLIGENCE_SKIP", "weather"),
        ("WEATHER_INTELLIGENCE_CLIMATE_SKIP", "climate"),
        ("WEATHER_INTELLIGENCE_WIND_SKIP", "wind"),
        ("SCHEDULE_RULE_SKIP_ADDED", None),
        ("ZONE_COMPLETED", None),
    ],
)
def test_skip_reason_labels(event_type: str, label: str | None) -> None:
    assert skip_reason(event_type) == label


def test_schedule_zones_from_device_keeps_enabled_rules_only() -> None:
    device = {
        "zones": [{"id": "a", "zoneNumber": 6}, {"id": "b", "zoneNumber": 10}],
        "scheduleRules": [
            {
                "name": "Back Trees",
                "enabled": True,
                "zones": [{"zoneId": "b"}, {"zoneId": "a"}],
            },
            {"name": "Lawn extra", "enabled": False, "zones": [{"zoneId": "a"}]},
        ],
        "flexScheduleRules": [{"name": "Flex", "enabled": True, "zones": [{"zoneId": "gone"}]}],
    }
    assert schedule_zones_from_device(device) == {"Back Trees": [6, 10], "Flex": []}


@pytest.mark.parametrize(
    ("summary", "schedules"),
    [
        # A full name never prefix-matches: a disabled "Lawn" is not "Lawn extra".
        ("Lawn was scheduled for 10/21 at 06:05 AM", {"Lawn extra": [1]}),
        # A truncated name that fits two schedules is ambiguous.
        ("Front Be... was scheduled for 10/21 at 06:05 AM", {"Front Beds": [3], "Front Berm": [4]}),
    ],
)
def test_skip_with_no_unique_schedule_names_no_zones(
    summary: str, schedules: dict[str, list[int]]
) -> None:
    row = {
        "event_type": "WEATHER_INTELLIGENCE_SKIP",
        "summary": summary,
        "event_date": START + timedelta(days=3),
    }
    run = _skipped_run(row, schedules)
    assert run is not None
    assert run.zone_numbers == []
