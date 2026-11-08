"""Soil moisture from an Ecowitt gateway: parsed, stored each poll, summarized weekly.

The payload is the shape a GW1100 returned on 2026-11-07 for two soil probes
whose channels had no names yet.
"""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import requests

from RachioFlume import report_format as rf
from RachioFlume.collector import WaterTrackingCollector
from RachioFlume.data_storage import WaterTrackingDB
from RachioFlume.ecowitt_client import EcowittClient, SoilReading, parse_soil
from RachioFlume.flume_client import FlumeClient
from RachioFlume.rachio_client import RachioClient
from RachioFlume.reporter import (
    ReportSummary,
    SoilStats,
    WaterUsageReport,
    WeeklyReporter,
    soil_stats,
)

NOW = datetime(2026, 11, 7, 18)
PAYLOAD: dict[str, Any] = {
    "common_list": [],
    "wh25": [{"intemp": "75.9", "unit": "F", "inhumi": "45%"}],
    "ch_soil": [
        {"channel": "1", "name": "", "battery": "2", "humidity": "80%"},
        {"channel": "2", "name": "Bed 12in", "battery": "2", "humidity": "73%"},
    ],
}


class FakeResponse:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise requests.HTTPError(f"{self.status}")

    def json(self) -> dict[str, Any]:
        return self.payload


class TestParse:
    def test_reads_each_channel(self) -> None:
        assert parse_soil(PAYLOAD, NOW) == [
            SoilReading(channel=1, name="", moisture_pct=80.0, read_at=NOW),
            SoilReading(channel=2, name="Bed 12in", moisture_pct=73.0, read_at=NOW),
        ]

    def test_no_soil_sensors_is_empty(self) -> None:
        assert parse_soil({"common_list": []}, NOW) == []

    def test_skips_a_channel_with_no_value(self) -> None:
        payload = {"ch_soil": [{"channel": "1", "humidity": "--"}, PAYLOAD["ch_soil"][1]]}
        assert [r.channel for r in parse_soil(payload, NOW)] == [2]


class TestClient:
    def test_calls_the_local_endpoint(self) -> None:
        seen: list[str] = []

        def get(url: str, timeout: float) -> FakeResponse:
            seen.append(url)
            return FakeResponse(PAYLOAD)

        readings = EcowittClient("gateway.example.com", get=get).soil_readings(NOW)
        assert seen == ["http://gateway.example.com/get_livedata_info"]
        assert len(readings) == 2

    def test_http_error_raises(self) -> None:
        client = EcowittClient(
            "gateway.example.com", get=lambda url, timeout: FakeResponse({}, 500)
        )
        with pytest.raises(requests.HTTPError):
            client.soil_readings(NOW)


def _reading(channel: int, pct: float, hours_ago: float, name: str = "") -> SoilReading:
    return SoilReading(channel, name, pct, NOW - timedelta(hours=hours_ago))


class TestStats:
    def test_latest_low_high_per_channel(self) -> None:
        rows = [
            _reading(1, 70, 48),
            _reading(1, 85, 24),
            _reading(1, 80, 1, name="Bed 4in"),
            _reading(2, 60, 2),
        ]
        assert soil_stats(rows) == [
            SoilStats(1, "Bed 4in", 80.0, 70.0, 85.0, NOW - timedelta(hours=1)),
            SoilStats(2, "Soil CH2", 60.0, 60.0, 60.0, NOW - timedelta(hours=2)),
        ]

    def test_none_is_empty(self) -> None:
        assert soil_stats([]) == []


@pytest.fixture
def db(tmp_path: Path) -> WaterTrackingDB:
    return WaterTrackingDB(str(tmp_path / "water.db"))


class TestStorage:
    def test_round_trip_within_period(self, db: WaterTrackingDB) -> None:
        db.save_soil_readings([_reading(1, 70, 24 * 8), _reading(1, 80, 1)])
        rows = db.get_soil_readings(NOW - timedelta(days=7), NOW)
        assert rows == [_reading(1, 80, 1)]

    def test_same_moment_twice_is_one_row(self, db: WaterTrackingDB) -> None:
        db.save_soil_readings([_reading(1, 80, 1)])
        db.save_soil_readings([_reading(1, 81, 1)])
        assert [r.moisture_pct for r in db.get_soil_readings(NOW - timedelta(days=1), NOW)] == [
            81.0
        ]

    def test_weekly_report_carries_soil(self, db: WaterTrackingDB) -> None:
        db.save_soil_readings([_reading(1, 70, 30), _reading(1, 80, 1)])
        report = WeeklyReporter(str(db.db_path)).generate_period_report_with_dates(
            NOW - timedelta(days=7), NOW, zone_thresholds={}, schedule_zones={}
        )
        assert [(s.channel, s.latest_pct, s.min_pct) for s in report.soil] == [(1, 80.0, 70.0)]


class FakeEcowitt:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def soil_readings(self, now: datetime) -> list[SoilReading]:
        if self.fail:
            raise requests.ConnectionError("gateway down")
        return parse_soil(PAYLOAD, now)


class TestCollector:
    def _collector(self, tmp_path: Path, soil: FakeEcowitt) -> WaterTrackingCollector:
        return WaterTrackingCollector(
            str(tmp_path / "water.db"),
            rachio_client=cast(RachioClient, object()),
            flume_client=cast(FlumeClient, object()),
            soil_client=cast(EcowittClient, soil),
        )

    @pytest.mark.asyncio
    async def test_saves_each_poll(self, tmp_path: Path) -> None:
        collector = self._collector(tmp_path, FakeEcowitt())
        await collector.collect_soil_data()
        start = datetime.now() - timedelta(minutes=1)
        assert (
            len(collector.db.get_soil_readings(start, datetime.now() + timedelta(minutes=1))) == 2
        )

    @pytest.mark.asyncio
    async def test_gateway_down_does_not_raise(self, tmp_path: Path) -> None:
        collector = self._collector(tmp_path, FakeEcowitt(fail=True))
        await collector.collect_soil_data()


def _report_with(soil: list[SoilStats]) -> WaterUsageReport:
    return WaterUsageReport(
        report_generated=NOW,
        period_start=NOW - timedelta(days=7),
        period_end=NOW,
        summary=ReportSummary(0, 0.0, 0.0, 0),
        zones=[],
        soil=soil,
    )


class TestFormat:
    FRESH = SoilStats(1, "Bed 4in", 80.0, 70.0, 85.0, NOW - timedelta(hours=1))
    STALE = SoilStats(2, "Bed 12in", 60.0, 55.0, 62.0, NOW - timedelta(days=2))

    def test_text_shows_now_and_range(self) -> None:
        text = rf.format_text(_report_with([self.FRESH]))
        assert "Soil moisture" in text
        assert "Bed 4in: 80% now, 70–85% this week" in text

    def test_html_shows_soil_table(self) -> None:
        html = rf.format_html(_report_with([self.FRESH]))
        assert "Bed 4in" in html and "80%" in html

    def test_silent_sensor_is_a_problem(self) -> None:
        found = rf.problems(_report_with([self.FRESH, self.STALE]))
        assert [(p.zone, p.detail) for p in found] == [("Bed 12in", "no soil reading since 11/05")]

    def test_no_sensors_no_section(self) -> None:
        assert "Soil" not in rf.format_text(_report_with([]))
        assert "Soil" not in rf.format_html(_report_with([]))
