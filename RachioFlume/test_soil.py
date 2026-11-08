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
        period = [
            _reading(1, 70, 48),
            _reading(1, 85, 24),
            _reading(1, 80, 1, name="Bed 4in"),
            _reading(2, 60, 2),
        ]
        last = [_reading(2, 60, 2), _reading(1, 80, 1, name="Bed 4in")]
        assert soil_stats(period, last) == [
            SoilStats(1, "Bed 4in", 80.0, 70.0, 85.0, NOW - timedelta(hours=1)),
            SoilStats(2, "Soil CH2", 60.0, 60.0, 60.0, NOW - timedelta(hours=2)),
        ]

    def test_channel_silent_all_period_keeps_its_row(self) -> None:
        last = [_reading(1, 75, 24 * 10)]
        assert soil_stats([], last) == [
            SoilStats(1, "Soil CH1", 75.0, None, None, NOW - timedelta(days=10))
        ]

    def test_none_is_empty(self) -> None:
        assert soil_stats([], []) == []


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

    def test_last_reading_per_channel_has_no_lower_bound(self, db: WaterTrackingDB) -> None:
        db.save_soil_readings(
            [_reading(1, 70, 24 * 30), _reading(1, 72, 24 * 20), _reading(2, 50, 1)]
        )
        assert db.get_last_soil_readings(NOW) == [_reading(1, 72, 24 * 20), _reading(2, 50, 1)]

    def _report(self, db: WaterTrackingDB, host: str = "gateway.example.com") -> WaterUsageReport:
        return WeeklyReporter(str(db.db_path)).generate_period_report_with_dates(
            NOW - timedelta(days=7),
            NOW,
            zone_thresholds={},
            schedule_zones={},
            soil_gateway_host=host,
        )

    def test_weekly_report_carries_soil(self, db: WaterTrackingDB) -> None:
        db.save_soil_readings([_reading(1, 70, 30), _reading(1, 80, 1)])
        report = self._report(db)
        assert [(s.channel, s.latest_pct, s.min_pct) for s in report.soil] == [(1, 80.0, 70.0)]
        assert report.soil_expected

    def test_probe_silent_all_week_is_a_problem(self, db: WaterTrackingDB) -> None:
        db.save_soil_readings([_reading(1, 70, 24 * 10), _reading(2, 60, 1)])
        found = rf.problems(self._report(db))
        assert [(p.zone, p.detail) for p in found] == [("Soil CH1", "no soil reading since 10/28")]

    def test_gateway_set_but_never_read_is_a_problem(self, db: WaterTrackingDB) -> None:
        found = rf.problems(self._report(db))
        assert [(p.zone, p.detail) for p in found] == [
            ("Soil", "no readings from the soil gateway")
        ]

    def test_no_gateway_no_soil_problem(self, db: WaterTrackingDB) -> None:
        assert rf.problems(self._report(db, host="")) == []

    def test_gateway_unset_drops_old_probes(self, db: WaterTrackingDB) -> None:
        db.save_soil_readings([_reading(1, 70, 24 * 10)])
        report = self._report(db, host="")
        assert report.soil == []
        assert rf.problems(report) == []


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

    @staticmethod
    def _stored(collector: WaterTrackingCollector) -> list[SoilReading]:
        return collector.db.get_soil_readings(datetime(2000, 1, 1), datetime(2100, 1, 1))

    @pytest.mark.asyncio
    async def test_saves_each_poll(self, tmp_path: Path) -> None:
        collector = self._collector(tmp_path, FakeEcowitt())
        await collector.collect_soil_data()
        assert [r.channel for r in self._stored(collector)] == [1, 2]

    @pytest.mark.asyncio
    async def test_gateway_down_saves_nothing_and_does_not_raise(self, tmp_path: Path) -> None:
        collector = self._collector(tmp_path, FakeEcowitt(fail=True))
        await collector.collect_soil_data()
        assert self._stored(collector) == []


def _report_with(soil: list[SoilStats], expected: bool = True) -> WaterUsageReport:
    return WaterUsageReport(
        report_generated=NOW,
        period_start=NOW - timedelta(days=7),
        period_end=NOW,
        summary=ReportSummary(0, 0.0, 0.0, 0),
        zones=[],
        soil=soil,
        soil_expected=expected,
    )


class TestFormat:
    FRESH = SoilStats(1, "Bed 4in", 80.0, 70.0, 85.0, NOW - timedelta(hours=1))
    STALE = SoilStats(2, "Bed 12in", 60.0, 55.0, 62.0, NOW - timedelta(days=2))

    def test_text_shows_now_and_range(self) -> None:
        text = rf.format_text(_report_with([self.FRESH]))
        assert "Soil moisture" in text
        assert "Bed 4in: 80% now, range 70–85%" in text

    def test_html_shows_soil_lines(self) -> None:
        html = rf.format_html(_report_with([self.FRESH]))
        assert "Bed 4in: 80% now, range 70–85%" in html

    def test_silent_all_period_line(self) -> None:
        old = SoilStats(3, "Bed 8in", 75.0, None, None, NOW - timedelta(days=10))
        text = rf.format_text(_report_with([old]))
        assert "Bed 8in: no reading this period (last 75% on 10/28)" in text

    def test_silent_sensor_is_a_problem(self) -> None:
        found = rf.problems(_report_with([self.FRESH, self.STALE]))
        assert [(p.zone, p.detail) for p in found] == [("Bed 12in", "no soil reading since 11/05")]

    def test_no_gateway_no_section(self) -> None:
        report = _report_with([], expected=False)
        assert "Soil" not in rf.format_text(report)
        assert "Soil" not in rf.format_html(report)
        assert rf.problems(report) == []
