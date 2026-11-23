#!/usr/bin/env python3
"""Unit tests for Tesla/power_log.py."""

import csv
from pathlib import Path

from Tesla.power_log import (
    POWER_FIELDS,
    append_rows,
    daily_rows,
    sample_row,
)


def test_sample_row_keeps_power_fields_and_stamps_time() -> None:
    live = {
        "load_power": 612.5,
        "solar_power": 0,
        "grid_power": 12,
        "battery_power": 600.5,
        "percentage_charged": 71.2,
        "site_name": "ignored",
    }
    row = sample_row(live, now=1_700_000_000.0)
    assert row["epoch"] == 1700000000
    assert row["load_power"] == 612.5
    assert "site_name" not in row
    assert set(POWER_FIELDS) <= set(row)


def test_sample_row_blanks_missing_fields() -> None:
    row = sample_row({"load_power": 500}, now=0.0)
    assert row["solar_power"] == ""


def test_append_rows_writes_header_once(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "power.csv"
    append_rows(path, [{"a": 1, "b": 2}])
    append_rows(path, [{"a": 3, "b": 4}])
    with path.open() as f:
        rows = list(csv.DictReader(f))
    assert rows == [{"a": "1", "b": "2"}, {"a": "3", "b": "4"}]


def test_append_rows_ignores_empty_list(tmp_path: Path) -> None:
    path = tmp_path / "power.csv"
    append_rows(path, [])
    assert not path.exists()


def test_daily_rows_groups_intervals_and_finds_night_floor() -> None:
    def interval(stamp: str, grid: int, battery: int) -> dict:
        return {
            "timestamp": stamp,
            "consumer_energy_imported_from_grid": grid,
            "consumer_energy_imported_from_battery": battery,
            "grid_energy_imported": grid,
        }

    series = [
        interval("2026-11-22T01:00:00-08:00", 0, 300),  # 600 W
        interval("2026-11-22T03:30:00-08:00", 0, 250),  # 500 W: the floor
        interval("2026-11-22T19:00:00-08:00", 900, 100),  # evening, not night
        interval("2026-11-21T02:00:00-08:00", 0, 260),
    ]
    rows = daily_rows(series)
    assert [r["date"] for r in rows] == ["2026-11-21", "2026-11-22"]
    day = rows[1]
    assert day["home_wh"] == 1550
    assert day["grid_imported_wh"] == 900
    assert day["night_floor_w"] == 500


def test_month_end() -> None:
    from datetime import datetime

    from Tesla.tesla_client import month_end

    now = datetime(2026, 11, 23, 9, 30, 15, 123)
    assert month_end(now, 0) == datetime(2026, 11, 23, 9, 30, 15)
    assert month_end(now, 1) == datetime(2026, 10, 31, 23, 59, 59)
    assert month_end(now, 3) == datetime(2026, 8, 31, 23, 59, 59)
    assert month_end(datetime(2026, 1, 5), 1) == datetime(2025, 12, 31, 23, 59, 59)


def test_manager_logs_power_and_survives_write_failure() -> None:
    from unittest.mock import MagicMock

    from lib.MyPushover import Pushover
    from Tesla.manage_power import PowerwallManager

    seen: list = []
    product = {"load_power": 550, "solar_power": 0}
    mgr = PowerwallManager("x", pushover=MagicMock(spec=Pushover), record_power=seen.append)
    mgr.log_power(product)
    assert seen[0]["load_power"] == 550

    def boom(_: dict) -> None:
        raise OSError("disk full")

    mgr = PowerwallManager("x", pushover=MagicMock(spec=Pushover), record_power=boom)
    mgr.log_power(product)  # must not raise


def test_manager_logs_power_from_battery_product() -> None:
    from typing import Any, cast
    from unittest.mock import MagicMock

    from lib.MyPushover import Pushover
    from Tesla.manage_power import PowerwallManager
    from Tesla.tesla_client import BatteryProduct

    product = BatteryProduct({"energy_site_id": 1, "load_power": 610}, client=cast(Any, None))
    seen: list = []
    mgr = PowerwallManager("x", pushover=MagicMock(spec=Pushover), record_power=seen.append)
    mgr.log_power(product)
    assert seen[0]["load_power"] == 610
