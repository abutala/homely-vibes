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


def test_daily_rows_sums_home_energy() -> None:
    history = {
        "time_series": [
            {
                "timestamp": "2026-11-22T00:00:00-08:00",
                "consumer_energy_imported_from_grid": 4000,
                "consumer_energy_imported_from_solar": 3000,
                "consumer_energy_imported_from_battery": 7000,
                "grid_energy_imported": 4100,
            }
        ]
    }
    (row,) = daily_rows(history)
    assert row["date"] == "2026-11-22"
    assert row["home_wh"] == 14000
    assert row["grid_energy_imported"] == 4100


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
