#!/usr/bin/env python3
"""Durable record of house power, for tracking idle load.

Two CSV files under `<paths.logging_dir>/power/`:
- `power_samples.csv`: one row per manage_power poll (live watts). It adds no
  API calls: manage_power already fetches live_status each poll.
- `power_daily.csv`: one row per day from calendar_history, written by this
  script's CLI (one API call per month). Tesla returns 30-min intervals, which
  this groups by day: `home_wh` (total home use, Wh) and `night_floor_w` (the
  lowest 30-min average home load, in W, from 00:00 to 05:00: the idle floor).

    uv run Tesla/power_log.py --months 12
"""

import argparse
import csv
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from lib.config import get_config

POWER_FIELDS = (
    "load_power",
    "solar_power",
    "grid_power",
    "battery_power",
    "percentage_charged",
)
HOME_SOURCES = (
    "consumer_energy_imported_from_grid",
    "consumer_energy_imported_from_solar",
    "consumer_energy_imported_from_battery",
    "consumer_energy_imported_from_generator",
)


def power_dir() -> Path:
    return Path(os.path.expanduser(get_config().paths.logging_dir)) / "power"


def sample_row(live: Dict[str, Any], now: float) -> Dict[str, Any]:
    """One CSV row of live watts from a live_status response."""
    row: Dict[str, Any] = {
        "epoch": int(now),
        "local_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
    }
    for field in POWER_FIELDS:
        row[field] = live.get(field, "")
    return row


NIGHT_HOURS = range(0, 5)
INTERVALS_PER_HOUR = 2  # calendar_history returns 30-min intervals


def daily_rows(series: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group calendar_history 30-min intervals into one row per day."""
    days: Dict[str, Dict[str, Any]] = {}
    for entry in series:
        stamp = str(entry.get("timestamp", ""))
        date, hour = stamp[:10], int(stamp[11:13] or 0)
        home_wh = sum(entry.get(key, 0) or 0 for key in HOME_SOURCES)
        day = days.setdefault(
            date, {"date": date, "home_wh": 0, "grid_imported_wh": 0, "night_floor_w": None}
        )
        day["home_wh"] += home_wh
        day["grid_imported_wh"] += entry.get("grid_energy_imported", 0) or 0
        if hour in NIGHT_HOURS:
            watts = home_wh * INTERVALS_PER_HOUR
            floor = day["night_floor_w"]
            day["night_floor_w"] = watts if floor is None else min(floor, watts)
    return [days[d] for d in sorted(days)]


def append_rows(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    """Append rows to a CSV, with a header when the file is new."""
    rows = list(rows)
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not path.exists()
    with path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), extrasaction="ignore")
        if is_new:
            writer.writeheader()
        writer.writerows(rows)


def record_sample(live: Dict[str, Any], path: Optional[Path] = None) -> None:
    append_rows(path or power_dir() / "power_samples.csv", [sample_row(live, time.time())])


def main() -> None:
    from Tesla.tesla_client import BatteryProduct, TeslaAPIClient

    parser = argparse.ArgumentParser(description="Write daily home energy to CSV")
    parser.add_argument("--months", type=int, default=12, help="Months of history to fetch")
    args = parser.parse_args()

    client = TeslaAPIClient()
    product = BatteryProduct(client.get_energy_sites()[0], client)
    series: List[Dict[str, Any]] = []
    for offset in range(args.months):
        series += product.get_energy_month(months_ago=offset).get("time_series", [])
    path = power_dir() / "power_daily.csv"
    path.unlink(missing_ok=True)  # Tesla's history is the source of truth: rewrite it whole
    rows = daily_rows(series)
    append_rows(path, rows)
    print(f"Wrote {len(rows)} days to {path}")


if __name__ == "__main__":
    main()
