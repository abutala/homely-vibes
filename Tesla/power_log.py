#!/usr/bin/env python3
"""Durable record of house power, for tracking idle load.

Two CSV files under `<paths.logging_dir>/power/`:
- `power_samples.csv`: one row per manage_power poll (live watts). It adds no
  API calls: manage_power already fetches live_status each poll.
- `power_daily.csv`: daily Wh from calendar_history (`home_wh` = total home use), written by this script's
  CLI (one API call per run).

    uv run Tesla/power_log.py --days 30
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


def daily_rows(history: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Daily rows from a calendar_history response, with total home use in Wh."""
    rows = []
    for entry in history.get("time_series", []):
        row: Dict[str, Any] = {"date": str(entry.get("timestamp", ""))[:10]}
        row["home_wh"] = sum(entry.get(key, 0) or 0 for key in HOME_SOURCES)
        row.update({k: v for k, v in entry.items() if k != "timestamp"})
        rows.append(row)
    return rows


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
    parser.add_argument("--days", type=int, default=30, help="Days of history to fetch")
    args = parser.parse_args()

    client = TeslaAPIClient()
    product = BatteryProduct(client.get_energy_sites()[0], client)
    history = product.get_energy_history(days=args.days)
    path = power_dir() / "power_daily.csv"
    path.unlink(missing_ok=True)  # Tesla's history is the source of truth: rewrite it whole
    rows = daily_rows(history)
    append_rows(path, rows)
    print(f"Wrote {len(rows)} days to {path}")


if __name__ == "__main__":
    main()
