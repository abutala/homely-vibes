#!/usr/bin/env python3
"""Durable record of house power, for tracking idle load.

Two CSV files under `<paths.logging_dir>/power/`:
- `power_samples.csv`: one row per manage_power poll (live watts). It adds no
  API calls: manage_power already fetches live_status each poll.
- `power_daily.csv`: one row per day from calendar_history, written by this
  script's CLI (one API call per month). Each run merges by date: the fetched
  days replace their old rows and older days stay, so a daily `--months 2` run
  keeps the full history. After the merge, through NodeCheck's Pushover: a P1
  alert when the last 7 nights' floor median is more than
  `tesla.idle_alert_threshold_w` above the 90 nights before, and on
  `tesla.idle_report_weekday` a weekly heartbeat (idle floor, kWh/day). Tesla returns 30-min intervals, which
  this groups by day: `home_wh` (total home use, Wh) and `night_floor_w` (the
  lowest 30-min average home load, in W, from 00:00 to 05:00: the idle floor).

    uv run Tesla/power_log.py --months 12
"""

import argparse
import csv
import os
import statistics
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

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


CHARGING_W = 3000  # a night floor above this is the car charging all night, not idle load
RECENT_DAYS = 7
BASELINE_DAYS = 90
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


def merge_daily(path: Path, rows: List[Dict[str, Any]]) -> int:
    """Merge rows into the daily CSV by date: new rows replace old ones, older days stay.

    Writes a temp file and renames it, so a crash never leaves a half-written history.
    Returns the number of days in the file.
    """
    days: Dict[str, Dict[str, Any]] = {}
    if path.exists():
        with path.open(newline="") as f:
            days = {row["date"]: row for row in csv.DictReader(f)}
    days.update({row["date"]: row for row in rows})
    if not days:
        return 0
    tmp = path.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    append_rows(tmp, [days[d] for d in sorted(days)])
    tmp.replace(path)
    return len(days)


def idle_floors(rows: Iterable[Dict[str, Any]]) -> List[float]:
    """Night floors by date, without the nights the car charged all night."""
    return [
        float(r["night_floor_w"])
        for r in sorted(rows, key=lambda r: r["date"])
        if r.get("night_floor_w") not in (None, "") and float(r["night_floor_w"]) < CHARGING_W
    ]


def floor_drift(rows: List[Dict[str, Any]], threshold_w: int) -> Optional[str]:
    """Alert text when the recent night floor sits threshold_w above its baseline, else None.

    Recent: median of the last RECENT_DAYS usable nights. Baseline: median of the
    BASELINE_DAYS nights before them. Nights the car charged all night are skipped.
    """
    floors = idle_floors(rows)
    recent, baseline = floors[-RECENT_DAYS:], floors[-RECENT_DAYS - BASELINE_DAYS : -RECENT_DAYS]
    if len(recent) < RECENT_DAYS or len(baseline) < 30:
        return None
    now, before = statistics.median(recent), statistics.median(baseline)
    if now - before <= threshold_w:
        return None
    return (
        f"House idle power rose: night floor {now:.0f} W over the last {RECENT_DAYS} nights, "
        f"vs {before:.0f} W over the {len(baseline)} before (+{now - before:.0f} W)."
    )


def weekly_report(rows: List[Dict[str, Any]]) -> str:
    """Heartbeat text: idle floor and average daily use over the last RECENT_DAYS days."""
    last = sorted(rows, key=lambda r: r["date"])[-RECENT_DAYS:]
    floors = idle_floors(last)
    floor = f"{statistics.median(floors):.0f} W" if floors else "n/a"
    kwh = statistics.mean(float(r["home_wh"]) for r in last) / 1000 if last else 0.0
    return f"Last {len(last)} days: idle floor {floor}, average use {kwh:.1f} kWh/day."


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
    rows = daily_rows(series)
    total = merge_daily(path, rows)
    print(f"Updated {len(rows)} days in {path} ({total} days in all)")
    with path.open(newline="") as f:
        history = list(csv.DictReader(f))
    notify_power(history, today_weekday=time.localtime().tm_wday)


def notify_power(
    history: List[Dict[str, Any]],
    today_weekday: int,
    send: Optional[Callable[[str, int], None]] = None,
) -> None:
    """P1 alert on idle drift; on the report weekday, a weekly heartbeat. Through NodeCheck's Pushover."""
    cfg = get_config().tesla
    if send is None:
        send = _nodecheck_pushover
    alert = floor_drift(history, cfg.idle_alert_threshold_w)
    if alert:
        send(alert, 1)
    if today_weekday == cfg.idle_report_weekday:
        send(weekly_report(history), 0)


def _nodecheck_pushover(message: str, priority: int) -> None:
    from lib.MyPushover import Pushover

    cfg = get_config()
    Pushover(cfg.pushover.user, cfg.pushover.tokens["NodeCheck"]).send_message(
        message, title="House idle power", priority=priority
    )
    print(message)


if __name__ == "__main__":
    main()
