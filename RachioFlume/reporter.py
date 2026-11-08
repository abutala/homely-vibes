"""Weekly reporting system for water tracking data."""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path

from RachioFlume.alert_rules import (
    ZoneThreshold,
    compact_zone_label,
    load_zone_thresholds_from_config,
    resolve_hose_threshold,
)
from RachioFlume.data_storage import WaterTrackingDB
from RachioFlume.ecowitt_client import SoilReading
from lib.config import get_config
from lib.logger import get_logger


@dataclass
class ZoneStats:
    """Statistics for a single zone (controller zone or hose-timer valve)."""

    zone_number: int  # controller zone number; hose valves use HOSE_ZONE_SENTINEL
    zone_name: str
    sessions: int
    total_duration_minutes: float
    average_duration_minutes: float
    total_water_gallons: float
    average_flow_rate_gpm: float
    threshold_gpm: float
    alert_sessions: int
    note: str = ""  # why the zone did not run in the period; "" when it ran
    problem: bool = False  # an idle zone that needs a look (missed run, valve offline)


@dataclass
class SkippedRun:
    """A scheduled run that Rachio skipped."""

    date: datetime
    schedule: str
    reason: str  # "weather", "climate", ...
    zone_numbers: List[int]  # empty when the schedule's zones are unknown


# Hose valves have no controller zone number; sort them after real zones.
HOSE_ZONE_SENTINEL = 999


def skip_reason(event_type: str) -> Optional[str]:
    """Short label for a Rachio schedule-skip subtype, or None when it is not a skip.

    WEATHER_INTELLIGENCE_SKIP is the plain weather skip; its variants name the
    cause between prefix and suffix (WEATHER_INTELLIGENCE_CLIMATE_SKIP -> "climate").
    SCHEDULE_RULE_SKIP_ADDED is a seasonal-adjustment notice, not a skipped run.
    """
    if not event_type.endswith("_SKIP"):
        return None
    cause = event_type.removesuffix("_SKIP").removeprefix("WEATHER_INTELLIGENCE").strip("_")
    return cause.lower().replace("_", " ") or "weather"


def _skipped_run(
    row: Dict[str, Any], schedule_zones: Optional[Dict[str, List[int]]]
) -> Optional[SkippedRun]:
    """Parse a skip event. Rachio truncates long schedule names in the summary
    ("Front Beds Sum... was scheduled for ..."), so a truncated name matches by
    prefix, and only when exactly one schedule fits; a full name must match exactly.
    """
    reason = skip_reason(row["event_type"])
    if reason is None:
        return None
    raw = row["summary"].split(" was scheduled", 1)[0].strip()
    name = raw.removesuffix("...")
    if name == raw:
        matches = [s for s in schedule_zones or {} if s == name]
    else:
        matches = [s for s in schedule_zones or {} if s.startswith(name)]
    schedule = matches[0] if len(matches) == 1 else None
    return SkippedRun(
        date=datetime.fromisoformat(str(row["event_date"])),
        schedule=schedule or name,
        reason=reason,
        zone_numbers=sorted(schedule_zones[schedule]) if schedule and schedule_zones else [],
    )


def _no_run_note(
    zone_number: int,
    skipped: List[SkippedRun],
    schedule_zones: Optional[Dict[str, List[int]]],
) -> tuple[str, bool]:
    """Why an enabled controller zone has no run in the period, and whether that
    is a problem: only a zone in an active schedule with no skip recorded is.
    With schedules unknown (Rachio unreachable) nothing is called a problem.
    """
    skips = [s for s in skipped if zone_number in s.zone_numbers]
    if skips:
        return "skipped: " + ", ".join(f"{s.reason} {s.date:%m/%d}" for s in skips), False
    if schedule_zones is None:
        return "no run recorded", False
    if not any(zone_number in z for z in schedule_zones.values()):
        return "in no active schedule", False
    return "scheduled, but no run or skip recorded", True


def _idle_row(zone_number: int, zone_name: str, note: str, problem: bool) -> ZoneStats:
    return ZoneStats(zone_number, zone_name, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, note, problem)


@dataclass
class SoilStats:
    """One soil probe over the report period."""

    channel: int
    label: str  # the channel's name in the Ecowitt app, else "Soil CH<n>"
    latest_pct: float
    min_pct: Optional[float]  # None when the probe sent nothing in the period
    max_pct: Optional[float]
    last_read: datetime


def soil_stats(period: List[SoilReading], last: List[SoilReading]) -> List[SoilStats]:
    """One row per channel ever seen: latest reading and its label from `last` (the
    newest per channel, however old), low and high from `period` (oldest first).
    A channel silent for the whole period keeps its row, with no low or high."""
    by_channel: Dict[int, List[float]] = {}
    for r in period:
        by_channel.setdefault(r.channel, []).append(r.moisture_pct)
    stats = []
    for newest in sorted(last, key=lambda r: r.channel):
        pcts = by_channel.get(newest.channel)
        stats.append(
            SoilStats(
                channel=newest.channel,
                label=newest.name or f"Soil CH{newest.channel}",
                latest_pct=newest.moisture_pct,
                min_pct=min(pcts) if pcts else None,
                max_pct=max(pcts) if pcts else None,
                last_read=newest.read_at,
            )
        )
    return stats


@dataclass
class ReportSummary:
    """Summary statistics for the entire report."""

    total_watering_sessions: int
    total_duration_minutes: float
    total_water_used_gallons: float
    zones_watered: int


@dataclass
class WaterUsageReport:
    """Complete water usage report."""

    report_generated: datetime
    period_start: datetime
    period_end: datetime
    summary: ReportSummary
    zones: List[ZoneStats]
    soil: List[SoilStats] = field(default_factory=list)
    soil_expected: bool = False  # a soil gateway is configured

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for compatibility."""
        return asdict(self)


class WeeklyReporter:
    """Generate weekly water usage reports by zone."""

    def __init__(self, db_path: str):
        self.db = WaterTrackingDB(db_path)
        self.logger = get_logger(__name__)
        self.logger.info("Weekly reporter initialized")

    def generate_period_report_with_dates(
        self,
        period_start: datetime,
        period_end: datetime,
        zone_thresholds: Optional[Dict[str, Dict[str, ZoneThreshold]]] = None,
        absolute_gpm: Optional[float] = None,
        percent_above: Optional[float] = None,
        min_runtime_minutes: Optional[int] = None,
        schedule_zones: Optional[Dict[str, List[int]]] = None,
        soil_gateway_host: Optional[str] = None,
    ) -> WaterUsageReport:
        """Generate a comprehensive period report.

        Args:
            period_start: Start of the period
            period_end: End of the period
            zone_thresholds: Per-device zone baselines; loaded from config when omitted
            absolute_gpm, percent_above, min_runtime_minutes: Zone-anomaly parameters;
                each read from config when omitted
            schedule_zones: Zone numbers per enabled Rachio schedule, used to say
                why a zone did not run; None when unknown (reasons fall back)
            soil_gateway_host: Ecowitt gateway; read from config when omitted.
                Set means soil readings are expected, so their absence is a problem

        Returns:
            WaterUsageReport containing period statistics
        """
        self.logger.info(
            f"Generating period report for {period_start.date()} to {period_end.date()}"
        )

        # Load anomaly config once — used to compute per-zone / per-valve
        # threshold (baseline + slack) and count how many sessions crossed it.
        rf_cfg = get_config().rachio_flume
        za_cfg = rf_cfg.alerts.zone_anomaly
        soil_host = rf_cfg.soil_gateway_host if soil_gateway_host is None else soil_gateway_host
        abs_gpm = za_cfg.absolute_gpm if absolute_gpm is None else absolute_gpm
        pct_above = za_cfg.percent_above if percent_above is None else percent_above
        # Same floor the alert engine applies: a seconds-long run divides a whole Flume
        # minute by a few seconds and reads as an absurd GPM.
        runtime_minutes = (
            za_cfg.min_runtime_minutes if min_runtime_minutes is None else min_runtime_minutes
        )
        min_runtime_seconds = runtime_minutes * 60

        if zone_thresholds is not None:
            all_thresholds = zone_thresholds
        else:
            try:
                all_thresholds = load_zone_thresholds_from_config()
            except Exception:
                all_thresholds = {}

        # Controller thresholds: flatten by str(zone_number). Hose keys (non-digit)
        # skipped; they're merged into the hose section below.
        # Assumes a single controller per deployment (current setup: Rachio-Main).
        # If two controllers ever share a zone number, the later-processed entry
        # would overwrite. Revisit when multi-controller support lands.
        ctrl_thresh: Dict[str, Any] = {}
        for _label, zones in all_thresholds.items():
            for zone_key, zone_zt in zones.items():
                if zone_key.isdigit():
                    ctrl_thresh[zone_key] = zone_zt

        # Per-session alert counts by zone_number and by (label, valve_name).
        ctrl_alerts: Dict[int, int] = {}
        for s in self.db.get_zone_sessions(period_start, period_end):
            sess_zt = ctrl_thresh.get(str(s["zone_number"]))
            long_enough = (s.get("duration_seconds") or 0) >= min_runtime_seconds
            if (
                sess_zt
                and long_enough
                and (s.get("average_flow_rate") or 0)
                > sess_zt.compute_threshold(abs_gpm, pct_above)
            ):
                ctrl_alerts[s["zone_number"]] = ctrl_alerts.get(s["zone_number"], 0) + 1

        # Get zone aggregate statistics for the period
        zone_stats = self.db.get_period_zone_stats(period_start, period_end)

        # Format zone statistics for display
        formatted_zones = []
        for stat in zone_stats:
            duration_minutes = (stat["total_duration_seconds"] or 0) / 60.0
            avg_duration_minutes = (stat["avg_duration_seconds"] or 0) / 60.0
            stat_zt = ctrl_thresh.get(str(stat["zone_number"]))
            threshold_gpm = (
                round(stat_zt.compute_threshold(abs_gpm, pct_above), 2) if stat_zt else 0.0
            )

            zone_stats_obj = ZoneStats(
                zone_number=stat["zone_number"],
                zone_name=stat["zone_name"],
                sessions=stat["session_count"],
                total_duration_minutes=round(duration_minutes, 1),
                average_duration_minutes=round(avg_duration_minutes, 1),
                total_water_gallons=round(stat["total_water_used"] or 0, 1),
                average_flow_rate_gpm=round(stat["avg_flow_rate"] or 0, 2),
                threshold_gpm=threshold_gpm,
                alert_sessions=ctrl_alerts.get(stat["zone_number"], 0),
            )
            formatted_zones.append(zone_stats_obj)

        # Aggregate hose-timer sessions and append as rows in the same table.
        # Hose valves are treated identically to controller zones: they count
        # toward zones_watered, contribute to total sessions / total duration,
        # and share the same column layout. Volume + rate come from the Flume
        # window aggregate captured by hose_timer_processor at run end.
        hose_sessions = self.db.get_hose_zone_sessions(period_start, period_end)
        hose_agg: Dict[tuple, Dict[str, Any]] = {}
        hose_alerts: Dict[tuple, int] = {}
        ran_valve_ids = {s["valve_id"] for s in hose_sessions}
        for s in hose_sessions:
            key = (s["base_station_label"], s["valve_name"])
            slot = hose_agg.setdefault(
                key, {"sessions": 0, "duration_sec_total": 0, "gal_total": 0.0}
            )
            slot["sessions"] += 1
            duration_sec = s.get("duration_seconds") or 0
            slot["duration_sec_total"] += duration_sec
            gal = float(s.get("total_water_used") or 0.0)
            slot["gal_total"] += gal
            hose_zt = resolve_hose_threshold(
                all_thresholds.get(s["base_station_label"], {}), s["valve_name"]
            )
            if hose_zt and duration_sec >= min_runtime_seconds:
                sess_avg = gal / (duration_sec / 60.0)
                if sess_avg > hose_zt.compute_threshold(abs_gpm, pct_above):
                    hose_alerts[key] = hose_alerts.get(key, 0) + 1

        for (label, name), v in hose_agg.items():
            zt = resolve_hose_threshold(all_thresholds.get(label, {}), name)
            threshold_gpm = round(zt.compute_threshold(abs_gpm, pct_above), 2) if zt else 0.0
            dur_min = v["duration_sec_total"] / 60.0
            avg_gpm = v["gal_total"] / dur_min if dur_min > 0 else 0.0
            formatted_zones.append(
                ZoneStats(
                    zone_number=HOSE_ZONE_SENTINEL,
                    zone_name=compact_zone_label(name),
                    sessions=v["sessions"],
                    total_duration_minutes=round(dur_min, 1),
                    average_duration_minutes=round(
                        (v["duration_sec_total"] / max(v["sessions"], 1)) / 60.0, 1
                    ),
                    total_water_gallons=round(v["gal_total"], 1),
                    average_flow_rate_gpm=round(avg_gpm, 1),
                    threshold_gpm=threshold_gpm,
                    alert_sessions=hose_alerts.get((label, name), 0),
                )
            )

        skipped = [
            run
            for run in (
                _skipped_run(row, schedule_zones)
                for row in self.db.get_skip_events(period_start, period_end)
            )
            if run
        ]
        idle_rows = self._idle_zones(
            {z.zone_number for z in formatted_zones}, ran_valve_ids, skipped, schedule_zones
        )
        formatted_zones.extend(idle_rows)

        # Sort: controller zones by number, hose valves alphabetical after them
        formatted_zones.sort(key=lambda x: (x.zone_number, x.zone_name))

        # Summary aggregates over the merged list so zones_watered / totals
        # include hose valves.
        summary = ReportSummary(
            total_watering_sessions=sum(z.sessions for z in formatted_zones),
            total_duration_minutes=round(sum(z.total_duration_minutes for z in formatted_zones), 1),
            total_water_used_gallons=round(sum(z.total_water_gallons for z in formatted_zones), 1),
            zones_watered=sum(1 for z in formatted_zones if z.sessions),
        )

        return WaterUsageReport(
            report_generated=datetime.now(),
            period_start=period_start,
            period_end=period_end,
            summary=summary,
            zones=formatted_zones,
            # Off means off: probes stored before the gateway was unset stay out.
            soil=(
                soil_stats(
                    self.db.get_soil_readings(period_start, period_end),
                    self.db.get_last_soil_readings(period_end),
                )
                if soil_host
                else []
            ),
            soil_expected=bool(soil_host),
        )

    def _idle_zones(
        self,
        ran_zone_numbers: set[int],
        ran_valve_ids: set[str],
        skipped: List[SkippedRun],
        schedule_zones: Optional[Dict[str, List[int]]],
    ) -> List[ZoneStats]:
        """Rows for enabled zones and valves with no run in the period, each with
        its reason. Disabled zones get no row.
        """
        rows: List[ZoneStats] = []
        for z in self.db.get_controller_zones():
            if z["zone_number"] in ran_zone_numbers:
                continue
            if not z["enabled"]:
                continue
            name = compact_zone_label(z["name"])
            note, problem = _no_run_note(z["zone_number"], skipped, schedule_zones)
            rows.append(_idle_row(z["zone_number"], name, note, problem))
        for v in self.db.get_hose_valves():
            if v["id"] in ran_valve_ids:
                continue
            # An idle valve is often just out of season; only an offline one needs a look.
            note = "no run recorded" if v["connected"] else "offline, no run recorded"
            label = compact_zone_label(v["name"])
            rows.append(_idle_row(HOSE_ZONE_SENTINEL, label, note, not v["connected"]))
        return rows

    def save_report_to_file(self, report: WaterUsageReport, filename: str) -> None:
        """Save report to JSON file.

        Args:
            report: Report data
            filename: Output filename
        """
        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)

    def print_raw_report(self, report: Dict[str, Any]) -> None:
        """Print raw data report in a readable format."""
        self.logger.info("=" * 35)
        self.logger.info("RAW WATER USAGE DATA REPORT")
        self.logger.info("=" * 35)
        self.logger.info(f"Report Generated: {report['report_generated']}")
        self.logger.info(f"Time Period: {report['period_start']} to {report['period_end']}")
        self.logger.info(f"Interval: {report['interval_minutes']} minutes")
        self.logger.info(f"Total Data Points: {len(report['data_points'])}")
        self.logger.info("")

        if not report["data_points"]:
            self.logger.info("No data available for this time period.")
        else:
            self.logger.info(
                "Time Interval               | Avg GPM | Max GPM | Min GPM | Points | Active Avg"
            )
            self.logger.info("-" * 35)

            for data_point in report["data_points"]:
                time_str = data_point["interval_start"]
                avg_flow = data_point["avg_flow_rate"] or 0
                max_flow = data_point["max_flow_rate"] or 0
                min_flow = data_point["min_flow_rate"] or 0
                points = data_point["data_points"]
                active_avg = data_point["avg_active_flow_rate"] or 0

                self.logger.info(
                    f"{time_str[:16]:25} | {avg_flow:7.2f} | {max_flow:7.2f} | {min_flow:7.2f} | {points:6} | {active_avg:7.2f}"
                )

        self.logger.info("=" * 35)

    def generate_raw_data_report(self, hours_back: int = 24) -> Dict[str, Any]:
        """Generate raw data report with 5-minute increments.

        Args:
            hours_back: Number of hours to look back from now (default: 24)

        Returns:
            Dict containing raw data in 5-minute intervals
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours_back)

        self.logger.info(f"Generating raw data report for {start_time} to {end_time}")

        # Get raw data in 5-minute intervals
        raw_data = self.db.get_raw_data_intervals(start_time, end_time, interval_minutes=5)

        return {
            "report_generated": datetime.now().isoformat(),
            "period_start": start_time.isoformat(),
            "period_end": end_time.isoformat(),
            "interval_minutes": 5,
            "data_points": raw_data,
        }
