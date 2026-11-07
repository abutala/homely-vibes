"""The weekly email puts problems first and stays quiet about expected idle zones.

Replays the prod week of 2026-10-31 → 11-07: Z8 and Z13 ran above their flow
limit and Z2 ran with no water measured, while five zones were weather-skipped.
"""

from datetime import datetime

from RachioFlume import report_format as rf
from RachioFlume.reporter import (
    HOSE_ZONE_SENTINEL,
    ReportSummary,
    WaterUsageReport,
    ZoneStats,
)

SKIP = "skipped: weather 11/03, climate 11/06"


def _zone(n: int, name: str, sessions: int, minutes: float, gal: float, gpm: float,
          thr: float = 0.0, alerts: int = 0, note: str = "") -> ZoneStats:  # fmt: skip
    return ZoneStats(n, name, sessions, minutes, minutes, gal, gpm, thr, alerts, note)


def _report(zones: list[ZoneStats]) -> WaterUsageReport:
    return WaterUsageReport(
        report_generated=datetime(2026, 11, 7, 2),
        period_start=datetime(2026, 10, 31, 2),
        period_end=datetime(2026, 11, 7, 2),
        summary=ReportSummary(
            total_watering_sessions=sum(z.sessions for z in zones),
            total_duration_minutes=sum(z.total_duration_minutes for z in zones),
            total_water_used_gallons=sum(z.total_water_gallons for z in zones),
            zones_watered=sum(1 for z in zones if z.sessions),
        ),
        zones=zones,
    )


PROD_WEEK = _report(
    [
        _zone(1, "Z1 FS", 1, 6.1, 41, 6.7, thr=8.8),
        _zone(2, "Z2 FS", 1, 6.2, 0, 0.0, thr=8.0),
        _zone(3, "Z3 FB", 0, 0, 0, 0, note=SKIP),
        _zone(4, "Z4 FB", 0, 0, 0, 0, note=SKIP),
        _zone(8, "Z8 BD", 1, 15.0, 63, 4.2, thr=1.8, alerts=1),
        _zone(9, "Z9 FD", 0, 0, 0, 0, note="in no active schedule"),
        _zone(HOSE_ZONE_SENTINEL, "Z13 BUD", 4, 40.0, 18, 0.4, thr=0.8, alerts=1),
    ]
)

QUIET_WEEK = _report(
    [
        _zone(1, "Z1 FS", 1, 6.1, 41, 6.7, thr=8.8),
        _zone(3, "Z3 FB", 0, 0, 0, 0, note=SKIP),
    ]
)


def test_problems_name_flow_over_limit_and_runs_with_no_water() -> None:
    assert [(p.zone, p.detail) for p in rf.problems(PROD_WEEK)] == [
        ("Z2 FS", "ran 6 min, no water measured"),
        ("Z8 BD", "1/1 runs above 1.8 GPM (avg 4.2)"),
        ("Z13 BUD", "1/4 runs above 0.8 GPM (avg 0.4)"),
    ]


def test_an_idle_zone_marked_as_a_problem_is_listed_and_kept_off_the_quiet_line() -> None:
    missed = _zone(6, "Z6 BB", 0, 0, 0, 0, note="scheduled, but no run or skip recorded")
    missed.problem = True
    report = _report([missed])
    assert [(p.zone, p.detail) for p in rf.problems(report)] == [
        ("Z6 BB", "scheduled, but no run or skip recorded")
    ]
    assert "Not run" not in rf.format_text(report)


def test_skipped_and_unscheduled_zones_are_not_problems() -> None:
    assert rf.problems(QUIET_WEEK) == []
    assert "No problems." in rf.format_text(QUIET_WEEK)
    assert "No problems" in rf.format_html(QUIET_WEEK)


def test_subject_carries_the_problem_count() -> None:
    assert rf.email_subject(PROD_WEEK) == "[Water Report] Oct 31 – Nov 7: 3 problems"
    assert rf.email_subject(QUIET_WEEK) == "[Water Report] Oct 31 – Nov 7: OK"


def test_idle_zones_fold_into_one_line_per_reason() -> None:
    text = rf.format_text(PROD_WEEK)
    assert f"  Z3 FB, Z4 FB — {SKIP}" in text
    assert "  Z9 FD — in no active schedule" in text
    # Idle zones get no row in the zone table.
    assert "\nZ3 FB " not in text


def test_problems_come_before_the_zone_table() -> None:
    html = rf.format_html(PROD_WEEK)
    assert html.startswith("<html>")
    assert html.index("Needs attention") < html.index(">Zone</th>")
    assert html.index("Z8 BD") < html.index(">Zone</th>")


def test_html_escapes_zone_names() -> None:
    report = _report([_zone(1, "<b>Z1</b>", 1, 5, 0, 0.0)])
    html = rf.format_html(report)
    assert "&lt;b&gt;Z1&lt;/b&gt;" in html
    assert "<b>Z1</b>" not in html
