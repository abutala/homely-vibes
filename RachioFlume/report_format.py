"""Render a WaterUsageReport for email (HTML) and logs (text).

Problems come first; a quiet week is one green line. Expected idle zones (skips,
zones in no schedule) fold into grey lines, one per reason; disabled zones are not shown.
"""

from dataclasses import dataclass
from html import escape
from itertools import groupby
from typing import List

from RachioFlume.reporter import WaterUsageReport, ZoneStats
from lib import Mailer


@dataclass(frozen=True)
class Problem:
    zone: str
    detail: str


def problems(report: WaterUsageReport) -> List[Problem]:
    """Zones that need a look: flow over the limit, a run with no water, or an
    idle zone the reporter marked as a problem (missed run, valve offline)."""
    found: List[Problem] = []
    for z in report.zones:
        if z.alert_sessions:
            found.append(
                Problem(
                    z.zone_name,
                    f"{z.alert_sessions}/{z.sessions} runs above {z.threshold_gpm:.1f} GPM"
                    f" (avg {z.average_flow_rate_gpm:.1f})",
                )
            )
        if z.sessions and z.total_water_gallons == 0:
            found.append(
                Problem(z.zone_name, f"ran {z.total_duration_minutes:.0f} min, no water measured")
            )
        if z.problem:
            found.append(Problem(z.zone_name, z.note))
    return found


def _ran(report: WaterUsageReport) -> List[ZoneStats]:
    return [z for z in report.zones if z.sessions]


def _quiet_idle(report: WaterUsageReport) -> List[str]:
    """One line per reason: "Z3 FB, Z4 FB — skipped: weather 11/03"."""
    idle = [z for z in report.zones if z.note and not z.problem]
    idle.sort(key=lambda z: z.note)
    return [
        f"{', '.join(z.zone_name for z in group)} — {note}"
        for note, group in groupby(idle, key=lambda z: z.note)
    ]


def _period(report: WaterUsageReport) -> str:
    return f"{report.period_start:%b %-d} – {report.period_end:%b %-d}"


def _totals(report: WaterUsageReport) -> str:
    s = report.summary
    return f"{s.total_water_used_gallons:.0f} gal · {s.total_duration_minutes:.0f} min"


def email_subject(report: WaterUsageReport) -> str:
    n = len(problems(report))
    status = f"{n} problem{'s' if n != 1 else ''}" if n else "OK"
    return f"[Water Report] {_period(report)}: {status}"


def format_text(report: WaterUsageReport) -> str:
    lines = [f"WATER {_period(report)} · {_totals(report)}", ""]
    found = problems(report)
    if found:
        lines.append("PROBLEMS:")
        lines.extend(f"  {p.zone}: {p.detail}" for p in found)
    else:
        lines.append("No problems.")
    ran = _ran(report)
    if ran:
        lines += ["", f"{'Zone':<8} {'Min':>5} {'Gal':>5} {'GPM':>5}"]
        lines.extend(
            f"{z.zone_name[:8]:<8} {z.total_duration_minutes:>5.0f} "
            f"{z.total_water_gallons:>5.0f} {z.average_flow_rate_gpm:>5.1f}"
            for z in ran
        )
    quiet = _quiet_idle(report)
    if quiet:
        lines += ["", "Not run:"] + [f"  {q}" for q in quiet]
    return "\n".join(lines)


RED = "#b3261e"
GREY = "#6b6b6b"
CELL = "padding:4px 8px;border-bottom:1px solid #e6e6e6;"
NUM = CELL + "text-align:right;font-variant-numeric:tabular-nums;"


def _problem_box(found: List[Problem]) -> str:
    if not found:
        return (
            '<p style="margin:12px 0;padding:10px 12px;background:#e8f5e9;color:#1b5e20;'
            'border-radius:6px;">✓ No problems</p>'
        )
    items = "".join(
        f'<li style="margin:4px 0;"><b>{escape(p.zone)}</b> {escape(p.detail)}</li>' for p in found
    )
    return (
        f'<div style="margin:12px 0;padding:10px 12px;background:#fdecea;'
        f'border-left:4px solid {RED};border-radius:6px;">'
        f'<b style="color:{RED};">Needs attention</b>'
        f'<ul style="margin:6px 0 0;padding-left:18px;">{items}</ul></div>'
    )


def _flagged(z: ZoneStats) -> bool:
    return bool(z.alert_sessions) or z.total_water_gallons == 0


def _zone_table(ran: List[ZoneStats]) -> str:
    if not ran:
        return ""
    head = "".join(
        f'<th style="{NUM if h != "Zone" else CELL}text-align:{"left" if h == "Zone" else "right"};'
        f'color:{GREY};font-weight:600;">{h}</th>'
        for h in ("Zone", "Min", "Gal", "GPM")
    )
    rows = "".join(
        f'<tr style="{f"color:{RED};font-weight:600;" if _flagged(z) else ""}">'
        f'<td style="{CELL}">{escape(z.zone_name)}</td>'
        f'<td style="{NUM}">{z.total_duration_minutes:.0f}</td>'
        f'<td style="{NUM}">{z.total_water_gallons:.0f}</td>'
        f'<td style="{NUM}">{z.average_flow_rate_gpm:.1f}</td></tr>'
        for z in ran
    )
    return (
        '<table style="border-collapse:collapse;width:100%;font-size:14px;">'
        f"<tr>{head}</tr>{rows}</table>"
    )


def format_html(report: WaterUsageReport) -> str:
    quiet = _quiet_idle(report)
    quiet_html = (
        f'<p style="margin:12px 0 0;font-size:13px;color:{GREY};">Not run:<br>'
        + "<br>".join(escape(q) for q in quiet)
        + "</p>"
        if quiet
        else ""
    )
    return (
        '<html><head><meta name="viewport" content="width=device-width,initial-scale=1">'
        '</head><body style="margin:0;padding:16px;font-family:-apple-system,'
        "'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a;\">"
        '<div style="max-width:480px;">'
        f'<div style="font-size:13px;color:{GREY};">{_period(report)} · {_totals(report)}</div>'
        f"{_problem_box(problems(report))}{_zone_table(_ran(report))}{quiet_html}"
        "</div></body></html>"
    )


def email_report(report: WaterUsageReport) -> None:
    Mailer.sendmail(
        topic=email_subject(report), alert=False, message=format_html(report), always_email=True
    )
