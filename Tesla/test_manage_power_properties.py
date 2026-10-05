#!/usr/bin/env python3
"""Property tests for the Powerwall battery-reading logic.

Each test replays a generated sequence of (minutes elapsed, reading) through
`sanitize_battery_percentage` and checks a rule that must hold after every
step, whatever the sequence. The example tests in test_manage_power.py pin
single scenarios; these search for the sequence nobody thought to write.
"""

from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from lib.config import get_config
from lib.MyPushover import Pushover
from Tesla.manage_power import BatteryHistory, PowerwallManager

# Zero and negative readings are how the API reports "no value"; weight them
# so outages long enough to page actually occur.
_reading = st.one_of(
    st.just(0.0),
    st.floats(min_value=-5.0, max_value=0.0),
    st.floats(min_value=0.01, max_value=100.0),
)
_minutes = st.integers(min_value=0, max_value=36 * 60)
_steps = st.lists(st.tuples(_minutes, _reading), max_size=60)


class _Run:
    """A manager on a fake clock, with a recording Pushover."""

    def __init__(self) -> None:
        self.now = 1_000_000.0
        self.pushover = MagicMock(spec=Pushover)
        self.manager = PowerwallManager(
            "test@example.com",
            send_notifications=False,
            pushover=self.pushover,
            clock=lambda: self.now,
        )

    def step(self, minutes: int, reading: float) -> float | None:
        self.now += minutes * 60
        return self.manager.sanitize_battery_percentage(reading, 1.0)

    @property
    def pages(self) -> int:
        return int(self.pushover.send_message.call_count)


def _trusted(reading: float) -> bool:
    return round(reading, 2) > 0


@settings(max_examples=300, deadline=None)
@given(_steps)
def test_history_holds_only_observed_readings(steps: list[tuple[int, float]]) -> None:
    run = _Run()
    observed: list[float] = []
    for minutes, reading in steps:
        run.step(minutes, reading)
        if _trusted(reading):
            observed.insert(0, round(reading, 2))
        assert run.manager.battery_history.percentages == observed[: BatteryHistory.MAX_HISTORY]


@settings(max_examples=300, deadline=None)
@given(_steps)
def test_result_is_a_percentage_or_nothing(steps: list[tuple[int, float]]) -> None:
    run = _Run()
    for minutes, reading in steps:
        result = run.step(minutes, reading)
        assert result is None or 0 <= result <= 100


@settings(max_examples=300, deadline=None)
@given(_steps)
def test_trusted_reading_ends_the_outage(steps: list[tuple[int, float]]) -> None:
    run = _Run()
    for minutes, reading in steps:
        run.step(minutes, reading)
        if _trusted(reading):
            assert run.manager.bad_read_since is None
            assert run.manager.last_staleness_alert is None


@settings(max_examples=300, deadline=None)
@given(_steps)
def test_pages_are_late_enough_and_spaced_within_an_outage(
    steps: list[tuple[int, float]],
) -> None:
    cfg = get_config().tesla
    alert_after = cfg.staleness_alert_after_min * 60
    realert_gap = cfg.staleness_realert_hours * 3600

    run = _Run()
    outage_start: float | None = None
    last_page: float | None = None
    for minutes, reading in steps:
        before = run.pages
        run.step(minutes, reading)
        paged = run.pages - before

        if _trusted(reading):
            assert paged == 0
            outage_start, last_page = None, None
            continue

        if outage_start is None:
            outage_start = run.now
        assert paged <= 1
        if paged:
            assert run.now - outage_start >= alert_after
            assert last_page is None or run.now - last_page >= realert_gap
            last_page = run.now


@settings(max_examples=300, deadline=None)
@given(_steps)
def test_an_outage_past_the_threshold_pages_and_repeats(steps: list[tuple[int, float]]) -> None:
    """The alert is not only rate-limited, it also fires: silence is the worse bug."""
    cfg = get_config().tesla
    alert_after = cfg.staleness_alert_after_min * 60
    realert_gap = cfg.staleness_realert_hours * 3600

    run = _Run()
    outage_start: float | None = None
    last_page: float | None = None
    for minutes, reading in steps:
        before = run.pages
        run.step(minutes, reading)
        if _trusted(reading):
            outage_start, last_page = None, None
            continue
        if outage_start is None:
            outage_start = run.now
            continue
        if run.now - outage_start < alert_after:
            continue
        due = last_page is None or run.now - last_page >= realert_gap
        assert (run.pages > before) == due
        if due:
            last_page = run.now
