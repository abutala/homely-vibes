#!/usr/bin/env python3
"""Tests for HeartbeatMonitor flap-suppression logic."""

from typing import Any, List, cast
from unittest.mock import MagicMock

import pytest

from lib.config import NodeConfig, NodeType
from NodeCheck.heartbeat_nodes import _MAX_CONSECUTIVE_UNKNOWN, HeartbeatMonitor, _build_node
from NodeCheck.nodes import CycleCachedRead, GenericNode, ProbeUnavailable, SshNode


def _fake_node(
    name: str, healthy_sequence: List[bool | Exception], down_polls_for_alert: int | None = None
) -> MagicMock:
    """Build a mock node whose heartbeat() returns the given sequence in order."""
    node = MagicMock()
    node.name = name
    node.config.down_polls_for_alert = down_polls_for_alert
    node.config.ip = f"192.0.2.{abs(hash(name)) % 200 + 1}"
    node.heartbeat.side_effect = healthy_sequence
    return node


def _monitor(nodes: List[MagicMock]) -> HeartbeatMonitor:
    """Construct a HeartbeatMonitor bypassing __init__ (no config, no pushover)."""
    monitor = HeartbeatMonitor.__new__(HeartbeatMonitor)
    monitor.specific_nodes = None
    monitor.pushover = MagicMock()
    monitor.monitored_nodes = cast(List[GenericNode], nodes)
    monitor.last_down_nodes = set()
    monitor.last_notification_time = None
    monitor.consecutive_down = {}
    monitor.consecutive_unknown = {}
    monitor.deco_clients = CycleCachedRead(lambda: [])
    return monitor


class TestFlapSuppression:
    def test_single_down_probe_is_suppressed(self) -> None:
        """One failing probe should NOT surface as down (streak=1 < 2)."""
        node = _fake_node("Phone", [False])
        monitor = _monitor([node])

        assert monitor.check_monitored_nodes() == set()
        assert monitor.consecutive_down["Phone"] == 1

    def test_two_consecutive_down_probes_alert(self) -> None:
        """Two consecutive failures surface the node as down."""
        node = _fake_node("Phone", [False, False])
        monitor = _monitor([node])

        assert monitor.check_monitored_nodes() == set()
        assert monitor.check_monitored_nodes() == {"Phone"}
        assert monitor.consecutive_down["Phone"] == 2

    def test_recovery_resets_streak(self) -> None:
        """A successful probe between failures resets the streak."""
        node = _fake_node("Phone", [False, True, False])
        monitor = _monitor([node])

        assert monitor.check_monitored_nodes() == set()  # streak=1, suppressed
        assert monitor.check_monitored_nodes() == set()  # healthy, reset
        assert monitor.consecutive_down["Phone"] == 0
        assert monitor.check_monitored_nodes() == set()  # streak=1 again, suppressed

    def test_exception_counts_as_down(self) -> None:
        """Uncaught heartbeat exception is treated as a failing probe."""
        node = _fake_node("Broken", [False])
        node.heartbeat.side_effect = RuntimeError("boom")
        monitor = _monitor([node])

        assert monitor.check_monitored_nodes() == set()
        assert monitor.consecutive_down["Broken"] == 1

    def test_mixed_nodes_independent_streaks(self) -> None:
        """Streaks are tracked independently per node."""
        healthy = _fake_node("Server", [True, True])
        flaky = _fake_node("Phone", [False, False])
        monitor = _monitor([healthy, flaky])

        assert monitor.check_monitored_nodes() == set()
        assert monitor.check_monitored_nodes() == {"Phone"}
        assert monitor.consecutive_down["Server"] == 0
        assert monitor.consecutive_down["Phone"] == 2


class TestPerNodeThreshold:
    def test_node_with_a_higher_threshold_alerts_later(self) -> None:
        """A device that leaves Wi-Fi often pages only after its own number of failed polls."""
        node = _fake_node("Phone", [False] * 4, down_polls_for_alert=4)
        monitor = _monitor([node])

        results = [monitor.check_monitored_nodes() for _ in range(4)]
        assert results == [set(), set(), set(), {"Phone"}]

    def test_threshold_is_per_node(self) -> None:
        slow = _fake_node("Phone", [False, False], down_polls_for_alert=4)
        default = _fake_node("Server", [False, False])
        monitor = _monitor([slow, default])

        monitor.check_monitored_nodes()
        assert monitor.check_monitored_nodes() == {"Server"}

    def test_unknown_probe_keeps_down_only_past_the_nodes_own_threshold(self) -> None:
        node = _fake_node(
            "Phone",
            [False, False, ProbeUnavailable("x"), False, False, ProbeUnavailable("x")],
            down_polls_for_alert=4,
        )
        monitor = _monitor([node])

        results = [monitor.check_monitored_nodes() for _ in range(6)]
        assert results == [set(), set(), set(), set(), {"Phone"}, {"Phone"}]

    def test_threshold_of_one_alerts_on_the_first_failed_poll(self) -> None:
        monitor = _monitor([_fake_node("Server", [False], down_polls_for_alert=1)])

        assert monitor.check_monitored_nodes() == {"Server"}

    def test_a_blind_probe_pages_later_for_a_higher_threshold(self) -> None:
        """Unknown polls past the limit count as failed polls toward the node's own threshold."""
        cycles = _MAX_CONSECUTIVE_UNKNOWN + 3
        node = _fake_node("Phone", [ProbeUnavailable("x")] * cycles, down_polls_for_alert=4)
        monitor = _monitor([node])

        results = [monitor.check_monitored_nodes() for _ in range(cycles)]
        assert results == [set()] * (cycles - 1) + [{"Phone"}]

    @pytest.mark.parametrize("bad", [0, -1])
    def test_threshold_below_one_is_a_config_error(self, bad: int) -> None:
        with pytest.raises(ValueError, match="down_polls_for_alert"):
            NodeConfig("192.0.2.1", NodeType.GENERIC, down_polls_for_alert=bad)


class TestUnknownProbe:
    def test_unknown_probe_is_not_a_failure(self) -> None:
        """A probe that could not run leaves the down streak alone."""
        node = _fake_node("Sensor", [False, ProbeUnavailable("list unreadable"), False])
        monitor = _monitor([node])

        assert monitor.check_monitored_nodes() == set()  # streak=1
        assert monitor.check_monitored_nodes() == set()  # unknown: streak stays 1
        assert monitor.consecutive_down["Sensor"] == 1
        assert monitor.check_monitored_nodes() == {"Sensor"}  # streak=2

    def test_unknown_probe_keeps_a_confirmed_down_node_down(self) -> None:
        """Else the monitor would send "recovered", then page again on the next poll."""
        node = _fake_node("Sensor", [False, False, ProbeUnavailable("list unreadable")])
        monitor = _monitor([node])

        monitor.check_monitored_nodes()
        assert monitor.check_monitored_nodes() == {"Sensor"}
        assert monitor.check_monitored_nodes() == {"Sensor"}

    def test_another_error_breaks_the_unknown_streak(self) -> None:
        node = _fake_node("Sensor", [ProbeUnavailable("x"), RuntimeError("boom")])
        monitor = _monitor([node])

        monitor.check_monitored_nodes()
        monitor.check_monitored_nodes()
        assert monitor.consecutive_unknown["Sensor"] == 0

    def test_unknown_probes_never_page_while_under_the_limit(self) -> None:
        node = _fake_node("Sensor", [ProbeUnavailable("x")] * (_MAX_CONSECUTIVE_UNKNOWN - 1))
        monitor = _monitor([node])

        for _ in range(_MAX_CONSECUTIVE_UNKNOWN - 1):
            assert monitor.check_monitored_nodes() == set()
        assert monitor.consecutive_down.get("Sensor", 0) == 0

    def test_unknown_for_too_long_counts_as_down(self) -> None:
        """A probe that stays blind must page in the end, not hide the node for ever."""
        cycles = _MAX_CONSECUTIVE_UNKNOWN + 1
        node = _fake_node("Sensor", [ProbeUnavailable("x")] * cycles)
        monitor = _monitor([node])

        results = [monitor.check_monitored_nodes() for _ in range(cycles)]
        assert results[:-1] == [set()] * (cycles - 1)
        assert results[-1] == {"Sensor"}

    def test_a_working_probe_resets_the_unknown_streak(self) -> None:
        node = _fake_node("Sensor", [ProbeUnavailable("x"), True])
        monitor = _monitor([node])

        monitor.check_monitored_nodes()
        monitor.check_monitored_nodes()
        assert monitor.consecutive_unknown["Sensor"] == 0

    def test_each_cycle_starts_a_fresh_deco_read(self) -> None:
        calls: List[int] = []

        def read() -> List[dict[str, Any]]:
            calls.append(1)
            return []

        monitor = _monitor([])
        monitor.deco_clients = CycleCachedRead(read)

        for _ in range(2):
            monitor.deco_clients()
            monitor.check_monitored_nodes()
            monitor.deco_clients()
        assert len(calls) == 3  # one before the first cycle, then one per cycle


class TestBuildNode:
    def test_deco_nodes_get_the_shared_read(self) -> None:
        calls: List[int] = []

        def read() -> List[dict[str, Any]]:
            calls.append(1)
            return [{"mac": "AA-BB-CC-00-11-22", "online": True}]

        shared = CycleCachedRead(read)
        config = NodeConfig(ip="192.0.2.79", node_type=NodeType.DECO, mac="AA-BB-CC-00-11-22")
        nodes = [_build_node(f"Node {i}", config, shared) for i in range(3)]

        assert all(node.heartbeat() for node in nodes)
        assert len(calls) == 1

    def test_other_types_keep_their_class(self) -> None:
        config = NodeConfig(ip="192.0.2.80", node_type=NodeType.SSH)
        assert type(_build_node("Host", config, CycleCachedRead(lambda: []))) is SshNode


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
