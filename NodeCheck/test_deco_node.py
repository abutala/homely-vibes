#!/usr/bin/env python3
"""Tests for DecoNode: presence by MAC on the Deco client list."""

from typing import Any

import pytest

from NetworkCheck.deco_client import DecoAPIError, DecoAuthError
from NodeCheck.heartbeat_nodes import _NODE_CLASS_BY_TYPE
from NodeCheck.nodes import CycleCachedRead, DecoNode, ProbeUnavailable
from lib.config import NodeConfig, NodeType
from lib.file_lock import LockTimeoutError

MAC = "AA-BB-CC-00-11-22"


def _node(clients: list[dict[str, Any]] | Exception, mac: str | None = MAC) -> DecoNode:
    def list_clients() -> list[dict[str, Any]]:
        if isinstance(clients, Exception):
            raise clients
        return clients

    config = NodeConfig(ip="192.0.2.79", node_type=NodeType.DECO, mac=mac)
    return DecoNode("Phone", config, list_clients=list_clients)


def test_online_client_means_up() -> None:
    node = _node([{"mac": MAC, "online": True, "interface": "guest"}])
    assert node.heartbeat() is True
    assert node.is_online is True


@pytest.mark.parametrize("configured", ["aa:bb:cc:00:11:22", "aa-bb-cc-00-11-22"])
def test_mac_match_ignores_case_and_separator(configured: str) -> None:
    assert _node([{"mac": MAC, "online": True}], mac=configured).heartbeat() is True


def test_client_without_online_field_counts_as_present() -> None:
    assert _node([{"mac": MAC}]).heartbeat() is True


def test_offline_client_means_down() -> None:
    node = _node([{"mac": MAC, "online": False}])
    assert node.heartbeat() is False
    assert node.is_online is False


def test_absent_client_means_down() -> None:
    assert _node([{"mac": "11-22-33-44-55-66", "online": True}]).heartbeat() is False


@pytest.mark.parametrize(
    "error",
    [
        DecoAPIError("no data"),
        DecoAuthError("bad password"),
        LockTimeoutError("busy"),
        OSError("unreachable"),
        TypeError("'NoneType' object is not iterable"),
        ValueError("bad key"),
    ],
)
def test_unreadable_client_list_is_unknown_not_down(error: Exception) -> None:
    node = _node(error)
    node.is_online = True
    with pytest.raises(ProbeUnavailable):
        node.heartbeat()
    assert node.is_online is True


@pytest.mark.parametrize("clients", [[], ["mac", "online"]])
def test_empty_or_malformed_client_list_is_unknown_not_down(clients: list[Any]) -> None:
    """The prod host is a client itself, so an empty list is a bad read, not an outage."""
    with pytest.raises(ProbeUnavailable):
        _node(clients).heartbeat()


def test_missing_mac_fails_the_probe_without_reading_the_deco() -> None:
    assert _node(AssertionError("must not be called"), mac=None).heartbeat() is False


def test_check_state_is_explicitly_unsupported() -> None:
    with pytest.raises(NotImplementedError):
        _node([]).check_state()


def test_heartbeat_maps_deco_type_to_deco_node() -> None:
    assert _NODE_CLASS_BY_TYPE[NodeType.DECO] is DecoNode


class TestCycleCachedRead:
    def test_reads_once_until_reset(self) -> None:
        calls: list[int] = []

        def read() -> list[dict[str, Any]]:
            calls.append(1)
            return [{"mac": MAC}]

        cached = CycleCachedRead(read)
        assert cached() == cached() == [{"mac": MAC}]
        assert len(calls) == 1
        cached.reset()
        cached()
        assert len(calls) == 2

    def test_failed_read_is_kept_for_the_cycle(self) -> None:
        calls: list[int] = []

        def read() -> list[dict[str, Any]]:
            calls.append(1)
            raise DecoAPIError("no data")

        cached = CycleCachedRead(read)
        for _ in range(3):
            with pytest.raises(DecoAPIError):
                cached()
        assert len(calls) == 1

    def test_an_unexpected_error_is_kept_too(self) -> None:
        calls: list[int] = []

        def read() -> list[dict[str, Any]]:
            calls.append(1)
            raise TypeError("'NoneType' object is not iterable")

        cached = CycleCachedRead(read)
        for _ in range(3):
            with pytest.raises(TypeError):
                cached()
        assert len(calls) == 1

    def test_nodes_sharing_one_read_log_in_once(self) -> None:
        calls: list[int] = []

        def read() -> list[dict[str, Any]]:
            calls.append(1)
            return [{"mac": MAC, "online": True}]

        cached = CycleCachedRead(read)
        config = NodeConfig(ip="192.0.2.79", node_type=NodeType.DECO, mac=MAC)
        nodes = [DecoNode(f"Node {i}", config, list_clients=cached) for i in range(3)]
        assert all(node.heartbeat() for node in nodes)
        assert len(calls) == 1
