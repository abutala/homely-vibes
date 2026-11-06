#!/usr/bin/env python3
"""Tests for SshNode: heartbeat by sshd banner, over a WAN forward when configured."""

import socket
from typing import Any
from unittest.mock import MagicMock

from NodeCheck.heartbeat_nodes import _NODE_CLASS_BY_TYPE
from NodeCheck.nodes import SshNode
from lib.config import NodeConfig, NodeType


class FakeConnect:
    """Stand-in for socket.create_connection: records the target, replies or raises."""

    def __init__(self, reply: bytes = b"", error: OSError | None = None) -> None:
        self.reply = reply
        self.error = error
        self.targets: list[tuple[str, int]] = []

    def __call__(self, target: tuple[str, int], timeout: float) -> Any:
        self.targets.append(target)
        if self.error:
            raise self.error
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.return_value = self.reply
        return sock


def _node(connect: FakeConnect, **overrides: Any) -> SshNode:
    config = NodeConfig(ip="192.0.2.80", node_type=NodeType.SSH, **overrides)
    return SshNode("Remote", config, connect=connect)


def test_banner_means_online() -> None:
    connect = FakeConnect(reply=b"SSH-2.0-OpenSSH_10.5\r\n")
    node = _node(connect)
    assert node.heartbeat() is True
    assert node.is_online is True


def test_probes_ssh_host_and_port_over_ip() -> None:
    connect = FakeConnect(reply=b"SSH-2.0-OpenSSH\r\n")
    _node(connect, ssh_host="wan.example.com", port=48222).heartbeat()
    assert connect.targets == [("wan.example.com", 48222)]


def test_defaults_to_ip_and_port_22() -> None:
    connect = FakeConnect(reply=b"SSH-2.0-OpenSSH\r\n")
    _node(connect).heartbeat()
    assert connect.targets == [("192.0.2.80", 22)]


def test_connection_error_means_offline() -> None:
    node = _node(FakeConnect(error=socket.timeout("no route")))
    assert node.heartbeat() is False
    assert node.is_online is False


def test_non_ssh_reply_means_offline() -> None:
    node = _node(FakeConnect(reply=b"HTTP/1.1 400 Bad Request\r\n"))
    assert node.heartbeat() is False


def test_closed_without_banner_means_offline() -> None:
    assert _node(FakeConnect(reply=b"")).heartbeat() is False


def test_heartbeat_maps_ssh_type_to_ssh_node() -> None:
    assert _NODE_CLASS_BY_TYPE[NodeType.SSH] is SshNode
