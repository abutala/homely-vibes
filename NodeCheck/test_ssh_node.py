#!/usr/bin/env python3
"""Tests for SshNode: heartbeat by sshd banner, over a WAN forward when configured."""

import socket
import socketserver
import threading
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

from NodeCheck.heartbeat_nodes import _NODE_CLASS_BY_TYPE
from NodeCheck.nodes import TCP_TIMEOUT_S, SshNode
from lib.config import NodeConfig, NodeType


class FakeConnect:
    """Stand-in for socket.create_connection: records the call, replies or raises."""

    def __init__(self, reply: bytes = b"", error: OSError | None = None) -> None:
        self.reply = reply
        self.error = error
        self.calls: list[tuple[tuple[str, int], float]] = []

    def __call__(self, target: tuple[str, int], timeout: float) -> Any:
        self.calls.append((target, timeout))
        if self.error:
            raise self.error
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.return_value = self.reply
        return sock


def _node(connect: Any, **overrides: Any) -> SshNode:
    config = NodeConfig(ip="192.0.2.80", node_type=NodeType.SSH, **overrides)
    return SshNode("Remote", config, connect=connect)


def test_banner_means_online() -> None:
    node = _node(FakeConnect(reply=b"SSH-2.0-OpenSSH_10.5\r\n"))
    assert node.heartbeat() is True
    assert node.is_online is True


def test_probes_host_and_port_over_ip() -> None:
    connect = FakeConnect(reply=b"SSH-2.0-OpenSSH\r\n")
    _node(connect, host="wan.example.com", port=48222).heartbeat()
    assert connect.calls == [(("wan.example.com", 48222), TCP_TIMEOUT_S)]


def test_defaults_to_ip_and_port_22() -> None:
    connect = FakeConnect(reply=b"SSH-2.0-OpenSSH\r\n")
    _node(connect).heartbeat()
    assert connect.calls == [(("192.0.2.80", 22), TCP_TIMEOUT_S)]


@pytest.mark.parametrize(
    "error", [socket.timeout("no route"), ConnectionRefusedError(), socket.gaierror("no name")]
)
def test_connection_error_means_offline(error: OSError) -> None:
    node = _node(FakeConnect(error=error), host="wan.example.com")
    assert node.heartbeat() is False
    assert node.is_online is False


def test_non_ssh_reply_means_offline() -> None:
    assert _node(FakeConnect(reply=b"HTTP/1.1 400 Bad Request\r\n")).heartbeat() is False


def test_closed_without_banner_means_offline() -> None:
    assert _node(FakeConnect(reply=b"")).heartbeat() is False


def test_check_state_is_explicitly_unsupported() -> None:
    with pytest.raises(NotImplementedError):
        _node(FakeConnect()).check_state()


def test_heartbeat_maps_ssh_type_to_ssh_node() -> None:
    assert _NODE_CLASS_BY_TYPE[NodeType.SSH] is SshNode


class _BannerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(b"SSH-2.0-Loopback\r\n")


@pytest.fixture
def banner_server() -> Iterator[int]:
    with socketserver.TCPServer(("127.0.0.1", 0), _BannerHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield server.server_address[1]
        server.shutdown()


def test_real_socket_reads_banner(banner_server: int) -> None:
    config = NodeConfig(ip="127.0.0.1", node_type=NodeType.SSH, port=banner_server)
    assert SshNode("Loopback", config).heartbeat() is True
