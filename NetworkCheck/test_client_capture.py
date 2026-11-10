"""Tests for the client capture. A fake host records every change, so no root and no network."""

from collections.abc import Callable

import pytest

from NetworkCheck.client_capture import (
    FIX_REPEATS,
    Refused,
    arp_lookup,
    arp_reply,
    capture,
    default_route,
)

IFACE = "eth0"
GATEWAY, GATEWAY_MAC = "192.0.2.1", "02-00-00-00-00-01"
HOST_MAC = "02-00-00-00-00-02"
CLIENT, CLIENT_MAC = "192.0.2.10", "02-00-00-00-00-0a"
ORIGINAL = {
    "net.ipv4.ip_forward": "0",
    "net.ipv4.conf.all.send_redirects": "1",
    f"net.ipv4.conf.{IFACE}.send_redirects": "1",
}


class FakeHost:
    def __init__(self, neighbours: dict[str, str] | None = None, fail: str = "") -> None:
        self.neighbours = (
            {GATEWAY: GATEWAY_MAC, CLIENT: CLIENT_MAC} if neighbours is None else neighbours
        )
        self.sysctls = dict(ORIGINAL)
        self.rules: list[str] = []
        self.sent: list[bytes] = []
        self.dumping = False
        self.clock = 0.0
        self.fail = fail
        self.interrupt_at: float | None = None

    def route(self) -> tuple[str, str]:
        return IFACE, GATEWAY

    def own_mac(self, iface: str) -> str:
        return HOST_MAC

    def neighbour_mac(self, iface: str, ip: str) -> str | None:
        return self.neighbours.get(ip)

    def get_sysctl(self, key: str) -> str:
        return self.sysctls[key]

    def set_sysctl(self, key: str, value: str) -> None:
        self.sysctls[key] = value

    def forward_rule(self, add: bool, ip: str) -> None:
        if self.fail == "rule" and not add:
            raise OSError("iptables gone")
        if self.fail == "rule-interrupt" and not add:
            raise KeyboardInterrupt
        self.rules = self.rules + [ip] if add else [r for r in self.rules if r != ip]

    def start_dump(self, iface: str, ip: str, out: str) -> Callable[[], None]:
        if self.fail == "dump":
            raise OSError("no tcpdump")
        self.dumping = True

        def stop() -> None:
            self.dumping = False

        return stop

    def send(self, iface: str, frame: bytes) -> None:
        self.sent.append(frame)

    def sleep(self, secs: float) -> None:
        self.clock += secs
        if self.interrupt_at is not None and self.clock >= self.interrupt_at:
            self.interrupt_at = None
            raise KeyboardInterrupt

    def now(self) -> float:
        return self.clock


def run(host: FakeHost, mac: str = CLIENT_MAC, secs: int = 60) -> list[str]:
    return capture(host, CLIENT, mac, secs, "/tmp/out.pcap", lambda _: None)


def assert_restored(host: FakeHost) -> None:
    assert host.sysctls == ORIGINAL
    assert host.rules == []
    assert not host.dumping
    fix = arp_reply(GATEWAY_MAC, GATEWAY, CLIENT_MAC, CLIENT)
    assert host.sent[-FIX_REPEATS:] == [fix] * FIX_REPEATS


class TestFrames:
    def test_arp_reply_says_the_ip_is_at_the_sender(self) -> None:
        frame = arp_reply(HOST_MAC, GATEWAY, CLIENT_MAC, CLIENT)
        assert frame[:6] == bytes.fromhex("02000000000a")
        assert frame[6:12] == bytes.fromhex("020000000002")
        assert frame[12:14] == b"\x08\x06"
        assert frame[20:22] == b"\x00\x02"
        assert frame[22:28] == bytes.fromhex("020000000002")
        assert frame[28:32] == bytes([192, 0, 2, 1])
        assert frame[38:42] == bytes([192, 0, 2, 10])

    def test_default_route_from_procfs(self) -> None:
        table = (
            "Iface\tDestination\tGateway\tFlags\n"
            "eth0\t000200C0\t00000000\t0001\n"
            "eth0\t00000000\t010200C0\t0003\n"
        )
        assert default_route(table) == ("eth0", "192.0.2.1")

    def test_no_default_route_refuses(self) -> None:
        with pytest.raises(Refused):
            default_route("Iface\tDestination\tGateway\n")

    def test_arp_lookup_skips_incomplete_entries(self) -> None:
        table = (
            "IP address  HW type  Flags  HW address  Mask  Device\n"
            "192.0.2.10  0x1  0x0  00:00:00:00:00:00  *  eth0\n"
            "192.0.2.1   0x1  0x2  02:00:00:00:00:01  *  eth0\n"
        )
        assert arp_lookup(table, "192.0.2.10") is None
        assert arp_lookup(table, "192.0.2.1") == "02:00:00:00:00:01"


class TestCapture:
    def test_forwards_without_redirects_while_capturing(self) -> None:
        host = FakeHost()
        seen: dict[str, str] = {}
        host.interrupt_at = 2.0
        original_sleep = host.sleep

        def snapshot(secs: float) -> None:
            seen.update(host.sysctls)
            original_sleep(secs)

        host.sleep = snapshot  # type: ignore[method-assign]
        run(host)
        assert seen == {key: "0" if "redirects" in key else "1" for key in ORIGINAL}

    def test_redirects_records_then_restores(self) -> None:
        host = FakeHost()
        assert run(host) == []
        spoof = arp_reply(HOST_MAC, GATEWAY, CLIENT_MAC, CLIENT)
        assert host.sent.count(spoof) == 30
        assert_restored(host)

    def test_ctrl_c_still_restores(self) -> None:
        host = FakeHost()
        host.interrupt_at = 10.0
        assert run(host) == []
        assert_restored(host)

    def test_one_failed_step_does_not_skip_the_others(self) -> None:
        host = FakeHost(fail="rule")
        assert run(host) == ["firewall rules"]
        assert host.sysctls == ORIGINAL
        assert not host.dumping

    def test_a_second_ctrl_c_during_undo_skips_only_that_step(self) -> None:
        host = FakeHost(fail="rule-interrupt")
        assert run(host) == ["firewall rules"]
        assert host.sysctls == ORIGINAL
        assert not host.dumping

    def test_a_failed_start_undoes_what_was_done(self) -> None:
        host = FakeHost(fail="dump")
        with pytest.raises(OSError):
            run(host)
        assert host.sysctls == ORIGINAL
        assert host.rules == []
        assert host.sent == []

    @pytest.mark.parametrize(
        ("neighbours", "mac", "secs", "why"),
        [
            (None, "02-00-00-00-00-0b", 60, "not 02-00-00-00-00-0b"),
            ({GATEWAY: GATEWAY_MAC}, CLIENT_MAC, 60, "no MAC"),
            ({CLIENT: CLIENT_MAC}, CLIENT_MAC, 60, "gateway"),
            (None, HOST_MAC, 60, "this host"),
            (None, CLIENT_MAC, 5, "--secs"),
            (None, "not-a-mac", 60, "Not a MAC"),
        ],
    )
    def test_refuses_before_changing_anything(
        self, neighbours: dict[str, str] | None, mac: str, secs: int, why: str
    ) -> None:
        host = FakeHost(neighbours)
        with pytest.raises(Refused, match=why):
            run(host, mac=mac, secs=secs)
        assert host.sysctls == ORIGINAL and host.rules == [] and host.sent == []
