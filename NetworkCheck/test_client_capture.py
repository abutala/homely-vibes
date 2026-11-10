"""Tests for the client capture. A fake host records every change, so no root and no network."""

import socket
import struct
from collections.abc import Callable

import pytest

from NetworkCheck.client_capture import (
    FIX_REPEATS,
    FRESH_CAP,
    SPOOF_INTERVAL,
    Refused,
    arp_lookup,
    arp_reply,
    capture,
    default_route,
    reset_reply,
)
from NetworkCheck.pcap_summary import mac_bytes

IFACE = "eth0"
GATEWAY, GATEWAY_MAC = "192.0.2.1", "02-00-00-00-00-01"
HOST, HOST_MAC = "192.0.2.2", "02-00-00-00-00-02"
CLIENT, CLIENT_MAC = "192.0.2.10", "02-00-00-00-00-0a"
PEER = "198.51.100.7"
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
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
        self.inbox: list[list[bytes]] = []

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

    def own_ip(self, gateway: str) -> str:
        return HOST

    def listen(self, iface: str, secs: float) -> list[bytes]:
        self.sleep(secs)
        return self.inbox.pop(0) if self.inbox else []

    def sleep(self, secs: float) -> None:
        self.clock = round(self.clock + secs, 6)
        if self.interrupt_at is not None and self.clock >= self.interrupt_at:
            self.interrupt_at = None
            raise KeyboardInterrupt

    def now(self) -> float:
        return self.clock


def run(host: FakeHost, mac: str = CLIENT_MAC, secs: int = 60, reset: bool = False) -> list[str]:
    return capture(host, CLIENT, mac, secs, "/tmp/out.pcap", lambda _: None, reset)


def tcp_frame(
    *,
    src_mac: str = CLIENT_MAC,
    dst_mac: str = HOST_MAC,
    dst_ip: str = PEER,
    proto: int = 6,
    frag: int = 0,
    sport: int = 40000,
    flags: int = ACK | PSH,
    seq: int = 1000,
    payload: bytes = b"x" * 10,
) -> bytes:
    """A frame the client sends to `dst_ip` through this host. Checksums are left at 0."""
    tcp = struct.pack("!HHIIBBHHH", sport, 8883, seq, 5000, 5 << 4, flags, 1024, 0, 0)
    tcp += payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcp), 1, frag, 64, proto, 0,
        socket.inet_aton(CLIENT), socket.inet_aton(dst_ip),
    )  # fmt: skip
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + b"\x08\x00" + ip + tcp


def answer(frame: bytes, fresh: set[tuple[bytes, int, int]] | None = None) -> bytes | None:
    return reset_reply(
        frame,
        mac_bytes(CLIENT_MAC),
        mac_bytes(HOST_MAC),
        socket.inet_aton(HOST),
        set() if fresh is None else fresh,
    )


def checksum_ok(data: bytes) -> bool:
    """True when the 16-bit ones' complement sum, checksum included, is all ones."""
    data += b"\x00" * (len(data) % 2)
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def split_reset(frame: bytes) -> tuple[bytes, bytes]:
    """(IP header, TCP header) of a reset, after checking its Ethernet header and checksums."""
    assert len(frame) == 54
    assert frame[:14] == mac_bytes(CLIENT_MAC) + mac_bytes(HOST_MAC) + b"\x08\x00"
    ip, tcp = frame[14:34], frame[34:]
    assert checksum_ok(ip)
    assert checksum_ok(ip[12:20] + struct.pack("!BBH", 0, 6, 20) + tcp)
    return ip, tcp


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


class TestReset:
    def test_an_old_connection_gets_a_reset_from_the_peer(self) -> None:
        reply = answer(tcp_frame())
        assert reply is not None
        ip, tcp = split_reset(reply)
        assert ip[9] == 6 and ip[8] == 64
        assert ip[12:20] == socket.inet_aton(PEER) + socket.inet_aton(CLIENT)
        assert struct.unpack("!HHII", tcp[:12]) == (8883, 40000, 5000, 0)
        assert tcp[13] == RST

    @pytest.mark.parametrize(
        ("flags", "payload", "acked"), [(PSH, b"x" * 10, 1010), (FIN, b"", 1001)]
    )
    def test_with_no_ack_the_reset_acks_the_segment(
        self, flags: int, payload: bytes, acked: int
    ) -> None:
        reply = answer(tcp_frame(flags=flags, payload=payload))
        assert reply is not None
        _, tcp = split_reset(reply)
        assert struct.unpack("!II", tcp[4:12]) == (0, acked)
        assert tcp[13] == RST | ACK

    def test_a_syn_keeps_only_its_own_connection_open(self) -> None:
        fresh: set[tuple[bytes, int, int]] = set()
        assert answer(tcp_frame(flags=SYN, payload=b""), fresh) is None
        assert answer(tcp_frame(), fresh) is None
        assert answer(tcp_frame(sport=40001), fresh) is not None
        assert answer(tcp_frame(dst_ip="198.51.100.8"), fresh) is not None

    def test_a_syn_flood_does_not_grow_memory_past_the_cap(self) -> None:
        fresh = {(b"\x00" * 4, n, 0) for n in range(FRESH_CAP)}
        assert answer(tcp_frame(flags=SYN, payload=b""), fresh) is None
        assert len(fresh) == FRESH_CAP
        assert answer(tcp_frame(), fresh) is not None

    def test_the_hosts_own_reset_is_never_answered(self) -> None:
        """AF_PACKET also sees what this host sends: no reset loop."""
        reply = answer(tcp_frame())
        assert reply is not None
        assert answer(reply) is None

    def test_ip_options_and_ethernet_padding_are_read(self) -> None:
        plain = tcp_frame()
        ip = bytes([0x46]) + plain[15:16] + struct.pack("!H", 24 + 30) + plain[18:34]
        with_options = plain[:14] + ip + b"\x01\x01\x01\x01" + plain[34:]
        assert answer(with_options) == answer(plain)
        assert answer(plain + b"\x00" * 8) == answer(plain)

    @pytest.mark.parametrize(
        "frame",
        [
            tcp_frame(flags=RST | ACK),
            tcp_frame(src_mac=GATEWAY_MAC),
            tcp_frame(dst_mac=GATEWAY_MAC),
            tcp_frame(dst_ip=HOST),
            tcp_frame(proto=17),
            tcp_frame(frag=0x2000),
            tcp_frame(frag=5),
            tcp_frame()[:40],
            tcp_frame()[:46] + bytes([0x40]) + tcp_frame()[47:],
            tcp_frame()[:46] + bytes([0xF0]) + tcp_frame()[47:],
            arp_reply(CLIENT_MAC, CLIENT, HOST_MAC, GATEWAY),
        ],
        ids=[
            "an RST",
            "from another sender",
            "not sent to this host",
            "to this host's own IP",
            "UDP",
            "first fragment",
            "later fragment",
            "cut short",
            "TCP header under 20 bytes",
            "TCP header past the segment",
            "ARP",
        ],
    )
    def test_no_reset(self, frame: bytes) -> None:
        assert answer(frame) is None


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
        assert host.sent.count(spoof) == round(60 / SPOOF_INTERVAL)
        assert_restored(host)

    def test_reset_answers_old_connections_while_capturing(self) -> None:
        host = FakeHost()
        host.inbox = [[tcp_frame(flags=SYN, payload=b"")], [tcp_frame(), tcp_frame(sport=40001)]]
        assert run(host, reset=True) == []
        reply = answer(tcp_frame(sport=40001))
        assert reply is not None and host.sent.count(reply) == 1
        assert answer(tcp_frame()) not in host.sent
        spoof = arp_reply(HOST_MAC, GATEWAY, CLIENT_MAC, CLIENT)
        assert host.sent.count(spoof) == round(60 / SPOOF_INTERVAL)
        assert_restored(host)

    def test_no_reset_unless_asked(self) -> None:
        host = FakeHost()
        host.inbox = [[tcp_frame()]]
        assert run(host) == []
        assert host.inbox == [[tcp_frame()]]

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
