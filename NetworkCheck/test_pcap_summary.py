"""Tests for the pcap summary. Pure functions over bytes built here, so no fakes."""

import socket
import struct

import pytest

from NetworkCheck.pcap_summary import dns_questions, frames, report, summarize, tls_sni

CLIENT_MAC = "02-00-00-00-00-01"
HOST_MAC = "02-00-00-00-00-02"
GATEWAY_MAC = "02-00-00-00-00-03"
CLIENT_IP, PEER_IP, DNS_IP = "192.0.2.10", "198.51.100.7", "192.0.2.53"


def mac(text: str) -> bytes:
    return bytes.fromhex(text.replace("-", ""))


def ipv4(src: str, dst: str, proto: int, l4: bytes, ttl: int = 64) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )  # fmt: skip
    return header + l4


def ether(src: str, dst: str, packet: bytes) -> bytes:
    return mac(dst) + mac(src) + b"\x08\x00" + packet


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 0, 0, 0) + payload


def dns_query(name: str, response: bool = False) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    flags = 0x8180 if response else 0x0100
    return struct.pack("!HHHHHH", 7, flags, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def client_hello(server: str) -> bytes:
    name = server.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack("!HH", 0, len(sni)) + sni
    body = b"\x03\x03" + 32 * b"\0" + b"\0" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(ext)) + ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def pcap(records: list[tuple[float, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in records:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame
    return out


def sent(ts: float, packet: bytes) -> tuple[float, bytes]:
    return ts, ether(CLIENT_MAC, HOST_MAC, packet)


class TestFrames:
    def test_rejects_a_file_that_is_not_pcap(self) -> None:
        with pytest.raises(ValueError, match="pcap"):
            list(frames(b"not a pcap at all, really"))

    def test_reads_each_record_with_its_time(self) -> None:
        data = pcap([(10.5, b"a" * 20), (12.25, b"b" * 30)])
        assert [(ts, len(f)) for ts, f in frames(data)] == [(10.5, 20), (12.25, 30)]


class TestDns:
    def test_reads_the_question(self) -> None:
        assert dns_questions(dns_query("device.example.com")) == ["device.example.com"]

    def test_a_response_gives_no_question(self) -> None:
        assert dns_questions(dns_query("device.example.com", response=True)) == []

    def test_follows_a_compression_pointer(self) -> None:
        query = dns_query("example.com")
        pointer = b"\x06device\xc0\x0c" + struct.pack("!HH", 1, 1)
        query = query[:4] + struct.pack("!H", 2) + query[6:] + pointer
        assert dns_questions(query) == ["example.com", "device.example.com"]

    def test_a_pointer_loop_gives_no_question(self) -> None:
        looped = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c"
        assert dns_questions(looped) == []

    def test_a_truncated_packet_gives_no_question(self) -> None:
        assert dns_questions(dns_query("device.example.com")[:15]) == []


class TestSni:
    def test_reads_the_server_name(self) -> None:
        assert tls_sni(client_hello("mqtt.example.com")) == "mqtt.example.com"

    @pytest.mark.parametrize("payload", [b"", b"\x17\x03\x03\x00\x05hello", b"\x16\x03\x01\x00"])
    def test_anything_else_gives_none(self, payload: bytes) -> None:
        assert tls_sni(payload) is None


class TestSummarize:
    def test_counts_only_frames_the_client_sent(self) -> None:
        query = ipv4(CLIENT_IP, DNS_IP, 17, udp(4000, 53, dns_query("device.example.com")))
        data = pcap(
            [
                sent(1.0, query),
                (1.0, ether(HOST_MAC, GATEWAY_MAC, query[:8] + b"\x3f" + query[9:])),
                (
                    1.1,
                    ether(GATEWAY_MAC, CLIENT_MAC, ipv4(DNS_IP, CLIENT_IP, 17, udp(53, 4000, b""))),
                ),
            ]
        )
        result = summarize(data, CLIENT_MAC)
        assert result.packets == 1
        assert result.dns == {"device.example.com": 1}

    def test_tracks_each_tls_connection_and_its_server_name(self) -> None:
        data = pcap(
            [
                sent(0.0, ipv4(CLIENT_IP, PEER_IP, 6, tcp(5000, 8883, 0x02))),
                sent(0.1, ipv4(CLIENT_IP, PEER_IP, 6, tcp(5000, 8883, 0x18, client_hello("mqtt.example.com")))),
                sent(2.0, ipv4(CLIENT_IP, PEER_IP, 6, tcp(5000, 8883, 0x11))),
                sent(12.0, ipv4(CLIENT_IP, PEER_IP, 6, tcp(5001, 8883, 0x02))),
            ]
        )  # fmt: skip
        result = summarize(data, CLIENT_MAC)
        assert result.sni == {"mqtt.example.com"}
        assert result.peers[(PEER_IP, "tcp", 8883)] == 4
        first, second = result.connections
        assert (first.port, first.end - first.start, first.flags) == (8883, 2.0, {"SYN", "FIN"})
        assert first.payload == len(client_hello("mqtt.example.com"))
        assert second.start == 12.0

    def test_a_reused_source_port_with_a_new_syn_is_a_new_connection(self) -> None:
        syn = ipv4(CLIENT_IP, PEER_IP, 6, tcp(5000, 443, 0x02))
        result = summarize(pcap([sent(0.0, syn), sent(30.0, syn)]), CLIENT_MAC)
        assert len(result.connections) == 2

    def test_report_names_the_pattern(self) -> None:
        data = pcap(
            [sent(t, ipv4(CLIENT_IP, PEER_IP, 6, tcp(5000 + i, 8883, 0x02))) for i, t in enumerate([0.0, 12.0, 24.0])]
        )  # fmt: skip
        lines = report(summarize(data, CLIENT_MAC), resolve=False)
        assert lines[0] == "packets from client: 3 over 24s"
        assert "DNS questions: none" in lines
        assert lines[-1] == "TCP connections: 3, median length 0.0s, median gap 12.0s"
