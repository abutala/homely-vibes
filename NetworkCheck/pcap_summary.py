"""What one LAN client said on the wire: DNS names, TLS server names, peers, connections.

Pure functions over the bytes of a classic pcap file. Only frames the client sent are read
(Ethernet source = its MAC): on the capturing host each forwarded frame also appears a second
time, on its way out, with a lower TTL.
"""

import socket
import struct
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

ETH_IPV4 = b"\x08\x00"
TCP, UDP = 6, 17
FLAG_FIN, FLAG_SYN, FLAG_RST = 0x01, 0x02, 0x04
PCAP_LE = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
PCAP_BE = (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
NANOSECOND_MAGIC = (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")


@dataclass
class Connection:
    """One TCP connection the client opened, keyed by peer and source port."""

    peer: str
    port: int
    start: float
    end: float
    packets: int = 0
    payload: int = 0
    flags: set[str] = field(default_factory=set)


@dataclass
class Summary:
    packets: int = 0
    first: float | None = None
    last: float | None = None
    dns: Counter[str] = field(default_factory=Counter)
    sni: set[str] = field(default_factory=set)
    peers: Counter[tuple[str, str, int]] = field(default_factory=Counter)
    connections: list[Connection] = field(default_factory=list)
    skipped: int = 0


def mac_bytes(mac: str) -> bytes:
    try:
        raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    except ValueError:
        raw = b""
    if len(raw) != 6:
        raise ValueError(f"Not a MAC address: {mac!r}")
    return raw


def frames(data: bytes) -> Iterator[tuple[float, bytes]]:
    """(timestamp, frame) for each record. Raises on a file that is not a classic pcap."""
    magic = data[:4]
    if magic not in PCAP_LE + PCAP_BE:
        raise ValueError("not a classic pcap file")
    endian = "<" if magic in PCAP_LE else ">"
    divisor = 1e9 if magic in NANOSECOND_MAGIC else 1e6
    off = 24
    while off + 16 <= len(data):
        secs, frac, incl, _ = struct.unpack(endian + "IIII", data[off : off + 16])
        yield secs + frac / divisor, data[off + 16 : off + 16 + incl]
        off += 16 + incl


def _name(buf: bytes, off: int) -> tuple[str, int]:
    """A DNS name at `off`, and the offset just past it. Follows compression pointers."""
    labels: list[str] = []
    resume = None
    for _ in range(128):
        length = buf[off]
        if length == 0:
            return ".".join(labels), resume if resume is not None else off + 1
        if length & 0xC0 == 0xC0:
            resume = off + 2 if resume is None else resume
            off = struct.unpack("!H", buf[off : off + 2])[0] & 0x3FFF
            continue
        labels.append(buf[off + 1 : off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    raise ValueError("DNS name loops")


def dns_questions(payload: bytes) -> list[str]:
    """Names asked in a DNS query. A response or a malformed packet gives none."""
    try:
        flags, count = struct.unpack("!HH", payload[2:6])
        if flags & 0x8000:
            return []
        names, off = [], 12
        for _ in range(count):
            name, off = _name(payload, off)
            names.append(name)
            off += 4
        return names
    except (IndexError, struct.error, ValueError):
        return []


def tls_sni(payload: bytes) -> str | None:
    """The server name in a TLS ClientHello, or None for anything else."""
    try:
        if payload[0] != 0x16 or payload[5] != 0x01:
            return None
        off = 43
        off += 1 + payload[off]
        off += 2 + struct.unpack("!H", payload[off : off + 2])[0]
        off += 1 + payload[off]
        end = off + 2 + struct.unpack("!H", payload[off : off + 2])[0]
        off += 2
        while off + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[off : off + 4])
            if ext_type == 0:
                name_len = struct.unpack("!H", payload[off + 7 : off + 9])[0]
                return payload[off + 9 : off + 9 + name_len].decode("ascii", "replace")
            off += 4 + ext_len
    except (IndexError, struct.error):
        return None
    return None


def summarize(data: bytes, client_mac: str) -> Summary:
    """Everything the client sent over IPv4, from one pcap."""
    src = mac_bytes(client_mac)
    out = Summary()
    open_conns: dict[tuple[str, int], Connection] = {}
    for ts, frame in frames(data):
        if frame[6:12] != src or frame[12:14] != ETH_IPV4:
            continue
        try:
            _read(out, open_conns, ts, frame[14:])
        except (IndexError, struct.error, OSError):
            out.skipped += 1
    return out


def _read(
    out: Summary, open_conns: dict[tuple[str, int], Connection], ts: float, ip: bytes
) -> None:
    """Add one IPv4 packet. Raises, changing nothing, on a header too short to read."""
    ihl, proto = (ip[0] & 0x0F) * 4, ip[9]
    total = struct.unpack("!H", ip[2:4])[0]
    peer = socket.inet_ntoa(ip[16:20])
    l4 = ip[ihl:total]
    if proto == TCP and len(l4) < 20:
        raise IndexError("short TCP header")
    out.packets += 1
    out.first = ts if out.first is None else out.first
    out.last = ts
    if proto not in (TCP, UDP) or len(l4) < 4:
        out.peers[(peer, str(proto), 0)] += 1
        return
    sport, dport = struct.unpack("!HH", l4[:4])
    out.peers[(peer, "tcp" if proto == TCP else "udp", dport)] += 1
    if proto == UDP and dport == 53:
        out.dns.update(dns_questions(l4[8:]))
    if proto == TCP:
        _track(open_conns, out, ts, peer, sport, l4)


def _track(
    open_conns: dict[tuple[str, int], Connection],
    out: Summary,
    ts: float,
    peer: str,
    sport: int,
    tcp: bytes,
) -> None:
    flags, payload = tcp[13], tcp[(tcp[12] >> 4) * 4 :]
    conn = open_conns.get((peer, sport))
    if conn is None or flags & FLAG_SYN:
        conn = Connection(peer, struct.unpack("!H", tcp[2:4])[0], ts, ts)
        open_conns[(peer, sport)] = conn
        out.connections.append(conn)
    conn.end, conn.packets, conn.payload = ts, conn.packets + 1, conn.payload + len(payload)
    conn.flags |= {
        n for bit, n in ((FLAG_SYN, "SYN"), (FLAG_FIN, "FIN"), (FLAG_RST, "RST")) if flags & bit
    }
    name = tls_sni(payload) if payload else None
    if name:
        out.sni.add(name)


def report(summary: Summary, resolve: bool = True) -> list[str]:
    """Lines for a person to read. `resolve` adds reverse DNS for each peer."""
    span = 0.0 if summary.first is None or summary.last is None else summary.last - summary.first
    lines = [f"packets from client: {summary.packets} over {span:.0f}s"]
    if summary.skipped:
        lines.append(f"skipped {summary.skipped} packets too short to read")
    lines.append(
        "DNS questions: " + (", ".join(f"{n} x{c}" for n, c in summary.dns.most_common()) or "none")
    )
    lines.append("TLS server names: " + (", ".join(sorted(summary.sni)) or "none"))
    lines.append("peers (address, protocol, port, packets, reverse DNS):")
    for (peer, proto, port), count in summary.peers.most_common(20):
        lines.append(
            f"  {peer:15} {proto:4} {port:5} {count:5}  {_reverse(peer) if resolve else '-'}"
        )
    conns = summary.connections
    if conns:
        durations = sorted(c.end - c.start for c in conns)
        gaps = sorted(b.start - a.start for a, b in zip(conns, conns[1:]))
        lines.append(
            f"TCP connections: {len(conns)}, median length {durations[len(durations) // 2]:.1f}s"
            + (f", median gap {gaps[len(gaps) // 2]:.1f}s" if gaps else "")
        )
    return lines


def _reverse(address: str) -> str:
    try:
        return socket.gethostbyaddr(address)[0]
    except OSError:
        return "-"
