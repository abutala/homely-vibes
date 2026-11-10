#!/usr/bin/env python3
"""Record one LAN client's traffic for a few minutes, to learn what the device is.

A device with no open ports names itself only by where it connects. On a switched LAN a
wired host never sees that traffic, so this tells the client alone that the gateway is
at this host (a one-way ARP redirect), forwards what arrives, and records it with tcpdump.
The gateway's ARP table is never touched, so replies go straight back to the client.

Run as root on the wired Linux host, from the repo root, with no lib imports and no
bytecode written, so nothing root-owned is left behind in the checkout:

    sudo .venv/bin/python -B -m NetworkCheck.client_capture capture <ip> <mac> --secs 600
    python -m NetworkCheck.client_capture summary <pcap> <mac>

A device names its server (DNS, TLS server name) only when it connects. With --reset, this
host answers each packet of a connection the device opened before the capture with a TCP
reset, as if from the peer, so the device reconnects through this host. No power cycle.

Every change is undone on Ctrl-C, SIGTERM, SIGHUP (a dropped SSH session) or an error:
the client's ARP entry, the forwarding sysctls and the firewall rules. A second Ctrl-C
during the undo skips only the step it lands in. SIGKILL or a power cut undoes nothing.
"""

import argparse
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from functools import partial
from pathlib import Path
from typing import NoReturn, Protocol

from NetworkCheck.pcap_summary import (
    ETH_IPV4,
    FLAG_ACK,
    FLAG_FIN,
    FLAG_RST,
    FLAG_SYN,
    TCP,
    mac_bytes,
    report,
    summarize,
)

DEFAULT_OUT = "/tmp/client_capture.pcap"
MIN_SECS, MAX_SECS = 30, 1800
SPOOF_INTERVAL = 0.1
FIX_REPEATS = 5
ETH_P_IP = 0x0800
FRESH_CAP = 10_000
Fresh = set[tuple[bytes, int, int]]


def forwarding_sysctls(iface: str) -> dict[str, str]:
    """Forwarding on; ICMP redirects off, or the kernel tells the client to use the real
    gateway. The kernel ORs `all` with the interface's own send_redirects, so both go to 0."""
    return {
        "net.ipv4.ip_forward": "1",
        "net.ipv4.conf.all.send_redirects": "0",
        f"net.ipv4.conf.{iface}.send_redirects": "0",
    }


# AF_PACKET exists only on Linux, and mypy on macOS rejects the attribute by name.
_AF_PACKET = "AF_PACKET"


class Refused(Exception):
    """A pre-flight check failed. Nothing was changed."""


class Host(Protocol):
    def route(self) -> tuple[str, str]: ...
    def own_mac(self, iface: str) -> str: ...
    def neighbour_mac(self, iface: str, ip: str) -> str | None: ...
    def get_sysctl(self, key: str) -> str: ...
    def set_sysctl(self, key: str, value: str) -> None: ...
    def forward_rule(self, add: bool, ip: str) -> None: ...
    def start_dump(self, iface: str, ip: str, out: str) -> Callable[[], None]: ...
    def send(self, iface: str, frame: bytes) -> None: ...
    def own_ip(self, gateway: str) -> str: ...
    def listen(self, iface: str, secs: float) -> list[bytes]: ...
    def sleep(self, secs: float) -> None: ...
    def now(self) -> float: ...


def arp_reply(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    """An Ethernet frame telling `target` that `sender_ip` is at `sender_mac`."""
    sender, target = mac_bytes(sender_mac), mac_bytes(target_mac)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    arp += sender + socket.inet_aton(sender_ip) + target + socket.inet_aton(target_ip)
    return target + sender + b"\x08\x06" + arp


def reset_reply(
    frame: bytes, client_mac: bytes, own_mac: bytes, own_ip: bytes, fresh: Fresh
) -> bytes | None:
    """A TCP reset that ends the client's connection, as if the peer sent it, or None.

    A SYN marks its connection fresh, and a fresh connection is never reset, so the
    reconnect goes through. An RST is never answered. The seq is the client's own ack
    number, the one value a stack must accept (RFC 5961). Past FRESH_CAP connections a
    SYN no longer counts, so a device that floods SYNs cannot use up memory."""
    found = _routed_tcp(frame, client_mac, own_mac, own_ip)
    if found is None:
        return None
    ip, tcp = found
    sport, dport, seq, ack = struct.unpack("!HHII", tcp[:12])
    flags, key = tcp[13], (ip[16:20], sport, dport)
    if flags & FLAG_SYN:
        if len(fresh) < FRESH_CAP:
            fresh.add(key)
        return None
    if flags & FLAG_RST or key in fresh:
        return None
    ports = tcp[2:4] + tcp[0:2]
    if flags & FLAG_ACK:
        segment = _ip_tcp(ip[16:20], ip[12:16], ports, ack, 0, FLAG_RST)
    else:
        length = len(tcp) - (tcp[12] >> 4) * 4 + (1 if flags & FLAG_FIN else 0)
        segment = _ip_tcp(
            ip[16:20], ip[12:16], ports, 0, (seq + length) % 2**32, FLAG_RST | FLAG_ACK
        )
    return client_mac + own_mac + ETH_IPV4 + segment


def _routed_tcp(
    frame: bytes, client_mac: bytes, own_mac: bytes, own_ip: bytes
) -> tuple[bytes, bytes] | None:
    """(IP header, TCP segment) of an unfragmented TCP packet the client sent through this
    host to another host, or None. Traffic to this host itself, such as SSH, is not counted."""
    if len(frame) < 34 or frame[:14] != own_mac + client_mac + ETH_IPV4:
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    fragment = struct.unpack("!H", ip[6:8])[0] & 0x3FFF
    if ip[0] >> 4 != 4 or ihl < 20 or ip[9] != TCP or fragment or ip[16:20] == own_ip:
        return None
    tcp = ip[ihl : struct.unpack("!H", ip[2:4])[0]]
    if len(tcp) < 20 or not 20 <= (tcp[12] >> 4) * 4 <= len(tcp):
        return None
    return ip[:ihl], tcp


def _ip_tcp(src: bytes, dst: bytes, ports: bytes, seq: int, ack: int, flags: int) -> bytes:
    """An IPv4 header and a bare TCP header, with both checksums."""
    tcp = ports + struct.pack("!IIBBHHH", seq, ack, 5 << 4, flags, 0, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, TCP, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, TCP, 0, src, dst)
    return ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:] + tcp


def _checksum(data: bytes) -> int:
    data += b"\x00" * (len(data) % 2)
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def default_route(proc_net_route: str) -> tuple[str, str]:
    """(interface, gateway IP) of the default route in /proc/net/route."""
    for line in proc_net_route.splitlines()[1:]:
        fields = line.split()
        if len(fields) > 2 and fields[1] == "00000000" and fields[2] != "00000000":
            return fields[0], socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
    raise Refused("no default route")


def arp_lookup(proc_net_arp: str, ip: str) -> str | None:
    """The MAC for `ip` in /proc/net/arp, or None when absent or incomplete."""
    for line in proc_net_arp.splitlines()[1:]:
        fields = line.split()
        if len(fields) > 3 and fields[0] == ip and fields[3] != "00:00:00:00:00:00":
            return fields[3]
    return None


def same_mac(a: str, b: str) -> bool:
    return mac_bytes(a) == mac_bytes(b)


def capture(
    host: Host,
    client_ip: str,
    client_mac: str,
    secs: int,
    out: str,
    say: Callable[[str], None],
    reset: bool = False,
) -> list[str]:
    """Redirect, record and restore. Returns the restore steps that failed (none, normally)."""
    if not MIN_SECS <= secs <= MAX_SECS:
        raise Refused(f"--secs must be {MIN_SECS}-{MAX_SECS}")
    try:
        mac_bytes(client_mac)
    except ValueError as err:
        raise Refused(str(err)) from err
    iface, gateway = host.route()
    if client_ip == gateway:
        raise Refused("the client is the gateway")
    own = host.own_mac(iface)
    if same_mac(client_mac, own):
        raise Refused("the client is this host")
    seen = host.neighbour_mac(iface, client_ip)
    if seen is None or not same_mac(seen, client_mac):
        raise Refused(f"{client_ip} is at {seen or 'no MAC'}, not {client_mac}")
    gateway_mac = host.neighbour_mac(iface, gateway)
    if gateway_mac is None:
        raise Refused(f"no ARP entry for the gateway {gateway}")
    fresh: Fresh = set()
    answer = (
        partial(
            reset_reply,
            client_mac=mac_bytes(client_mac),
            own_mac=mac_bytes(own),
            own_ip=socket.inet_aton(host.own_ip(gateway)),
            fresh=fresh,
        )
        if reset
        else None
    )

    forwarding = forwarding_sysctls(iface)
    saved = {key: host.get_sysctl(key) for key in forwarding}
    spoof = arp_reply(own, gateway, client_mac, client_ip)
    fix = arp_reply(gateway_mac, gateway, client_mac, client_ip)
    undo: list[tuple[str, Callable[[], None]]] = []

    def restore_sysctls() -> None:
        for key, value in saved.items():
            host.set_sysctl(key, value)

    try:
        undo.append(("sysctls", restore_sysctls))
        for key, value in forwarding.items():
            host.set_sysctl(key, value)
        undo.append(("firewall rules", lambda: host.forward_rule(False, client_ip)))
        host.forward_rule(True, client_ip)
        undo.append(("tcpdump", host.start_dump(iface, client_ip, out)))
        undo.append(("client ARP entry", lambda: _repeat(host, iface, fix)))
        say(f"capturing {client_ip} for {secs}s -> {out}" + (", with resets" if reset else ""))
        _redirect(host, iface, spoof, secs, answer, say)
    except KeyboardInterrupt:
        say("stopped early")
    finally:
        failed = _undo_all(reversed(undo), say)
    return failed


def _redirect(
    host: Host,
    iface: str,
    spoof: bytes,
    secs: int,
    answer: Callable[[bytes], bytes | None] | None,
    say: Callable[[str], None],
) -> None:
    """Repeat the redirect until `secs` pass. With `answer`, read the client's frames between
    repeats and send the reset it returns for each. Each connection is reported once."""
    told: set[bytes] = set()
    end = host.now() + secs
    while host.now() < end:
        host.send(iface, spoof)
        if answer is None:
            host.sleep(SPOOF_INTERVAL)
            continue
        for frame in host.listen(iface, SPOOF_INTERVAL):
            reply = answer(frame)
            if reply is None:
                continue
            host.send(iface, reply)
            connection = reply[26:30] + reply[34:38]
            if connection not in told:
                told.add(connection)
                port = struct.unpack("!H", reply[34:36])[0]
                say(f"reset {socket.inet_ntoa(reply[26:30])}:{port}")


def _repeat(host: Host, iface: str, frame: bytes) -> None:
    for _ in range(FIX_REPEATS):
        host.send(iface, frame)
        host.sleep(0.5)


def _undo_all(
    steps: Iterable[tuple[str, Callable[[], None]]], say: Callable[[str], None]
) -> list[str]:
    """Run every undo step even when one fails or a second Ctrl-C lands in it, and name the
    ones that failed."""
    failed = []
    for name, step in steps:
        try:
            step()
            say(f"restored {name}")
        except (Exception, KeyboardInterrupt) as err:
            failed.append(name)
            say(f"FAILED to restore {name}: {err}")
    return failed


class LinuxHost:
    """The real host: procfs, sysctl, iptables, tcpdump and a raw socket. Needs root."""

    def __init__(self) -> None:
        self._sock: socket.socket | None = None
        self._recv: socket.socket | None = None

    def route(self) -> tuple[str, str]:
        return default_route(Path("/proc/net/route").read_text())

    def own_mac(self, iface: str) -> str:
        return Path(f"/sys/class/net/{iface}/address").read_text().strip()

    def neighbour_mac(self, iface: str, ip: str) -> str | None:
        subprocess.run(["ping", "-c", "1", "-W", "2", "-I", iface, ip], capture_output=True)
        return arp_lookup(Path("/proc/net/arp").read_text(), ip)

    def get_sysctl(self, key: str) -> str:
        return subprocess.run(
            ["sysctl", "-n", key], capture_output=True, text=True, check=True
        ).stdout.strip()

    def set_sysctl(self, key: str, value: str) -> None:
        subprocess.run(["sysctl", "-qw", f"{key}={value}"], check=True)

    def forward_rule(self, add: bool, ip: str) -> None:
        for side in ("-s", "-d"):
            rule = ["FORWARD", side, ip, "-j", "ACCEPT"]
            subprocess.run(["iptables", "-I" if add else "-D", *rule], check=True)

    def start_dump(self, iface: str, ip: str, out: str) -> Callable[[], None]:
        dump = subprocess.Popen(
            ["tcpdump", "-i", iface, "-s", "2000", "-U", "-w", out, "host", ip],
            stderr=subprocess.DEVNULL,
        )

        def stop() -> None:
            dump.terminate()
            try:
                dump.wait(timeout=10)
            except subprocess.TimeoutExpired:
                dump.kill()
                dump.wait()
            if os.path.exists(out):
                os.chmod(out, 0o644)

        return stop

    def send(self, iface: str, frame: bytes) -> None:
        if self._sock is None:
            self._sock = socket.socket(getattr(socket, _AF_PACKET), socket.SOCK_RAW)
            self._sock.bind((iface, 0))
        self._sock.send(frame)

    def own_ip(self, gateway: str) -> str:
        """The address this host uses toward the gateway. A UDP connect sends no packet."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((gateway, 9))
            return str(probe.getsockname()[0])

    def listen(self, iface: str, secs: float) -> list[bytes]:
        """Every IPv4 frame on `iface` for `secs`. The send socket (protocol 0) receives
        nothing, so this one is separate. No kernel filter: one client's traffic is small."""
        if self._recv is None:
            self._recv = socket.socket(
                getattr(socket, _AF_PACKET), socket.SOCK_RAW, socket.htons(ETH_P_IP)
            )
            self._recv.bind((iface, 0))
        got = []
        end = time.monotonic() + secs
        while (left := end - time.monotonic()) > 0 and select.select([self._recv], [], [], left)[0]:
            got.append(self._recv.recv(65535))
        return got

    def sleep(self, secs: float) -> None:
        time.sleep(secs)

    def now(self) -> float:
        return time.monotonic()


def _interrupt(*_: object) -> NoReturn:
    raise KeyboardInterrupt


def _say(message: str) -> None:
    """Print now; a dead terminal (a dropped SSH session) must not stop the undo."""
    try:
        print(message, flush=True)
    except OSError:
        pass


def _summary_lines(pcap: str, mac: str) -> list[str]:
    try:
        return report(summarize(Path(pcap).read_bytes(), mac))
    except (OSError, ValueError) as err:
        return [f"cannot summarise {pcap}: {err}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    cap = sub.add_parser("capture", help="redirect, record and summarise one client (root)")
    cap.add_argument("ip")
    cap.add_argument("mac")
    cap.add_argument("--secs", type=int, default=600)
    cap.add_argument("--out", default=DEFAULT_OUT)
    cap.add_argument(
        "--reset",
        action="store_true",
        help="reset the client's older TCP connections, so it reconnects through this host",
    )
    summ = sub.add_parser("summary", help="summarise a capture file")
    summ.add_argument("pcap")
    summ.add_argument("mac")
    args = parser.parse_args()

    if args.command == "summary":
        print("\n".join(_summary_lines(args.pcap, args.mac)))
        return 0
    if os.geteuid() != 0:
        print("capture needs root: run it with sudo", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, _interrupt)
    signal.signal(signal.SIGHUP, _interrupt)
    try:
        failed = capture(LinuxHost(), args.ip, args.mac, args.secs, args.out, _say, args.reset)
    except Refused as err:
        print(f"refused, nothing changed: {err}", file=sys.stderr)
        return 2
    if failed:
        print("restore incomplete: " + ", ".join(failed), file=sys.stderr)
        return 1
    _say("\n".join(_summary_lines(args.out, args.mac)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
