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

Every change is undone on Ctrl-C, SIGTERM, SIGHUP (a dropped SSH session) or an error:
the client's ARP entry, the forwarding sysctls and the firewall rules. A second Ctrl-C
during the undo skips only the step it lands in. SIGKILL or a power cut undoes nothing.
"""

import argparse
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import NoReturn, Protocol

from NetworkCheck.pcap_summary import mac_bytes, report, summarize

DEFAULT_OUT = "/tmp/client_capture.pcap"
MIN_SECS, MAX_SECS = 30, 1800
SPOOF_INTERVAL = 2.0
FIX_REPEATS = 5


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
    def sleep(self, secs: float) -> None: ...
    def now(self) -> float: ...


def arp_reply(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    """An Ethernet frame telling `target` that `sender_ip` is at `sender_mac`."""
    sender, target = mac_bytes(sender_mac), mac_bytes(target_mac)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    arp += sender + socket.inet_aton(sender_ip) + target + socket.inet_aton(target_ip)
    return target + sender + b"\x08\x06" + arp


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
    host: Host, client_ip: str, client_mac: str, secs: int, out: str, say: Callable[[str], None]
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
        say(f"capturing {client_ip} for {secs}s -> {out}")
        end = host.now() + secs
        while host.now() < end:
            host.send(iface, spoof)
            host.sleep(SPOOF_INTERVAL)
    except KeyboardInterrupt:
        say("stopped early")
    finally:
        failed = _undo_all(reversed(undo), say)
    return failed


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
            ["tcpdump", "-i", iface, "-s", "600", "-U", "-w", out, "host", ip],
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
        failed = capture(LinuxHost(), args.ip, args.mac, args.secs, args.out, _say)
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
