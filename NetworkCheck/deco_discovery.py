#!/usr/bin/env python3
"""Put a name to a Deco client: what a device says about itself on the LAN.

The Deco shows a MAC and whatever name a device advertises, and the vendor's app
often hides the MAC. Some devices announce their vendor ID on the LAN, and that ID
is what the vendor's app and Alexa know them by. Each command joins that ID to the
client's MAC through its IP, and prints the current label.

Prints labels and vendor IDs, and holds the admin session: run by hand, never from cron.

Usage:
    python -m NetworkCheck.deco_discovery ewelink          # macOS only: uses dns-sd
    python -m NetworkCheck.deco_discovery tuya [--secs 30]
"""

import argparse
import hashlib
import json
import select
import socket
import subprocess
import time
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from lib.config import get_config
from NetworkCheck.common import deco_admin_lock
from NetworkCheck.deco_client import DecoClient
from NetworkCheck.deco_names import canonical_names
from NetworkCheck.gatekeeper_policy import canonical_mac

EWELINK_SERVICE = "_ewelink._tcp"
BROWSE_SECS = 12.0
RESOLVE_SECS = 4.0

TUYA_PORTS = (6666, 6667)
# Public: every Tuya device on earth encrypts its discovery broadcast with this.
TUYA_UDP_KEY_SEED = b"yGAdlopoPVldABfn"
TUYA_HEADER_BYTES = 20
TUYA_FOOTER_BYTES = 8

DnsSd = Callable[[list[str], float], str]


def parse_browse(output: str) -> list[str]:
    """Instance names from `dns-sd -B`, added ones only."""
    lines = (line.split() for line in output.splitlines())
    return [fields[-1] for fields in lines if len(fields) >= 7 and fields[1] == "Add"]


def parse_address(output: str) -> Optional[str]:
    """The address from `dns-sd -G v4`, or None if nothing answered."""
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[1] == "Add":
            return fields[5]
    return None


def _json_object(raw: bytes) -> Optional[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _tuya_decrypt(body: bytes) -> bytes:
    key = hashlib.md5(TUYA_UDP_KEY_SEED, usedforsecurity=False).digest()
    # Tuya's protocol, not a choice: the broadcast is AES-ECB under a public key.
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # nosemgrep
    plain = decryptor.update(body) + decryptor.finalize()
    return plain[: -plain[-1]] if 0 < plain[-1] <= 16 else plain


def parse_tuya(packet: bytes) -> Optional[dict[str, Any]]:
    """Device ID, product key and version from a broadcast, or None if unreadable.
    Older firmware sends plain JSON, newer firmware encrypts it. Newer framing than
    this (a different header) is unreadable, not an error."""
    body = packet[TUYA_HEADER_BYTES:-TUYA_FOOTER_BYTES]
    info = _json_object(body)
    if info is None and body and len(body) % 16 == 0:
        info = _json_object(_tuya_decrypt(body))
    if info is None or "gwId" not in info:
        return None
    return {
        "gwId": info["gwId"],
        "productKey": info.get("productKey"),
        "version": info.get("version"),
    }


def collect_tuya(packets: Iterable[tuple[bytes, str]]) -> dict[str, str]:
    """IP to device ID, from the first readable broadcast of each sender."""
    found: dict[str, str] = {}
    for packet, ip in packets:
        if ip not in found and (info := parse_tuya(packet)) is not None:
            found[ip] = str(info["gwId"])
    return found


def match_clients(
    devices: Mapping[str, Optional[str]],
    clients: list[dict[str, Any]],
    labels: Mapping[str, str],
) -> list[str]:
    """One line per vendor ID: its address, then the Deco client at that address."""
    by_ip = {c.get("ip"): c for c in clients}
    lines = []
    for device_id, ip in sorted(devices.items()):
        client = by_ip.get(ip)
        if ip is None:
            lines.append(f"{device_id}  (no address)")
        elif client is None:
            lines.append(f"{device_id}  {ip}  (not on the Deco)")
        else:
            mac = canonical_mac(client["mac"])
            label = labels.get(mac, "(no label)")
            lines.append(f"{device_id}  {ip}  {mac}  {client.get('interface', '?')}  {label}")
    return lines


def _dns_sd(args: list[str], secs: float) -> str:
    """dns-sd never exits on its own: run it for `secs`, keep what it printed."""
    try:
        return subprocess.run(
            ["dns-sd", *args], capture_output=True, text=True, timeout=secs, check=False
        ).stdout
    except subprocess.TimeoutExpired as err:
        out = err.stdout or b""
        return out.decode(errors="replace") if isinstance(out, bytes) else out


def ewelink_devices(run: DnsSd = _dns_sd) -> dict[str, Optional[str]]:
    """eWeLink device ID to IP: each announces itself as `eWeLink_<id>`."""
    names = parse_browse(run(["-B", EWELINK_SERVICE, "local."], BROWSE_SECS))
    return {
        name.removeprefix("eWeLink_"): parse_address(
            run(["-G", "v4", f"{name}.local"], RESOLVE_SECS)
        )
        for name in names
    }


def _tuya_broadcasts(secs: float) -> Iterator[tuple[bytes, str]]:
    socks = []
    try:
        for port in TUYA_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            socks.append(sock)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Broadcasts arrive on any interface. Nothing is served: it only listens.
            sock.bind(
                ("", port)
            )  # nosemgrep: python.lang.security.audit.network.bind.avoid-bind-to-all-interfaces
        deadline = time.monotonic() + secs
        while (left := deadline - time.monotonic()) > 0:
            ready, _, _ = select.select(socks, [], [], left)
            for sock in ready:
                data, (ip, _) = sock.recvfrom(4096)
                yield data, ip
    finally:
        for sock in socks:
            sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Join vendor device IDs to Deco clients")
    parser.add_argument("command", choices=["ewelink", "tuya"])
    parser.add_argument("--secs", type=float, default=30.0, help="Tuya: how long to listen")
    args = parser.parse_args()

    if args.command == "ewelink":
        devices = ewelink_devices()
    else:
        devices = {
            device_id: ip for ip, device_id in collect_tuya(_tuya_broadcasts(args.secs)).items()
        }

    cfg = get_config().network_check
    wd = cfg.uplink_watchdog
    with deco_admin_lock():
        clients = DecoClient(wd.deco_host, wd.deco_username, wd.deco_password).list_clients()
    for line in match_clients(devices, clients, canonical_names(cfg.deco_names)):
        print(line)


if __name__ == "__main__":
    main()
