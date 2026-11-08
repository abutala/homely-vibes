#!/usr/bin/env python3
"""Read-only dump of the Deco mesh config, for a backup.

Reads every form the local admin API is known to answer, and writes ``deco_dump.json``
and ``devices.md`` to --out, both 0600. It writes nothing if any read fails. The JSON
holds Wi-Fi passwords, as the router returns them, so keep it out of this repo.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from NetworkCheck.common import deco_admin_lock
from NetworkCheck.deco_client import DecoClient
from lib.config import get_config
from lib.logger import get_logger
from lib.secure_io import write_secret_atomic

READ_OPERATIONS = frozenset({"read", "get", "list"})
ENCODED_FIELDS = frozenset({"name", "nickname", "ssid"})
SESSION_TOKEN = re.compile(r"stok=[0-9a-zA-Z]+")


@dataclass(frozen=True)
class Form:
    path: str
    form: str
    operation: str = "read"
    params: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.path}?form={self.form}"

    @property
    def payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"operation": self.operation}
        if self.params:
            payload["params"] = self.params
        return payload


FORMS = (
    Form("admin/device", "device_list"),
    Form("admin/device", "mode"),
    Form("admin/client", "client_list", params={"device_mac": "default"}),
    Form("admin/client", "black_list", "list"),
    Form("admin/wireless", "wlan"),
    Form("admin/wireless", "power"),
    Form("admin/network", "internet"),
    Form("admin/network", "wan_ipv4"),
    Form("admin/network", "performance"),
    Form("admin/component_control", "switch_list"),
    Form("admin/web", "extra_component_info", "get"),
)

ReadForm = Callable[[str, str, dict[str, Any]], dict[str, Any]]


def _decoded(text: str) -> str | None:
    try:
        return base64.b64decode(text, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None


def add_decoded_names(value: Any) -> Any:
    """Copy the value, adding <field>_decoded beside each base64 name the router returns."""
    if isinstance(value, list):
        return [add_decoded_names(item) for item in value]
    if not isinstance(value, dict):
        return value
    out = {key: add_decoded_names(item) for key, item in value.items()}
    for key in ENCODED_FIELDS & value.keys():
        if isinstance(value[key], str) and (text := _decoded(value[key])) is not None:
            out[f"{key}_decoded"] = text
    return out


def collect(read_form: ReadForm, taken_at: str) -> dict[str, Any]:
    """Read every form. Any failure stops the dump, so a partial one is never written."""
    dump: dict[str, Any] = {"taken_at": taken_at}
    for form in FORMS:
        if form.operation not in READ_OPERATIONS:
            raise ValueError(f"not a read operation: {form.key} {form.operation}")
        dump[form.key] = add_decoded_names(read_form(form.path, form.form, form.payload))
    return dump


def _result(dump: dict[str, Any], form: Form) -> dict[str, Any]:
    return dump[form.key].get("result") or {}


def _table(header: tuple[str, ...], rows: list[tuple[Any, ...]]) -> list[str]:
    def row(cells: tuple[Any, ...]) -> str:
        text = ("" if c is None else str(c).strip().replace("|", "/") for c in cells)
        return "| " + " | ".join(text) + " |"

    return [row(header), "|" + "---|" * len(header), *sorted(row(r) for r in rows), ""]


def _form(name: str) -> Form:
    return next(f for f in FORMS if f.form == name)


def _network_rows(wlan: dict[str, Any]) -> list[tuple[Any, ...]]:
    return [
        (band, kind, net.get("ssid_decoded"), net.get("enable"), net.get("channel"))
        for band, nets in wlan.items()
        if isinstance(nets, dict)
        for kind, net in nets.items()
    ]


def render_devices_md(dump: dict[str, Any]) -> str:
    """The readable index beside deco_dump.json. It never prints a password."""
    units = _result(dump, _form("device_list")).get("device_list", [])
    clients = _result(dump, _form("client_list")).get("client_list", [])
    blocked = _result(dump, _form("black_list")).get("client_list", [])
    return "\n".join(
        [
            f"# Deco config, {dump['taken_at'][:10]}",
            "",
            "Read from the Deco's local admin API, with no change made. Full data: "
            "`deco_dump.json`. It holds Wi-Fi passwords.",
            "",
            "Not included, because the local API did not answer: IoT network settings, DHCP, "
            "address reservations, port forwarding, IPv6, LAN IP, time, parental controls and "
            "QoS. The Deco app holds those. Nothing here restores by itself.",
            "",
            "## Mesh units",
            "",
            *_table(
                ("Name", "Model", "Role", "MAC", "IP", "Software", "Hardware"),
                [
                    (
                        u.get("nickname_decoded") or u.get("nickname"),
                        u.get("device_model"),
                        u.get("role"),
                        u.get("mac"),
                        u.get("device_ip"),
                        u.get("software_ver"),
                        u.get("hardware_ver"),
                    )
                    for u in units
                ],
            ),
            "## Wi-Fi networks",
            "",
            *_table(
                ("Band", "Network", "SSID", "Enabled", "Channel"),
                _network_rows(_result(dump, _form("wlan"))),
            ),
            "## Clients seen at the dump",
            "",
            *_table(
                ("Name", "MAC", "IP", "Network", "Link", "Online"),
                [
                    (
                        c.get("name_decoded"),
                        c.get("mac"),
                        c.get("ip"),
                        c.get("interface"),
                        c.get("connection_type"),
                        c.get("online"),
                    )
                    for c in clients
                ],
            ),
            "## Blocked clients",
            "",
            *_table(
                ("Name", "MAC", "Type"),
                [(b.get("name_decoded"), b.get("mac"), b.get("client_type")) for b in blocked],
            ),
        ]
    )


def write_dump(out_dir: Path, dump: dict[str, Any]) -> None:
    """Write both files 0600. The index renders first, so a bad dump writes nothing."""
    index = render_devices_md(dump)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_secret_atomic(out_dir / "deco_dump.json", json.dumps(dump, indent=1, sort_keys=True))
    write_secret_atomic(out_dir / "devices.md", index)


def scrub_session(message: str) -> str:
    """Client errors quote the request URL, which holds the session token."""
    return SESSION_TOKEN.sub("stok=REDACTED", message)


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only dump of the Deco mesh config.")
    parser.add_argument("--out", type=Path, required=True, help="Directory outside this repo")
    args = parser.parse_args()

    logger = get_logger(__name__)
    watchdog = get_config().network_check.uplink_watchdog
    try:
        with deco_admin_lock():
            deco = DecoClient(watchdog.deco_host, watchdog.deco_username, watchdog.deco_password)
            dump = collect(deco.read_form, datetime.now(UTC).isoformat())
        write_dump(args.out, dump)
    except Exception as e:
        logger.error(f"Deco config dump failed: {scrub_session(str(e))}")
        sys.exit(1)
    logger.info(f"Deco config dump written to {args.out}")


if __name__ == "__main__":
    main()
