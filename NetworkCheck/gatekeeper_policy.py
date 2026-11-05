#!/usr/bin/env python3
"""Which clients the IoT gatekeeper blocks. Pure: no network, no clock, no I/O.

The whole risk of the gatekeeper is a wrong block -- an IoT device that drops
off the network until a human notices. So every rule here leans toward "block
nothing and say so": an empty allowlist, an IoT network that looks empty, and
more strangers in one tick than the cap all refuse the whole tick.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional

IOT_INTERFACE = "iot"
_HEX12 = re.compile(r"^[0-9A-F]{12}$")


def canonical_mac(raw: object) -> str:
    """``AA-BB-CC-DD-EE-FF`` from any separator or case. Raises on anything else.

    A non-string is rejected outright: YAML reads an unquoted all-digit MAC
    written with colons as a base-60 integer, which would silently stop matching.
    """
    if not isinstance(raw, str):
        raise ValueError(f"MAC must be a quoted string, got {type(raw).__name__}: {raw!r}")
    digits = raw.replace(":", "").replace("-", "").upper()
    if not _HEX12.match(digits):
        raise ValueError(f"Not a MAC address: {raw!r}")
    return "-".join(digits[i : i + 2] for i in range(0, 12, 2))


def canonical_allowlist(raw: list[object]) -> frozenset[str]:
    """The allowlist as canonical MACs. One malformed entry fails the whole load."""
    return frozenset(canonical_mac(entry) for entry in raw)


@dataclass(frozen=True)
class Plan:
    """What one tick will do.

    ``refusal`` set means block nothing this tick; ``strangers`` still lists who
    would have been blocked so the alert can name them.
    """

    to_block: list[dict[str, Any]] = field(default_factory=list)
    strangers: list[dict[str, Any]] = field(default_factory=list)
    # Unknown on the IoT network but seen elsewhere too. The blocklist is
    # mesh-wide by MAC, so blocking these would also cut the main network.
    shared_macs: list[str] = field(default_factory=list)
    refusal: Optional[str] = None


def _is_live_wireless(client: dict[str, Any]) -> bool:
    return bool(client.get("online", True)) and client.get("connection_type") != "wired"


def plan_blocks(
    clients: list[dict[str, Any]],
    allowed: frozenset[str],
    blocked: frozenset[str],
    max_blocks: int,
) -> Plan:
    """Decide this tick's blocks from one client list and one blocklist."""
    if not allowed:
        return Plan(refusal="the allowlist is empty")

    clients = [c for c in clients if c.get("mac")]
    iot = [c for c in clients if c.get("interface") == IOT_INTERFACE]
    if not iot:
        return Plan(refusal="no clients on the IoT network (interface renamed?)")

    elsewhere = {canonical_mac(c["mac"]) for c in clients if c.get("interface") != IOT_INTERFACE}
    unknown = [
        c
        for c in iot
        if _is_live_wireless(c)
        and canonical_mac(c["mac"]) not in allowed
        and canonical_mac(c["mac"]) not in blocked
    ]
    shared = sorted(
        canonical_mac(c["mac"]) for c in unknown if canonical_mac(c["mac"]) in elsewhere
    )
    strangers = [c for c in unknown if canonical_mac(c["mac"]) not in elsewhere]

    if len(strangers) > max_blocks:
        return Plan(
            strangers=strangers,
            shared_macs=shared,
            refusal=f"{len(strangers)} unknown devices is more than the cap of {max_blocks}",
        )
    return Plan(to_block=strangers, strangers=strangers, shared_macs=shared)
