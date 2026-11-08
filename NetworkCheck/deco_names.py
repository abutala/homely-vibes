#!/usr/bin/env python3
"""Deco client labels from config -- `network_check.deco_names`, MAC to label.

The Deco only lists clients that are online, so a device can be labelled only
while it is connected. `sync` renames every listed client whose label differs;
the IoT gatekeeper runs the same sync on each tick that read the Deco cleanly
(only while the gatekeeper is enabled), so a device that is offline today gets
its label on the first tick after it reconnects.

At most MAX_RENAMES_PER_RUN writes per run: a burst of admin writes times the
Deco out (Logbook), and the tick holds the shared admin lock. Later runs do the rest.

Labels are household data: logs carry MACs only, as in the gatekeeper.

Usage:
    python -m NetworkCheck.deco_names sync [--dry-run]
    python -m NetworkCheck.deco_names list   # online clients with no label in config
"""

import argparse
import logging
from typing import Any, Mapping, Protocol

from lib.config import get_config
from lib.logger import get_logger
from NetworkCheck.common import deco_admin_lock, log_invocation
from NetworkCheck.deco_client import DecoClient
from NetworkCheck.gatekeeper_policy import canonical_mac, decode_name

MAX_RENAMES_PER_RUN = 10


class NameControl(Protocol):
    """The slice of `DecoClient` the sync needs."""

    def list_clients(self) -> list[dict[str, Any]]: ...

    def rename(self, mac: str, name: str, client_type: str) -> None: ...


def canonical_names(raw: Mapping[str, str] | None) -> dict[str, str]:
    """Config map with canonical MACs and trimmed labels. Raises on a bad MAC or
    a blank label, so a typo renames nothing at all instead of the wrong device.
    A bare `deco_names:` key (null) is an empty map."""
    names: dict[str, str] = {}
    for mac, label in (raw or {}).items():
        label = str(label).strip()
        if not label:
            raise ValueError(f"Blank label for {mac!r}")
        names[canonical_mac(mac)] = label
    return names


def name_changes(
    clients: list[dict[str, Any]], wanted: Mapping[str, str]
) -> list[tuple[dict[str, Any], str]]:
    """(client, label) for each listed client whose current label differs."""
    changes = []
    for client in clients:
        label = wanted.get(canonical_mac(client["mac"]))
        if label is not None and decode_name(client.get("name", "")) != label:
            changes.append((client, label))
    return changes


def sync_names(
    deco: NameControl,
    wanted: Mapping[str, str],
    logger: logging.Logger,
    dry_run: bool = False,
    max_renames: int = MAX_RENAMES_PER_RUN,
) -> list[str]:
    """Rename what differs, up to `max_renames`. Returns the MACs renamed (or, in a
    dry run, that would be). A failed rename is logged and left for the next run."""
    changes = name_changes(deco.list_clients(), wanted)
    if len(changes) > max_renames:
        logger.info(
            "%d labels differ; setting %d now, the rest next run", len(changes), max_renames
        )
    done = []
    for client, label in changes[:max_renames]:
        mac = canonical_mac(client["mac"])
        if not dry_run:
            try:
                deco.rename(client["mac"], label, str(client.get("client_type", "other")))
            except Exception as err:
                logger.error("Deco rename failed for %s: %s", mac, err)
                continue
        logger.info("%s label for %s", "Would set" if dry_run else "Set", mac)
        done.append(mac)
    return done


def unlabelled(clients: list[dict[str, Any]], wanted: Mapping[str, str]) -> list[str]:
    """Config lines for online clients with no label yet. Interactive only: this
    prints device names, so never run it from cron."""
    lines = []
    for c in sorted(clients, key=lambda c: (str(c.get("client_type")), str(c.get("mac")))):
        mac = canonical_mac(c["mac"])
        if mac not in wanted:
            lines.append(
                f'"{mac}": "{decode_name(c.get("name", ""))}"'
                f"  # {c.get('client_type', '?')}, {c.get('ip', '?')}"
            )
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply Deco client labels from config")
    parser.add_argument("command", choices=["sync", "list"])
    parser.add_argument("--dry-run", action="store_true", help="Log what would change")
    args = parser.parse_args()

    logger = get_logger(__name__)
    if args.command == "sync":
        # `list` output is pasted into config; the banner goes to stdout too.
        log_invocation(logger)
    cfg = get_config().network_check
    wanted = canonical_names(cfg.deco_names)
    wd = cfg.uplink_watchdog
    with deco_admin_lock():
        deco = DecoClient(wd.deco_host, wd.deco_username, wd.deco_password)
        if args.command == "list":
            for line in unlabelled(deco.list_clients(), wanted):
                print(line)
            return
        done = sync_names(deco, wanted, logger, dry_run=args.dry_run)
        print(f"{'would rename' if args.dry_run else 'renamed'}={len(done)}")


if __name__ == "__main__":
    main()
