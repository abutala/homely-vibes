#!/usr/bin/env python3
"""IoT gatekeeper -- keep unknown devices off the Deco's IoT network.

The IoT SSID's password is old and widely shared, and it cannot change: the IoT
devices are too hard to re-provision. So the MAC is the credential. Every tick
reads the client list and blocks any device on the IoT network whose MAC is not
on the allowlist. The main and guest networks are never blocked. After a clean
read, the tick also re-applies the Deco client labels (`deco_names.py`) on every
network: labels only, no access change.

The Deco's own Allow List cannot do this: it covers every SSID except guest,
and devices on the main network must be free to change their MAC.

Layout:
    gatekeeper_policy.py -- who to block; pure and testable
    deco_names.py        -- client labels from config, re-applied each tick
    deco_client.py       -- the Deco local admin API (blocklist verbs)
    common.py            -- notifier, invocation banner, shared Deco admin lock

Deployment: cron runs `check` every few minutes, offset from the watchdog.
"""

import argparse
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Optional, Protocol

from lib.config import IotGatekeeperConfig, get_config
from lib.file_lock import LockTimeoutError
from lib.logger import get_logger
from lib.notifications import Notifier
from NetworkCheck.common import deco_admin_lock, log_invocation, network_notifier
from NetworkCheck.deco_client import DecoAPIError, DecoAuthError, DecoClient
from NetworkCheck.deco_names import NameControl, canonical_names, sync_names
from NetworkCheck.gatekeeper_policy import (
    IOT_INTERFACE,
    Plan,
    canonical_allowlist,
    canonical_mac,
    decode_name,
    plan_blocks,
)

ALERT_TITLE = "IoT Gatekeeper"
NOTICE_INTERVAL_S = 86400
AUTH_PAUSE_S = 3600
# The Deco times out on ~2% of reads and never twice in a row (Logbook), and
# each read already retries three times. Three failed ticks is a real fault.
READ_FAILURES_BEFORE_ALERT = 3
MAX_NAME_CHARS = 40


class GateControl(Protocol):
    """The slice of `DecoClient` the gatekeeper needs."""

    def list_clients(self) -> list[dict[str, Any]]: ...

    def list_blocked(self) -> list[dict[str, Any]]: ...

    def block(self, mac: str, name: str, client_type: str) -> None: ...

    def unblock(self, macs: list[str]) -> None: ...


@dataclass
class GatekeeperState:
    """What survives between cron ticks."""

    read_failures: int = 0
    # A failed login stops the job for an hour. One failure per tick after a
    # password change could otherwise use up the router's login attempts and
    # lock out the watchdog too.
    auth_paused_until: Optional[float] = None
    # Notice key -> when it was last sent. One notice per key per day.
    notices: dict[str, float] = field(default_factory=dict)


def load_state(path: str) -> GatekeeperState:
    try:
        with open(path) as fh:
            raw = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return GatekeeperState()
    if not isinstance(raw, dict):
        return GatekeeperState()
    known = {f.name for f in fields(GatekeeperState)}
    return GatekeeperState(**{k: v for k, v in raw.items() if k in known})


def save_state(path: str, state: GatekeeperState) -> None:
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as fh:
        json.dump(asdict(state), fh)
    os.replace(tmp_path, path)


def describe(client: dict[str, Any]) -> str:
    """MAC and device type only, for logs. Client names are household data and
    stay out of the cron log, as in the watchdog's census."""
    return f"{canonical_mac(client['mac'])} ({client.get('client_type', '?')})"


def push_label(client: dict[str, Any]) -> str:
    """The device's self-reported name on one line, MAC and type on the next.
    For a push only.

    The device picks its own name, so it can claim anything; the MAC stays the
    identity. Quotes and control characters are dropped and the name is cut.
    """
    raw = decode_name(client.get("name", "")).replace('"', "'")
    name = "".join(ch for ch in raw if ch.isprintable()).strip()
    if len(name) > MAX_NAME_CHARS:
        name = name[:MAX_NAME_CHARS] + "…"
    ident = f"{canonical_mac(client['mac'])} · {client.get('client_type', '?')}"
    return f'"{name}"\n{ident}' if name else ident


class IotGatekeeper:
    """Runs one tick: read, decide, block, alert, persist."""

    def __init__(
        self,
        cfg: IotGatekeeperConfig,
        deco: GateControl,
        notifier: Notifier,
        logger: logging.Logger,
        state_file: str,
    ) -> None:
        self.cfg = cfg
        self.deco = deco
        self.notifier = notifier
        self.logger = logger
        self.state_file = state_file
        self.state = load_state(state_file)

    def check_once(self, now: Optional[float] = None, dry_run: bool = False) -> list[str]:
        """One cron tick. Returns the MACs blocked (or, in a dry run, that would be)."""
        now = time.time() if now is None else now
        paused = self.state.auth_paused_until
        if paused is not None and now < paused:
            self.logger.info("Paused after a failed login until %s", time.ctime(paused))
            return []
        try:
            plan = self._plan(now, dry_run)
            return [] if plan is None else self._apply(plan, now, dry_run)
        finally:
            # A dry run must not pause or reset the live job's counters.
            if not dry_run:
                self._prune_notices(now)
                save_state(self.state_file, self.state)

    def _plan(self, now: float, dry_run: bool) -> Optional[Plan]:
        # Parsed per tick, not at start: `snapshot` and `unblock` -- the fix
        # for a wrong block -- must still run when the allowlist is malformed.
        try:
            allowed = canonical_allowlist(list(self.cfg.allowed_macs))
        except ValueError as err:
            self._notice("allowlist", f"Blocked nothing: bad allowed_macs: {err}", 1, now, dry_run)
            return None
        try:
            clients = self.deco.list_clients()
            blocked = frozenset(canonical_mac(e["mac"]) for e in self.deco.list_blocked())
            # Inside the guard: a client row with an unparsable MAC must count
            # as a failed read and alert, not crash every tick in silence.
            plan = plan_blocks(clients, allowed, blocked, self.cfg.max_blocks_per_tick)
        except DecoAuthError as err:
            self.state.auth_paused_until = now + AUTH_PAUSE_S
            self._notice("auth", f"Deco login failed; paused for an hour: {err}", 0, now, dry_run)
            return None
        except Exception as err:
            # Broad on purpose: block nothing on any read we cannot trust.
            self.state.read_failures += 1
            self.logger.error("Deco read failed (%d in a row): %s", self.state.read_failures, err)
            if self.state.read_failures >= READ_FAILURES_BEFORE_ALERT:
                self._notice(
                    "read",
                    f"Cannot read the Deco for {self.state.read_failures} ticks: {err}",
                    1,
                    now,
                    dry_run,
                )
            return None

        self.state.read_failures = 0
        self.state.auth_paused_until = None
        return plan

    def _apply(self, plan: Plan, now: float, dry_run: bool) -> list[str]:
        """One push per device: a short message each, never a list to scan."""
        for client in plan.shared:
            self._notice(
                f"shared:{canonical_mac(client['mac'])}",
                f"Not blocked, also on another network: {describe(client)}",
                0,
                now,
                dry_run,
                push=f"{push_label(client)}\n\nNot blocked: also on another network,\n"
                "and the Deco block is mesh-wide.",
            )
        if plan.refusal:
            for client in plan.strangers:
                self._notice(
                    f"refusal:{canonical_mac(client['mac'])}",
                    f"Not blocked: {plan.refusal}: {describe(client)}",
                    1,
                    now,
                    dry_run,
                    push=f"{push_label(client)}\n\nNot blocked: {plan.refusal}.",
                )
            if not plan.strangers:
                self._notice("refusal", f"Blocked nothing: {plan.refusal}", 1, now, dry_run)
            return []

        done: list[str] = []
        for client in plan.to_block:
            mac = canonical_mac(client["mac"])
            if dry_run:
                self.logger.info("Dry run -- would block %s", describe(client))
                done.append(mac)
                continue
            try:
                self.deco.block(
                    mac, str(client.get("name", "")), str(client.get("client_type", ""))
                )
            except DecoAPIError as err:
                self._notice(
                    f"block:{mac}",
                    f"Block of {describe(client)} failed: {err}",
                    1,
                    now,
                    dry_run,
                    push=f"{push_label(client)}\n\nBlock failed: {err}",
                )
                break
            self.logger.info("Blocked %s", describe(client))
            self._send(
                f"{push_label(client)}\n\nBlocked on the IoT Wi-Fi.\n"
                f"Undo: iot_gatekeeper unblock {mac}\n"
                "then add it to allowed_macs.",
                0,
            )
            done.append(mac)
        return done

    def _notice(
        self,
        key: str,
        message: str,
        priority: int,
        now: float,
        dry_run: bool,
        push: Optional[str] = None,
    ) -> None:
        """Log `message` every time; push `push` (default `message`) at most once
        a day per key, never in a dry run. `push` may carry device names."""
        self.logger.warning(message)
        if dry_run or now - self.state.notices.get(key, 0) < NOTICE_INTERVAL_S:
            return
        if self._send(message if push is None else push, priority):
            self.state.notices[key] = now

    def _prune_notices(self, now: float) -> None:
        self.state.notices = {
            k: ts for k, ts in self.state.notices.items() if now - ts < NOTICE_INTERVAL_S
        }

    def _send(self, message: str, priority: int) -> bool:
        try:
            return self.notifier.send_message(message, title=ALERT_TITLE, priority=priority)
        except Exception as err:
            self.logger.error("Notifier raised: %s", err)
            return False

    def snapshot(self) -> list[str]:
        """The IoT network's clients as allowlist lines, for the operator to prune.

        Interactive only: this prints device names, so never run it from cron.
        """
        clients = [c for c in self.deco.list_clients() if c.get("interface") == IOT_INTERFACE]
        lines = [f"# {len(clients)} client(s) on the IoT network. Delete what is not yours."]
        for c in sorted(clients, key=lambda c: (str(c.get("client_type")), str(c.get("mac")))):
            lines.append(
                f'- "{canonical_mac(c["mac"])}"  # {c.get("client_type", "?")}: '
                f"{decode_name(c.get('name', ''))}"
            )
        return lines

    def unblock(self, raw_mac: str) -> str:
        mac = canonical_mac(raw_mac)
        self.deco.unblock([mac])
        return mac


def _deco() -> DecoClient:
    wd = get_config().network_check.uplink_watchdog
    return DecoClient(wd.deco_host, wd.deco_username, wd.deco_password)


def _build(logger: logging.Logger, deco: DecoClient) -> IotGatekeeper:
    cfg = get_config()
    gk = cfg.network_check.iot_gatekeeper
    state_file = os.path.join(cfg.paths.logging_dir, gk.state_file)
    return IotGatekeeper(gk, deco, network_notifier(), logger, state_file)


def _run(args: argparse.Namespace, logger: logging.Logger) -> None:
    deco = _deco()
    gatekeeper = _build(logger, deco)
    if args.command == "snapshot":
        for line in gatekeeper.snapshot():
            print(line)
    elif args.command == "unblock":
        print(f"Unblocked {gatekeeper.unblock(args.mac)}")
    elif not gatekeeper.cfg.enabled and not args.dry_run:
        logger.info("Gatekeeper disabled in config; nothing to do")
    else:
        done = gatekeeper.check_once(dry_run=args.dry_run)
        print(f"{'would block' if args.dry_run else 'blocked'}={len(done)}")
        _sync_labels(deco, gatekeeper.state, logger, args.dry_run)


def _sync_labels(
    deco: NameControl, state: GatekeeperState, logger: logging.Logger, dry_run: bool
) -> None:
    """Re-apply `deco_names` on the same login, so a device that was offline gets
    its label on the first tick after it reconnects. Only after a clean read:
    while the login is paused or reads fail, another login would add to the
    failed attempts and hold the admin lock longer. Labels are cosmetic: a
    failure is logged and retried next tick, never alerted."""
    if state.auth_paused_until is not None or state.read_failures:
        return
    try:
        wanted = canonical_names(get_config().network_check.deco_names)
        if wanted:
            sync_names(deco, wanted, logger, dry_run=dry_run)
    except Exception as err:
        logger.error("Deco label sync failed: %s", err)


def main() -> None:
    parser = argparse.ArgumentParser(description="Block unknown MACs on the Deco IoT network")
    parser.add_argument("command", choices=["check", "snapshot", "unblock"])
    parser.add_argument("mac", nargs="?", help="MAC address, for unblock")
    parser.add_argument("--dry-run", action="store_true", help="Decide and log, never block")
    args = parser.parse_args()
    if args.command == "unblock" and not args.mac:
        parser.error("unblock needs a MAC")

    logger = get_logger(__name__)
    log_invocation(logger)
    try:
        with deco_admin_lock():
            _run(args, logger)
    except LockTimeoutError:
        logger.warning("Another script holds the Deco admin session; skipping this tick")
        if args.command != "check":
            raise SystemExit(f"{args.command}: the Deco admin session is busy; try again") from None


if __name__ == "__main__":
    main()
