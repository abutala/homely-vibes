"""Tests for the IoT gatekeeper tick. A fake Deco behind the GateControl
Protocol stands in for the router; no patching."""

import base64
import logging
from pathlib import Path
from typing import Any, Optional

import pytest

from lib.config import IotGatekeeperConfig
from NetworkCheck.conftest import NOW, FakeNotifier
from NetworkCheck.deco_client import DecoAPIError, DecoAuthError
from NetworkCheck.iot_gatekeeper import (
    AUTH_PAUSE_S,
    MAX_NAME_CHARS,
    NOTICE_INTERVAL_S,
    READ_FAILURES_BEFORE_ALERT,
    IotGatekeeper,
    decode_name,
    push_label,
)

KNOWN = "AA-AA-AA-AA-AA-01"
STRANGER = "BB-BB-BB-BB-BB-02"


def iot(mac: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "mac": mac,
        "interface": "iot",
        "connection_type": "band2_4",
        "online": True,
        "client_type": "phone",
        "name": "U2VjcmV0IFBob25l",  # "Secret Phone"
    }
    row.update(extra)
    return row


class FakeDeco:
    def __init__(self, clients: list[dict[str, Any]], read_error: Optional[Exception] = None):
        self.clients = clients
        self.blocked: list[dict[str, Any]] = []
        self.read_error = read_error
        self.block_error: Optional[Exception] = None
        self.block_calls: list[tuple[str, str, str]] = []
        self.unblocked: list[str] = []

    def list_clients(self) -> list[dict[str, Any]]:
        if self.read_error:
            raise self.read_error
        return self.clients

    def list_blocked(self) -> list[dict[str, Any]]:
        return self.blocked

    def block(self, mac: str, name: str, client_type: str) -> None:
        if self.block_error:
            raise self.block_error
        self.block_calls.append((mac, name, client_type))
        self.blocked.append({"mac": mac})

    def unblock(self, macs: list[str]) -> None:
        self.unblocked += macs


def make(
    tmp_path: Path, deco: FakeDeco, allowed: Optional[list[Any]] = None
) -> tuple[IotGatekeeper, FakeNotifier]:
    cfg = IotGatekeeperConfig(
        enabled=True,
        allowed_macs=[KNOWN] if allowed is None else allowed,
        max_blocks_per_tick=3,
        state_file="state.json",
    )
    notifier = FakeNotifier()
    gk = IotGatekeeper(cfg, deco, notifier, logging.getLogger("test"), str(tmp_path / "state.json"))
    return gk, notifier


def test_blocks_a_stranger_and_pushes_its_name_but_never_logs_it(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    deco = FakeDeco([iot(KNOWN), iot(STRANGER)])
    gk, notifier = make(tmp_path, deco)
    with caplog.at_level(logging.DEBUG):
        assert gk.check_once(NOW) == [STRANGER]
    assert deco.block_calls == [(STRANGER, "U2VjcmV0IFBob25l", "phone")]
    assert len(notifier.sent) == 1
    message = notifier.sent[0][0]
    assert message.startswith(f'"Secret Phone"\n{STRANGER} · phone\n')
    assert "Secret Phone" not in caplog.text


def test_each_blocked_device_gets_its_own_push(tmp_path: Path) -> None:
    other = "BB-BB-BB-BB-BB-03"
    deco = FakeDeco([iot(KNOWN), iot(STRANGER), iot(other)])
    gk, notifier = make(tmp_path, deco)
    assert gk.check_once(NOW) == [STRANGER, other]
    assert [m for m, _, _ in notifier.sent if STRANGER in m] == [notifier.sent[0][0]]
    assert [m for m, _, _ in notifier.sent if other in m] == [notifier.sent[1][0]]


def test_a_refusal_pushes_once_per_device_with_its_name_but_never_logs_it(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    strangers = [iot(f"BB-BB-BB-BB-BB-{i:02X}") for i in range(4)]
    deco = FakeDeco([iot(KNOWN), *strangers])
    gk, notifier = make(tmp_path, deco)
    with caplog.at_level(logging.DEBUG):
        gk.check_once(NOW)
    assert len(notifier.sent) == 4
    for (message, _, priority), client in zip(notifier.sent, strangers):
        assert client["mac"] in message and '"Secret Phone"' in message and priority == 1
    assert "Secret Phone" not in caplog.text


def test_a_refusal_with_no_strangers_pushes_once(tmp_path: Path) -> None:
    deco = FakeDeco([iot(STRANGER)])
    gk, notifier = make(tmp_path, deco, allowed=[])
    gk.check_once(NOW)
    assert len(notifier.sent) == 1 and "allowlist is empty" in notifier.sent[0][0]


def test_each_shared_mac_gets_its_own_push(tmp_path: Path) -> None:
    other = "BB-BB-BB-BB-BB-03"
    rows = [iot(KNOWN), iot(STRANGER), iot(other)]
    deco = FakeDeco(rows + [{**r, "interface": "main"} for r in rows[1:]])
    gk, notifier = make(tmp_path, deco)
    gk.check_once(NOW)
    assert [m.splitlines()[0] for m, _, _ in notifier.sent] == [STRANGER, other]


class TestPushLabel:
    def test_a_device_without_a_name_shows_mac_and_type(self) -> None:
        assert push_label(iot(STRANGER, name="")) == f"{STRANGER} · phone"

    def test_control_characters_are_dropped(self) -> None:
        raw = base64.b64encode(b"Evil\nPhone\x1b[0m").decode()
        assert push_label(iot(STRANGER, name=raw)) == f'"EvilPhone[0m"\n{STRANGER} · phone'

    def test_a_quote_in_the_name_cannot_fake_label_text(self) -> None:
        raw = base64.b64encode(b'x" AA-AA-AA-AA-AA-01 (phone) "').decode()
        assert push_label(iot(STRANGER, name=raw)).count('"') == 2

    def test_a_long_name_is_cut(self) -> None:
        raw = base64.b64encode(b"x" * 100).decode()
        label = push_label(iot(STRANGER, name=raw))
        assert label.startswith('"' + "x" * MAX_NAME_CHARS + '…"')


def test_a_blocked_stranger_is_not_blocked_or_alerted_again(tmp_path: Path) -> None:
    deco = FakeDeco([iot(KNOWN), iot(STRANGER)])
    gk, notifier = make(tmp_path, deco)
    gk.check_once(NOW)
    assert gk.check_once(NOW + 300) == []
    assert len(deco.block_calls) == 1 and len(notifier.sent) == 1


def test_a_dry_run_blocks_nothing_and_pushes_nothing(tmp_path: Path) -> None:
    deco = FakeDeco([iot(KNOWN), iot(STRANGER)])
    gk, notifier = make(tmp_path, deco)
    assert gk.check_once(NOW, dry_run=True) == [STRANGER]
    assert deco.block_calls == [] and notifier.sent == []


def test_a_malformed_allowlist_blocks_nothing_and_alerts(tmp_path: Path) -> None:
    deco = FakeDeco([iot(STRANGER)])
    gk, notifier = make(tmp_path, deco, allowed=[KNOWN, 123456])
    assert gk.check_once(NOW) == []
    assert deco.block_calls == []
    assert len(notifier.sent) == 1 and notifier.sent[0][2] == 1


def test_unblock_works_while_the_allowlist_is_malformed(tmp_path: Path) -> None:
    deco = FakeDeco([])
    gk, _ = make(tmp_path, deco, allowed=["not-a-mac"])
    assert gk.unblock(STRANGER) == STRANGER


def test_a_client_with_a_bad_mac_counts_as_a_failed_read(tmp_path: Path) -> None:
    deco = FakeDeco([iot(KNOWN), iot(STRANGER), {**iot("N/A"), "interface": "main"}])
    gk, _ = make(tmp_path, deco)
    assert gk.check_once(NOW) == []
    assert gk.state.read_failures == 1 and deco.block_calls == []


def test_a_dry_run_leaves_the_live_state_alone(tmp_path: Path) -> None:
    deco = FakeDeco([iot(STRANGER)], read_error=DecoAuthError("bad password"))
    gk, _ = make(tmp_path, deco)
    gk.check_once(NOW, dry_run=True)
    again, _ = make(tmp_path, deco)
    assert again.state.auth_paused_until is None


def test_old_notices_are_pruned(tmp_path: Path) -> None:
    deco = FakeDeco([iot(STRANGER)], read_error=DecoAuthError("bad password"))
    gk, _ = make(tmp_path, deco)
    gk.check_once(NOW)
    assert "auth" in gk.state.notices
    deco.read_error = None
    gk.check_once(NOW + NOTICE_INTERVAL_S + AUTH_PAUSE_S)
    assert "auth" not in gk.state.notices


def test_a_refusal_alerts_once_a_day_per_device(tmp_path: Path) -> None:
    strangers = [iot(f"BB-BB-BB-BB-BB-{i:02X}") for i in range(4)]
    deco = FakeDeco([iot(KNOWN), *strangers])
    gk, notifier = make(tmp_path, deco)
    gk.check_once(NOW)
    gk.check_once(NOW + 300)
    assert deco.block_calls == []
    assert len(notifier.sent) == 4
    gk.check_once(NOW + NOTICE_INTERVAL_S)
    assert len(notifier.sent) == 8


def test_read_failures_block_nothing_and_alert_only_after_several(tmp_path: Path) -> None:
    deco = FakeDeco([iot(STRANGER)], read_error=DecoAPIError("timeout"))
    gk, notifier = make(tmp_path, deco)
    for tick in range(READ_FAILURES_BEFORE_ALERT - 1):
        gk.check_once(NOW + tick * 300)
    assert notifier.sent == []
    gk.check_once(NOW + 3000)
    assert len(notifier.sent) == 1
    assert deco.block_calls == []


def test_a_good_read_resets_the_failure_count(tmp_path: Path) -> None:
    deco = FakeDeco([iot(KNOWN)], read_error=DecoAPIError("timeout"))
    gk, _ = make(tmp_path, deco)
    gk.check_once(NOW)
    deco.read_error = None
    gk.check_once(NOW + 300)
    assert gk.state.read_failures == 0


def test_a_failed_login_pauses_for_an_hour(tmp_path: Path) -> None:
    deco = FakeDeco([iot(STRANGER)], read_error=DecoAuthError("bad password"))
    gk, notifier = make(tmp_path, deco)
    gk.check_once(NOW)
    deco.read_error = None
    assert gk.check_once(NOW + 300) == []
    assert len(notifier.sent) == 1 and notifier.sent[0][2] == 0
    assert gk.check_once(NOW + AUTH_PAUSE_S) == [STRANGER]


def test_a_failed_block_stops_the_tick_and_alerts(tmp_path: Path) -> None:
    deco = FakeDeco([iot(KNOWN), iot(STRANGER), iot("BB-BB-BB-BB-BB-03")])
    deco.block_error = DecoAPIError("Maximum number exceeded")
    gk, notifier = make(tmp_path, deco)
    assert gk.check_once(NOW) == []
    assert len(notifier.sent) == 1 and "Maximum number exceeded" in notifier.sent[0][0]


def test_state_survives_a_restart(tmp_path: Path) -> None:
    deco = FakeDeco([iot(STRANGER)], read_error=DecoAPIError("timeout"))
    gk, _ = make(tmp_path, deco)
    gk.check_once(NOW)
    again, _ = make(tmp_path, deco)
    assert again.state.read_failures == 1


def test_snapshot_lists_only_the_iot_network_as_quoted_macs(tmp_path: Path) -> None:
    deco = FakeDeco([iot("aa:aa:aa:aa:aa:01"), {**iot(STRANGER), "interface": "main"}])
    gk, _ = make(tmp_path, deco)
    lines = gk.snapshot()
    assert lines[1] == '- "AA-AA-AA-AA-AA-01"  # phone: Secret Phone'
    assert len(lines) == 2


def test_unblock_canonicalizes_the_mac(tmp_path: Path) -> None:
    deco = FakeDeco([])
    gk, _ = make(tmp_path, deco)
    assert gk.unblock("bb:bb:bb:bb:bb:02") == STRANGER
    assert deco.unblocked == [STRANGER]


def test_decode_name_falls_back_to_the_raw_value() -> None:
    assert decode_name("not base64!") == "not base64!"
