"""Tests for the Deco config dump. No patch(): the read function is a parameter."""

from __future__ import annotations

import base64
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from NetworkCheck.deco_client import DecoAPIError
from NetworkCheck.deco_config_dump import (
    FORMS,
    READ_OPERATIONS,
    add_decoded_names,
    collect,
    render_devices_md,
    scrub_session,
    write_dump,
)

TAKEN_AT = "2026-01-02T03:04:05+00:00"
WIFI_PASSWORD = "wifi-password-value"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


RESPONSES: dict[str, dict[str, Any]] = {
    "device_list": {
        "device_list": [
            {
                "nickname": _b64("Unit A"),
                "device_model": "model-1",
                "role": "master",
                "mac": "AA-AA-AA-AA-AA-AA",
                "device_ip": "192.0.2.1",
                "software_ver": "1.0",
                "hardware_ver": "2.0",
            }
        ]
    },
    "client_list": {
        "client_list": [
            {
                "name": _b64("Client A"),
                "mac": "BB-BB-BB-BB-BB-BB",
                "ip": "192.0.2.2",
                "interface": "main",
                "connection_type": "band5",
                "online": True,
            }
        ]
    },
    "black_list": {
        "client_list": [{"name": _b64("Client B"), "mac": "CC-CC-CC-CC-CC-CC", "client_type": "x"}]
    },
    "wlan": {
        "band2_4": {
            "host": {
                "ssid": _b64("Net A"),
                "password": WIFI_PASSWORD,
                "enable": True,
                "channel": 6,
            }
        },
        "is_eg": False,
    },
}


def _read(path: str, form: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"error_code": 0, "result": RESPONSES.get(form, {})}


def _dump() -> dict[str, Any]:
    return collect(_read, TAKEN_AT)


class TestCollect:
    def test_every_form_is_a_read(self) -> None:
        assert {f.operation for f in FORMS} <= READ_OPERATIONS

    def test_reads_each_form_once_with_its_payload(self) -> None:
        calls: list[tuple[str, str, dict[str, Any]]] = []

        def read(path: str, form: str, payload: dict[str, Any]) -> dict[str, Any]:
            calls.append((path, form, payload))
            return {"result": {}}

        collect(read, TAKEN_AT)

        assert len(calls) == len(FORMS)
        assert (
            "admin/client",
            "client_list",
            {"operation": "read", "params": {"device_mac": "default"}},
        ) in calls
        assert ("admin/client", "black_list", {"operation": "list"}) in calls

    def test_keys_each_form_by_path_and_form(self) -> None:
        dump = _dump()

        assert dump["taken_at"] == TAKEN_AT
        assert dump["admin/wireless?form=wlan"]["result"]["band2_4"]["host"]["enable"] is True

    def test_a_failed_read_stops_the_dump(self) -> None:
        def read(path: str, form: str, payload: dict[str, Any]) -> dict[str, Any]:
            raise DecoAPIError("boom")

        with pytest.raises(DecoAPIError):
            collect(read, TAKEN_AT)


class TestAddDecodedNames:
    def test_adds_a_decoded_copy_and_keeps_the_original(self) -> None:
        encoded = _b64("Net A")

        assert add_decoded_names({"ssid": encoded}) == {"ssid": encoded, "ssid_decoded": "Net A"}

    def test_walks_nested_lists(self) -> None:
        assert add_decoded_names({"a": [{"name": _b64("X")}]})["a"][0]["name_decoded"] == "X"

    @pytest.mark.parametrize("value", ["not base64!", None, 3, _b64("x")[:-1]])
    def test_leaves_a_value_it_cannot_decode(self, value: Any) -> None:
        assert add_decoded_names({"name": value}) == {"name": value}

    def test_does_not_decode_a_password(self) -> None:
        encoded = _b64("secret")

        assert add_decoded_names({"password": encoded}) == {"password": encoded}


class TestRenderDevicesMd:
    def test_lists_units_networks_clients_and_blocked(self) -> None:
        text = render_devices_md(_dump())

        assert "# Deco config, 2026-01-02" in text
        assert "| Unit A | model-1 | master | AA-AA-AA-AA-AA-AA | 192.0.2.1 | 1.0 | 2.0 |" in text
        assert "| band2_4 | host | Net A | True | 6 |" in text
        assert "| Client A | BB-BB-BB-BB-BB-BB | 192.0.2.2 | main | band5 | True |" in text
        assert "| Client B | CC-CC-CC-CC-CC-CC | x |" in text

    def test_a_plain_text_nickname_is_shown_as_it_is(self) -> None:
        def read(path: str, form: str, payload: dict[str, Any]) -> dict[str, Any]:
            if form == "device_list":
                return {"result": {"device_list": [{"nickname": "office"}]}}
            return _read(path, form, payload)

        assert "| office |" in render_devices_md(collect(read, TAKEN_AT))

    def test_never_prints_a_password(self) -> None:
        assert WIFI_PASSWORD not in render_devices_md(_dump())


class TestWriteDump:
    def test_writes_both_files_owner_only(self, tmp_path: Path) -> None:
        out = tmp_path / "new" / "dir"

        write_dump(out, _dump())

        assert json.loads((out / "deco_dump.json").read_text())["taken_at"] == TAKEN_AT
        assert "Unit A" in (out / "devices.md").read_text()
        for name in ("deco_dump.json", "devices.md"):
            assert stat.S_IMODE((out / name).stat().st_mode) == 0o600

    def test_a_render_failure_writes_nothing(self, tmp_path: Path) -> None:
        with pytest.raises(KeyError):
            write_dump(tmp_path / "out", {"taken_at": TAKEN_AT})

        assert not (tmp_path / "out").exists()


def test_scrub_session_removes_the_token_from_an_error() -> None:
    message = "500 for url: http://192.0.2.1/cgi-bin/luci/;stok=abc123DEF/admin/x?form=y"

    assert scrub_session(message) == (
        "500 for url: http://192.0.2.1/cgi-bin/luci/;stok=REDACTED/admin/x?form=y"
    )
