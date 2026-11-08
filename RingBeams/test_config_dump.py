"""Tests for the read-only Ring config dump. No patch(): dependencies are parameters."""

from __future__ import annotations

import asyncio
import json
import logging
import stat
from pathlib import Path
from typing import Any

import pytest
from ring_doorbell import AuthenticationError, RingError

from RingBeams.beams_manager import BeamsAuthError, run_raw_sidecar
from RingBeams.config_dump import (
    DumpRefusedError,
    collect_rest,
    find_secret_paths,
    render_devices_md,
    take_dump,
    write_dump,
)
from lib.config import RingBeamsConfig

TAKEN_AT = "2026-01-02T03:04:05+00:00"
LOCATION = "loc-1"
ACCOUNT_DEVICES: dict[str, list[dict[str, Any]]] = {
    "stickup_cams": [
        {
            "id": 1,
            "description": " Cam A",
            "kind": "cam_v1",
            "device_id": "aabbcc",
            "location_id": LOCATION,
            "firmware_version": "Up to Date",
        }
    ],
    "chimes": [{"id": 2, "description": "Chime A", "kind": "chime_v1", "location_id": LOCATION}],
    "beams": [{"id": 3, "description": "Beam A", "kind": "beam_v1", "location_id": LOCATION}],
}
ALARM_DEVICE = {
    "zid": "zid-1",
    "name": "Door A",
    "deviceType": "sensor.contact",
    "batteryLevel": 80,
    "commStatus": "ok",
    "lastCommTime": 1_800_000_000_000,
    "locationName": "Home",
}


def _rest_responses() -> dict[str, Any]:
    return {
        "https://api.ring.com/clients_api/ring_devices": ACCOUNT_DEVICES,
        "https://api.ring.com/devices/v1/locations": {"user_locations": []},
        f"https://api.ring.com/groups/v1/locations/{LOCATION}/groups": {"device_groups": []},
        f"https://app.ring.com/api/v1/mode/location/{LOCATION}": {"mode": "disarmed"},
        f"https://app.ring.com/api/v1/mode/location/{LOCATION}/settings": {"home": []},
        f"https://app.ring.com/api/v1/mode/location/{LOCATION}/sharing": {"on": False},
        "https://api.ring.com/clients_api/doorbots/1/health": {"device_health": {}},
        "https://api.ring.com/devices/v1/devices/1/settings": {"motion_settings": {}},
        "https://api.ring.com/clients_api/chimes/2/health": {"device_health": {}},
        "https://api.ring.com/clients_api/chimes/2/linked_doorbells": {"doorbells": []},
    }


def _fake_query(responses: dict[str, Any]) -> Any:
    async def query(url: str) -> Any:
        if url not in responses:
            raise RingError(f"HTTP error with status code 404 during query of url {url}")
        response = responses[url]
        if isinstance(response, Exception):
            raise response
        return response

    return query


def _collect(responses: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(collect_rest(_fake_query(responses), TAKEN_AT))


def _valid_dump(alarm_devices: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    dump = _collect(_rest_responses())
    dump["alarm_devices"] = [ALARM_DEVICE] if alarm_devices is None else alarm_devices
    return dump


class TestCollectRest:
    def test_collects_each_device_family_and_location(self) -> None:
        dump = _collect(_rest_responses())

        assert dump["taken_at"] == TAKEN_AT
        assert dump["per_device"]["1"]["settings_v1"] == {"motion_settings": {}}
        assert dump["per_device"]["2"]["linked_doorbells"] == {"doorbells": []}
        assert dump["per_device"]["3"] == {"family": "beams", "name": "Beam A"}
        assert dump["per_location"][LOCATION]["mode"] == {"mode": "disarmed"}
        assert dump["per_location"][LOCATION]["mode_settings"] == {"home": []}

    def test_a_failed_endpoint_is_logged_and_the_rest_continue(self) -> None:
        responses = _rest_responses()
        del responses["https://api.ring.com/clients_api/doorbots/1/health"]

        dump = _collect(responses)

        assert dump["per_device"]["1"]["health"] is None
        assert "404" in dump["_fetch_log"]["/clients_api/doorbots/1/health"]
        assert dump["_fetch_log"]["/devices/v1/devices/1/settings"] == "ok"

    def test_auth_failure_stops_the_dump(self) -> None:
        responses = _rest_responses()
        responses["https://api.ring.com/clients_api/doorbots/1/health"] = AuthenticationError("no")

        with pytest.raises(AuthenticationError):
            _collect(responses)

    def test_no_account_device_list_stops_the_dump(self) -> None:
        responses = _rest_responses()
        del responses["https://api.ring.com/clients_api/ring_devices"]

        with pytest.raises(RuntimeError, match="device list"):
            _collect(responses)

    def test_an_account_with_no_devices_stops_the_dump(self) -> None:
        responses = _rest_responses()
        responses["https://api.ring.com/clients_api/ring_devices"] = {"stickup_cams": []}

        with pytest.raises(RuntimeError, match="device list"):
            _collect(responses)


class TestFindSecretPaths:
    @pytest.mark.parametrize(
        "key",
        ["refresh_token", "accessToken", "password", "pinCode", "access_code", "pin", "api_key"],
    )
    def test_flags_a_secret_named_key_and_never_returns_the_value(self, key: str) -> None:
        paths = find_secret_paths({"devices": [{key: "value-1234"}]})

        assert paths == [f"devices[]/{key}"]
        assert "value-1234" not in json.dumps(paths)

    @pytest.mark.parametrize(
        ("shape", "path"),
        [
            ({"codes": ["1234"]}, "codes"),
            ({"codes": [{"code": "1234"}]}, "codes"),
            ({"passcode": "1234"}, "passcode"),
            ({"pin_code": {"value": "1234"}}, "pin_code"),
            ({"tokens": ["abc"]}, "tokens"),
            ({"meta": '{"pinCode": "1234"}'}, "meta/pinCode"),
            ({"note": "eyJydCI6ImFiYyIsImhpZCI6ImRlZiJ9"}, "note"),
        ],
    )
    def test_flags_nested_and_embedded_shapes(self, shape: dict[str, Any], path: str) -> None:
        assert path in find_secret_paths(shape)

    def test_flags_a_numeric_pin(self) -> None:
        assert find_secret_paths({"pin": 1234}) == ["pin"]

    def test_flags_a_token_shaped_value_under_any_key(self) -> None:
        assert find_secret_paths({"note": "eyJhbGciOiJIUzI1NiJ9.e30.abc"}) == ["note"]

    def test_flags_an_access_code_device_by_type(self) -> None:
        assert find_secret_paths({"deviceType": "access-code.vault"}) == ["deviceType"]

    @pytest.mark.parametrize(
        "clean",
        [
            {"refresh_token": None},
            {"refresh_token": ""},
            {"token_enabled": True},
            {"auth_settings": {"protocol": "oauth"}},
            {"pin_settings": {}},
            {"pir_settings": {"sensitivity": 3}},
            {"codes": []},
            {"zip_code": "00000"},
            {"country_code": "US"},
            {"meta": '{"zid": "zid-1"}'},
            {"note": "{not json"},
            {"deviceType": "sensor.contact"},
        ],
    )
    def test_ignores_empty_values_and_plain_settings(self, clean: dict[str, Any]) -> None:
        assert find_secret_paths(clean) == []


class TestRenderDevicesMd:
    def test_lists_account_and_alarm_devices(self) -> None:
        text = render_devices_md(_valid_dump())

        assert "# Ring devices, 2026-01-02" in text
        assert "| stickup_cams | Cam A | cam_v1 | aabbcc | Up to Date |" in text
        assert "| Door A | sensor.contact | zid-1 | 80 | ok | 2027-01-15 |" in text

    def test_zero_comm_time_means_no_time(self) -> None:
        hub = {**ALARM_DEVICE, "name": "Hub", "lastCommTime": 0, "batteryLevel": None}

        assert "| Hub | sensor.contact | zid-1 |  | ok |  |" in render_devices_md(
            _valid_dump([hub])
        )

    def test_a_pipe_in_a_name_does_not_break_the_table(self) -> None:
        odd = {**ALARM_DEVICE, "name": "Door | Back"}

        assert "| Door / Back |" in render_devices_md(_valid_dump([odd]))


class TestWriteDump:
    def test_writes_both_files_owner_only(self, tmp_path: Path) -> None:
        out = tmp_path / "new" / "dir"

        write_dump(out, _valid_dump())

        assert json.loads((out / "ring_dump.json").read_text())["taken_at"] == TAKEN_AT
        assert "Door A" in (out / "devices.md").read_text()
        for name in ("ring_dump.json", "devices.md"):
            assert stat.S_IMODE((out / name).stat().st_mode) == 0o600

    def test_refuses_a_dump_holding_a_secret_and_writes_nothing(self, tmp_path: Path) -> None:
        bad = _valid_dump([{**ALARM_DEVICE, "pinCode": "1234"}])

        with pytest.raises(DumpRefusedError) as exc:
            write_dump(tmp_path / "out", bad)

        assert "alarm_devices[]/pinCode" in str(exc.value)
        assert "1234" not in str(exc.value)
        assert not (tmp_path / "out").exists()

    def test_a_render_failure_writes_nothing(self, tmp_path: Path) -> None:
        bad = _valid_dump([{**ALARM_DEVICE, "lastCommTime": "not-a-number"}])

        with pytest.raises(TypeError):
            write_dump(tmp_path / "out", bad)

        assert not (tmp_path / "out").exists()


def _sidecar_config(tmp_path: Path) -> RingBeamsConfig:
    token = tmp_path / "token.json"
    token.write_text("{}")
    return RingBeamsConfig(
        token_file=str(token),
        battery_threshold_pct=25,
        sidecar_timeout_seconds=30,
        offline_after_hours=36,
    )


def _fake_sidecar(tmp_path: Path, body: str) -> str:
    script = tmp_path / "sidecar.sh"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    return str(script)


class TestRunRawSidecar:
    def test_asks_the_sidecar_for_raw_data_and_returns_it(self, tmp_path: Path) -> None:
        # The fake answers only when the flag reaches it, so the flag is what is tested.
        fake = _fake_sidecar(
            tmp_path,
            """[ "$RING_BEAMS_RAW" = "1" ] || exit 9
echo '{"devices": [{"zid": "zid-1"}], "errors": []}'""",
        )

        devices, errors = run_raw_sidecar(
            _sidecar_config(tmp_path),
            logging.getLogger("test"),
            node_path="/bin/sh",
            script_path=fake,
        )

        assert devices == [{"zid": "zid-1"}]
        assert errors == []

    def test_auth_exit_raises_auth_error(self, tmp_path: Path) -> None:
        fake = _fake_sidecar(tmp_path, """echo '{"error": "bad"}' >&2; exit 5""")

        with pytest.raises(BeamsAuthError):
            run_raw_sidecar(
                _sidecar_config(tmp_path),
                logging.getLogger("test"),
                node_path="/bin/sh",
                script_path=fake,
            )


class TestTakeDump:
    @staticmethod
    def _run(tmp_path: Path, sidecar_devices: list[Any], errors: list[str]) -> dict[str, Any]:
        def sidecar(lock_fd: int) -> tuple[list[dict[str, Any]], list[str]]:
            assert lock_fd >= 0
            return sidecar_devices, errors

        return take_dump(
            str(tmp_path / "token.json"),
            lambda: collect_rest(_fake_query(_rest_responses()), TAKEN_AT),
            sidecar,
        )

    def test_merges_rest_and_sidecar(self, tmp_path: Path) -> None:
        dump = self._run(tmp_path, [ALARM_DEVICE], [])

        assert dump["alarm_devices"] == [ALARM_DEVICE]
        assert dump["per_device"]["1"]["name"] == " Cam A"

    def test_a_sidecar_error_stops_the_dump(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="getDevices"):
            self._run(tmp_path, [ALARM_DEVICE], ["getDevices(Home): boom"])

    def test_no_alarm_devices_stops_the_dump(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="no alarm devices"):
            self._run(tmp_path, [], [])
