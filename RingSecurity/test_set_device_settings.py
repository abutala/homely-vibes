"""Tests for the Ring device settings helper. No patch(): read and write are parameters."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from RingSecurity.ring_manager import RingAuthError, open_auth
from RingSecurity.set_device_settings import (
    SettingNotAppliedError,
    change_settings,
    parse_args,
)

SETTINGS: dict[str, Any] = {
    "motion_settings": {"motion_on": False, "mode": "edge"},
    "alerts": {"person": {"notify": False, "record": None}},
    "zones": [],
}


class FakeDevice:
    """Holds settings like Ring: a write merges, and can move linked fields too."""

    def __init__(self, linked: dict[str, Any] | None = None, ignores_writes: bool = False) -> None:
        self.settings: dict[str, Any] = {
            "motion_settings": dict(SETTINGS["motion_settings"]),
            "alerts": {"person": dict(SETTINGS["alerts"]["person"])},
            "zones": [],
        }
        self.writes: list[dict[str, Any]] = []
        self.linked = linked or {}
        self.ignores_writes = ignores_writes

    async def read(self) -> dict[str, Any]:
        return self.settings

    async def write(self, patch: dict[str, Any]) -> None:
        self.writes.append(patch)
        if self.ignores_writes:
            return
        self.settings["motion_settings"].update(patch.get("motion_settings", {}))
        self.settings["motion_settings"].update(self.linked)


def _change(device: FakeDevice, patch: dict[str, Any], *, apply: bool) -> dict[str, Any]:
    return asyncio.run(change_settings(device.read, device.write, patch, apply=apply, settle_s=0))


class TestDryRun:
    def test_writes_nothing_and_shows_the_planned_change(self) -> None:
        device = FakeDevice()

        changes = _change(device, {"motion_settings": {"motion_on": True}}, apply=False)

        assert device.writes == []
        assert changes == {"motion_settings.motion_on": [False, True]}

    def test_a_value_already_set_is_no_change(self) -> None:
        assert _change(FakeDevice(), {"motion_settings": {"mode": "edge"}}, apply=False) == {}


class TestApply:
    def test_sends_only_the_patch_once(self) -> None:
        device = FakeDevice()
        patch = {"motion_settings": {"motion_on": True}}

        changes = _change(device, patch, apply=True)

        assert device.writes == [patch]
        assert changes == {"motion_settings.motion_on": [False, True]}

    def test_reports_a_linked_field_that_ring_also_moved(self) -> None:
        device = FakeDevice(linked={"mode": "cloud"})

        changes = _change(device, {"motion_settings": {"motion_on": True}}, apply=True)

        assert changes == {
            "motion_settings.mode": ["edge", "cloud"],
            "motion_settings.motion_on": [False, True],
        }

    def test_a_write_that_did_not_take_raises_and_names_the_setting(self) -> None:
        device = FakeDevice(ignores_writes=True)

        with pytest.raises(SettingNotAppliedError, match="motion_settings.motion_on"):
            _change(device, {"motion_settings": {"motion_on": True}}, apply=True)

    def test_a_field_ring_moved_back_is_still_reported_when_the_write_fails(self) -> None:
        device = FakeDevice(linked={"motion_on": False, "mode": "cloud"})

        with pytest.raises(SettingNotAppliedError, match="motion_settings.mode"):
            _change(device, {"motion_settings": {"motion_on": True}}, apply=True)


class TestStrictCompare:
    """A device that ignores writes, so the read-back sees the value it started with."""

    @staticmethod
    def _apply(settings: dict[str, Any], patch: dict[str, Any], after: dict[str, Any]) -> Any:
        reads = iter([settings, after])

        async def read() -> dict[str, Any]:
            return next(reads)

        async def write(_: dict[str, Any]) -> None:
            return None

        return asyncio.run(change_settings(read, write, patch, apply=True, settle_s=0))

    def test_true_is_not_one(self) -> None:
        with pytest.raises(SettingNotAppliedError, match="x"):
            self._apply({"x": 1}, {"x": True}, {"x": 1})

    def test_true_over_one_is_a_planned_change(self) -> None:
        async def read() -> dict[str, Any]:
            return {"x": 1}

        async def write(_: dict[str, Any]) -> None:
            raise AssertionError("a dry run must not write")

        changes = asyncio.run(change_settings(read, write, {"x": True}, apply=False, settle_s=0))

        assert changes == {"x": [1, True]}

    def test_a_null_request_fails_when_the_setting_went_away(self) -> None:
        with pytest.raises(SettingNotAppliedError, match="m.on"):
            self._apply({"m": {"on": True}}, {"m": {"on": None}}, {})

    def test_a_null_request_fails_when_the_setting_became_a_group(self) -> None:
        with pytest.raises(SettingNotAppliedError, match="x"):
            self._apply({"x": 1}, {"x": None}, {"x": {"y": 2}})

    def test_a_null_request_passes_when_the_setting_is_null(self) -> None:
        assert self._apply({"x": 1}, {"x": None}, {"x": None}) == {"x": [1, None]}


class TestOpenAuth:
    def test_a_missing_token_says_how_to_fix_it(self, tmp_path: Path) -> None:
        async def open_it() -> None:
            async with open_auth(str(tmp_path / "absent.json")):
                raise AssertionError("must not open without a token")

        with pytest.raises(RingAuthError, match="ring_manager.py auth"):
            asyncio.run(open_it())


class TestRefusals:
    @pytest.mark.parametrize("apply", [True, False])
    def test_a_dotted_key_is_not_a_nested_setting(self, apply: bool) -> None:
        device = FakeDevice()

        with pytest.raises(ValueError, match="motion_settings.motion_on"):
            _change(device, {"motion_settings.motion_on": True}, apply=apply)

        assert device.writes == []

    @pytest.mark.parametrize("apply", [True, False])
    def test_an_unknown_setting_writes_nothing(self, apply: bool) -> None:
        device = FakeDevice()

        with pytest.raises(ValueError, match="motion_settings.motion_onn"):
            _change(device, {"motion_settings": {"motion_onn": True}}, apply=apply)

        assert device.writes == []

    def test_a_patch_that_replaces_a_group_with_a_scalar_writes_nothing(self) -> None:
        device = FakeDevice()

        with pytest.raises(ValueError, match="motion_settings"):
            _change(device, {"motion_settings": True}, apply=True)

        assert device.writes == []

    def test_a_list_setting_can_be_set(self) -> None:
        assert _change(FakeDevice(), {"zones": ["a"]}, apply=False) == {"zones": [[], ["a"]]}


class TestParseArgs:
    def test_defaults_to_a_dry_run(self) -> None:
        device_id, patch, apply = parse_args(["123", '{"a": {"b": true}}'])

        assert (device_id, patch, apply) == ("123", {"a": {"b": True}}, False)

    def test_apply_is_explicit(self) -> None:
        assert parse_args(["123", '{"a": 1}', "--apply"])[2] is True

    @pytest.mark.parametrize(
        "argv",
        [
            ["../123", '{"a": 1}'],
            ["123/x", '{"a": 1}'],
            ["123", "not json"],
            ["123", "[1]"],
            ["123", "{}"],
        ],
    )
    def test_refuses_a_bad_device_id_or_patch(self, argv: list[str]) -> None:
        with pytest.raises(SystemExit):
            parse_args(argv)
