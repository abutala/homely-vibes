"""Tests for Samsung Frame TV CLI handlers."""

import argparse
from typing import Any

import pytest

from SamsungFrame.manage_samsung import COMMANDS, build_parser, purge_art, run_command
from SamsungFrame.samsung_client import SamsungFrameClient


class FakeArtApi:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def delete_list(self, ids: list[str]) -> None:
        self.deleted += ids


class FakeTv:
    def __init__(self) -> None:
        self.art_api = FakeArtApi()

    def art(self) -> FakeArtApi:
        return self.art_api


class FakeClient:
    """Stands in for a connected SamsungFrameClient; `ready=False` fails the connect."""

    def __init__(self, ready: bool = True, reboot_ok: bool = True, art: list[str] | None = None):
        self.ready, self.reboot_ok = ready, reboot_ok
        self.art = [{"content_id": i, "image_date": ""} for i in art or ["MY_F001"]]
        self.tv = FakeTv()
        self.closed = False

    def __enter__(self) -> "FakeClient":
        if not self.ready:
            raise ConnectionError("Failed to get TV ready at 192.0.2.4")
        return self

    def __exit__(self, *_: object) -> None:
        self.closed = True

    def reboot_and_reconnect(self) -> bool:
        return self.reboot_ok

    def get_device_info(self) -> dict[str, Any]:
        return {"device": {"modelName": "Frame", "FrameTVSupport": "true"}}

    def get_available_art(self) -> list[dict[str, str]]:
        return self.art

    def check_art_support(self) -> bool:
        return True


def run(name: str, client: FakeClient, **args: object) -> int:
    return run_command(name, argparse.Namespace(**args), lambda: client)  # type: ignore[arg-type, return-value]


class TestRunCommand:
    @pytest.mark.parametrize("name", ["reboot", "status", "list-art"])
    def test_connect_failure_returns_1(self, name: str) -> None:
        assert run(name, FakeClient(ready=False)) == 1

    def test_client_is_closed_after_the_command(self) -> None:
        client = FakeClient()
        assert run("list-art", client) == 0
        assert client.closed

    def test_status_success_returns_0(self) -> None:
        assert run("status", FakeClient()) == 0

    def test_reboot_result_decides_the_exit_code(self) -> None:
        assert run("reboot", FakeClient(reboot_ok=True)) == 0
        assert run("reboot", FakeClient(reboot_ok=False)) == 1

    def test_every_subcommand_has_a_handler(self) -> None:
        parser = build_parser()
        choices = parser._subparsers._group_actions[0].choices  # type: ignore[union-attr]
        assert set(choices) == set(COMMANDS)  # type: ignore[arg-type]


class TestPurge:
    ART = [f"MY_F{i:03}" for i in range(105)]

    def purge(self, client: FakeClient, force: bool, answer: str = "y") -> int:
        args = argparse.Namespace(days=1, force=force)
        return purge_art(client, args, ask=lambda _prompt: answer, min_images=100)  # type: ignore[arg-type]

    def test_deletes_down_to_the_minimum_and_no_further(self) -> None:
        client = FakeClient(art=self.ART)  # undated art is stale
        assert self.purge(client, force=True) == 0
        assert len(client.tv.art_api.deleted) == 5

    def test_declined_confirmation_deletes_nothing(self) -> None:
        client = FakeClient(art=self.ART)
        assert self.purge(client, force=False, answer="n") == 0
        assert client.tv.art_api.deleted == []

    def test_at_the_minimum_nothing_is_purged(self) -> None:
        client = FakeClient(art=self.ART[:100])
        assert self.purge(client, force=True) == 0
        assert client.tv.art_api.deleted == []


def test_fake_client_matches_the_real_interface() -> None:
    for name in (
        "reboot_and_reconnect",
        "get_device_info",
        "get_available_art",
        "check_art_support",
    ):
        assert hasattr(SamsungFrameClient, name)
