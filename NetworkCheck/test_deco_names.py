"""Deco client labels come from config and are re-applied whenever a device is seen.

A device that is offline today is not in the client list, so it cannot be renamed
now; the next tick after it reconnects must label it.
"""

import base64
import logging
from typing import Any

import pytest

from NetworkCheck.deco_names import canonical_names, name_changes, sync_names

LOG = logging.getLogger("test")


def _client(mac: str, name: str, client_type: str = "iot_device") -> dict[str, Any]:
    return {
        "mac": mac,
        "name": base64.b64encode(name.encode()).decode(),
        "client_type": client_type,
    }


class FakeDeco:
    def __init__(self, clients: list[dict[str, Any]]) -> None:
        self.clients = clients
        self.renamed: list[tuple[str, str, str]] = []

    def list_clients(self) -> list[dict[str, Any]]:
        return self.clients

    def rename(self, mac: str, name: str, client_type: str) -> None:
        self.renamed.append((mac, name, client_type))
        for c in self.clients:
            if c["mac"] == mac:
                c["name"] = base64.b64encode(name.encode()).decode()


WANTED = {"AA-BB-CC-00-00-01": "Fan - Room A", "AA-BB-CC-00-00-02": "Phone - Person B"}


class TestCanonicalNames:
    def test_normalises_mac_format(self) -> None:
        assert canonical_names({"aa:bb:cc:00:00:01": " Fan - Room A "}) == {
            "AA-BB-CC-00-00-01": "Fan - Room A"
        }

    def test_bad_mac_raises(self) -> None:
        with pytest.raises(ValueError):
            canonical_names({"not-a-mac": "X"})

    def test_blank_name_raises(self) -> None:
        with pytest.raises(ValueError):
            canonical_names({"AA-BB-CC-00-00-01": "  "})


class TestNameChanges:
    def test_only_listed_clients_whose_name_differs(self) -> None:
        clients = [
            _client("AA-BB-CC-00-00-01", "AirFan 1"),
            _client("AA-BB-CC-00-00-02", "Phone - Person B", "phone"),
            _client("AA-BB-CC-00-00-03", "Someone else"),
        ]
        assert name_changes(clients, WANTED) == [(clients[0], "Fan - Room A")]

    def test_client_mac_in_any_format_matches(self) -> None:
        clients = [_client("aa:bb:cc:00:00:01", "AirFan 1")]
        assert name_changes(clients, WANTED) == [(clients[0], "Fan - Room A")]


class TestSync:
    def test_renames_with_current_client_type(self) -> None:
        deco = FakeDeco([_client("AA-BB-CC-00-00-02", "iPhone", "phone")])
        assert sync_names(deco, WANTED, LOG) == ["AA-BB-CC-00-00-02"]
        assert deco.renamed == [("AA-BB-CC-00-00-02", "Phone - Person B", "phone")]

    def test_second_run_changes_nothing(self) -> None:
        deco = FakeDeco([_client("AA-BB-CC-00-00-02", "iPhone", "phone")])
        sync_names(deco, WANTED, LOG)
        assert sync_names(deco, WANTED, LOG) == []
        assert len(deco.renamed) == 1

    def test_dry_run_renames_nothing(self) -> None:
        deco = FakeDeco([_client("AA-BB-CC-00-00-02", "iPhone", "phone")])
        assert sync_names(deco, WANTED, LOG, dry_run=True) == ["AA-BB-CC-00-00-02"]
        assert deco.renamed == []

    def test_offline_device_is_labelled_once_it_reconnects(self) -> None:
        deco = FakeDeco([])
        assert sync_names(deco, WANTED, LOG) == []
        deco.clients.append(_client("AA-BB-CC-00-00-01", "AirFan 1"))
        assert sync_names(deco, WANTED, LOG) == ["AA-BB-CC-00-00-01"]

    def test_one_failed_rename_does_not_stop_the_rest(self) -> None:
        class Flaky(FakeDeco):
            def rename(self, mac: str, name: str, client_type: str) -> None:
                if mac == "AA-BB-CC-00-00-01":
                    raise RuntimeError("Deco said no")
                super().rename(mac, name, client_type)

        deco = Flaky(
            [_client("AA-BB-CC-00-00-01", "AirFan 1"), _client("AA-BB-CC-00-00-02", "iPhone")]
        )
        assert sync_names(deco, WANTED, LOG) == ["AA-BB-CC-00-00-02"]

    def test_names_stay_out_of_the_log(self, caplog: pytest.LogCaptureFixture) -> None:
        deco = FakeDeco([_client("AA-BB-CC-00-00-02", "iPhone", "phone")])
        with caplog.at_level(logging.INFO):
            sync_names(deco, WANTED, LOG)
        assert "Person B" not in caplog.text
        assert "AA-BB-CC-00-00-02" in caplog.text
