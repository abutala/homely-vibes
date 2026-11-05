"""Tests for the IoT gatekeeper's block policy. Pure function, so no fakes."""

from typing import Any

import pytest

from NetworkCheck.gatekeeper_policy import canonical_allowlist, canonical_mac, plan_blocks

KNOWN = "AA-AA-AA-AA-AA-01"
STRANGER = "BB-BB-BB-BB-BB-02"
OTHER = "CC-CC-CC-CC-CC-03"


def client(mac: str, interface: str = "iot", **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "mac": mac,
        "interface": interface,
        "connection_type": "band2_4",
        "online": True,
        "client_type": "phone",
    }
    row.update(extra)
    return row


def plan(clients: list[dict[str, Any]], blocked: frozenset[str] = frozenset(), cap: int = 3):  # type: ignore[no-untyped-def]
    return plan_blocks(clients, frozenset({KNOWN}), blocked, cap)


class TestCanonicalMac:
    @pytest.mark.parametrize(
        "raw", ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabbccddeeff", "Aa-bB:cc-DD:ee-FF"]
    )
    def test_any_separator_or_case(self, raw: str) -> None:
        assert canonical_mac(raw) == "AA-BB-CC-DD-EE-FF"

    @pytest.mark.parametrize(
        "raw", ["", "AA-BB-CC-DD-EE", "GG-BB-CC-DD-EE-FF", "AA-BB-CC-DD-EE-FF-00"]
    )
    def test_malformed_raises(self, raw: str) -> None:
        with pytest.raises(ValueError):
            canonical_mac(raw)

    def test_a_number_is_rejected(self) -> None:
        """YAML reads an unquoted all-digit MAC with colons as a base-60 int."""
        with pytest.raises(ValueError, match="quoted string"):
            canonical_mac(374_865_225_011)

    def test_one_bad_entry_fails_the_whole_allowlist(self) -> None:
        with pytest.raises(ValueError):
            canonical_allowlist([KNOWN, "not-a-mac"])


class TestPlan:
    def test_blocks_a_stranger_on_the_iot_network(self) -> None:
        result = plan([client(KNOWN), client(STRANGER)])
        assert [c["mac"] for c in result.to_block] == [STRANGER]
        assert result.refusal is None

    def test_matches_the_allowlist_across_formats(self) -> None:
        assert plan([client("aa:aa:aa:aa:aa:01")]).to_block == []

    def test_never_touches_the_main_or_guest_network(self) -> None:
        result = plan([client(KNOWN), client(STRANGER, "main"), client(OTHER, "guest")])
        assert result.to_block == []

    def test_an_unknown_interface_value_is_never_blocked(self) -> None:
        assert plan([client(KNOWN), client(STRANGER, "mlo")]).to_block == []

    def test_skips_already_blocked_offline_and_wired_clients(self) -> None:
        clients = [
            client(KNOWN),
            client(STRANGER),
            client(OTHER, online=False),
            client("DD-DD-DD-DD-DD-04", connection_type="wired"),
        ]
        assert plan(clients, blocked=frozenset({STRANGER})).to_block == []

    def test_a_mac_also_on_another_network_is_reported_not_blocked(self) -> None:
        """The blocklist is mesh-wide, so this block would also cut main."""
        result = plan([client(KNOWN), client(STRANGER), client(STRANGER, "main")])
        assert result.to_block == []
        assert result.shared_macs == [STRANGER]

    def test_an_empty_allowlist_blocks_nothing(self) -> None:
        result = plan_blocks([client(STRANGER)], frozenset(), frozenset(), 3)
        assert result.to_block == []
        assert result.refusal == "the allowlist is empty"

    def test_an_empty_iot_network_blocks_nothing(self) -> None:
        result = plan([client(STRANGER, "main")])
        assert result.refusal is not None and "no clients on the IoT network" in result.refusal

    def test_more_strangers_than_the_cap_blocks_none(self) -> None:
        strangers = [client(f"BB-BB-BB-BB-BB-{i:02X}") for i in range(4)]
        result = plan([client(KNOWN), *strangers], cap=3)
        assert result.to_block == []
        assert len(result.strangers) == 4
        assert result.refusal is not None and "cap of 3" in result.refusal

    def test_exactly_the_cap_is_blocked(self) -> None:
        strangers = [client(f"BB-BB-BB-BB-BB-{i:02X}") for i in range(3)]
        assert len(plan([client(KNOWN), *strangers], cap=3).to_block) == 3

    def test_a_client_without_a_mac_is_ignored(self) -> None:
        assert plan([client(KNOWN), {"interface": "iot"}]).to_block == []
