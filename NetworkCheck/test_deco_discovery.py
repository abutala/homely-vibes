"""What a device says about itself on the LAN puts a name to a Deco client."""

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from NetworkCheck.deco_discovery import (
    TUYA_UDP_KEY_SEED,
    collect_tuya,
    match_clients,
    parse_address,
    parse_browse,
    parse_tuya,
)

BROWSE = """Browsing for _ewelink._tcp.local.
DATE: ---Sun 01 Jan 2026---
 0:59:37.319  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
 0:59:37.320  Add        3  15 local.               _ewelink._tcp.       eWeLink_1000aaaa01
 0:59:37.320  Rmv        2  15 local.               _ewelink._tcp.       eWeLink_1000aaaa02
 0:59:37.320  Add        2  15 local.               _ewelink._tcp.       eWeLink_1000aaaa03
"""

ADDRESS = """DATE: ---Sun 01 Jan 2026---
 1:00:58.411  ...STARTING...
Timestamp     A/R  Flags         IF  Hostname                  Address          TTL
 1:00:58.412  Add  40000002      15  eWeLink_1000aaaa01.local. 192.0.2.39       3600
"""


def _tuya_cipher_packet(body: dict[str, Any]) -> bytes:
    key = hashlib.md5(TUYA_UDP_KEY_SEED, usedforsecurity=False).digest()
    padder = padding.PKCS7(128).padder()
    plain = padder.update(json.dumps(body).encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305
    return b"\0" * 20 + enc.update(plain) + enc.finalize() + b"\0" * 8


def _tuya_plain_packet(body: dict[str, Any]) -> bytes:
    return b"\0" * 20 + json.dumps(body).encode() + b"\0" * 8


class TestDnsSd:
    def test_browse_returns_added_instances_only(self) -> None:
        assert parse_browse(BROWSE) == ["eWeLink_1000aaaa01", "eWeLink_1000aaaa03"]

    def test_browse_of_nothing_is_empty(self) -> None:
        assert parse_browse("") == []

    def test_address_is_taken_from_the_add_line(self) -> None:
        assert parse_address(ADDRESS) == "192.0.2.39"

    def test_no_answer_is_none(self) -> None:
        assert parse_address("Timestamp A/R Flags IF Hostname Address TTL\n") is None


class TestTuya:
    def test_encrypted_broadcast_gives_the_device_id(self) -> None:
        packet = _tuya_cipher_packet({"gwId": "id-one", "productKey": "pk", "version": "3.3"})
        assert parse_tuya(packet) == {"gwId": "id-one", "productKey": "pk", "version": "3.3"}

    def test_plain_broadcast_gives_the_device_id(self) -> None:
        packet = _tuya_plain_packet({"gwId": "id-two", "version": "3.1", "ip": "192.0.2.5"})
        assert parse_tuya(packet) == {"gwId": "id-two", "productKey": None, "version": "3.1"}

    def test_unreadable_packet_is_none_not_an_error(self) -> None:
        assert parse_tuya(b"\0" * 20 + b"not a block multiple" + b"\0" * 8) is None
        assert parse_tuya(b"short") is None

    def test_json_without_a_device_id_is_none(self) -> None:
        assert parse_tuya(_tuya_plain_packet({"version": "3.1"})) is None

    def test_collect_keeps_the_readable_packet_per_address(self) -> None:
        good = _tuya_plain_packet({"gwId": "id-one", "version": "3.1"})
        assert collect_tuya(
            [(b"junk", "192.0.2.1"), (good, "192.0.2.1"), (good, "192.0.2.1"), (b"x", "192.0.2.2")]
        ) == {"192.0.2.1": "id-one"}


class TestMatch:
    def test_match_joins_address_to_client(self) -> None:
        clients = [
            {"mac": "AA-BB-CC-00-00-01", "ip": "192.0.2.1", "interface": "iot"},
            {"mac": "AA-BB-CC-00-00-02", "ip": "192.0.2.2", "interface": "main"},
        ]
        labels = {"AA-BB-CC-00-00-01": "Plug - One"}
        assert match_clients({"id-one": "192.0.2.1", "id-two": "192.0.2.2"}, clients, labels) == [
            "id-one  192.0.2.1  AA-BB-CC-00-00-01  iot  Plug - One",
            "id-two  192.0.2.2  AA-BB-CC-00-00-02  main  (no label)",
        ]

    def test_address_no_client_has_is_reported(self) -> None:
        assert match_clients({"id-one": "192.0.2.9"}, [], {}) == [
            "id-one  192.0.2.9  (not on the Deco)"
        ]

    def test_device_with_no_address_is_reported(self) -> None:
        assert match_clients({"id-one": None}, [], {}) == ["id-one  (no address)"]
