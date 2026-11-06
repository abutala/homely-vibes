#!/usr/bin/env python3
"""TP-Link Deco local admin API client.

Speaks the Deco's on-router HTTP API (``/cgi-bin/luci/``) so we can reboot the
mesh without the TP-Link cloud -- which matters because the whole point is to
recover from a Deco whose WAN plane has wedged while its LAN plane still works.

Protocol (ported from the reverse-engineered flow in amosyuen/ha-tplink-deco,
https://github.com/amosyuen/ha-tplink-deco):

1. ``POST /cgi-bin/luci/;stok=/login?form=keys`` -> RSA (n, e) used to encrypt
   the admin password.
2. ``POST /cgi-bin/luci/;stok=/login?form=auth`` -> a second RSA key used to
   sign requests, plus an incrementing ``seq``.
3. ``POST /cgi-bin/luci/;stok=/login?form=login`` -> session ``stok`` in the
   body and a ``sysauth`` cookie.

Every authenticated request body is ``sign=<hex>&data=<urlencoded base64>``:
``data`` is the AES-128-CBC ciphertext of the JSON payload, ``sign`` is the
RSA ciphertext of ``k=<aes_key>&i=<aes_iv>&h=<md5(user+pass)>&s=<seq+len(data)>``.

The requests Session is injected so tests can supply a fake transport without
patching production code.
"""

import base64
import hashlib
import json
import math
import secrets
import time
from collections.abc import Callable
from typing import Any, Optional
from urllib.parse import quote_plus

import requests
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from lib.logger import get_logger

logger = get_logger(__name__)

# TP-Link requires the AES key and IV to each be a 16-digit number with no
# leading zeros -- the decimal string is what gets used as the 16 raw bytes.
# Note the consequence: 16 decimal digits is ~53 bits of entropy, not the 128
# the cipher suggests. That is the router's constraint, not a choice, and it is
# why this must never be lifted out as a general-purpose AES key generator.
_AES_DIGITS = 16
_MIN_AES_KEY = 10 ** (_AES_DIGITS - 1)
_MAX_AES_KEY = (10**_AES_DIGITS) - 1

# PKCS#1 v1.5 padding overhead; the router chunks plaintext to fit one block.
_PKCS1_HEADER_BYTES = 11

_DEFAULT_TIMEOUT = 15
_POST_ATTEMPTS = 3
_RETRY_BACKOFF_S = 1.0
# Only genuinely transient transport faults. An HTTPError (4xx/5xx from
# raise_for_status) is a real answer from the router and retrying it just
# repeats the same rejection.
_TRANSIENT_ERRORS = (requests.Timeout, requests.ConnectionError)


class DecoAuthError(Exception):
    """Deco admin login failed (bad password, or admin session held elsewhere)."""


class DecoAPIError(Exception):
    """Deco admin API returned an error or an unparsable response."""


class DecoSessionLost(DecoAPIError):
    """The session was evicted by another login with the same admin account.

    The router answers an evicted session with ``{"data": ""}`` (measured on an
    XE75 Pro, firmware 1.4.5). A fresh login fixes it.
    """


def _form(params: dict[str, str]) -> str:
    """Name the call for an error message.

    Interpolating the whole `params` dict was the original sin behind a
    production alert reading `Deco request to {'form': 'client_list'} failed`.
    These strings end up in Pushover bodies, so the form name is the only part
    that carries meaning to a human.
    """
    return params.get("form", "request")


def _byte_len(n: int) -> int:
    """Byte length of the RSA modulus."""
    return (int(math.log2(n)) + 8) >> 3


def _rsa_encrypt(n: int, e: int, plaintext: bytes) -> str:
    """RSA-encrypt in router-sized blocks, returning concatenated hex.

    TP-Link splits the plaintext across PKCS#1 v1.5 blocks and concatenates the
    hex of each block rather than encrypting once, so we must match that shape.
    """
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    bytes_per_block = _byte_len(n) - _PKCS1_HEADER_BYTES

    chunks = []
    for index in range(0, len(plaintext), bytes_per_block):
        block = plaintext[index : index + bytes_per_block]
        chunks.append(public_key.encrypt(block, asym_padding.PKCS1v15()).hex())
    return "".join(chunks)


def _aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# `connection_type` on a client_list entry is one of `wired`, `band2_4` or
# `band5`. TP-Link publishes none of this; the values are documented by the
# same reverse-engineered integration the login flow was ported from --
# https://github.com/amosyuen/ha-tplink-deco#client-attributes
_WIRED_CONNECTION_TYPE = "wired"


def count_wireless_clients(clients: list[dict[str, Any]]) -> int:
    """How many of the mesh's clients are associated over the radios.

    Anything not explicitly wired counts as wireless, and that direction is
    deliberate: a firmware that adds `band6` for Wi-Fi 6E must not make the
    census read zero radios and reboot a perfectly healthy house. Unknown
    means wireless; only the one string we have seen means wired.

    Entries the router explicitly marks offline are excluded. `online` is
    absent on some firmware, in which case presence in the list is the signal.
    """
    return sum(
        1
        for client in clients
        if client.get("online", True)
        and str(client.get("connection_type", "")).lower() != _WIRED_CONNECTION_TYPE
    )


class DecoClient:
    """Local-API client for a TP-Link Deco mesh."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        session: Optional[requests.Session] = None,
        timeout: int = _DEFAULT_TIMEOUT,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.session = session or requests.Session()
        self.timeout = timeout
        self._sleep = sleep

        self._aes_key = str(secrets.randbelow(_MAX_AES_KEY - _MIN_AES_KEY) + _MIN_AES_KEY)
        self._aes_iv = str(secrets.randbelow(_MAX_AES_KEY - _MIN_AES_KEY) + _MIN_AES_KEY)
        self._password_rsa: tuple[int, int] | None = None
        self._sign_rsa: tuple[int, int] | None = None
        self._seq: int | None = None
        self._stok: str | None = None

    def login(self) -> None:
        """Run the three-step handshake and cache the session token."""
        self._fetch_password_key()
        self._fetch_sign_key()

        n, e = self._require(self._password_rsa, "password RSA key")
        payload = {
            "operation": "login",
            "params": {"password": _rsa_encrypt(n, e, self.password.encode())},
        }
        data = self._post_encrypted("/cgi-bin/luci/;stok=/login", {"form": "login"}, payload)

        error_code = data.get("error_code")
        if error_code == -5002:
            attempts = (data.get("result") or {}).get("attemptsAllowed", "unknown")
            raise DecoAuthError(f"Invalid Deco admin password ({attempts} attempts left)")
        if error_code:
            raise DecoAuthError(f"Deco login failed: error_code={error_code}")

        try:
            self._stok = data["result"]["stok"]
        except (KeyError, TypeError) as err:
            raise DecoAPIError(f"Deco login response missing stok: {data}") from err

        if "sysauth" not in self.session.cookies:
            raise DecoAPIError("Deco login did not set a sysauth cookie")
        logger.debug("Deco login succeeded")

    def login_if_needed(self) -> None:
        if self._stok is None:
            self.login()

    def list_decos(self) -> list[dict[str, Any]]:
        """Return the mesh device list (one entry per Deco unit)."""
        data = self._read("admin/device", "device_list", {"operation": "read"})
        try:
            device_list = data["result"]["device_list"]
        except (KeyError, TypeError) as err:
            raise DecoAPIError(f"Unexpected device_list response: {data}") from err
        return list(device_list)

    def list_clients(self) -> list[dict[str, Any]]:
        """Return every client the mesh currently sees, wired and wireless."""
        data = self._read(
            "admin/client",
            "client_list",
            {"operation": "read", "params": {"device_mac": "default"}},
        )
        try:
            client_list = data["result"]["client_list"]
        except (KeyError, TypeError) as err:
            raise DecoAPIError(f"Unexpected client_list response: {data}") from err
        return list(client_list)

    def list_blocked(self) -> list[dict[str, Any]]:
        """Return the mesh-wide blocklist.

        The router sends an empty dict, not an empty list, when nothing is
        blocked. Anything else that is not a list raises: reading it as empty
        would make every tick block and alert again.
        """
        data = self._read("admin/client", "black_list", {"operation": "list"})
        try:
            blocked = data["result"]["client_list"]
        except (KeyError, TypeError) as err:
            raise DecoAPIError(f"Unexpected black_list response: {data}") from err
        if blocked == {}:
            return []
        if not isinstance(blocked, list):
            raise DecoAPIError(f"Unexpected black_list shape: {type(blocked).__name__}")
        return blocked

    def block(self, mac: str, name: str, client_type: str) -> None:
        """Add one client to the mesh-wide blocklist.

        ``name`` is the base64 name exactly as ``client_list`` returns it. Never
        retried: the next tick reads the blocklist again, so a lost reply only
        delays the outcome.
        """
        entry = {"mac": mac, "name": name, "client_type": client_type}
        self._command(
            "admin/client", "black_list", {"operation": "block", "params": {"client_list": [entry]}}
        )
        logger.info("Deco block issued for %s", mac)

    def unblock(self, macs: list[str]) -> None:
        """Remove clients from the mesh-wide blocklist."""
        if not macs:
            raise ValueError("unblock() requires at least one MAC")
        self._command(
            "admin/client", "black_list", {"operation": "unblock", "params": {"client_list": macs}}
        )
        logger.info("Deco unblock issued for %s", ", ".join(macs))

    def rename(self, mac: str, name: str) -> None:
        """Set the client's display name, as the Deco app does.

        ``mac`` is sent as ``client_list`` returns it. The firmware ignores an
        entry without ``user_set_name_type``, so it is always set.
        """
        if not name.strip():
            raise ValueError("rename() requires a non-blank name")
        entry = {
            "mac": mac,
            "name": base64.b64encode(name.encode()).decode(),
            "user_set_name_type": True,
        }
        self._command(
            "admin/client",
            "client_list",
            {"operation": "write", "params": {"client_list": [entry]}},
        )
        logger.info("Deco rename issued for %s", mac)

    def reboot(self, macs: list[str]) -> None:
        """Reboot the named Deco units.

        Never retried. A timeout here is ambiguous -- the reboot may well have
        landed before the response was lost -- and re-issuing it can bounce a
        mesh that is already coming back up. Callers treat a failure as "did not
        reboot", which is the safe reading.
        """
        if not macs:
            raise ValueError("reboot() requires at least one MAC")
        self._command(
            "admin/device",
            "system",
            {"operation": "reboot", "params": {"mac_list": [{"mac": m} for m in macs]}},
        )
        logger.info("Deco reboot issued for %s", ", ".join(macs))

    def _read(self, path: str, form: str, payload: dict[str, Any]) -> dict[str, Any]:
        """An authenticated read. Logs in again once if another login evicted us.

        Reads are safe to repeat, so a lost session costs one extra handshake
        instead of a failed tick -- which for the watchdog's census would read
        as zero clients and start the outage clock.
        """
        self.login_if_needed()
        try:
            data = self._post_encrypted(self._admin_path(path), {"form": form}, payload)
        except DecoSessionLost:
            logger.warning("Deco %s: session evicted by another login; logging in again", form)
            self.login()
            data = self._post_encrypted(self._admin_path(path), {"form": form}, payload)
        self._raise_for_error(data, form)
        return data

    def _command(self, path: str, form: str, payload: dict[str, Any]) -> dict[str, Any]:
        """An authenticated write. Never retried and never re-sent after an eviction.

        Some writes answer with a plain, unencrypted ``{"error_code": 0}``
        rather than an encrypted ``data`` field, so both shapes are accepted.
        """
        self.login_if_needed()
        response = self._post(
            self._admin_path(path), {"form": form}, self._encode_payload(payload), retry=False
        )
        if "data" in response:
            data = self._decrypt_data(response, form)
        elif "error_code" in response or "errorcode" in response:
            data = response
        else:
            raise DecoAPIError(f"Deco {form} returned no data")
        self._raise_for_error(data, form)
        return data

    def _admin_path(self, path: str) -> str:
        return f"/cgi-bin/luci/;stok={self._stok}/{path}"

    def _fetch_password_key(self) -> None:
        result = self._post_plain("/cgi-bin/luci/;stok=/login", {"form": "keys"})
        try:
            keys = result["result"]["password"]
            self._password_rsa = (int(keys[0], 16), int(keys[1], 16))
        except (KeyError, IndexError, TypeError, ValueError) as err:
            raise DecoAPIError(f"Unexpected form=keys response: {result}") from err

    def _fetch_sign_key(self) -> None:
        result = self._post_plain("/cgi-bin/luci/;stok=/login", {"form": "auth"})
        try:
            auth = result["result"]
            self._sign_rsa = (int(auth["key"][0], 16), int(auth["key"][1], 16))
            self._seq = int(auth["seq"])
        except (KeyError, IndexError, TypeError, ValueError) as err:
            raise DecoAPIError(f"Unexpected form=auth response: {result}") from err

    def _post_plain(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        return self._post(path, params, json.dumps({"operation": "read"}))

    def _post_encrypted(
        self, path: str, params: dict[str, str], payload: dict[str, Any]
    ) -> dict[str, Any]:
        response = self._post(path, params, self._encode_payload(payload))
        return self._decrypt_data(response, _form(params))

    def _decrypt_data(self, response: dict[str, Any], form: str) -> dict[str, Any]:
        if "data" not in response:
            raise DecoAPIError(f"Deco {form} returned no data")
        if not response["data"]:
            raise DecoSessionLost(f"Deco {form} returned empty data (session evicted)")
        return self._decrypt(response["data"])

    def _post(
        self, path: str, params: dict[str, str], body: str, *, retry: bool = True
    ) -> dict[str, Any]:
        url = f"{self.host}{path}"
        attempts = _POST_ATTEMPTS if retry else 1
        for attempt in range(1, attempts + 1):
            try:
                response = self.session.post(
                    url,
                    params=params,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                response.raise_for_status()
                return dict(response.json())
            except _TRANSIENT_ERRORS as err:
                if attempt == attempts:
                    raise DecoAPIError(
                        f"Deco {_form(params)} request failed after {attempt} attempt(s): {err}"
                    ) from err
                logger.warning(
                    "Deco %s attempt %d/%d failed (%s); retrying",
                    _form(params),
                    attempt,
                    attempts,
                    err,
                )
                self._sleep(_RETRY_BACKOFF_S)
            except requests.RequestException as err:
                raise DecoAPIError(f"Deco {_form(params)} request failed: {err}") from err
            except ValueError as err:
                raise DecoAPIError(f"Deco {_form(params)} response was not JSON: {err}") from err
        raise AssertionError("unreachable")

    def _encode_payload(self, payload: dict[str, Any]) -> str:
        data = base64.b64encode(
            _aes_encrypt(
                self._aes_key.encode(),
                self._aes_iv.encode(),
                json.dumps(payload, separators=(",", ":")).encode(),
            )
        ).decode()
        return f"sign={self._encode_sign(len(data))}&data={quote_plus(data)}"

    def _encode_sign(self, data_len: int) -> str:
        n, e = self._require(self._sign_rsa, "sign RSA key")
        if self._seq is None:
            raise DecoAPIError("Cannot sign request before fetching seq")
        # MD5 is dictated by the Deco firmware, which computes the same digest
        # and compares -- this is a wire-format constant, not a storage hash we
        # get to choose. The digest never lands on disk and never leaves the
        # LAN. Changing it to anything stronger simply fails to authenticate.
        # CodeQL flags this (py/weak-sensitive-data-hashing) and is right about
        # the pattern -- but MD5 here is dictated by the Deco firmware, which
        # computes the same digest and compares. It is a wire-format constant,
        # not a storage hash we get to choose; anything stronger simply fails to
        # authenticate. The digest never touches disk and never leaves the LAN.
        # The alert is dismissed as "won't fix" in code scanning, not suppressed
        # here: GitHub does not honour inline `# codeql[...]` comments.
        auth_hash = hashlib.md5(
            f"{self.username}{self.password}".encode(), usedforsecurity=False
        ).hexdigest()
        sign_text = f"k={self._aes_key}&i={self._aes_iv}&h={auth_hash}&s={self._seq + data_len}"
        return _rsa_encrypt(n, e, sign_text.encode())

    def _decrypt(self, encrypted: str) -> dict[str, Any]:
        try:
            plaintext = _aes_decrypt(
                self._aes_key.encode(), self._aes_iv.encode(), base64.b64decode(encrypted)
            )
            return dict(json.loads(plaintext))
        except Exception as err:
            raise DecoAPIError(f"Could not decrypt Deco response: {err}") from err

    @staticmethod
    def _require(value: tuple[int, int] | None, what: str) -> tuple[int, int]:
        if value is None:
            raise DecoAPIError(f"Missing {what}; login was not completed")
        return value

    @staticmethod
    def _raise_for_error(data: dict[str, Any], context: str) -> None:
        error_code = data.get("error_code") or data.get("errorcode")
        if error_code:
            raise DecoAPIError(f"Deco {context} returned error_code={error_code}")
