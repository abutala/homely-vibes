# /// script
# requires-python = ">=3.13"
# dependencies = ["yalexs-ble==6.1.0"]
# ///
"""Print the expected bytes of AugustBLEProtocolTests.swift from yalexs-ble's own classes.

Uses a test key only (00..0f). Run: uv run --script AugustUnlock/scripts/gen_ble_vectors.py
"""

import asyncio
import importlib.metadata

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from yalexs_ble import util
from yalexs_ble.const import Commands
from yalexs_ble.secure_session import SecureSession
from yalexs_ble.session import Session

KEY = bytes(range(16))
SLOT = 4
NONCE = bytes(range(0x10, 0x20))
LOCK_HALF = bytes(range(0x20, 0x28))


class _Services:
    def get_characteristic(self, uuid: str) -> str:
        return uuid


class _Client:
    services = _Services()
    is_connected = True


def show(name: str, frame: bytes | bytearray) -> None:
    print(f"{name:14} {bytes(frame).hex()}")


def handshake(secure: SecureSession) -> bytearray:
    """Both secure commands, and the lock's ECB reply to the first; returns the session key."""
    secure.set_key(KEY)
    cmd1 = secure.build_command(0x01)
    util._copy(cmd1, NONCE[0:8], destLocation=0x04)
    secure._write_checksum(cmd1)
    secure._encrypt_command(cmd1, "key exchange")
    show("cmd1_wire", cmd1)

    reply = bytearray(18)
    reply[0] = 0x02
    util._copy(reply, LOCK_HALF, destLocation=0x04)
    reply[0x10:0x12] = bytes([0x0F, SLOT])
    secure._write_checksum(reply)
    lock_side = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()  # nosec
    reply_wire = lock_side.update(bytes(reply[0:16])) + bytes(reply[16:18])
    show("reply1_wire", reply_wire)
    decrypted = secure.decrypt(reply_wire)
    secure._validate_response(decrypted)

    session_key = bytearray(NONCE[0:8] + decrypted[0x04:0x0C])
    show("session_key", session_key)
    secure.set_key(session_key)
    cmd2 = secure.build_command(0x03)
    util._copy(cmd2, NONCE[8:16], destLocation=0x04)
    secure._write_checksum(cmd2)
    secure._encrypt_command(cmd2, "initialization")
    show("cmd2_wire", cmd2)
    return session_key


def plain_channel(plain: Session, session_key: bytearray) -> None:
    """Three chained commands, then an ack and op-response as the lock would encrypt them."""
    plain.set_key(session_key)
    for name, opcode in (
        ("unlock1", Commands.UNLOCK),
        ("lock2", Commands.LOCK),
        ("unlock3", Commands.UNLOCK),
    ):
        command = plain.build_operation_command(opcode, 0x00)
        plain._write_checksum(command)
        plain._encrypt_command(command, name)
        show(f"{name}_wire", command)

    ack = bytearray(18)
    ack[0:2] = bytes([0xAA, Commands.UNLOCK])
    ack[0x10] = 0x02
    ack[3] = util._simple_checksum(ack)
    result = bytearray.fromhex("bb0a003b0000000000000000000000000000")
    lock_side = Cipher(algorithms.AES(bytes(session_key)), modes.CBC(bytes(16))).encryptor()  # nosec
    for name, frame in (("ack", ack), ("op", result)):
        wire = lock_side.update(bytes(frame[0:16])) + bytes(frame[16:18])
        show(f"{name}_wire", wire)
        decrypted = plain.decrypt(wire)
        plain._validate_response(decrypted)
        assert decrypted == bytes(frame)


async def main() -> None:
    print("yalexs-ble", importlib.metadata.version("yalexs-ble"))
    lock = asyncio.Lock()
    secure = SecureSession(_Client(), "vectors", lock, set(), SLOT)
    plain = Session(_Client(), "vectors", lock, set(), None)
    plain_channel(plain, handshake(secure))


if __name__ == "__main__":
    asyncio.run(main())
