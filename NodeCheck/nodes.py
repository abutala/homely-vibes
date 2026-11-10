#!/usr/bin/env python3
import json
import re
import socket
import subprocess
import time
from collections.abc import Callable
from typing import Any
from lib import NetHelpers
from lib.config import NodeConfig, get_config
from lib.logger import SystemLogger
from NetworkCheck.common import deco_admin_lock
from NetworkCheck.deco_client import DecoAPIError, DecoAuthError, DecoClient

logger = SystemLogger.get_logger(__name__)

# 3 consecutive packet losses before a node is considered down. Matches the
# Nagios-style max_check_attempts=3 convention and tolerates a single radio sleep.
HEARTBEAT_PING_COUNT = 3

# One budget for a TCP connect and for each read. The heartbeat loop probes nodes one by one.
TCP_TIMEOUT_S = 4


class GenericNode:
    def __init__(
        self,
        name: str,
        config: NodeConfig,
        connect: Callable[..., socket.socket] | None = None,
    ):
        self.name = name
        self.config = config
        self.is_online = False
        self._connect = connect

    def _open_tcp(self, default_port: int) -> socket.socket:
        """Connect to `host or ip` on `port or default_port`. Reads time out after TCP_TIMEOUT_S."""
        connect = self._connect or socket.create_connection
        target = (self.config.host or self.config.ip, self.config.port or default_port)
        sock = connect(target, timeout=TCP_TIMEOUT_S)
        sock.settimeout(TCP_TIMEOUT_S)
        return sock

    def _probe_failed(self, reason: str) -> bool:
        logger.warning(f"{self.name}: {reason}")
        self.is_online = False
        return False

    def check_state(self, desired_up: bool = True, attempts: int = 5) -> bool:
        """Check if node is in desired state (up/down) - used for reboot verification"""
        for attempt in range(attempts):
            current_state = NetHelpers.ping_output(node=self.config.ip, desired_up=desired_up)
            logger.debug(
                f"{attempt=} for {self.name}, {desired_up=} In desired state: {current_state}"
            )
            if current_state == desired_up:
                self.is_online = current_state if desired_up else not current_state
                return True
            time.sleep(1)
        self.is_online = False if desired_up else True
        return False

    def heartbeat(self) -> bool:
        """Base health check - ping test. Subclasses should call super() then add specific checks"""
        self.is_online = NetHelpers.ping_output(
            node=self.config.ip, count=HEARTBEAT_PING_COUNT, desired_up=True
        )
        logger.debug(f"Ping check for {self.name}: {self.is_online}")
        return self.is_online

    def reboot_node(self) -> str:
        """Reboot the node and return status message"""
        return "Reboot not supported for generic node"


class FoscamNode(GenericNode):
    def reboot_node(self) -> str:
        """Reboot Foscam camera via HTTP API"""
        cmd = "http://%s:88//cgi-bin/CGIProxy.fcgi?cmd=rebootSystem&usr=%s&pwd=%s" % (
            self.config.ip,
            self.config.username,
            self.config.password,
        )
        try:
            msg = str(NetHelpers.http_req(cmd))
            logger.info(f"Rebooted foscam node: {self.name}")
            return msg
        except OSError as e:
            err_msg = getattr(e, "message", repr(e))
            msg = f">> ERROR: When rebooting {self.name}. Got {err_msg[:100]}..."
            logger.error(msg)
            return msg

    def heartbeat(self) -> bool:
        """Check Foscam health: ping + image capture"""
        if not super().heartbeat():
            return False

        # TODO: Odroid is sigsegv on matplotlib
        # try:
        #     # Then do Foscam-specific image capture test
        #     from lib.FoscamImager import FoscamImager

        #     MAX_COUNT = 2
        #     for attempt in range(MAX_COUNT):
        #         try:
        #             myCam = FoscamImager(self.config.ip, False)
        #             image = myCam.getImage()
        #             if image is not None:
        #                 logger.info(f"Got image from node: {self.name}")
        #                 return True
        #         except Exception as e:
        #             logger.error(f"Attempt {attempt + 1}/{MAX_COUNT} failed for {self.name}: {e}")
        #             logger.debug(traceback.format_exc())
        #             if attempt < MAX_COUNT - 1:
        #                 time.sleep(30)

        #     logger.error(f"Failed to get image after {MAX_COUNT} attempts from: {self.name}")
        #     return False
        # except Exception:
        #     # not supported on this platform
        #     pass

        return True


class SomfyMyLinkNode(GenericNode):
    """Somfy myLink controller. Layered check: ping then JSON-RPC over TCP:44100."""

    DEFAULT_PORT = 44100

    def heartbeat(self) -> bool:
        """Check myLink health: ping + JSON-RPC mylink.status.info round-trip"""
        if not super().heartbeat():
            return False

        if not self.config.auth_token:
            # Ping-only fallback. A page on missing config would mean "operator forgot
            # a token", not "device is sick" — wrong signal for an emergency alert.
            logger.warning(f"{self.name}: no auth_token configured; myLink API check skipped")
            return True

        request = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "mylink.status.info",
                    "params": {"auth": self.config.auth_token},
                }
            )
            + "\n"
        ).encode()

        # myLink replies with one JSON object then keeps the connection open (no
        # newline / FIN). Parse incrementally and stop on first complete object —
        # waiting for a delimiter or EOF would block until socket timeout.
        try:
            with self._open_tcp(self.DEFAULT_PORT) as sock:
                sock.sendall(request)
                buf = b""
                response: dict | None = None
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break  # server closed
                    buf += chunk
                    try:
                        response = json.loads(buf.decode())
                        break  # got a complete object
                    except json.JSONDecodeError:
                        continue  # partial — keep reading
            if response is None:
                return self._probe_failed(
                    f"myLink API check failed: incomplete response ({len(buf)} bytes)"
                )
        except OSError as e:
            return self._probe_failed(f"myLink API check failed: {e!r}")

        if "error" in response:
            return self._probe_failed(f"myLink RPC error: {response['error']}")
        if "result" not in response:
            return self._probe_failed(f"unexpected myLink response: {response!r}")

        logger.debug(f"{self.name}: myLink API live, target={response['result'].get('targetID')}")
        return True


class WindowsNode(GenericNode):
    def reboot_node(self) -> str:
        """Reboot Windows machine via SSH"""
        winCmd = 'cmd /c "shutdown /r /f & ping localhost -n 3 > nul"'
        return str(
            NetHelpers.ssh_cmd(self.config.ip, self.config.username, self.config.password, winCmd)
        )

    def heartbeat(self) -> bool:
        """Check Windows health: ping + uptime statistics"""
        # First do base ping check
        if not super().heartbeat():
            return False

        # Then do Windows-specific uptime check
        winCmd = "net statistics workstation"
        output = str(
            NetHelpers.ssh_cmd(self.config.ip, self.config.username, self.config.password, winCmd)
        )
        if "successful" in output:
            match = re.search("Statistics since (.*)", output)
            if match:
                foundStr = match.group(1)
                logger.info(f"{self.name} is up since {foundStr}")
                return True
        return False


# WiFi devices in power-save (notably iPhones) drop ICMP replies but stay
# associated with the AP, so the router's ARP cache still has a valid MAC.
# ArpNode probes presence via the ARP cache instead of ICMP.
_MAC_RE = re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


class ArpNode(GenericNode):
    def heartbeat(self) -> bool:
        # Fire one ping to trigger ARP resolution if the entry is stale.
        # Result is intentionally discarded — we only care about the ARP cache.
        # A single cold-cache false-negative is absorbed by HeartbeatMonitor's
        # consecutive-failure flap suppression.
        NetHelpers.ping_output(node=self.config.ip, count=1, desired_up=True)
        try:
            result = subprocess.run(
                ["arp", "-n", self.config.ip],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.debug(f"ARP check for {self.name}: timeout")
            self.is_online = False
            return False
        except FileNotFoundError:
            # `arp` binary missing (minimal Linux images may ship only iproute2).
            logger.warning(f"ARP check for {self.name}: `arp` binary not found on PATH")
            self.is_online = False
            return False

        stdout = result.stdout or ""
        has_mac = bool(_MAC_RE.search(stdout))
        is_incomplete = "incomplete" in stdout.lower()
        self.is_online = has_mac and not is_incomplete
        logger.debug(f"ARP check for {self.name}: {self.is_online} ({stdout!r})")
        return self.is_online


class SshNode(GenericNode):
    """Host with no LAN path: probe its sshd banner, through a WAN port forward if configured.

    The banner proves the forward and the sshd answer. It needs no key on the probing host.
    """

    DEFAULT_PORT = 22

    def heartbeat(self) -> bool:
        """No ping first: the host is reachable only through its forwarded SSH port."""
        try:
            with self._open_tcp(self.DEFAULT_PORT) as sock:
                banner = sock.recv(256)
        except socket.gaierror as e:
            return self._probe_failed(f"DNS lookup of {self.config.host} failed: {e!r}")
        except OSError as e:
            return self._probe_failed(f"SSH port unreachable: {e!r}")
        if not banner.startswith(b"SSH-"):
            return self._probe_failed(f"not an SSH banner: {banner!r}")
        self.is_online = True
        return True

    def check_state(self, desired_up: bool = True, attempts: int = 5) -> bool:
        raise NotImplementedError("check_state pings ip, which an SSH-only host does not answer")


# Short of the watchdog's own wait: a poll that cannot get the lock fails, and the
# flap suppression absorbs one miss.
DECO_LOCK_WAIT_S = 30


def read_deco_clients() -> list[dict[str, Any]]:
    """The Deco client list, under the lock every Deco login shares (the admin is single-session)."""
    wd = get_config().network_check.uplink_watchdog
    with deco_admin_lock(timeout_s=DECO_LOCK_WAIT_S):
        return DecoClient(wd.deco_host, wd.deco_username, wd.deco_password).list_clients()


_DECO_READ_ERRORS = (DecoAPIError, DecoAuthError, OSError)


class ProbeUnavailable(Exception):
    """The probe could not run, so the node's state is unknown. Not evidence that it is down."""


class CycleCachedRead:
    """One Deco read per heartbeat cycle, shared by every deco node. A failed read is kept too."""

    def __init__(self, read: Callable[[], list[dict[str, Any]]] = read_deco_clients):
        self._read = read
        self._outcome: list[dict[str, Any]] | Exception | None = None

    def reset(self) -> None:
        self._outcome = None

    def __call__(self) -> list[dict[str, Any]]:
        if self._outcome is None:
            try:
                self._outcome = self._read()
            except _DECO_READ_ERRORS as e:
                self._outcome = e
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


def _normalize_mac(mac: str) -> str:
    return mac.upper().replace(":", "-")


class DecoNode(GenericNode):
    """Presence by MAC on the Deco client list, on any network: main, guest or IoT.

    For a host ping cannot reach. The MAC must be stable: an iPhone needs its
    Private Wi-Fi Address set to Fixed, not Rotating.
    """

    def __init__(
        self,
        name: str,
        config: NodeConfig,
        list_clients: Callable[[], list[dict[str, Any]]] = read_deco_clients,
    ):
        super().__init__(name, config)
        self._list_clients = list_clients

    def heartbeat(self) -> bool:
        """No ping first: the Deco sees the client where the prod host cannot.

        Raises ProbeUnavailable when the list cannot be read: that says nothing about this node.
        """
        if not self.config.mac:
            return self._probe_failed("deco node has no mac configured")
        try:
            clients = self._list_clients()
        except _DECO_READ_ERRORS as e:
            raise ProbeUnavailable(f"Deco client list unreadable: {e!r}") from e
        want = _normalize_mac(self.config.mac)
        client = next((c for c in clients if _normalize_mac(str(c.get("mac") or "")) == want), None)
        if client is None:
            return self._probe_failed(f"{want} not on the Deco client list")
        # Some firmware omits `online`; then presence in the list is the signal.
        if not client.get("online", True):
            return self._probe_failed(f"{want} is offline on the Deco")
        self.is_online = True
        return True

    def check_state(self, desired_up: bool = True, attempts: int = 5) -> bool:
        raise NotImplementedError("check_state pings ip, which a Deco-probed host does not answer")
