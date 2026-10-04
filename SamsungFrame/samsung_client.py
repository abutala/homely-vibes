"""Samsung Frame TV client for art mode management."""

import json
import os
import random
import signal
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, cast

import requests
from PIL import Image
from pydantic import BaseModel
from samsungtvws import SamsungTVWS
from samsungtvws.rest import SamsungTVRest
from tenacity import retry, stop_after_attempt, wait_exponential
from tqdm import tqdm

from lib.config import SamsungFrameConfig, get_config
from lib.logger import get_logger
from lib.secure_io import ensure_secret_perms

logger = get_logger(__name__)

ART_UPLOAD_TIMEOUT = 30
CONNECT_ATTEMPTS = 3
MIN_UPLOAD_PAUSE = 5  # seconds between uploads; grows while the TV needs a cooldown
MAX_UPLOAD_PAUSE = 30
MY_PICTURES_CATEGORY = "MY-C0002"
USER_ART_PREFIX = "MY_F"  # content ids of photos a user uploaded, as opposed to Samsung art
SHUFFLE_SLIDESHOW_TYPE = "shuffleslideshow"
SLIDESHOW_SETTLE_SECONDS = 2
IMAGE_DATE_FORMAT = "%Y:%m:%d %H:%M:%S"

VALID_MATTE_COLORS = [
    "seafoam",
    "black",
    "neutral",
    "antique",
    "warm",
    "polar",
    "sand",
    "sage",
    "burgandy",
    "navy",
    "apricot",
    "byzantine",
    "lavender",
    "redorange",
    "skyblue",
    "turqoise",
]

ArtList = List[Dict[str, Any]]


def _udp_socket() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


@dataclass(frozen=True)
class TvIo:
    """Everything the client reaches outside the process; tests pass fakes instead."""

    tv: Callable[..., SamsungTVWS] = SamsungTVWS
    rest: Callable[..., SamsungTVRest] = SamsungTVRest
    post: Callable[..., requests.Response] = requests.post
    udp_socket: Callable[[], socket.socket] = _udp_socket
    sleep: Callable[[float], None] = time.sleep


class ImageUploadSummary(BaseModel):
    """Summary of batch image upload operation."""

    total_images: int
    successful_uploads: int
    failed_uploads: int
    uploaded_image_ids: List[str]
    errors: List[Dict[str, str]]


class SlideshowStatus(BaseModel):
    """What the TV reports it is playing."""

    interval_minutes: int
    category_id: str
    shuffle: bool
    current_id: str
    playlist_ids: List[str]


def user_art(art_list: ArtList) -> ArtList:
    return [a for a in art_list if a.get("content_id", "").startswith(USER_ART_PREFIX)]


def user_art_ids(art_list: ArtList) -> set[str]:
    return {a["content_id"] for a in user_art(art_list)}


def parse_slideshow_status(raw: Dict[str, Any]) -> SlideshowStatus:
    """Turn the TV's `get_slideshow_status` reply into a SlideshowStatus."""
    playlist = json.loads(raw.get("content_list") or "[]")
    interval = str(raw.get("value", ""))
    return SlideshowStatus(
        interval_minutes=int(interval) if interval.isdigit() else 0,  # "off" when disabled
        category_id=raw.get("category_id", ""),
        shuffle=raw.get("type") == SHUFFLE_SLIDESHOW_TYPE,
        current_id=raw.get("current_content_id", ""),
        playlist_ids=[item["content_id"] for item in playlist],
    )


def slideshow_problems(
    status: SlideshowStatus,
    art_ids: set[str],
    interval_minutes: int,
    shuffle: bool,
    art_mode_on: bool,
) -> List[str]:
    """Differences between what the TV is playing and what should be playing; [] = verified."""
    playlist = set(status.playlist_ids)
    problems = []
    if not art_mode_on:
        problems.append("art mode is off")
    if not art_ids:
        problems.append("no user-uploaded photos are on the TV")
    if status.category_id != MY_PICTURES_CATEGORY:
        problems.append(f"playing category {status.category_id!r}, expected My Pictures")
    if status.interval_minutes == 0:
        problems.append("slideshow is off")
    elif status.interval_minutes != interval_minutes:
        problems.append(f"interval is {status.interval_minutes} min, expected {interval_minutes}")
    if status.shuffle != shuffle:
        problems.append(
            f"shuffle is {'on' if status.shuffle else 'off'}, expected {'on' if shuffle else 'off'}"
        )
    if missing := art_ids - playlist:
        problems.append(f"playlist is missing {len(missing)} photos that are on the TV")
    if stale := playlist - art_ids:
        problems.append(f"playlist holds {len(stale)} items that are not on the TV")
    if status.current_id and status.current_id not in art_ids:
        problems.append(f"current item {status.current_id} is not a photo on the TV")
    return problems


def validate_matte(matte: str, available_mattes: List[str]) -> None:
    """Raise ValueError unless `matte` is `<type>` or `<type>_<color>` the TV supports."""
    base, _, color = matte.rpartition("_") if "_" in matte else (matte, "", "")
    if base not in available_mattes:
        raise ValueError(f"Invalid matte type: {base}. Supported: {', '.join(available_mattes)}")
    if color and color not in VALID_MATTE_COLORS:
        raise ValueError(f"Invalid color: {color}. Supported: {', '.join(VALID_MATTE_COLORS)}")


class SamsungFrameClient:
    """Client for Samsung Frame TV art mode management."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        token_file: Optional[str] = None,
        timeout: int = 60,
        config: Optional[SamsungFrameConfig] = None,
        io: TvIo = TvIo(),
    ):
        self.cfg = config or get_config().samsung_frame
        self.io = io
        self.host = host or self.cfg.ip
        self.port = port or self.cfg.port
        self.token_file = token_file or self.cfg.token_file
        self.timeout = timeout

        if not self.host:
            raise ValueError("Samsung Frame TV IP address required")

        self.tv: Optional[SamsungTVWS] = None
        self.logger = get_logger(__name__)
        self.logger.info(f"Samsung Frame client initialized for {self.host}:{self.port}")

    def __enter__(self) -> "SamsungFrameClient":
        """Context manager: connect_ready() and return client."""
        if not self.connect_ready():
            raise ConnectionError(f"Failed to get TV ready at {self.host}")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _connected_tv(self) -> SamsungTVWS:
        if not self.tv:
            raise RuntimeError("Not connected to TV - call connect() first")
        return self.tv

    def connect(self) -> bool:
        retry_delay = 2
        for attempt in range(1, CONNECT_ATTEMPTS + 1):
            try:
                token_dir = os.path.dirname(self.token_file)
                if not os.path.exists(token_dir):
                    os.makedirs(token_dir, exist_ok=True)
                    self.logger.info(f"Created token directory: {token_dir}")

                if not os.path.exists(self.token_file):
                    self.logger.warning("No token file found - first-time authentication required")
                    self.logger.info("TV will display pairing prompt - accept on TV screen")
                    self.logger.info(f"Token will be saved to: {self.token_file}")

                self.tv = self.io.tv(
                    host=self.host, port=self.port, token_file=self.token_file, timeout=self.timeout
                )
                self.tv.open()
                self.tv.art().supported()
                self.logger.info(f"Connected to Samsung Frame TV at {self.host}")

                # SamsungTVWS owns the token write; tighten perms after.
                ensure_secret_perms(self.token_file)
                return True
            except Exception as e:
                self.logger.error(f"Connection attempt {attempt}/{CONNECT_ATTEMPTS} failed: {e}")
                if attempt < CONNECT_ATTEMPTS:
                    self.logger.info(f"Retrying in {retry_delay} seconds...")
                    self.io.sleep(retry_delay)
                    retry_delay *= 2

        self.logger.error(f"Failed to connect to TV at {self.host}:{self.port}")
        self.logger.error("Verify TV is powered on and on same network")
        return False

    def _send_wol(self) -> bool:
        """Send Wake-on-LAN magic packets to TV.

        Hardened strategy: sends 3 rounds to both broadcast and directed IP,
        on ports 9 and 7, with optional SecureON password support.
        """
        mac = self.cfg.mac
        if not mac:
            self.logger.warning("No MAC address configured — cannot send Wake-on-LAN")
            return False

        try:
            magic = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "").replace("-", "")) * 16
            wol_password = self.cfg.wol_password
            if wol_password:
                magic += bytes.fromhex(wol_password.replace(":", "").replace("-", ""))

            targets = [("<broadcast>", 9), ("<broadcast>", 7), (self.host, 9), (self.host, 7)]
            for attempt in range(3):
                with self.io.udp_socket() as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    for addr, port in targets:
                        s.sendto(magic, (addr, port))
                if attempt < 2:
                    self.io.sleep(0.5)

            self.logger.info(
                f"Wake-on-LAN sent to {mac} (3 rounds, {len(targets)} targets"
                f"{', SecureON' if wol_password else ''})"
            )
            return True
        except Exception as e:
            self.logger.error(f"Wake-on-LAN failed: {e}")
            return False

    def _smartthings_power_on(self) -> bool:
        """Power on TV via SmartThings cloud API (fallback when WoL fails)."""
        token = self.cfg.smartthings_token
        device_id = self.cfg.smartthings_device_id
        if not token or not device_id:
            return False

        try:
            resp = self.io.post(
                f"https://api.smartthings.com/v1/devices/{device_id}/commands",
                headers={"Authorization": f"Bearer {token}"},
                json={"commands": [{"component": "main", "capability": "switch", "command": "on"}]},
                timeout=10,
            )
            if resp.ok:
                self.logger.info("SmartThings power-on command sent")
                return True
            self.logger.warning(f"SmartThings power-on failed: {resp.status_code} {resp.text}")
            return False
        except Exception as e:
            self.logger.error(f"SmartThings API error: {e}")
            return False

    def _is_tv_reachable(self) -> bool:
        """Check if TV REST API is reachable (works in standby)."""
        try:
            self.io.rest(self.host, port=8001, timeout=3).rest_device_info()
            return True
        except Exception:
            return False

    def _wake_and_connect(self) -> bool:
        """Send WoL + SmartThings, then establish WebSocket connection.

        This is the ONLY method that should be used to (re)connect to the TV.
        Handles wake-from-off via WoL/SmartThings, standby via REST detection,
        and direct WebSocket connect when TV is already on.
        """
        wol_sent = self._send_wol()
        st_sent = self._smartthings_power_on()
        woke = wol_sent or st_sent

        if self.connect():
            return True

        # Connect failed — check if TV is reachable via REST (standby)
        if self._is_tv_reachable():
            self.logger.info("TV in standby, waiting for WebSocket...")
            self.io.sleep(5)
            if self.connect():
                return True

        # TV still unreachable — only wait if a wake signal was actually sent
        if woke and self._wait_for_power(target_on=True, timeout=60, poll_interval=3):
            self.io.sleep(5)
            return self.connect()

        return False

    def connect_ready(self) -> bool:
        """Get TV to art-mode-ready state from any starting state.

        Handles: TV off → WoL → wait → connect → art mode
                 TV standby → connect → art mode
                 TV on (regular) → connect → toggle to art mode
                 TV in art mode → connect → verify
        """
        if self._wake_and_connect():
            if self.ensure_art_mode():
                return True
            self.logger.warning("Connected but art mode failed — rebooting...")
            return self.reboot_and_reconnect()

        self.logger.error("Cannot reach TV — verify power and network")
        return False

    def ping(self) -> bool:
        """Lightweight health check via art().supported(). Raises on failure."""
        self._connected_tv().art().supported()
        return True

    def check_art_support(self) -> bool:
        if not self.tv:
            self.logger.error("Not connected to TV - call connect() first")
            return False

        try:
            support_info = self.tv.art().supported()
            self.logger.info(f"Art mode support: {support_info}")
            return bool(support_info)
        except Exception as e:
            self.logger.error(f"Error checking art mode support: {e}")
            return False

    def get_device_info(self) -> Optional[Dict[str, Any]]:
        if not self.tv:
            self.logger.error("Not connected to TV - call connect() first")
            return None

        try:
            return self.tv.rest_device_info()
        except Exception as e:
            self.logger.error(f"Error getting device info: {e}")
            return None

    def validate_image_file(self, file_path: str) -> bool:
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return False

            ext = Path(file_path).suffix.lower().lstrip(".")
            if ext not in self.cfg.supported_formats:
                self.logger.error(
                    f"Unsupported format: {ext}. Supported: {self.cfg.supported_formats}"
                )
                return False

            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if file_size_mb > self.cfg.max_image_size_mb:
                self.logger.error(
                    f"File too large: {file_size_mb:.2f}MB > {self.cfg.max_image_size_mb}MB"
                )
                return False

            with Image.open(file_path) as img:
                img.verify()

            return True

        except Exception as e:
            self.logger.error(f"Error validating image {file_path}: {e}")
            return False

    def upload_image(self, image_path: str, matte: Optional[str] = None) -> Optional[str]:
        if not self.tv:
            self.logger.error("Not connected to TV - call connect() first")
            return None

        matte = matte or self.cfg.default_matte
        if not self.validate_image_file(image_path):
            return None

        try:
            image_data = Path(image_path).read_bytes()
            file_ext = Path(image_path).suffix.lower().lstrip(".")
            if file_ext == "jpeg":
                file_ext = "jpg"

            self.logger.debug(f"Uploading {image_path} ({file_ext}) with matte '{matte}'...")

            def _timeout_handler(_signum: int, _frame: Any) -> None:
                raise TimeoutError(f"Upload exceeded {ART_UPLOAD_TIMEOUT}s")

            old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(ART_UPLOAD_TIMEOUT)
            try:
                image_id = self.tv.art(timeout=10).upload(
                    image_data, matte=matte, file_type=file_ext
                )
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)

            self.logger.debug(f"Successfully uploaded {image_path} -> ID: {image_id}")
            return str(image_id) if image_id else None

        except TimeoutError:
            self.logger.error(f"Upload timed out after {ART_UPLOAD_TIMEOUT}s: {image_path}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to upload {image_path}: {e}")
            return None

    def _recover_art_mode(self, may_reboot: bool) -> tuple[bool, bool]:
        """After a failed upload: (TV is usable again, a reboot was spent getting there)."""
        if self.ensure_art_mode():
            return True, False
        if not may_reboot:
            return False, False
        self.logger.warning("Lost art mode, attempting reboot recovery...")
        return self.reboot_and_reconnect(), True

    def upload_images(
        self,
        image_files: List[str],
        *,
        matte: Optional[str] = None,
        on_uploaded: Optional[Callable[[str, str], None]] = None,
    ) -> ImageUploadSummary:
        """Upload image files to the TV, pausing between images and recovering a TV that stalls.

        Args:
            image_files: List of absolute paths to upload-ready images
            matte: Matte style override (default from config)
            on_uploaded: Optional callback called as (source path, TV content id) the moment an
                        image is on the TV, so a caller can checkpoint it.

        A failed image is checked against the TV's art list (an upload can land despite a
        timeout), then the TV is brought back to art mode, by one reboot per run if it must be.
        The run stops when the TV cannot be recovered. An error raised by `on_uploaded`
        propagates: a checkpoint that cannot be written must stop the run.
        """
        self._connected_tv()
        matte = matte or self.cfg.default_matte
        self.logger.info(f"Uploading {len(image_files)} images")

        uploaded_ids: List[str] = []
        errors: List[Dict[str, str]] = []
        known_ids = self._get_art_ids_on_tv() if image_files else set()
        rebooted = False
        pause = MIN_UPLOAD_PAUSE

        try:
            pbar = tqdm(image_files, desc="Uploading images", unit="img")
            for image_path in pbar:
                name = os.path.basename(image_path)
                pbar.set_postfix_str(name)
                image_id = self.upload_image(image_path, matte=matte)
                if not image_id:
                    image_id = self._check_for_new_upload(known_ids)
                if image_id:
                    uploaded_ids.append(image_id)
                    known_ids.add(image_id)
                    if on_uploaded:
                        on_uploaded(image_path, image_id)
                    pause = max(pause - 1, MIN_UPLOAD_PAUSE)
                    self.io.sleep(pause)
                    continue

                errors.append({"file": name, "error": "Upload did not arrive on the TV"})
                pause = min(pause + 5, MAX_UPLOAD_PAUSE)
                self.logger.info(f"TV needs cooldown, pausing {pause}s")
                self.io.sleep(pause)
                usable, spent_reboot = self._recover_art_mode(may_reboot=not rebooted)
                rebooted = rebooted or spent_reboot
                if not usable:
                    self.logger.error("Cannot recover art mode — stopping uploads")
                    break
        except (KeyboardInterrupt, SystemExit):
            self.logger.warning(
                f"Upload interrupted — {len(uploaded_ids)} successful, {len(errors)} failed"
            )

        summary = ImageUploadSummary(
            total_images=len(image_files),
            successful_uploads=len(uploaded_ids),
            failed_uploads=len(errors),
            uploaded_image_ids=uploaded_ids,
            errors=errors,
        )
        complete = len(uploaded_ids) + len(errors) == len(image_files)
        self.logger.info(
            f"Upload {'complete' if complete else 'stopped early'}"
            f": {summary.successful_uploads}/{summary.total_images} successful"
        )
        return summary

    def _get_art_ids_on_tv(self) -> set[str]:
        """Current user-uploaded art ids on the TV; empty when the TV cannot be read."""
        try:
            return user_art_ids(self.get_available_art())
        except Exception:
            return set()

    def _check_for_new_upload(self, known_ids: set[str]) -> Optional[str]:
        """The new art ID if exactly one appeared on the TV (upload succeeded despite timeout).

        Zero means it did not arrive; several means the baseline listing was unreliable, and
        guessing would record some old photo's id as this upload's.
        """
        new_ids = self._get_art_ids_on_tv() - known_ids
        return next(iter(new_ids)) if len(new_ids) == 1 else None

    def ensure_art_mode(self) -> bool:
        """Ensure TV is in art mode. Try art API first, power-cycle if needed.

        Frame TVs boot into art mode from standby, so: KEY_POWER (off) → wait →
        reconnect (wakes into art mode).

        Returns:
            True if TV is confirmed in art mode with art API responding
        """
        self._send_wol()
        if not self.tv:
            if not self._wake_and_connect():
                return False

        # Already in art mode?
        try:
            self.get_available_art_strict()
            self.logger.debug("Art mode confirmed, API responding")
            return True
        except Exception:
            pass

        # KEY_POWER toggles: TV mode → off, off → art mode
        # May need two toggles if TV is in regular mode
        self.logger.info("Art API not responding, toggling KEY_POWER into art mode...")
        try:
            if self.tv:
                self.tv.send_key("KEY_POWER")
        except Exception:
            pass
        self.close()

        for attempt in range(1, 4):
            wait = 10 * attempt
            self.logger.info(f"Waiting {wait}s for art mode (attempt {attempt}/3)...")
            self.io.sleep(wait)
            try:
                if self._wake_and_connect():
                    self.get_available_art_strict()
                    self.logger.info("Art mode activated via KEY_POWER toggle")
                    return True
            except Exception:
                self.close()

        self.logger.error("Failed to activate art mode after retries")
        return False

    def _reconnect(self) -> bool:
        """Close and re-establish TV connection."""
        self.logger.info("Closing stale connection...")
        self.close()
        self.io.sleep(2)
        return self._wake_and_connect()

    def _wait_for_power(self, target_on: bool, timeout: int = 120, poll_interval: int = 3) -> bool:
        """Poll REST API until TV power state matches target or timeout.

        REST API (HTTP GET on port 8001) works without WebSocket — lightweight check.
        """
        rest = self.io.rest(self.host, port=8001, timeout=5)
        state_name = "on" if target_on else "off"
        elapsed = 0

        while elapsed < timeout:
            try:
                if rest.rest_power_state() == target_on:
                    self.logger.info(f"TV power state is {state_name}")
                    return True
            except Exception:
                if not target_on:
                    # Connection refused = TV is off
                    self.logger.info("TV is off (REST unreachable)")
                    return True
            self.io.sleep(poll_interval)
            elapsed += poll_interval

        self.logger.warning(f"Timed out waiting for TV to be {state_name}")
        return False

    def reboot_and_reconnect(self, max_attempts: int = 3) -> bool:
        """Reboot TV, poll for power cycle, reconnect into art mode."""
        if not self.reboot():
            # No WebSocket connection — try WoL to wake TV instead
            self.logger.info("Cannot reboot (not connected) — trying WoL wake...")
            if not self._send_wol():
                self.logger.error("No connection and WoL failed — cannot proceed")
                return False

        # Wait for TV to go down (or timeout — it may already be restarting)
        self._wait_for_power(target_on=False, timeout=15, poll_interval=2)

        # Wait for TV to come back up
        if not self._wait_for_power(target_on=True, timeout=120, poll_interval=5):
            self.logger.error("TV did not come back after reboot")
            return False

        # TV is up — connect and get into art mode
        for attempt in range(1, max_attempts + 1):
            self.logger.info(f"Connecting to art mode (attempt {attempt}/{max_attempts})...")
            try:
                if self._wake_and_connect() and self.ensure_art_mode():
                    self.logger.info("Reconnected after reboot, art mode verified")
                    return True
            except Exception:
                self.close()
            self.io.sleep(5)

        self.logger.error("TV is up but art mode failed")
        return False

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def _fetch_art_list(self) -> ArtList:
        """Fetch art list with retry. Raises on error."""
        art_list = self._connected_tv().art().available()
        if isinstance(art_list, dict) and art_list.get("event") == "ms.channel.timeOut":
            raise TimeoutError("TV art list request timed out")
        return cast(ArtList, art_list)

    def get_available_art_strict(self) -> ArtList:
        """Get available art, raising on error instead of returning []."""
        self._connected_tv()
        art_list = self._fetch_art_list()
        self.logger.debug(f"Retrieved {len(user_art(art_list))} user uploaded images from TV")
        return art_list

    def get_available_art(self) -> ArtList:
        """Get available art; [] when the TV cannot be read (not connected still raises)."""
        self._connected_tv()
        try:
            return self.get_available_art_strict()
        except Exception as e:
            self.logger.error(f"Error getting available art after retries: {e}")
            return []

    def _matte_types(self) -> List[str]:
        matte_list = self._connected_tv().art().get_matte_list()
        return [matte_type for elem in matte_list for matte_type in elem.values()]

    def get_available_mattes(self) -> List[str]:
        self._connected_tv()
        try:
            available_mattes = self._matte_types()
            self.logger.info(f"Retrieved {len(available_mattes)} available matte types")
            return available_mattes
        except Exception as e:
            self.logger.error(f"Error getting matte list: {e}")
            return []

    def update_all_mattes(
        self, matte: Optional[str] = None, user_photos_only: bool = True
    ) -> Dict[str, int]:
        tv = self._connected_tv()
        matte = matte or self.cfg.default_matte
        validate_matte(matte, self._matte_types())

        art_list = self.get_available_art()
        if user_photos_only:
            art_list = user_art(art_list)

        if not art_list:
            self.logger.warning("No art found on TV to update")
            return {"total": 0, "updated": 0, "skipped": 0, "failed": 0}

        updated = 0
        skipped = 0
        failed = 0

        for art_item in tqdm(art_list, desc="Updating mattes", unit="art"):
            content_id = art_item.get("content_id")
            current_matte = art_item.get("matte_id")

            if not content_id:
                self.logger.warning("Skipping art item without content_id")
                failed += 1
                continue

            if current_matte == matte:
                self.logger.info(f"Art {content_id} already has matte '{matte}', skipping")
                skipped += 1
                continue

            try:
                self.logger.info(
                    f"Changing matte for {content_id} from '{current_matte}' to '{matte}'"
                )
                tv.art().change_matte(content_id, matte)
                updated += 1
            except Exception as e:
                self.logger.error(f"Failed to update matte for art ID {content_id}: {e}")
                failed += 1

            self.io.sleep(1)
            try:
                self.ping()
            except Exception:
                self.logger.warning("Connection lost, reconnecting...")
                if not self._reconnect():
                    self.logger.error("Reconnect failed — stopping matte updates")
                    break
                tv = self._connected_tv()

        self.logger.info(
            f"Matte update complete: {updated} updated, {skipped} skipped, {failed} failed"
        )
        return {"total": len(art_list), "updated": updated, "skipped": skipped, "failed": failed}

    def enable_art_mode(self) -> bool:
        if not self.tv:
            self.logger.error("Not connected to TV - call connect() first")
            return False

        try:
            if self.tv.art().get_artmode() == "on":
                self.logger.info("Already in art mode")
                return True
        except Exception:
            pass

        try:
            self.tv.art().set_artmode(True)
            self.logger.info("Art mode enabled")
            return True
        except Exception as e:
            if "timed out" in str(e).lower():
                self.logger.debug("Art mode set timed out (likely already in art mode)")
                return True
            self.logger.error(f"Error enabling art mode: {e}")
            return False

    def start_slideshow(self, duration: int = 15, shuffle: bool = True) -> bool:
        """Start slideshow with automatic image cycling. Retries up to 3 times.

        Args:
            duration: Time in minutes between image changes (default: 15)
            shuffle: Enable shuffle mode (default: True)

        Returns:
            True if slideshow started successfully
        """
        if not self.tv:
            self.logger.error("Not connected to TV - call connect() first")
            return False

        self.enable_art_mode()

        for attempt in range(1, 4):
            try:
                self.tv.art().set_slideshow_status(duration=duration, type=shuffle, category=2)
                self.logger.info(
                    f"Slideshow started: {duration}min interval, "
                    f"{'shuffle' if shuffle else 'sequential'} mode"
                )
                return True
            except Exception as e:
                # slideshow_image_changed response means it's actually working
                if "slideshow_image_changed" in str(e):
                    self.logger.info("Slideshow confirmed running (image changed event)")
                    return True
                self.logger.warning(f"Slideshow attempt {attempt}/3 failed: {e}")
                self.io.sleep(2)

        self.logger.error("Failed to start slideshow after 3 attempts")
        return False

    def get_slideshow_status(self) -> SlideshowStatus:
        return parse_slideshow_status(self._connected_tv().art().get_slideshow_status())

    def verify_slideshow(
        self, duration: int, shuffle: bool, settle_seconds: float = SLIDESHOW_SETTLE_SECONDS
    ) -> List[str]:
        """Read the slideshow back from the TV; returns the problems found (empty = verified).

        A TV that cannot be read back is a problem, not an exception: the caller's question is
        "is it verified", and an unreadable TV is not.
        """
        tv = self._connected_tv()
        self.io.sleep(settle_seconds)
        try:
            status = self.get_slideshow_status()
            art_ids = user_art_ids(self.get_available_art_strict())
            art_mode_on = tv.art().get_artmode() == "on"
        except Exception as e:
            return [f"could not read the slideshow back from the TV: {e}"]
        self.logger.info(
            f"Slideshow reads back as {len(status.playlist_ids)} photos, "
            f"{status.interval_minutes} min, {'shuffle' if status.shuffle else 'sequential'}, "
            f"current {status.current_id}"
        )
        return slideshow_problems(status, art_ids, duration, shuffle, art_mode_on)

    def cycle_images(
        self, period: int = 15, user_photos_only: bool = True, shuffle: bool = True
    ) -> None:
        """Show each image for `period` seconds, forever, until Ctrl+C.

        Args:
            period: Time in seconds between image changes (default: 15)
            user_photos_only: Only cycle through user-uploaded photos (default: True)
            shuffle: Randomize image order each cycle (default: True)
        """
        tv = self._connected_tv()
        art_list = self.get_available_art()
        if user_photos_only:
            art_list = user_art(art_list)
        if not art_list:
            self.logger.warning("No art items to cycle through")
            return

        self.enable_art_mode()
        self.logger.info(
            f"Cycling {len(art_list)} items every {period}s "
            f"({'shuffle' if shuffle else 'sequential'} mode); press Ctrl+C to stop"
        )

        cycle_count = 0
        try:
            while True:
                if shuffle:
                    random.shuffle(art_list)

                for art_item in art_list:
                    content_id = art_item.get("content_id")
                    if not content_id:
                        continue
                    try:
                        tv.art().select_image(content_id)
                        self.logger.info(f"Displaying: {content_id}")
                    except Exception as e:
                        self.logger.error(f"Failed to display {content_id}: {e}")
                        continue
                    self.io.sleep(period)

                cycle_count += 1
                self.logger.info(f"Completed cycle {cycle_count}")

        except KeyboardInterrupt:
            self.logger.info(f"Image cycling stopped after {cycle_count} complete cycles")

    def download_thumbnails(self, output_dir: str, user_photos_only: bool = True) -> Dict[str, int]:
        tv = self._connected_tv()
        os.makedirs(output_dir, exist_ok=True)

        art_list = self.get_available_art()
        if user_photos_only:
            art_list = user_art(art_list)
        if not art_list:
            self.logger.warning("No art found on TV")
            return {"total": 0, "downloaded": 0, "failed": 0}

        downloaded = 0
        failed = 0

        for art_item in art_list:
            content_id = art_item.get("content_id")
            if not content_id:
                self.logger.warning("Skipping art item without content_id")
                failed += 1
                continue

            try:
                output_path = Path(output_dir) / f"{content_id}.jpg"
                output_path.write_bytes(tv.art().get_thumbnail(content_id))
                self.logger.info(f"Saved thumbnail to {output_path}")
                downloaded += 1
            except Exception as e:
                self.logger.error(f"Failed to download thumbnail for {content_id}: {e}")
                failed += 1

        self.logger.info(f"Thumbnail download complete: {downloaded} downloaded, {failed} failed")
        return {"total": len(art_list), "downloaded": downloaded, "failed": failed}

    def reboot(self) -> bool:
        """Hard reboot TV via 5s power hold. Does not wait for TV to come back.

        hold_key sends Press, sleeps 5s, sends Release. The TV reboots mid-hold,
        dropping the WebSocket — the resulting exception is the expected success path.
        Always returns True once hold_key is called.
        """
        if not self.tv:
            self.logger.error("Not connected to TV - call connect() first")
            return False

        try:
            self.logger.info("Sending hold_key(KEY_POWER, 5) for hard reboot...")
            self.tv.hold_key("KEY_POWER", 5)
        except Exception as e:
            self.logger.info(f"hold_key interrupted (expected during reboot): {e}")
        finally:
            self.close()
        return True

    def close(self) -> None:
        """Close connection to TV."""
        if self.tv:
            try:
                self.tv.close()
                self.logger.info("Closed connection to TV")
            except Exception as e:
                self.logger.warning(f"Error closing TV connection: {e}")


@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5), reraise=True)
def _delete_with_retry(delete: Callable[[Any], None], target: Any) -> None:
    delete(target)


def delete_art_by_ids(client: SamsungFrameClient, content_ids: List[str]) -> Dict[str, int]:
    """Delete art by content id: one batch call, falling back to one call per id.

    Returns:
        {'total': int, 'deleted': int, 'failed': int}
    """
    tv = client.tv
    if not tv:
        raise RuntimeError("Not connected to TV")

    total = len(content_ids)
    if total == 0:
        return {"total": 0, "deleted": 0, "failed": 0}

    logger.info(f"Deleting {total} art items...")
    try:
        _delete_with_retry(
            lambda ids: tv.art().delete_list(ids), content_ids
        )  # fresh channel per try
        logger.info(f"Successfully deleted {total} items via batch delete")
        return {"total": total, "deleted": total, "failed": 0}
    except Exception as e:
        logger.warning(f"Batch delete failed after retries: {e}. Falling back to individual...")

    failed = 0
    for content_id in content_ids:
        try:
            _delete_with_retry(lambda cid: tv.art().delete(cid), content_id)
        except Exception as e:
            logger.error(f"Failed to delete {content_id} after retries: {e}")
            failed += 1

    logger.info(f"Individual deletion complete: {total - failed} deleted, {failed} failed")
    return {"total": total, "deleted": total - failed, "failed": failed}


def delete_all_art(
    client: SamsungFrameClient, force: bool = False, ask: Callable[[str], str] = input
) -> Dict[str, int]:
    """Delete all user-uploaded art from TV (not pre-loaded Samsung art); confirms unless forced."""
    if not client.tv:
        raise RuntimeError("Not connected to TV")

    content_ids = sorted(user_art_ids(client.get_available_art()))
    total = len(content_ids)
    if total == 0:
        logger.info("No user-uploaded art found on TV")
        return {"total": 0, "deleted": 0, "failed": 0}

    prompt = f"Delete {total} user-uploaded art items from TV? [y/N]: "
    if not force and ask(prompt).strip().lower() != "y":
        logger.info("Deletion cancelled by user")
        return {"total": total, "deleted": 0, "failed": 0}

    return delete_art_by_ids(client, content_ids)


def _image_time(art: Dict[str, Any]) -> Optional[datetime]:
    """The TV's upload timestamp for an art item; None when missing or unreadable.

    The TV reports its own wall-clock time with no zone, so the value is naive local time.
    """
    try:
        return datetime.strptime(art.get("image_date") or "", IMAGE_DATE_FORMAT)
    except ValueError:
        return None


def get_stale_art_ids(
    art_list: ArtList, max_age_hours: int = 24, now: Optional[datetime] = None
) -> List[str]:
    """User art older than max_age_hours by the TV's image_date, oldest first.

    `now` is naive local time, like the TV's dates. An item with no readable date counts as
    oldest.
    """
    now = now or datetime.now()
    by_id = {a["content_id"]: a for a in user_art(art_list)}  # the TV can list a photo twice
    dated = sorted((_image_time(a) or datetime.min, cid) for cid, a in by_id.items())
    return [cid for ts, cid in dated if (now - ts).total_seconds() / 3600 > max_age_hours]


def plan_purge(
    art_list: ArtList, max_age_hours: int, min_images: int, now: Optional[datetime] = None
) -> List[str]:
    """Stale user art to delete, oldest first, keeping the TV at `min_images` user photos."""
    stale = get_stale_art_ids(art_list, max_age_hours, now)
    deletable = max(0, len(user_art_ids(art_list)) - min_images)
    return stale[:deletable]
