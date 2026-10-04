"""Tests for Samsung Frame TV client."""

import json
import os
import socket
import tempfile

import pytest
from PIL import Image
from unittest.mock import Mock, patch, MagicMock

from SamsungFrame.samsung_client import (
    MY_PICTURES_CATEGORY,
    SamsungFrameClient,
    SlideshowStatus,
    parse_slideshow_status,
    slideshow_problems,
)

TV_HOST = "192.0.2.4"
TOKEN_FILE = "/tmp/token.txt"


def make_client(**kwargs: object) -> SamsungFrameClient:
    kwargs.setdefault("host", TV_HOST)
    kwargs.setdefault("token_file", TOKEN_FILE)
    return SamsungFrameClient(**kwargs)  # type: ignore[arg-type]


class TestSamsungFrameClient:
    def test_init_with_config(self) -> None:
        mock_cfg = MagicMock()
        mock_cfg.samsung_frame.ip = TV_HOST
        mock_cfg.samsung_frame.port = 8002
        mock_cfg.samsung_frame.token_file = TOKEN_FILE

        with patch("SamsungFrame.samsung_client.cfg", mock_cfg):
            client = SamsungFrameClient()
            assert client.host == TV_HOST
            assert client.port == 8002

    def test_init_missing_host(self) -> None:
        mock_cfg = MagicMock()
        mock_cfg.samsung_frame.ip = ""
        mock_cfg.samsung_frame.port = 8002
        mock_cfg.samsung_frame.token_file = TOKEN_FILE

        with patch("SamsungFrame.samsung_client.cfg", mock_cfg):
            with pytest.raises(ValueError, match="Samsung Frame TV IP address required"):
                SamsungFrameClient()

    @patch("SamsungFrame.samsung_client.SamsungTVWS")
    @patch("os.path.exists", return_value=True)
    @patch("os.chmod")
    def test_connect_success(self, _chmod: Mock, _exists: Mock, mock_tv: Mock) -> None:
        mock_tv_instance = Mock()
        mock_tv_instance.art().supported.return_value = True
        mock_tv.return_value = mock_tv_instance

        client = make_client()
        assert client.connect() is True
        assert client.tv is not None

    @patch("SamsungFrame.samsung_client.SamsungTVWS")
    @patch("os.path.exists", return_value=True)
    @patch("os.chmod")
    @patch("time.sleep")
    def test_connect_with_retry(
        self, mock_sleep: Mock, _chmod: Mock, _exists: Mock, mock_tv: Mock
    ) -> None:
        fail = Mock()
        fail.art().supported.side_effect = ConnectionError("fail")
        success = Mock()
        success.art().supported.return_value = True
        mock_tv.side_effect = [fail, fail, success]

        client = make_client()
        assert client.connect() is True
        assert mock_tv.call_count == 3

    @patch("SamsungFrame.samsung_client.SamsungTVWS")
    @patch("os.path.exists", return_value=True)
    @patch("time.sleep")
    def test_connect_max_retries(self, _sleep: Mock, _exists: Mock, mock_tv: Mock) -> None:
        mock_tv_instance = Mock()
        mock_tv_instance.art().supported.side_effect = ConnectionError("fail")
        mock_tv.return_value = mock_tv_instance

        client = make_client()
        assert client.connect() is False
        assert mock_tv.call_count == 3

    def test_validate_image_file_invalid_format(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            path = f.name
        try:
            assert make_client().validate_image_file(path) is False
        finally:
            os.unlink(path)

    def test_validate_image_file_success(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            Image.new("RGB", (100, 100), color="red").save(f, format="JPEG")
            path = f.name
        try:
            assert make_client().validate_image_file(path) is True
        finally:
            os.unlink(path)

    def test_upload_image_success(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            Image.new("RGB", (100, 100), color="blue").save(f, format="JPEG")
            path = f.name
        try:
            mock_tv = Mock()
            mock_tv.art().upload.return_value = "image123"
            client = make_client()
            client.tv = mock_tv
            assert client.upload_image(path) == "image123"
        finally:
            os.unlink(path)

    @patch("SamsungFrame.samsung_client.SamsungTVWS")
    def test_upload_images_success(self, mock_tv_cls: Mock) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = []
            for i in range(3):
                p = os.path.join(tmp_dir, f"img{i}.jpg")
                Image.new("RGB", (100, 100)).save(p, format="JPEG")
                paths.append(p)

            mock_tv = Mock()
            mock_tv.art().upload.side_effect = ["id1", "id2", "id3"]
            client = make_client()
            client.tv = mock_tv

            summary = client.upload_images(paths)
            assert summary.successful_uploads == 3
            assert summary.failed_uploads == 0

    @patch("SamsungFrame.samsung_client.SamsungTVWS")
    def test_upload_images_partial_failure(self, mock_tv_cls: Mock) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = []
            for i in range(2):
                p = os.path.join(tmp_dir, f"img{i}.jpg")
                Image.new("RGB", (100, 100)).save(p, format="JPEG")
                paths.append(p)
            bad = os.path.join(tmp_dir, "bad.jpg")
            with open(bad, "w") as f:
                f.write("not an image")
            paths.append(bad)

            mock_tv = Mock()
            mock_tv.art().upload.side_effect = ["id1", "id2"]
            client = make_client()
            client.tv = mock_tv

            summary = client.upload_images(paths)
            assert summary.successful_uploads == 2
            assert summary.failed_uploads == 1

    def test_enable_art_mode_already_on(self) -> None:
        mock_tv = Mock()
        mock_tv.art().get_artmode.return_value = "on"
        client = make_client()
        client.tv = mock_tv

        assert client.enable_art_mode() is True
        mock_tv.art().set_artmode.assert_not_called()

    def test_enable_art_mode_timeout_is_success(self) -> None:
        mock_tv = Mock()
        mock_tv.art().get_artmode.return_value = "off"
        mock_tv.art().set_artmode.side_effect = TimeoutError("timed out")
        client = make_client()
        client.tv = mock_tv

        assert client.enable_art_mode() is True

    @patch("time.sleep")
    def test_cycle_images_filters_user_photos(self, mock_sleep: Mock) -> None:
        mock_tv = Mock()
        mock_tv.art().available.return_value = [
            {"content_id": "MY_F0001"},
            {"content_id": "MY_F0002"},
            {"content_id": "ART_12345"},
        ]
        mock_tv.art().set_artmode.return_value = None
        mock_sleep.side_effect = [None, KeyboardInterrupt()]

        client = make_client()
        client.tv = mock_tv
        client.cycle_images(period=15, user_photos_only=True)

        assert mock_tv.art().select_image.call_count == 2
        mock_tv.art().select_image.assert_any_call("MY_F0001")
        mock_tv.art().select_image.assert_any_call("MY_F0002")


class TestPing:
    def test_not_connected_raises(self) -> None:
        with pytest.raises(RuntimeError, match="Not connected"):
            make_client().ping()

    def test_failure_propagates(self) -> None:
        mock_tv = Mock()
        mock_tv.art().supported.side_effect = TimeoutError("timeout")
        client = make_client()
        client.tv = mock_tv

        with pytest.raises(TimeoutError):
            client.ping()


class TestGetAvailableArtStrict:
    def test_not_connected_raises(self) -> None:
        with pytest.raises(RuntimeError):
            make_client().get_available_art_strict()

    def test_success(self) -> None:
        mock_tv = Mock()
        mock_tv.art().available.return_value = [{"content_id": "MY_F001"}]
        client = make_client()
        client.tv = mock_tv

        result = client.get_available_art_strict()
        assert len(result) == 1

    def test_timeout_response_raises(self) -> None:
        mock_tv = Mock()
        mock_tv.art().available.return_value = {"event": "ms.channel.timeOut"}
        client = make_client()
        client.tv = mock_tv

        with pytest.raises(TimeoutError):
            client.get_available_art_strict()

    def test_lenient_returns_empty_on_error(self) -> None:
        mock_tv = Mock()
        mock_tv.art().available.side_effect = ConnectionError("closed")
        client = make_client()
        client.tv = mock_tv

        assert client.get_available_art() == []


class TestReconnectDuringUpload:
    @patch("time.sleep")
    def test_stops_after_reconnect_fails(self, _sleep: Mock) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = []
            for i in range(5):
                p = os.path.join(tmp_dir, f"img_{i}.jpg")
                Image.new("RGB", (100, 100)).save(p, format="JPEG")
                paths.append(p)

            mock_tv = Mock()
            mock_tv.art().upload.return_value = None
            client = make_client()
            client.tv = mock_tv

            with (
                patch.object(client, "_reconnect", return_value=False),
                patch.object(client, "ensure_art_mode", return_value=False),
                patch.object(client, "_reboot_and_reconnect", return_value=False),
            ):
                summary = client.upload_images(paths, max_consecutive_failures=3)

            assert summary.successful_uploads == 0

    @patch("time.sleep")
    def test_only_one_reboot_per_batch(self, _sleep: Mock) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = []
            for i in range(8):
                p = os.path.join(tmp_dir, f"img_{i}.jpg")
                Image.new("RGB", (100, 100)).save(p, format="JPEG")
                paths.append(p)

            mock_tv = Mock()
            mock_tv.art().upload.return_value = None
            client = make_client()
            client.tv = mock_tv

            reboot_mock = Mock(return_value=False)
            with (
                patch.object(client, "ensure_art_mode", return_value=False),
                patch.object(client, "_reboot_and_reconnect", reboot_mock),
            ):
                client.upload_images(paths, max_consecutive_failures=3)

            reboot_mock.assert_called_once()


class TestSendWol:
    def test_no_mac_returns_false(self) -> None:
        mock_cfg = MagicMock()
        mock_cfg.samsung_frame.mac = ""
        with patch("SamsungFrame.samsung_client.cfg", mock_cfg):
            assert make_client()._send_wol() is False

    @patch("SamsungFrame.samsung_client.time")
    @patch("SamsungFrame.samsung_client.socket")
    def test_multi_target_packets(self, mock_socket_mod: Mock, _time: Mock) -> None:
        mock_cfg = MagicMock()
        mock_cfg.samsung_frame.mac = "AA:BB:CC:DD:EE:FF"
        mock_cfg.samsung_frame.wol_password = ""
        mock_sock = MagicMock()
        mock_socket_mod.socket.return_value.__enter__ = Mock(return_value=mock_sock)
        mock_socket_mod.socket.return_value.__exit__ = Mock(return_value=False)
        mock_socket_mod.AF_INET = socket.AF_INET
        mock_socket_mod.SOCK_DGRAM = socket.SOCK_DGRAM
        mock_socket_mod.SOL_SOCKET = socket.SOL_SOCKET
        mock_socket_mod.SO_BROADCAST = socket.SO_BROADCAST

        with patch("SamsungFrame.samsung_client.cfg", mock_cfg):
            assert make_client()._send_wol() is True

        assert mock_sock.sendto.call_count == 12  # 3 rounds × 4 targets
        magic = mock_sock.sendto.call_args_list[0][0][0]
        assert magic[:6] == b"\xff" * 6
        assert len(magic) == 102  # no SecureON

    @patch("SamsungFrame.samsung_client.time")
    @patch("SamsungFrame.samsung_client.socket")
    def test_secureon_appends_password(self, mock_socket_mod: Mock, _time: Mock) -> None:
        mock_cfg = MagicMock()
        mock_cfg.samsung_frame.mac = "AA:BB:CC:DD:EE:FF"
        mock_cfg.samsung_frame.wol_password = "11:22:33:44:55:66"
        mock_sock = MagicMock()
        mock_socket_mod.socket.return_value.__enter__ = Mock(return_value=mock_sock)
        mock_socket_mod.socket.return_value.__exit__ = Mock(return_value=False)
        mock_socket_mod.AF_INET = socket.AF_INET
        mock_socket_mod.SOCK_DGRAM = socket.SOCK_DGRAM
        mock_socket_mod.SOL_SOCKET = socket.SOL_SOCKET
        mock_socket_mod.SO_BROADCAST = socket.SO_BROADCAST

        with patch("SamsungFrame.samsung_client.cfg", mock_cfg):
            assert make_client()._send_wol() is True

        magic = mock_sock.sendto.call_args_list[0][0][0]
        assert len(magic) == 108  # 102 + 6 SecureON


class TestSmartThingsPowerOn:
    def test_no_config_returns_false(self) -> None:
        mock_cfg = MagicMock()
        mock_cfg.samsung_frame.smartthings_token = ""
        mock_cfg.samsung_frame.smartthings_device_id = ""
        with patch("SamsungFrame.samsung_client.cfg", mock_cfg):
            assert make_client()._smartthings_power_on() is False

    @patch("requests.post")
    def test_success(self, mock_post: Mock) -> None:
        mock_cfg = MagicMock()
        mock_cfg.samsung_frame.smartthings_token = "test-token"
        mock_cfg.samsung_frame.smartthings_device_id = "device-123"
        mock_post.return_value = Mock(ok=True)

        with patch("SamsungFrame.samsung_client.cfg", mock_cfg):
            assert make_client()._smartthings_power_on() is True

        assert mock_post.call_args[1]["headers"]["Authorization"] == "Bearer test-token"

    @patch("requests.post")
    def test_api_error(self, mock_post: Mock) -> None:
        mock_cfg = MagicMock()
        mock_cfg.samsung_frame.smartthings_token = "test-token"
        mock_cfg.samsung_frame.smartthings_device_id = "device-123"
        mock_post.return_value = Mock(ok=False, status_code=403, text="Forbidden")

        with patch("SamsungFrame.samsung_client.cfg", mock_cfg):
            assert make_client()._smartthings_power_on() is False


class TestContextManager:
    def test_enter_calls_connect_ready_and_exit_closes(self) -> None:
        client = make_client()
        with (
            patch.object(client, "connect_ready", return_value=True) as mock_cr,
            patch.object(client, "close") as mock_close,
        ):
            with client as c:
                assert c is client
                mock_cr.assert_called_once()
            mock_close.assert_called_once()

    def test_enter_raises_on_failure(self) -> None:
        client = make_client()
        with patch.object(client, "connect_ready", return_value=False):
            with pytest.raises(ConnectionError):
                client.__enter__()

    def test_exit_closes_on_exception(self) -> None:
        client = make_client()
        with (
            patch.object(client, "connect_ready", return_value=True),
            patch.object(client, "close") as mock_close,
        ):
            try:
                with client:
                    raise ValueError("boom")
            except ValueError:
                pass
            mock_close.assert_called_once()


class TestConnectReady:
    @patch("time.sleep")
    def test_already_connected(self, _sleep: Mock) -> None:
        client = make_client()
        with (
            patch.object(client, "_send_wol"),
            patch.object(client, "_smartthings_power_on"),
            patch.object(client, "connect", return_value=True),
            patch.object(client, "ensure_art_mode", return_value=True),
        ):
            assert client.connect_ready() is True

    @patch("time.sleep")
    def test_art_fails_triggers_reboot(self, _sleep: Mock) -> None:
        client = make_client()
        with (
            patch.object(client, "_send_wol"),
            patch.object(client, "_smartthings_power_on"),
            patch.object(client, "connect", return_value=True),
            patch.object(client, "ensure_art_mode", return_value=False),
            patch.object(client, "_reboot_and_reconnect", return_value=True),
        ):
            assert client.connect_ready() is True

    @patch("time.sleep")
    def test_wol_wakes_tv(self, _sleep: Mock) -> None:
        client = make_client()
        connect_results = iter([False, True])

        with (
            patch.object(client, "_send_wol", return_value=True),
            patch.object(client, "_smartthings_power_on"),
            patch.object(client, "connect", side_effect=lambda: next(connect_results)),
            patch.object(client, "_is_tv_reachable", return_value=False),
            patch.object(client, "_wait_for_power", return_value=True),
            patch.object(client, "ensure_art_mode", return_value=True),
        ):
            assert client.connect_ready() is True

    @patch("time.sleep")
    def test_standby_retry(self, _sleep: Mock) -> None:
        client = make_client()
        connect_results = iter([False, True])

        with (
            patch.object(client, "_send_wol"),
            patch.object(client, "_smartthings_power_on"),
            patch.object(client, "connect", side_effect=lambda: next(connect_results)),
            patch.object(client, "_is_tv_reachable", return_value=True),
            patch.object(client, "ensure_art_mode", return_value=True),
        ):
            assert client.connect_ready() is True

    @patch("time.sleep")
    def test_all_phases_fail(self, _sleep: Mock) -> None:
        client = make_client()
        with (
            patch.object(client, "_send_wol"),
            patch.object(client, "_smartthings_power_on"),
            patch.object(client, "connect", return_value=False),
            patch.object(client, "_is_tv_reachable", return_value=False),
            patch.object(client, "_wait_for_power", return_value=False),
        ):
            assert client.connect_ready() is False

    @patch("time.sleep")
    def test_wol_fires_before_connect(self, _sleep: Mock) -> None:
        client = make_client()
        call_order: list[str] = []

        def _track_connect() -> bool:
            call_order.append("connect")
            return True

        with (
            patch.object(client, "_send_wol", side_effect=lambda: call_order.append("wol")),
            patch.object(
                client, "_smartthings_power_on", side_effect=lambda: call_order.append("st")
            ),
            patch.object(client, "connect", side_effect=_track_connect),
            patch.object(client, "ensure_art_mode", return_value=True),
        ):
            assert client.connect_ready() is True

        assert call_order[:2] == ["wol", "st"]
        assert call_order[2] == "connect"


class TestReboot:
    def test_not_connected(self) -> None:
        assert make_client().reboot() is False

    def test_success(self) -> None:
        mock_tv = Mock()
        client = make_client()
        client.tv = mock_tv

        assert client.reboot() is True
        mock_tv.hold_key.assert_called_once_with("KEY_POWER", 5)
        mock_tv.close.assert_called_once()

    def test_exception_during_hold_is_success(self) -> None:
        mock_tv = Mock()
        mock_tv.hold_key.side_effect = OSError("Connection lost")
        client = make_client()
        client.tv = mock_tv

        assert client.reboot() is True
        mock_tv.close.assert_called_once()


class TestRebootAndReconnect:
    @patch("time.sleep")
    def test_wol_fallback_fails(self, _sleep: Mock) -> None:
        client = make_client()
        with patch.object(client, "_send_wol", return_value=False):
            assert client._reboot_and_reconnect() is False

    @patch("time.sleep")
    @patch("SamsungFrame.samsung_client.SamsungTVWS")
    @patch("os.path.exists", return_value=True)
    @patch("os.chmod")
    def test_wol_fallback_succeeds(
        self, _chmod: Mock, _exists: Mock, mock_tv_cls: Mock, _sleep: Mock
    ) -> None:
        mock_tv = Mock()
        mock_tv.art().supported.return_value = True
        mock_tv.art().available.return_value = [{"content_id": "MY_F001"}]
        mock_tv_cls.return_value = mock_tv

        client = make_client()
        with (
            patch.object(client, "_send_wol", return_value=True),
            patch.object(client, "_wait_for_power", return_value=True),
        ):
            assert client._reboot_and_reconnect() is True

    @patch("time.sleep")
    def test_tv_doesnt_come_back(self, _sleep: Mock) -> None:
        mock_tv = Mock()
        client = make_client()
        client.tv = mock_tv

        with patch.object(client, "_wait_for_power", side_effect=[True, False]):
            assert client._reboot_and_reconnect() is False


class TestWaitForPower:
    @patch("time.sleep")
    def test_immediate_match(self, _sleep: Mock) -> None:
        client = make_client()
        with patch("samsungtvws.rest.SamsungTVRest") as mock_rest_cls:
            mock_rest_cls.return_value = Mock(rest_power_state=Mock(return_value=True))
            assert client._wait_for_power(target_on=True, timeout=10) is True

    @patch("time.sleep")
    def test_connection_refused_means_off(self, _sleep: Mock) -> None:
        client = make_client()
        with patch("samsungtvws.rest.SamsungTVRest") as mock_rest_cls:
            mock_rest_cls.return_value = Mock(
                rest_power_state=Mock(side_effect=ConnectionError("refused"))
            )
            assert client._wait_for_power(target_on=False, timeout=10) is True

    @patch("time.sleep")
    def test_timeout(self, _sleep: Mock) -> None:
        client = make_client()
        with patch("samsungtvws.rest.SamsungTVRest") as mock_rest_cls:
            mock_rest_cls.return_value = Mock(rest_power_state=Mock(return_value=False))
            assert client._wait_for_power(target_on=True, timeout=5, poll_interval=3) is False


class TestStartSlideshow:
    def test_slideshow_image_changed_is_success(self) -> None:
        mock_tv = Mock()
        mock_tv.art().get_artmode.return_value = "on"
        mock_tv.art().set_slideshow_status.side_effect = Exception("slideshow_image_changed event")
        client = make_client()
        client.tv = mock_tv

        assert client.start_slideshow() is True

    @patch("time.sleep")
    def test_retries_on_failure(self, _sleep: Mock) -> None:
        mock_tv = Mock()
        mock_tv.art().get_artmode.return_value = "on"
        mock_tv.art().set_slideshow_status.side_effect = [
            Exception("network error"),
            Exception("network error"),
            None,
        ]
        client = make_client()
        client.tv = mock_tv

        assert client.start_slideshow() is True
        assert mock_tv.art().set_slideshow_status.call_count == 3


class TestTimeout:
    @patch("SamsungFrame.samsung_client.SamsungTVWS")
    @patch("os.path.exists", return_value=True)
    @patch("os.chmod")
    def test_timeout_passed_to_tv(self, _chmod: Mock, _exists: Mock, mock_tv_cls: Mock) -> None:
        mock_tv_cls.return_value = Mock(
            art=Mock(return_value=Mock(supported=Mock(return_value=True)))
        )

        client = make_client(timeout=120)
        client.connect()

        mock_tv_cls.assert_called_once_with(
            host=TV_HOST, port=8002, token_file=TOKEN_FILE, timeout=120
        )


def raw_slideshow_reply(ids: list[str], **overrides: str) -> dict[str, str]:
    reply = {
        "event": "get_slideshow_status",
        "value": "3",
        "category_id": MY_PICTURES_CATEGORY,
        "current_content_id": ids[0],
        "type": "shuffleslideshow",
        "content_list": json.dumps(
            [{"content_id": i, "category_id": MY_PICTURES_CATEGORY} for i in ids]
        ),
    }
    reply.update(overrides)
    return reply


class TestParseSlideshowStatus:
    def test_reads_every_field(self) -> None:
        status = parse_slideshow_status(raw_slideshow_reply(["MY_F1", "MY_F2"]))
        assert status == SlideshowStatus(
            interval_minutes=3,
            category_id=MY_PICTURES_CATEGORY,
            shuffle=True,
            current_id="MY_F1",
            playlist_ids=["MY_F1", "MY_F2"],
        )

    def test_sequential_type_is_not_shuffle(self) -> None:
        assert not parse_slideshow_status(raw_slideshow_reply(["MY_F1"], type="slideshow")).shuffle

    def test_off_value_parses_as_zero_interval(self) -> None:
        assert (
            parse_slideshow_status(raw_slideshow_reply(["MY_F1"], value="off")).interval_minutes
            == 0
        )

    def test_missing_playlist_parses_as_empty(self) -> None:
        assert parse_slideshow_status({"value": "3"}).playlist_ids == []


class FakeArt:
    def __init__(self, ids: list[str], reply: dict[str, str] | None = None, artmode: str = "on"):
        self.ids, self.reply, self.artmode = ids, reply, artmode

    def get_slideshow_status(self) -> dict[str, str]:
        if self.reply is None:
            raise AssertionError("TV sent no reply")
        return self.reply

    def available(self) -> list[dict[str, str]]:
        return [{"content_id": i} for i in self.ids] + [{"content_id": "SAM-S1"}]

    def get_artmode(self) -> str:
        return self.artmode


class FakeTv:
    def __init__(self, art: FakeArt):
        self._art = art

    def art(self) -> FakeArt:
        return self._art


class TestVerifySlideshow:
    IDS = ["MY_F1", "MY_F2"]

    def verify(self, art: FakeArt, duration: int = 3) -> list[str]:
        client = make_client()
        client.tv = FakeTv(art)  # type: ignore[assignment]
        return client.verify_slideshow(duration, True, settle_seconds=0)

    def test_matching_tv_is_verified(self) -> None:
        assert self.verify(FakeArt(self.IDS, raw_slideshow_reply(self.IDS))) == []

    def test_preinstalled_art_is_not_expected_in_playlist(self) -> None:
        assert self.verify(FakeArt(self.IDS, raw_slideshow_reply(self.IDS))) == []

    def test_stale_playlist_after_purge_is_reported(self) -> None:
        stale = FakeArt(["MY_F2"], raw_slideshow_reply(self.IDS))
        problems = self.verify(stale)
        assert "playlist holds 1 items that are not on the TV" in problems
        assert any("current item MY_F1" in p for p in problems)

    def test_slideshow_off_is_reported_not_raised(self) -> None:
        off = FakeArt(self.IDS, raw_slideshow_reply(self.IDS, value="off"))
        assert self.verify(off) == ["slideshow is off"]

    def test_wrong_interval_is_reported(self) -> None:
        art = FakeArt(self.IDS, raw_slideshow_reply(self.IDS))
        assert self.verify(art, duration=7) == ["interval is 3 min, expected 7"]

    def test_art_mode_off_is_reported(self) -> None:
        art = FakeArt(self.IDS, raw_slideshow_reply(self.IDS), artmode="off")
        assert self.verify(art) == ["art mode is off"]

    def test_unreadable_tv_is_a_problem_not_an_exception(self) -> None:
        (problem,) = self.verify(FakeArt(self.IDS, reply=None))
        assert problem.startswith("could not read the slideshow back from the TV")

    def test_not_connected_raises(self) -> None:
        with pytest.raises(RuntimeError):
            make_client().verify_slideshow(3, True, settle_seconds=0)


class TestSlideshowProblems:
    IDS = {"MY_F1", "MY_F2", "MY_F3"}

    def status(self, **overrides: str) -> SlideshowStatus:
        return parse_slideshow_status(raw_slideshow_reply(sorted(self.IDS), **overrides))

    def problems(self, status: SlideshowStatus, ids: set[str] | None = None) -> list[str]:
        return slideshow_problems(status, self.IDS if ids is None else ids, 3, True, True)

    def test_matching_state_has_no_problems(self) -> None:
        assert self.problems(self.status()) == []

    def test_art_mode_off(self) -> None:
        assert slideshow_problems(self.status(), self.IDS, 3, True, False) == ["art mode is off"]

    def test_photos_missing_from_playlist(self) -> None:
        (problem,) = self.problems(self.status(), self.IDS | {"MY_F4", "MY_F5"})
        assert problem == "playlist is missing 2 photos that are on the TV"

    def test_playlist_holds_deleted_photos(self) -> None:
        problems = self.problems(self.status(), {"MY_F1", "MY_F2"})
        assert "playlist holds 1 items that are not on the TV" in problems

    def test_current_item_deleted(self) -> None:
        problems = self.problems(self.status(current_content_id="MY_F9"))
        assert problems == ["current item MY_F9 is not a photo on the TV"]

    def test_wrong_interval_category_and_shuffle(self) -> None:
        problems = self.problems(self.status(value="15", category_id="MY-C0001", type="slideshow"))
        assert len(problems) == 3
        assert any("interval is 15 min" in p for p in problems)
        assert any("My Pictures" in p for p in problems)
        assert any("shuffle is off" in p for p in problems)

    def test_no_photos_on_tv(self) -> None:
        assert "no user-uploaded photos are on the TV" in self.problems(self.status(), set())
