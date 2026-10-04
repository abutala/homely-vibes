"""Tests for Samsung Frame TV client."""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import Mock

import pytest
from PIL import Image

from lib.config import SamsungFrameConfig
from SamsungFrame.samsung_client import (
    MY_PICTURES_CATEGORY,
    SamsungFrameClient,
    SlideshowStatus,
    TvIo,
    delete_all_art,
    get_stale_art_ids,
    parse_slideshow_status,
    plan_purge,
    slideshow_problems,
    validate_matte,
)

TV_HOST = "192.0.2.4"


def fake_config(**overrides: Any) -> SamsungFrameConfig:
    values: dict[str, Any] = dict(
        ip=TV_HOST,
        mac="",
        wol_password="",
        smartthings_token="",
        smartthings_device_id="",
        port=8002,
        token_file="/nonexistent/token.txt",
        default_matte="shadowbox_black",
        supported_formats=["jpg", "jpeg", "png"],
        max_image_size_mb=10,
        min_size_mb=0.75,
        min_images=100,
        slideshow_delay_seconds=0,
    )
    return SamsungFrameConfig(**(values | overrides))


def fake_io(**overrides: Any) -> TvIo:
    """No network, no waiting: every outside call is a Mock unless a test supplies its own."""
    values: dict[str, Any] = dict(
        tv=Mock(), rest=Mock(), post=Mock(), udp_socket=Mock(), sleep=lambda _seconds: None
    )
    return TvIo(**(values | overrides))


def make_client(io: TvIo | None = None, **config: Any) -> SamsungFrameClient:
    return SamsungFrameClient(config=fake_config(**config), io=io or fake_io())


def connected(tv: Any, io: TvIo | None = None, **config: Any) -> SamsungFrameClient:
    client = make_client(io, **config)
    client.tv = tv
    return client


def token_file(tmp_path: Path) -> str:
    path = tmp_path / "token.txt"
    path.write_text("token")
    return str(path)


def jpgs(tmp_path: Path, count: int) -> list[str]:
    paths = []
    for i in range(count):
        path = tmp_path / f"img{i}.jpg"
        Image.new("RGB", (100, 100)).save(path, format="JPEG")
        paths.append(str(path))
    return paths


class Scripted(SamsungFrameClient):
    """The real client, with the methods named in `script` answered from it instead of the TV.

    A list answers successive calls in order; anything else answers every call. `calls` records
    the scripted and unscripted calls to these methods, in order.
    """

    def __init__(self, script: dict[str, Any], io: TvIo | None = None, **config: Any):
        super().__init__(config=fake_config(**config), io=io or fake_io())
        self.script = {k: iter(v) if isinstance(v, list) else v for k, v in script.items()}
        self.calls: list[str] = []

    def _play(self, name: str, real: Any) -> Any:
        self.calls.append(name)
        if name not in self.script:
            return real()
        answer = self.script[name]
        return next(answer) if isinstance(answer, Iterator) else answer

    def _send_wol(self) -> bool:
        return bool(self._play("_send_wol", super()._send_wol))

    def _smartthings_power_on(self) -> bool:
        return bool(self._play("_smartthings_power_on", super()._smartthings_power_on))

    def _is_tv_reachable(self) -> bool:
        return bool(self._play("_is_tv_reachable", super()._is_tv_reachable))

    def _wait_for_power(self, target_on: bool, timeout: int = 120, poll_interval: int = 3) -> bool:
        real = super()._wait_for_power
        return bool(self._play("_wait_for_power", lambda: real(target_on, timeout, poll_interval)))

    def connect(self) -> bool:
        return bool(self._play("connect", super().connect))

    def connect_ready(self) -> bool:
        return bool(self._play("connect_ready", super().connect_ready))

    def ensure_art_mode(self) -> bool:
        return bool(self._play("ensure_art_mode", super().ensure_art_mode))

    def reboot_and_reconnect(self, max_attempts: int = 3) -> bool:
        real = super().reboot_and_reconnect
        return bool(self._play("reboot_and_reconnect", lambda: real(max_attempts)))

    def close(self) -> None:
        self._play("close", super().close)


class TestSamsungFrameClient:
    def test_init_with_config(self) -> None:
        client = make_client()
        assert client.host == TV_HOST
        assert client.port == 8002

    def test_explicit_arguments_win_over_config(self) -> None:
        client = SamsungFrameClient(host="192.0.2.9", port=1, config=fake_config(), io=fake_io())
        assert (client.host, client.port) == ("192.0.2.9", 1)

    def test_init_missing_host(self) -> None:
        with pytest.raises(ValueError, match="Samsung Frame TV IP address required"):
            make_client(ip="")

    def test_connect_success(self, tmp_path: Path) -> None:
        tv = Mock()
        tv.art().supported.return_value = True
        client = make_client(fake_io(tv=Mock(return_value=tv)), token_file=token_file(tmp_path))
        assert client.connect() is True
        assert client.tv is tv

    def test_connect_tightens_the_token_file(self, tmp_path: Path) -> None:
        token = token_file(tmp_path)
        os.chmod(token, 0o644)
        make_client(fake_io(), token_file=token).connect()
        assert os.stat(token).st_mode & 0o777 == 0o600

    def test_connect_with_retry(self, tmp_path: Path) -> None:
        fail = Mock()
        fail.art().supported.side_effect = ConnectionError("fail")
        success = Mock()
        factory = Mock(side_effect=[fail, fail, success])
        client = make_client(fake_io(tv=factory), token_file=token_file(tmp_path))
        assert client.connect() is True
        assert factory.call_count == 3

    def test_connect_max_retries(self, tmp_path: Path) -> None:
        tv = Mock()
        tv.art().supported.side_effect = ConnectionError("fail")
        factory = Mock(return_value=tv)
        client = make_client(fake_io(tv=factory), token_file=token_file(tmp_path))
        assert client.connect() is False
        assert factory.call_count == 3

    def test_timeout_passed_to_tv(self, tmp_path: Path) -> None:
        factory = Mock()
        token = token_file(tmp_path)
        client = SamsungFrameClient(
            timeout=120, config=fake_config(token_file=token), io=fake_io(tv=factory)
        )
        client.connect()
        factory.assert_called_once_with(host=TV_HOST, port=8002, token_file=token, timeout=120)

    def test_validate_image_file_invalid_format(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.txt"
        path.write_bytes(b"test")
        assert make_client().validate_image_file(str(path)) is False

    def test_validate_image_file_success(self, tmp_path: Path) -> None:
        assert make_client().validate_image_file(jpgs(tmp_path, 1)[0]) is True

    def test_validate_image_file_too_large(self, tmp_path: Path) -> None:
        assert make_client(max_image_size_mb=0).validate_image_file(jpgs(tmp_path, 1)[0]) is False

    def test_upload_image_success(self, tmp_path: Path) -> None:
        tv = Mock()
        tv.art().upload.return_value = "image123"
        assert connected(tv).upload_image(jpgs(tmp_path, 1)[0]) == "image123"

    def test_enable_art_mode_already_on(self) -> None:
        tv = Mock()
        tv.art().get_artmode.return_value = "on"
        assert connected(tv).enable_art_mode() is True
        tv.art().set_artmode.assert_not_called()

    def test_enable_art_mode_timeout_is_success(self) -> None:
        tv = Mock()
        tv.art().get_artmode.return_value = "off"
        tv.art().set_artmode.side_effect = TimeoutError("timed out")
        assert connected(tv).enable_art_mode() is True

    def test_cycle_images_filters_user_photos(self) -> None:
        tv = Mock()
        tv.art().available.return_value = [
            {"content_id": "MY_F0001"},
            {"content_id": "MY_F0002"},
            {"content_id": "ART_12345"},
        ]
        sleep = Mock(side_effect=[None, KeyboardInterrupt()])
        connected(tv, fake_io(sleep=sleep)).cycle_images(period=15, shuffle=False)

        assert [c.args[0] for c in tv.art().select_image.call_args_list] == ["MY_F0001", "MY_F0002"]


def upload_tv(results: list[str | None], on_tv: list[str] | None = None) -> Mock:
    """A TV whose uploads return `results` in order and whose art list is `on_tv`."""
    tv = Mock()
    tv.art().upload.side_effect = results
    tv.art().available.return_value = [{"content_id": i} for i in on_tv or []]
    return tv


class TestUploadImages:
    def test_success(self, tmp_path: Path) -> None:
        client = connected(upload_tv(["id1", "id2", "id3"]))
        summary = client.upload_images(jpgs(tmp_path, 3))
        assert (summary.successful_uploads, summary.failed_uploads) == (3, 0)
        assert summary.uploaded_image_ids == ["id1", "id2", "id3"]

    def test_partial_failure(self, tmp_path: Path) -> None:
        paths = jpgs(tmp_path, 2)
        bad = tmp_path / "bad.jpg"
        bad.write_text("not an image")
        summary = connected(upload_tv(["id1", "id2"])).upload_images(paths + [str(bad)])
        assert (summary.successful_uploads, summary.failed_uploads) == (2, 1)
        assert summary.errors[0]["file"] == "bad.jpg"

    def test_each_image_is_checkpointed_as_it_lands(self, tmp_path: Path) -> None:
        paths = jpgs(tmp_path, 2)
        landed: list[tuple[str, str]] = []
        connected(upload_tv(["id1", "id2"])).upload_images(
            paths, on_uploaded=lambda path, cid: landed.append((path, cid))
        )
        assert landed == [(paths[0], "id1"), (paths[1], "id2")]

    def test_a_checkpoint_that_cannot_be_written_stops_the_run(self, tmp_path: Path) -> None:
        def full_disk(_path: str, _cid: str) -> None:
            raise OSError("disk full")

        with pytest.raises(OSError, match="disk full"):
            connected(upload_tv(["id1", "id2"])).upload_images(
                jpgs(tmp_path, 2), on_uploaded=full_disk
            )

    def test_a_working_tv_is_not_health_checked_between_uploads(self, tmp_path: Path) -> None:
        client = Scripted({})
        client.tv = upload_tv(["id1", "id2"])
        client.upload_images(jpgs(tmp_path, 2))
        assert "ensure_art_mode" not in client.calls

    def test_upload_that_landed_despite_a_timeout_is_recovered(self, tmp_path: Path) -> None:
        tv = upload_tv([None])
        tv.art().available.side_effect = [[], [{"content_id": "MY_F7"}]]
        summary = connected(tv).upload_images(jpgs(tmp_path, 1))
        assert summary.uploaded_image_ids == ["MY_F7"]

    def test_stops_when_the_tv_cannot_be_recovered(self, tmp_path: Path) -> None:
        client = Scripted({"ensure_art_mode": False, "reboot_and_reconnect": False})
        client.tv = upload_tv([None] * 5)
        summary = client.upload_images(jpgs(tmp_path, 5))
        assert (summary.successful_uploads, summary.failed_uploads) == (0, 1)

    def test_only_one_reboot_per_batch(self, tmp_path: Path) -> None:
        client = Scripted({"ensure_art_mode": False, "reboot_and_reconnect": True})
        client.tv = upload_tv([None] * 8)
        summary = client.upload_images(jpgs(tmp_path, 8))
        assert client.calls.count("reboot_and_reconnect") == 1
        assert summary.failed_uploads == 2  # the reboot bought one more try, then it stopped

    def test_failures_do_not_stop_a_tv_that_stays_in_art_mode(self, tmp_path: Path) -> None:
        client = Scripted({"ensure_art_mode": True})
        client.tv = upload_tv([None, None, None, "id4"])
        summary = client.upload_images(jpgs(tmp_path, 4))
        assert (summary.successful_uploads, summary.failed_uploads) == (1, 3)

    def test_pause_grows_on_failure_and_shrinks_on_success(self, tmp_path: Path) -> None:
        sleep = Mock()
        client = Scripted({"ensure_art_mode": True}, fake_io(sleep=sleep))
        client.tv = upload_tv([None, None, "id3", "id4"])
        client.upload_images(jpgs(tmp_path, 4))
        assert [c.args[0] for c in sleep.call_args_list] == [10, 15, 14, 13]

    def test_not_connected_raises(self) -> None:
        with pytest.raises(RuntimeError, match="Not connected"):
            make_client().upload_images(["a.jpg"])


class TestPing:
    def test_not_connected_raises(self) -> None:
        with pytest.raises(RuntimeError, match="Not connected"):
            make_client().ping()

    def test_failure_propagates(self) -> None:
        tv = Mock()
        tv.art().supported.side_effect = TimeoutError("timeout")
        with pytest.raises(TimeoutError):
            connected(tv).ping()


class TestGetAvailableArtStrict:
    def test_not_connected_raises(self) -> None:
        with pytest.raises(RuntimeError):
            make_client().get_available_art_strict()

    def test_lenient_not_connected_raises_too(self) -> None:
        with pytest.raises(RuntimeError):
            make_client().get_available_art()

    def test_success(self) -> None:
        tv = Mock()
        tv.art().available.return_value = [{"content_id": "MY_F001"}]
        assert len(connected(tv).get_available_art_strict()) == 1

    def test_timeout_response_raises(self) -> None:
        tv = Mock()
        tv.art().available.return_value = {"event": "ms.channel.timeOut"}
        with pytest.raises(TimeoutError):
            connected(tv).get_available_art_strict()

    def test_lenient_returns_empty_on_error(self) -> None:
        tv = Mock()
        tv.art().available.side_effect = ConnectionError("closed")
        assert connected(tv).get_available_art() == []


class FakeSocket:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def setsockopt(self, *_: object) -> None:
        pass

    def sendto(self, data: bytes, target: tuple[str, int]) -> None:
        self.sent.append((data, target))


class TestSendWol:
    def wol(self, **config: str) -> FakeSocket:
        sock = FakeSocket()
        client = make_client(fake_io(udp_socket=lambda: sock), mac="AA:BB:CC:DD:EE:FF", **config)
        assert client._send_wol() is True
        return sock

    def test_no_mac_returns_false(self) -> None:
        assert make_client(mac="")._send_wol() is False

    def test_multi_target_packets(self) -> None:
        sock = self.wol()
        assert len(sock.sent) == 12  # 3 rounds × 4 targets
        assert {target for _, target in sock.sent} == {
            ("<broadcast>", 9),
            ("<broadcast>", 7),
            (TV_HOST, 9),
            (TV_HOST, 7),
        }
        magic = sock.sent[0][0]
        assert magic[:6] == b"\xff" * 6
        assert len(magic) == 102  # no SecureON

    def test_secureon_appends_password(self) -> None:
        assert len(self.wol(wol_password="11:22:33:44:55:66").sent[0][0]) == 108  # 102 + 6


class TestSmartThingsPowerOn:
    CREDS = {"smartthings_token": "test-token", "smartthings_device_id": "device-123"}

    def test_no_config_returns_false(self) -> None:
        assert make_client()._smartthings_power_on() is False

    def test_success(self) -> None:
        post = Mock(return_value=Mock(ok=True))
        assert make_client(fake_io(post=post), **self.CREDS)._smartthings_power_on() is True
        assert post.call_args[1]["headers"]["Authorization"] == "Bearer test-token"
        assert "device-123" in post.call_args[0][0]

    def test_api_error(self) -> None:
        post = Mock(return_value=Mock(ok=False, status_code=403, text="Forbidden"))
        assert make_client(fake_io(post=post), **self.CREDS)._smartthings_power_on() is False


class TestContextManager:
    def test_enter_calls_connect_ready_and_exit_closes(self) -> None:
        client = Scripted({"connect_ready": True, "close": None})
        with client as c:
            assert c is client
            assert client.calls == ["connect_ready"]
        assert client.calls == ["connect_ready", "close"]

    def test_enter_raises_on_failure(self) -> None:
        with pytest.raises(ConnectionError):
            Scripted({"connect_ready": False}).__enter__()

    def test_exit_closes_on_exception(self) -> None:
        client = Scripted({"connect_ready": True, "close": None})
        with pytest.raises(ValueError):
            with client:
                raise ValueError("boom")
        assert client.calls[-1] == "close"


class TestConnectReady:
    AWAKE = {"_send_wol": True, "_smartthings_power_on": False}

    def test_already_connected(self) -> None:
        script = self.AWAKE | {"connect": True, "ensure_art_mode": True}
        assert Scripted(script).connect_ready() is True

    def test_art_fails_triggers_reboot(self) -> None:
        client = Scripted(
            self.AWAKE | {"connect": True, "ensure_art_mode": False, "reboot_and_reconnect": True}
        )
        assert client.connect_ready() is True
        assert "reboot_and_reconnect" in client.calls

    def test_wol_wakes_tv(self) -> None:
        client = Scripted(
            self.AWAKE
            | {
                "connect": [False, True],
                "_is_tv_reachable": False,
                "_wait_for_power": True,
                "ensure_art_mode": True,
            }
        )
        assert client.connect_ready() is True

    def test_standby_retry(self) -> None:
        client = Scripted(
            self.AWAKE
            | {"connect": [False, True], "_is_tv_reachable": True, "ensure_art_mode": True}
        )
        assert client.connect_ready() is True
        assert "_wait_for_power" not in client.calls

    def test_no_wake_signal_means_no_waiting_for_power(self) -> None:
        client = Scripted(
            {
                "_send_wol": False,
                "_smartthings_power_on": False,
                "connect": False,
                "_is_tv_reachable": False,
            }
        )
        assert client.connect_ready() is False
        assert "_wait_for_power" not in client.calls

    def test_all_phases_fail(self) -> None:
        client = Scripted(
            self.AWAKE | {"connect": False, "_is_tv_reachable": False, "_wait_for_power": False}
        )
        assert client.connect_ready() is False

    def test_wol_fires_before_connect(self) -> None:
        client = Scripted(self.AWAKE | {"connect": True, "ensure_art_mode": True})
        assert client.connect_ready() is True
        assert client.calls[:4] == [
            "connect_ready",
            "_send_wol",
            "_smartthings_power_on",
            "connect",
        ]


class TestReboot:
    def test_not_connected(self) -> None:
        assert make_client().reboot() is False

    def test_success(self) -> None:
        tv = Mock()
        assert connected(tv).reboot() is True
        tv.hold_key.assert_called_once_with("KEY_POWER", 5)
        tv.close.assert_called_once()

    def test_exception_during_hold_is_success(self) -> None:
        tv = Mock()
        tv.hold_key.side_effect = OSError("Connection lost")
        assert connected(tv).reboot() is True
        tv.close.assert_called_once()


class TestRebootAndReconnect:
    def test_wol_fallback_fails(self) -> None:
        assert Scripted({"_send_wol": False}).reboot_and_reconnect() is False

    def test_wol_fallback_succeeds(self, tmp_path: Path) -> None:
        tv = Mock()
        tv.art().available.return_value = [{"content_id": "MY_F001"}]
        client = Scripted(
            {"_send_wol": True, "_wait_for_power": True},
            fake_io(tv=Mock(return_value=tv)),
            token_file=token_file(tmp_path),
        )
        assert client.reboot_and_reconnect() is True
        assert client.tv is tv

    def test_tv_doesnt_come_back(self) -> None:
        client = Scripted({"_wait_for_power": [True, False]})
        client.tv = Mock()
        assert client.reboot_and_reconnect() is False


class TestWaitForPower:
    def client(self, power_state: Mock) -> SamsungFrameClient:
        return make_client(fake_io(rest=Mock(return_value=Mock(rest_power_state=power_state))))

    def test_immediate_match(self) -> None:
        client = self.client(Mock(return_value=True))
        assert client._wait_for_power(target_on=True, timeout=10) is True

    def test_connection_refused_means_off(self) -> None:
        client = self.client(Mock(side_effect=ConnectionError("refused")))
        assert client._wait_for_power(target_on=False, timeout=10) is True

    def test_timeout(self) -> None:
        power_state = Mock(return_value=False)
        client = self.client(power_state)
        assert client._wait_for_power(target_on=True, timeout=5, poll_interval=3) is False
        assert power_state.call_count == 2


class TestStartSlideshow:
    def tv(self, results: list[Any]) -> Mock:
        tv = Mock()
        tv.art().get_artmode.return_value = "on"
        tv.art().set_slideshow_status.side_effect = results
        return tv

    def test_slideshow_image_changed_is_success(self) -> None:
        tv = self.tv([Exception("slideshow_image_changed event")])
        assert connected(tv).start_slideshow() is True

    def test_retries_on_failure(self) -> None:
        tv = self.tv([Exception("network error"), Exception("network error"), None])
        assert connected(tv).start_slideshow() is True
        assert tv.art().set_slideshow_status.call_count == 3

    def test_gives_up_after_three_attempts(self) -> None:
        assert connected(self.tv([Exception("down")] * 3)).start_slideshow() is False


class TestValidateMatte:
    TYPES = ["shadowbox", "modern"]

    def test_type_alone_and_type_with_color_are_valid(self) -> None:
        validate_matte("modern", self.TYPES)
        validate_matte("shadowbox_black", self.TYPES)

    def test_unknown_type_is_refused(self) -> None:
        with pytest.raises(ValueError, match="Invalid matte type: flexible"):
            validate_matte("flexible_black", self.TYPES)

    def test_unknown_color_is_refused(self) -> None:
        with pytest.raises(ValueError, match="Invalid color: mauve"):
            validate_matte("shadowbox_mauve", self.TYPES)


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
        client = connected(FakeTv(art))
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


class TestCheckForNewUpload:
    def client_with(self, ids: list[str]) -> SamsungFrameClient:
        return connected(FakeTv(FakeArt(ids)))

    def test_exactly_one_new_id_is_the_upload(self) -> None:
        client = self.client_with(["MY_F1", "MY_F2"])
        assert client._check_for_new_upload({"MY_F1"}) == "MY_F2"

    def test_no_new_id_means_it_did_not_arrive(self) -> None:
        assert self.client_with(["MY_F1"])._check_for_new_upload({"MY_F1"}) is None

    def test_several_new_ids_are_not_guessed_at(self) -> None:
        client = self.client_with(["MY_F1", "MY_F2", "MY_F3"])
        assert client._check_for_new_upload(set()) is None  # an unreliable baseline


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


class TestArtDeletion:
    def client(self, ids: list[str], batch_fails: bool = False) -> Mock:
        client = Mock(spec=SamsungFrameClient)
        client.tv = Mock()
        if batch_fails:
            client.tv.art().delete_list.side_effect = Exception("Batch failed")
        client.get_available_art.return_value = [{"content_id": i} for i in ids]
        return client

    def test_delete_with_confirmation(self) -> None:
        client = self.client(["MY_F0001", "MY_F0002"])
        prompts: list[str] = []

        def ask(prompt: str) -> str:
            prompts.append(prompt)
            return "y"

        result = delete_all_art(client, force=False, ask=ask)

        assert result == {"total": 2, "deleted": 2, "failed": 0}
        assert len(prompts) == 1
        client.tv.art().delete_list.assert_called_once()

    def test_delete_cancelled(self) -> None:
        client = self.client(["MY_F0001"])
        result = delete_all_art(client, force=False, ask=lambda _prompt: "n")
        assert result["deleted"] == 0
        client.tv.art().delete_list.assert_not_called()

    def test_delete_with_force_never_asks(self) -> None:
        def ask(_prompt: str) -> str:
            raise AssertionError("asked despite force")

        client = self.client(["MY_F0001"])
        assert delete_all_art(client, force=True, ask=ask)["deleted"] == 1

    def test_delete_empty_list(self) -> None:
        result = delete_all_art(self.client([]), force=True)
        assert result == {"total": 0, "deleted": 0, "failed": 0}

    def test_delete_filters_user_art_only(self) -> None:
        client = self.client(["MY_F0001", "SAM_0001", "MY_F0002"])
        result = delete_all_art(client, force=True)
        assert result["deleted"] == 2
        assert client.tv.art().delete_list.call_args[0][0] == ["MY_F0001", "MY_F0002"]

    def test_delete_batch_failure_fallback(self) -> None:
        client = self.client(["MY_F0001", "MY_F0002"], batch_fails=True)
        result = delete_all_art(client, force=True)
        assert result["deleted"] == 2
        assert client.tv.art().delete.call_count == 2

    def test_delete_not_connected(self) -> None:
        client = Mock(spec=SamsungFrameClient)
        client.tv = None
        with pytest.raises(RuntimeError, match="Not connected to TV"):
            delete_all_art(client, force=True)


class TestStaleArtFromApi:
    def test_recent_art_not_stale(self) -> None:
        now = datetime.now()
        recent = now.strftime("%Y:%m:%d %H:%M:%S")
        art_list = [{"content_id": "MY_F001", "image_date": recent}]
        assert get_stale_art_ids(art_list, max_age_hours=24) == []

    def test_old_art_is_stale(self) -> None:
        old = (datetime.now() - timedelta(hours=48)).strftime("%Y:%m:%d %H:%M:%S")
        art_list = [{"content_id": "MY_F001", "image_date": old}]
        assert get_stale_art_ids(art_list, max_age_hours=24) == ["MY_F001"]

    def test_empty_image_date_is_stale(self) -> None:
        art_list = [{"content_id": "MY_F001", "image_date": ""}]
        assert get_stale_art_ids(art_list, max_age_hours=24) == ["MY_F001"]

    def test_samsung_art_excluded(self) -> None:
        old = (datetime.now() - timedelta(hours=48)).strftime("%Y:%m:%d %H:%M:%S")
        art_list = [
            {"content_id": "SAM-S001", "image_date": ""},
            {"content_id": "MY_F001", "image_date": old},
        ]
        stale = get_stale_art_ids(art_list, max_age_hours=24)
        assert stale == ["MY_F001"]

    def test_mixed_ages(self) -> None:
        now = datetime.now()
        recent = now.strftime("%Y:%m:%d %H:%M:%S")
        old = (now - timedelta(hours=48)).strftime("%Y:%m:%d %H:%M:%S")
        art_list = [
            {"content_id": "MY_F001", "image_date": recent},
            {"content_id": "MY_F002", "image_date": old},
            {"content_id": "MY_F003", "image_date": ""},
        ]
        stale = get_stale_art_ids(art_list, max_age_hours=24)
        assert "MY_F001" not in stale
        assert "MY_F002" in stale
        assert "MY_F003" in stale

    def test_image_date_is_the_tvs_local_wall_clock(self) -> None:
        now = datetime(2026, 1, 10, 12, 0, 0)
        art_list = [{"content_id": "MY_F1", "image_date": "2026:01:09 11:00:00"}]  # 25h before
        assert get_stale_art_ids(art_list, 24, now) == ["MY_F1"]
        assert get_stale_art_ids(art_list, 26, now) == []

    def test_stale_ids_come_oldest_first_with_undated_oldest(self) -> None:
        now = datetime(2026, 1, 10)
        art_list = [
            {"content_id": "MY_F_new", "image_date": "2026:01:05 00:00:00"},
            {"content_id": "MY_F_undated", "image_date": ""},
            {"content_id": "MY_F_old", "image_date": "2026:01:01 00:00:00"},
        ]
        assert get_stale_art_ids(art_list, 24, now) == ["MY_F_undated", "MY_F_old", "MY_F_new"]


class TestPlanPurge:
    NOW = datetime(2026, 1, 10)

    def art(self, days_old: list[int]) -> list[dict[str, str]]:
        return [
            {
                "content_id": f"MY_F{i}",
                "image_date": (self.NOW - timedelta(days=d)).strftime("%Y:%m:%d %H:%M:%S"),
            }
            for i, d in enumerate(days_old)
        ]

    def test_everything_stale_goes_when_the_minimum_is_met(self) -> None:
        assert plan_purge(self.art([5, 4, 0, 0]), 24, 2, self.NOW) == ["MY_F0", "MY_F1"]

    def test_the_minimum_spares_the_newest_stale_photos(self) -> None:
        assert plan_purge(self.art([5, 4, 3, 0]), 24, 2, self.NOW) == ["MY_F0", "MY_F1"]

    def test_a_photo_the_tv_lists_twice_counts_once_toward_the_minimum(self) -> None:
        art = self.art([5, 4, 3])
        assert plan_purge(art + art, 24, 2, self.NOW) == ["MY_F0"]

    def test_a_null_image_date_is_oldest_not_a_crash(self) -> None:
        art = self.art([5, 0, 0]) + [{"content_id": "MY_Fnull", "image_date": None}]
        assert plan_purge(art, 24, 2, self.NOW) == ["MY_Fnull", "MY_F0"]

    def test_at_or_below_the_minimum_nothing_goes(self) -> None:
        assert plan_purge(self.art([5, 4]), 24, 2, self.NOW) == []
        assert plan_purge(self.art([5]), 24, 2, self.NOW) == []
