import plistlib
import socket
import subprocess
from pathlib import Path

import pytest

from lib.config import SshTunnelConfig
from ScreenShare.icon import initials, make_icon
from ScreenShare.build_app import (
    _absolute_path,
    TEMPLATE,
    WAIT_SECONDS,
    Connection,
    connection_label,
    default_app_name,
    dock_has,
    host_label,
    applescript_string,
    bundle_id,
    find_connection,
    parse_connections,
    render,
    through_tunnel,
    tunnel_command,
)


def _prefs(*targets: dict) -> bytes:
    details = {
        str(i): {"connectionParameters": {"networkAddress": {"_0": t}}}
        for i, t in enumerate(targets)
    }
    store = plistlib.dumps({"connectionDetails": details}, fmt=plistlib.FMT_BINARY)
    return plistlib.dumps({"connectionsStore": store})


BONJOUR = {
    "displayName": "Studio Mac",
    "displayConfiguration": {"displayType": {"compatibilityMode": {}}},
    "address": "Studio%20Mac._rfb._tcp.local",
    "port": 5900,
    "username": "alex",
}
PLAIN = {"displayName": "beta", "address": "192.0.2.10", "username": ""}
TUNNELED = Connection(
    name="Studio Mác", address="localhost", url="vnc://alex@localhost:5901", port=5901
)


def test_parse_builds_url_with_user_and_port() -> None:
    [conn] = parse_connections(_prefs(BONJOUR))
    assert conn == Connection(
        name="Studio Mac",
        address="Studio%20Mac._rfb._tcp.local",
        url="vnc://alex@Studio%20Mac._rfb._tcp.local:5900?numVirtualDisplays=0",
        port=5900,
        user="alex",
        query="?numVirtualDisplays=0",
    )


def test_parse_omits_empty_user_port_and_unknown_type() -> None:
    [conn] = parse_connections(_prefs(PLAIN))
    assert conn.url == "vnc://192.0.2.10"


def test_parse_without_store_is_empty() -> None:
    assert parse_connections(plistlib.dumps({})) == []


def test_find_matches_name_or_address_case_insensitively() -> None:
    conns = parse_connections(_prefs(BONJOUR, PLAIN))
    assert find_connection(conns, "studio mac").name == "Studio Mac"
    assert find_connection(conns, "192.0.2.10").name == "beta"


def test_find_unknown_lists_saved_names() -> None:
    conns = parse_connections(_prefs(BONJOUR))
    with pytest.raises(ValueError, match='Saved: "Studio Mac"'):
        find_connection(conns, "nope")


def test_applescript_string_escapes_quotes_and_backslashes() -> None:
    assert applescript_string('a"b\\c') == '"a\\"b\\\\c"'


def test_render_fills_every_placeholder() -> None:
    conn = Connection(name='Ma"c', address="x", url="vnc://x")
    assert render("__URL__|__TITLE__", conn) == '"vnc://x"|"Ma\\"c"'


def test_render_fills_tunnel_fallback_and_wait() -> None:
    conn = Connection(name="n", address="a", url="vnc://a")
    out = render("__TUNNEL__|__FALLBACK__|__WAIT__", conn, "ssh x", "Remote App")
    assert out == f'"ssh x"|"Remote App"|{WAIT_SECONDS}'


def test_render_does_not_replace_inside_a_value() -> None:
    conn = Connection(name="__URL__", address="a", url="vnc://a")
    assert render("__TITLE__", conn) == '"__URL__"'


def test_bundle_id_is_stable_slug() -> None:
    assert bundle_id("My Mac.app") == "com.homelyvibes.screenshare.my-mac-app"
    assert bundle_id("ELP") == "com.homelyvibes.screenshare.elp"


def test_real_template_has_no_placeholder_left() -> None:
    conn = Connection(name="n", address="a", url="vnc://a")
    assert "__" not in render(TEMPLATE.read_text(), conn)


@pytest.mark.parametrize(
    ("address", "label"),
    [
        ("Studio%20M%C3%A1c._rfb._tcp.local", "Studio Mac"),
        ("studio-mac.local", "Studio Mac"),
        ("office_mini", "Office Mini"),
        ("192.0.2.10", "192.0.2.10"),
        ("fe80::1", "fe80::1"),
    ],
)
def test_host_label_title_cases_ascii_words(address: str, label: str) -> None:
    assert host_label(address) == label


def test_default_app_name_prefixes_vnc() -> None:
    conn = Connection(name="Studio Mác", address="studio-mac.local", url="vnc://studio-mac.local")
    assert default_app_name(conn) == "VNC Studio Mac"


def test_dock_has_matches_file_url_with_trailing_slash() -> None:
    app = Path("/Applications/VNC Studio Mac.app")
    tile = {"tile-data": {"file-data": {"_CFURLString": app.as_uri() + "/"}}}
    assert dock_has([{"tile-data": {}}, tile], app)
    assert not dock_has([{"tile-data": {}}], app)


@pytest.mark.parametrize(
    ("label", "expected"),
    [("Studio Mac", "SM"), ("office", "O"), ("Big Studio Mac", "BS"), ("192.0.2.10", "10")],
)
def test_icon_initials(label: str, expected: str) -> None:
    assert initials(label) == expected


def test_make_icon_is_square_rgba() -> None:
    image = make_icon("Studio Mac")
    assert image.size == (1024, 1024)
    assert image.mode == "RGBA"


def test_dock_has_matches_label_when_url_is_missing() -> None:
    app = Path("/Applications/VNC Studio Mac.app")
    assert dock_has([{"tile-data": {"file-label": "VNC Studio Mac"}}], app)


def test_dest_expands_tilde_to_absolute() -> None:
    dest = _absolute_path("~/Apps")
    assert dest.is_absolute()
    assert dest == Path.home() / "Apps"


def test_through_tunnel_keeps_name_user_and_type() -> None:
    [conn] = parse_connections(_prefs(BONJOUR))
    tunneled = through_tunnel(conn, 5901)
    assert tunneled.name == "Studio Mac"
    assert tunneled.url == "vnc://alex@localhost:5901?numVirtualDisplays=0"


def test_find_prefers_the_real_host_over_its_tunnel_entry() -> None:
    saved_by_tunnel = {"displayName": "Studio Mac", "address": "localhost", "port": 5901}
    conns = parse_connections(_prefs(saved_by_tunnel, BONJOUR))
    assert find_connection(conns, "Studio Mac").address == "Studio%20Mac._rfb._tcp.local"


def test_tunnel_command_forwards_local_to_remote_port() -> None:
    tunnel = SshTunnelConfig(host="vnc.example.com", port=2222, user="alex")
    command = tunnel_command(tunnel, 5901)
    assert "-p 2222 -L 5901:localhost:5900 alex@vnc.example.com" in command
    assert "BatchMode=yes" in command
    assert "ServerAliveInterval=10" in command


def test_tunnel_command_without_user_uses_bare_host() -> None:
    command = tunnel_command(SshTunnelConfig(host="vnc.example.com"), 5901)
    assert "-p 22 -L 5901:localhost:5900 vnc.example.com " in command


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_tunnel_command_skips_ssh_when_port_already_listens() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        unreachable = SshTunnelConfig(host="127.0.0.1", port=_free_port())
        result = subprocess.run(
            ["/bin/sh", "-c", tunnel_command(unreachable, port)], capture_output=True, timeout=10
        )
    assert result.returncode == 0


def test_tunnel_command_fails_with_ssh_error_on_stderr() -> None:
    unreachable = SshTunnelConfig(host="127.0.0.1", port=_free_port())
    result = subprocess.run(
        ["/bin/sh", "-c", tunnel_command(unreachable, _free_port())],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode != 0
    assert "Connection refused" in result.stderr


def test_connection_label_uses_name_for_localhost() -> None:
    assert connection_label(TUNNELED) == "Studio Mac"
    assert default_app_name(TUNNELED) == "VNC Studio Mac"
