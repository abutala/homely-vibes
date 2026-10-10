import plistlib
from pathlib import Path

import pytest

from ScreenShare.icon import initials, make_icon
from ScreenShare.build_app import (
    TEMPLATE,
    Connection,
    default_app_name,
    dock_has,
    host_label,
    applescript_string,
    bundle_id,
    find_connection,
    parse_connections,
    render,
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


def test_parse_builds_url_with_user_and_port() -> None:
    [conn] = parse_connections(_prefs(BONJOUR))
    assert conn == Connection(
        name="Studio Mac",
        address="Studio%20Mac._rfb._tcp.local",
        url="vnc://alex@Studio%20Mac._rfb._tcp.local:5900?numVirtualDisplays=0",
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
    assert render("__URL__|__TITLE__|__ZOOM__", conn, None) == '"vnc://x"|"Ma\\"c"|missing value'
    assert render("__ZOOM__", conn, 2) == "2"


def test_bundle_id_is_stable_slug() -> None:
    assert bundle_id("My Mac.app") == "com.homelyvibes.screenshare.my-mac-app"
    assert bundle_id("ELP") == "com.homelyvibes.screenshare.elp"


def test_real_template_has_no_placeholder_left() -> None:
    conn = Connection(name="n", address="a", url="vnc://a")
    assert "__" not in render(TEMPLATE.read_text(), conn, 1)


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
