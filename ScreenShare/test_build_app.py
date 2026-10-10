import plistlib

import pytest

from ScreenShare.build_app import (
    TEMPLATE,
    Connection,
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
        url="vnc://alex@Studio%20Mac._rfb._tcp.local:5900",
    )


def test_parse_omits_empty_user_and_missing_port() -> None:
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
    out = render("__URL__|__TITLE__|__SCALE__", conn, scale_on=False)
    assert out == '"vnc://x"|"Ma\\"c"|false'


def test_bundle_id_is_stable_slug() -> None:
    assert bundle_id("My Mac.app") == "com.homelyvibes.screenshare.my-mac-app"
    assert bundle_id("ELP") == "com.homelyvibes.screenshare.elp"


def test_real_template_has_no_placeholder_left() -> None:
    conn = Connection(name="n", address="a", url="vnc://a")
    assert "__" not in render(TEMPLATE.read_text(), conn, scale_on=True)
