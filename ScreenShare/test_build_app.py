import plistlib
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from lib.config import SshTunnelConfig
from ScreenShare.icon import initials, make_icon
from ScreenShare.build_app import (
    _absolute_path,
    _bash,
    _shell_functions,
    DEADLINE_SECONDS,
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
    stop_command,
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


def test_render_fills_tunnel_stop_fallback_and_times() -> None:
    conn = Connection(name="n", address="a", url="vnc://a")
    out = render(
        "__TUNNEL__|__STOP__|__FALLBACK__|__WAIT__|__DEADLINE__",
        conn,
        "ssh x",
        "Remote App",
        "kill",
    )
    assert out == f'"ssh x"|"kill"|"Remote App"|{WAIT_SECONDS}|{DEADLINE_SECONDS}'


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


@contextmanager
def _vnc_server(banner: bytes, delay: float = 0.0) -> Iterator[int]:
    """A local listener that sends `banner` to each client after `delay` (empty: says nothing)."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    done = threading.Event()

    def serve() -> None:
        while not done.is_set():
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            time.sleep(delay)
            if banner:
                client.sendall(banner)
            done.wait(3)
            client.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield int(listener.getsockname()[1])
    finally:
        done.set()
        thread.join()
        listener.close()


def _run(command: str, timeout: float = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/sh", "-c", command], capture_output=True, text=True, timeout=timeout
    )


def _probe(port: int) -> int:
    return _run(_bash(_shell_functions(port, 1) + "probe")).returncode


def test_tunnel_command_runs_under_bash() -> None:
    assert tunnel_command(SshTunnelConfig(host="vnc.example.com"), 5901).startswith("/bin/bash -c ")


@pytest.mark.parametrize(
    ("banner", "delay", "up"),
    [
        (b"RFB 003.008\n", 0.0, True),
        (b"RFB 003.008\n", 0.5, True),  # a slow host, inside the timeout
        (b"", 0.0, False),  # a stale ssh holds the port; nothing answers
        (b"SSH-2.0-x\n", 0.0, False),  # something else answers
    ],
)
def test_probe_wants_a_vnc_banner(banner: bytes, delay: float, up: bool) -> None:
    with _vnc_server(banner, delay) as port:
        assert (_probe(port) == 0) is up


def test_probe_fails_when_nothing_listens() -> None:
    assert _probe(_free_port()) != 0


def test_tunnel_command_reuses_a_tunnel_that_answers() -> None:
    unreachable = SshTunnelConfig(host="127.0.0.1", port=_free_port())
    with _vnc_server(b"RFB 003.008\n") as port:
        result = _run(tunnel_command(unreachable, port, probe_seconds=1))
    assert (result.returncode, result.stdout.strip()) == (0, "reused")


def test_tunnel_command_replaces_a_silent_tunnel() -> None:
    """A port that listens but never answers is not reused: ssh runs (and fails here)."""
    unreachable = SshTunnelConfig(host="127.0.0.1", port=_free_port())
    with _vnc_server(b"") as port:
        result = _run(tunnel_command(unreachable, port, probe_seconds=1))
    assert result.returncode != 0
    assert "Connection refused" in result.stderr


def test_tunnel_command_fails_with_ssh_error_on_stderr() -> None:
    unreachable = SshTunnelConfig(host="127.0.0.1", port=_free_port())
    result = _run(tunnel_command(unreachable, _free_port(), probe_seconds=1))
    assert result.returncode != 0
    assert "Connection refused" in result.stderr


LISTENER_C = r"""
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[1])),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 8)) return 1;
    for (;;) pause();
}
"""

needs_mac_cc = pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("cc") is None, reason="needs macOS lsof and cc"
)


@pytest.fixture(scope="module")
def listener_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A silent listener; `stop` matches on the process name, so tests copy it as `ssh`."""
    folder = tmp_path_factory.mktemp("listener")
    (folder / "listen.c").write_text(LISTENER_C)
    subprocess.run(["cc", "-o", str(folder / "listen"), str(folder / "listen.c")], check=True)
    return folder / "listen"


@contextmanager
def _listening(
    binary: Path, name: str, forward_port_offset: int
) -> Iterator[subprocess.Popen[bytes]]:
    """Run the listener as `name` on a free port, with `-L <port + offset>:localhost:5900`."""
    named = binary.with_name(name)
    shutil.copy(binary, named)
    port = _free_port()
    proc = subprocess.Popen(
        [str(named), str(port), "-L", f"{port + forward_port_offset}:localhost:5900"]
    )
    proc.port = port  # type: ignore[attr-defined]
    try:
        for _ in range(50):
            with socket.socket() as sock:
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.05)
        yield proc
    finally:
        proc.kill()
        proc.wait()


@needs_mac_cc
def test_stop_ends_the_ssh_that_forwards_the_port(listener_binary: Path) -> None:
    with _listening(listener_binary, "ssh", 0) as proc:
        assert _run(stop_command(proc.port)).returncode == 0  # type: ignore[attr-defined]
        assert proc.wait(timeout=3) is not None


@needs_mac_cc
@pytest.mark.parametrize(
    ("name", "offset"), [("ssh", 1), ("python3", 0)], ids=["ssh-for-another-port", "not-ssh"]
)
def test_stop_leaves_other_processes(listener_binary: Path, name: str, offset: int) -> None:
    with _listening(listener_binary, name, offset) as proc:
        assert _run(stop_command(proc.port)).returncode == 0  # type: ignore[attr-defined]
        time.sleep(0.3)
        assert proc.poll() is None


def test_connection_label_uses_name_for_localhost() -> None:
    assert connection_label(TUNNELED) == "Studio Mac"
    assert default_app_name(TUNNELED) == "VNC Studio Mac"
