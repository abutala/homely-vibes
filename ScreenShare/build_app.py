#!/usr/bin/env python3
"""Install an app that opens one saved Screen Sharing connection in full screen.

The app opens the connection Screen Sharing already has saved (same address and user), so
it never creates a second entry. It goes to ~/Applications and the Dock, named
"VNC <Host Name>". See README.md for the settings.
"""

import argparse
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote

TEMPLATE = Path(__file__).with_name("launcher.applescript")
PERMISSION_PANE = (
    "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility"
)
NAME_PATTERN = re.compile(r"^[\w][\w .-]*$")
IP_PATTERN = re.compile(r"^[0-9.]+$|:")
HOST_SUFFIXES = ("._rfb._tcp.local.", "._rfb._tcp.local", ".local.", ".local")


@dataclass(frozen=True)
class Connection:
    name: str
    address: str
    url: str


def parse_connections(prefs: bytes) -> list[Connection]:
    """Saved connections from `defaults export com.apple.ScreenSharing -` output."""
    store_blob = plistlib.loads(prefs).get("connectionsStore")
    if store_blob is None:
        return []
    details = plistlib.loads(store_blob).get("connectionDetails", {})
    return [_connection(entry) for entry in details.values()]


def _connection(entry: dict) -> Connection:
    target = entry["connectionParameters"]["networkAddress"]["_0"]
    address = target["address"]  # already percent-encoded, e.g. a Bonjour name
    user = target.get("username") or ""
    port = target.get("port")
    url = "vnc://" + (f"{quote(user)}@" if user else "") + address + (f":{port}" if port else "")
    return Connection(name=target["displayName"], address=address, url=url + _type_query(target))


def _type_query(target: dict) -> str:
    """Pass the saved Standard type on, or Screen Sharing asks Standard vs High Performance."""
    display_type = target.get("displayConfiguration", {}).get("displayType", {})
    return "?numVirtualDisplays=0" if "compatibilityMode" in display_type else ""


def find_connection(connections: list[Connection], wanted: str) -> Connection:
    """Match on the name Screen Sharing shows, or on the address. Case-insensitive."""
    key = wanted.casefold()
    for conn in connections:
        if key in (conn.name.casefold(), conn.address.casefold()):
            return conn
    names = ", ".join(f'"{c.name}"' for c in connections) or "none"
    raise ValueError(
        f'No saved Screen Sharing connection "{wanted}". Saved: {names}. '
        "Connect once in Screen Sharing to save it."
    )


def applescript_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(template: str, conn: Connection, scale_on: bool) -> str:
    return (
        template.replace("__URL__", applescript_string(conn.url))
        .replace("__TITLE__", applescript_string(conn.name))
        .replace("__SCALE__", "true" if scale_on else "false")
    )


def host_label(address: str) -> str:
    """'El%20Peque%C3%B1o._rfb._tcp.local' or 'el-pequeno.local' -> 'El Pequeno'. IPs unchanged."""
    host = unquote(address)
    for suffix in HOST_SUFFIXES:
        host = host.removesuffix(suffix)
    if IP_PATTERN.search(host):
        return host
    ascii_host = unicodedata.normalize("NFKD", host).encode("ascii", "ignore").decode()
    words = [w for w in re.split(r"[-_.\s]+", ascii_host) if w]
    return " ".join(w[:1].upper() + w[1:] for w in words)


def default_app_name(conn: Connection) -> str:
    return f"VNC {host_label(conn.address)}"


def bundle_id(app_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", app_name.lower()).strip("-") or "app"
    return f"com.homelyvibes.screenshare.{slug}"


def compile_app(source: str, app: Path) -> None:
    """osacompile, then a bundle ID so macOS privacy settings can track the app."""
    with tempfile.NamedTemporaryFile("w", suffix=".applescript") as script:
        script.write(source)
        script.flush()
        shutil.rmtree(app, ignore_errors=True)
        subprocess.run(["osacompile", "-o", str(app), script.name], check=True)
    info_path = app / "Contents" / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["CFBundleIdentifier"] = bundle_id(app.stem)
    info_path.write_bytes(plistlib.dumps(info))
    subprocess.run(["codesign", "--force", "--sign", "-", str(app)], check=True)


def dock_has(persistent_apps: list[dict], app: Path) -> bool:
    url = app.as_uri() + "/"
    return any(
        tile.get("tile-data", {}).get("file-data", {}).get("_CFURLString") == url
        for tile in persistent_apps
    )


def add_to_dock(app: Path) -> bool:
    """Append a Dock tile for the app unless one exists. True when a tile was added."""
    dock = plistlib.loads(
        subprocess.run(
            ["defaults", "export", "com.apple.dock", "-"], capture_output=True, check=True
        ).stdout
    )
    if dock_has(dock.get("persistent-apps", []), app):
        return False
    tile = (
        "<dict><key>tile-data</key><dict><key>file-data</key><dict>"
        f"<key>_CFURLString</key><string>{app.as_uri()}/</string>"
        "<key>_CFURLStringType</key><integer>15</integer></dict></dict></dict>"
    )
    subprocess.run(
        ["defaults", "write", "com.apple.dock", "persistent-apps", "-array-add", tile], check=True
    )
    subprocess.run(["killall", "Dock"], check=True)
    return True


def show_permission_pane(app: Path) -> None:
    subprocess.run(["open", "-R", str(app)], check=True)
    subprocess.run(["open", PERMISSION_PANE], check=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connection", required=True, help="saved connection name or address")
    parser.add_argument("--name", help='app name; default "VNC <Host Name>"')
    parser.add_argument("--scale", choices=["on", "off"], default="on")
    parser.add_argument("--dest", type=Path, default=Path.home() / "Applications")
    parser.add_argument("--no-dock", action="store_true", help="do not add a Dock tile")
    parser.add_argument("--no-settings", action="store_true", help="do not open Settings")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    prefs = subprocess.run(
        ["defaults", "export", "com.apple.ScreenSharing", "-"], capture_output=True, check=True
    ).stdout
    try:
        conn = find_connection(parse_connections(prefs), args.connection)
    except ValueError as err:
        print(err)
        return 1
    name = args.name or default_app_name(conn)
    if not NAME_PATTERN.match(name):
        print(f"App name may hold letters, digits, space, '.', '_' and '-': {name}")
        return 1
    app = args.dest / f"{name}.app"
    args.dest.mkdir(parents=True, exist_ok=True)
    compile_app(render(TEMPLATE.read_text(), conn, args.scale == "on"), app)
    print(f'Built {app} for "{conn.name}" ({conn.url}), scaling {args.scale}.')
    if not args.no_dock and add_to_dock(app):
        print("Added to the Dock.")
    if not args.no_settings:
        show_permission_pane(app)
        print(f"Drag {name} from Finder into the Accessibility list and turn it on.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
