"""The launcher's pure handlers, run in AppleScript itself: `decide` (what the wait does next)
and `classify` (a Screen Sharing window by its shape). The state machine around them is
formal/screenshare_connect.qnt."""

import subprocess
import sys
from pathlib import Path

import pytest

from ScreenShare.build_app import DEADLINE_SECONDS, TEMPLATE, WAIT_SECONDS, Connection, render

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="needs osascript")

TITLE = "Studio Mac"
NOTHING = {
    "isRunning": True,
    "offSpace": False,
    "hasSession": False,
    "hasPrompt": False,
    "hasFailed": False,
    "hasBusy": False,
}
WINDOW = {
    "winTitle": "",
    "winSubrole": "AXStandardWindow",
    "hasBusy": False,
    "buttonCount": 0,
    "hasField": False,
    "sheetButtons": 0,
}


@pytest.fixture(scope="module")
def launcher(tmp_path_factory: pytest.TempPathFactory) -> Path:
    conn = Connection(name=TITLE, address="localhost", url="vnc://alex@localhost:5901")
    folder = tmp_path_factory.mktemp("launcher")
    source = folder / "launcher.applescript"
    source.write_text(render(TEMPLATE.read_text(), conn, "true", "Other App", "true"))
    compiled = folder / "launcher.scpt"
    subprocess.run(["osacompile", "-o", str(compiled), str(source)], check=True)
    return compiled


def _record(values: dict[str, object]) -> str:
    def literal(value: object) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, str):
            return '"' + value + '"'
        return str(value)

    return "{" + ", ".join(f"{key}:{literal(value)}" for key, value in values.items()) + "}"


def _call(launcher: Path, expression: str) -> str:
    script = f'set L to load script POSIX file "{launcher}"\nreturn L\'s {expression}'
    result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _decide(launcher: Path, launch: float, prompt_for: float, gone: float, **snap: bool) -> str:
    return _call(
        launcher, f"decide({_record({**NOTHING, **snap})}, {launch}, {prompt_for}, {gone})"
    )


LATE = DEADLINE_SECONDS + 1


@pytest.mark.parametrize(
    ("snap", "launch", "prompt_for", "gone", "expected"),
    [
        ({"hasSession": True}, LATE, LATE, 0, "session"),
        ({"hasPrompt": True}, LATE, WAIT_SECONDS - 1, 0, "wait"),  # the clock stops on a prompt
        ({"hasPrompt": True}, 5, WAIT_SECONDS, 0, "promptTimeout"),
        ({"hasPrompt": True, "hasFailed": True}, 5, 5, 0, "wait"),  # never clean up under a prompt
        ({"hasFailed": True}, 3, 3, 0, "failed"),
        ({"hasBusy": True}, DEADLINE_SECONDS - 1, 10, 0, "wait"),
        ({"hasBusy": True}, DEADLINE_SECONDS, 10, 0, "hung"),
        ({}, 10, 10, 4, "cancelled"),  # the Connecting window went and nothing came
        ({}, 10, 10, 3, "wait"),  # a slow alert after the Connecting window goes
        ({"offSpace": True}, 10, 10, 5, "wait"),  # its windows are on another Space
        ({"offSpace": True}, LATE, LATE, 5, "timeout"),
        ({}, 10, 10, 0, "wait"),
        ({}, LATE, LATE, 0, "timeout"),  # never saw a known window: leave it, offer the fallback
    ],
)
def test_decide(
    launcher: Path,
    snap: dict[str, bool],
    launch: float,
    prompt_for: float,
    gone: float,
    expected: str,
) -> None:
    assert _decide(launcher, launch, prompt_for, gone, **snap) == expected


@pytest.mark.parametrize(
    ("window", "expected"),
    [
        ({"winTitle": TITLE}, "session"),
        ({"winTitle": TITLE, "hasField": True}, "prompt"),
        ({"winTitle": TITLE, "sheetButtons": 1}, "failed"),  # an alert on the session window
        ({"winTitle": TITLE, "sheetButtons": 2}, "other"),
        ({"hasBusy": True, "buttonCount": 1}, "busy"),  # "Connecting to …" with Cancel
        ({"hasBusy": True, "buttonCount": 2}, "other"),
        ({"winSubrole": "AXDialog", "buttonCount": 1}, "failed"),  # "Connection failed" with OK
        ({"winSubrole": "AXDialog", "buttonCount": 1, "hasField": True}, "prompt"),
        ({"winSubrole": "AXDialog", "buttonCount": 2}, "other"),
        ({"winTitle": "Another Mac"}, "other"),
    ],
)
def test_classify(launcher: Path, window: dict[str, object], expected: str) -> None:
    assert _call(launcher, f"classify({_record({**WINDOW, **window})})") == expected
