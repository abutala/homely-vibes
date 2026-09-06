# VoiceNotes — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Error reference

### `This process is not trusted! Input event monitoring will not be possible...`

Cosmetic warning from pynput at startup. If hotkey events still fire, ignore it. If they don't fire at all, re-grant Accessibility permission.

### App quits immediately after pressing the key (clean exit, no traceback)

Was a real bug — fixed in PR #162. If you still see it, you're on stale code; `git pull` and `uv sync --extra voice` again.

### Hotkey doesn't respond

Verify Accessibility for Terminal. After granting, fully quit and relaunch your terminal — pynput won't pick up newly-granted permissions in an already-running process.

### Microphone access denied or no audio captured

Verify Microphone permission. macOS will silently terminate the process if it tries to capture without permission.

### Slow first transcription

Expected — first key press triggers the 1.5 GB model download (`large-v3-turbo`). Watch download progress in the terminal.

---

## Landmines

### A newly-granted macOS permission does not reach an already-running process

Accessibility and Microphone grants are read at process start. Granting one while the app is up changes nothing — fully quit and relaunch the terminal, then rerun.
