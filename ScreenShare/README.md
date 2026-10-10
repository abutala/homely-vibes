# ScreenShare

Gotchas and dead ends: [Logbook.md](Logbook.md).

Builds a double-click macOS app that opens one **saved** Screen Sharing connection in full
screen, with scaling set. Scaling on is "Scale to fit available space": the remote screen fits
the window, and the remote resolution does not change.

The app opens the connection Screen Sharing already has saved, with its own address and user.
It never makes a new connection entry, so your saved login and settings apply.

## Build

1. Connect once in Screen Sharing so the connection is saved. Note its name in the
   Screen Sharing window (e.g. `Studio Mac`).
2. Build:

   ```bash
   make screenshare-app CONNECTION="Studio Mac" NAME=Studio 2>&1 | tee /tmp/screenshare-app.log
   ```

3. `make` opens the Accessibility list and shows the new app in Finder. Drag the app into
   the list and turn it on. That is the only manual step.

An unknown `CONNECTION` fails and prints the names of the saved connections.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `CONNECTION` | required | Saved connection name as Screen Sharing shows it, or its address |
| `NAME` | `ScreenShare` | App name. The file is `<NAME>.app` |
| `SCALE` | `on` | `on` = scale the remote screen to fit the window. `off` = show it at full size |
| `DEST` | `~/Desktop` | Folder for the app |

Direct use: `uv run python ScreenShare/build_app.py --connection "Studio Mac" --name Studio`.
Add `--no-settings` to skip opening the Accessibility list.

## Permissions

- **Accessibility** — needed to set full screen and scaling. On macOS 27 the list is
  **System Settings → Device Control and Data Access → Accessibility** (on older macOS:
  Privacy & Security → Accessibility). `make` opens it for you.
- **Automation** — on the first run macOS asks "… wants to control System Events". Click
  **Allow**. It asks once.
- **After each rebuild, grant Accessibility again.** A rebuild makes a new signature, and macOS
  does not keep the old permission. `make` opens the list again; remove the old entry (**−**)
  and drag the new app in.

If the app runs without Accessibility, it opens the list, shows itself in Finder, and says
what to do.

## How it works

1. Opens the saved connection's `vnc://user@address:port` URL.
2. Waits up to 90 s for the window with the connection's name.
3. Clicks **View → Turn Scaling On** (or **Off**), only when the menu shows the other state.
4. Sets the window to full screen.
