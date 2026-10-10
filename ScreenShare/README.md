# ScreenShare

Gotchas and dead ends: [Logbook.md](Logbook.md).

Builds a double-clickable macOS app that opens one remote Mac in Screen Sharing, in full
screen, with scaling set. Scaling on is "Scale to fit available space": the remote screen
fits the window, and the remote resolution does not change.

## Build

```bash
make screenshare-app HOST=mac-mini.local NAME=MiniFull 2>&1 | tee /tmp/screenshare-app.log
```

The app goes to `~/Desktop/MiniFull.app`. Make one app per remote Mac.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `HOST` | required | Hostname or IP of the remote Mac, e.g. `mac-mini.local` |
| `NAME` | `ScreenShare` | App name. The file is `<NAME>.app` |
| `SCALE` | `on` | `on` = scale the remote screen to fit the window. `off` = show it at full size |
| `DEST` | `~/Desktop` | Folder for the app |

The script `Scripts/build_app.sh` reads the same settings from the environment, so
`HOST=mac-mini.local Scripts/build_app.sh` also works.

## Give the app Accessibility permission (one time)

The app uses System Events to set full screen and scaling. macOS allows this only for apps
on the Accessibility list. Without it, the session opens but stays in a window.

1. Build the app.
2. Open **System Settings → Privacy & Security → Accessibility**.
3. Click **+**, select the app (e.g. `~/Desktop/MiniFull.app`), and turn it on.
4. Quit Screen Sharing. Double-click the app.

**After each rebuild, do steps 2–3 again.** A rebuild makes a new app signature, and macOS
does not keep the old permission. Remove the old entry (**−**), then add the app again.

## How it works

1. Opens `vnc://<HOST>`. Screen Sharing asks for the login if it has none saved.
2. Waits up to 90 s for the session window for that host.
3. Clicks **View → Turn Scaling On** (or **Off**), only when the menu shows the other state.
4. Sets the window to full screen.

If the host is already connected, the app brings that session to the front and applies the
same settings.
