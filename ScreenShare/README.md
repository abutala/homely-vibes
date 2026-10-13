# ScreenShare

Landmines and dead ends: [Logbook.md](Logbook.md).

Installs `~/Applications/VNC <Host Name>.app` with a Dock tile, one per configured connection.
Each app opens a **saved** Screen Sharing connection in full screen, fitted to the screen,
with no extra questions. If that session is already in full screen, the app only switches to
it. Its icon is a monitor with the host's initials (`icon.py`).

## Install

1. Connect once in Screen Sharing so the connection is saved.
2. Add it to `config/local.yaml`:

   ```yaml
   screen_share:
     apps:
       - connection: "Studio Mac"   # name in Screen Sharing's All Connections list
   ```

3. Run `make screenshare-app 2>&1 | tee /tmp/screenshare-app.log`.
4. Launch the app from the Dock. On the first launch, allow "… wants to control System
   Events" (and Finder and System Settings, which it uses to lay out the permission windows).
   Without Accessibility it does not connect: it opens that list and Finder side by side and
   says what to do. Remove any old entry for it, drag it in, turn it on, and launch
   it again.

A rebuild drops the Accessibility grant, even though the old entry still shows as on.

## Settings (per entry in `screen_share.apps`)

| Key | Default | What it does |
|---|---|---|
| `connection` | required | Saved connection name or address. An unknown one lists the saved names |
| `name` | `VNC <Host Name>` | App name. `studio-mac.local` → `VNC Studio Mac`. An IP stays as is |

The fit needs no setting: from Actual Size the app zooms in until a scroll bar appears, then
zooms out one step. A remote larger than this screen gets scaling instead.
`make screenshare-app DEST=<dir>` installs elsewhere;
`ScreenShare/build_app.py` also takes `--no-dock`.
