# ScreenShare

Landmines and dead ends: [Logbook.md](Logbook.md).

Installs `~/Applications/VNC <Host Name>.app` with a Dock tile, one per configured connection.
Each app opens a **saved** Screen Sharing connection in full screen, fitted to the screen,
with no extra questions. Its icon is a monitor with the host's initials (`icon.py`).

## Install

1. Connect once in Screen Sharing so the connection is saved.
2. Add it to `config/local.yaml`:

   ```yaml
   screen_share:
     apps:
       - connection: "Studio Mac"   # name in Screen Sharing's All Connections list
         zoom_in_steps: 1           # omit to scale to fit
   ```

3. Run `make screenshare-app 2>&1 | tee /tmp/screenshare-app.log`.
4. Launch the app from the Dock. On the first launch, allow "… wants to control System
   Events". If it lacks Accessibility, it opens that list and shows itself in Finder: drag it
   in, turn it on, and launch it again.

A rebuild drops the Accessibility grant. The app asks again on its next launch; remove the old
entry first.

## Settings (per entry in `screen_share.apps`)

| Key | Default | What it does |
|---|---|---|
| `connection` | required | Saved connection name or address. An unknown one lists the saved names |
| `zoom_in_steps` | none | View → Actual Size, then this many Zoom In clicks. None = scale to fit, which only shrinks |
| `name` | `VNC <Host Name>` | App name. `el-pequeno.local` → `VNC El Pequeno`. An IP stays as is |

To find `zoom_in_steps`, use the zoom buttons in the Screen Sharing toolbar until the picture
fits, counting clicks from Actual Size. `make screenshare-app DEST=<dir>` installs elsewhere;
`ScreenShare/build_app.py` also takes `--no-dock`.
