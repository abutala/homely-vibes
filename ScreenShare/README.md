# ScreenShare

Landmines and dead ends: [Logbook.md](Logbook.md).

Installs `~/Applications/VNC <Host Name>.app` with a Dock tile, one per configured connection.
Each app opens a **saved** Screen Sharing connection in full screen, fitted to the screen,
with no extra questions.

## Install

1. Connect once in Screen Sharing so the connection is saved.
2. Add it to `config/local.yaml`:

   ```yaml
   screen_share:
     apps:
       - connection: "Studio Mac"   # name in Screen Sharing's All Connections list
         zoom_in_steps: 1           # omit to scale to fit
   ```

3. Run `make screenshare-app 2>&1 | tee /tmp/screenshare-app.log`. It opens the
   Accessibility list and shows the app in Finder. Drag the app into the list and turn it on.
4. On the first launch, allow "… wants to control System Events".

Do step 3's drag again after each rebuild. Remove the old entry first.

## Settings (per entry in `screen_share.apps`)

| Key | Default | What it does |
|---|---|---|
| `connection` | required | Saved connection name or address. An unknown one lists the saved names |
| `zoom_in_steps` | none | View → Actual Size, then this many Zoom In clicks. None = scale to fit, which only shrinks |
| `name` | `VNC <Host Name>` | App name. `el-pequeno.local` → `VNC El Pequeno`. An IP stays as is |

To find `zoom_in_steps`, use the zoom buttons in the Screen Sharing toolbar until the picture
fits, counting clicks from Actual Size. `make screenshare-app DEST=<dir>` installs elsewhere;
`ScreenShare/build_app.py` also takes `--no-dock` and `--no-settings`.
