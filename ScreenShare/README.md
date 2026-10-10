# ScreenShare

Landmines and dead ends: [Logbook.md](Logbook.md).

Installs `~/Applications/VNC <Host Name>.app` with a Dock tile. It opens one **saved** Screen
Sharing connection in full screen, scaled to fit, with no extra questions.

## Install

1. Connect once in Screen Sharing so the connection is saved.
2. Run, with the name shown in Screen Sharing's All Connections list:

   ```bash
   make screenshare-app CONNECTION="Studio Mac" 2>&1 | tee /tmp/screenshare-app.log
   ```

3. `make` opens the Accessibility list and shows the app in Finder. Drag the app into the list
   and turn it on.
4. On the first launch, allow "… wants to control System Events".

Do step 3 again after each rebuild. Remove the old entry first.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `CONNECTION` | required | Saved connection name or address. An unknown one lists the saved names |
| `NAME` | `VNC <Host Name>` | App name. `el-pequeno.local` → `VNC El Pequeno`. An IP stays as is |
| `SCALE` | `on` | `on` fits the remote screen to the window. `off` shows it at full size |
| `DEST` | `~/Applications` | Folder for the app |

`ScreenShare/build_app.py` takes the same settings as flags, plus `--no-dock` and
`--no-settings`.
