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
| `name` | `VNC <Host Name>` | App name. `studio-mac.local` → `VNC Studio Mac`. An IP stays as is. A `localhost` connection takes its saved name |
| `ssh_tunnel` | none | Connect through an SSH server. See [Reach a Mac from anywhere](#reach-a-mac-from-anywhere) |
| `fallback_app` | none | App to offer when the connection fails, e.g. `Splashtop Personal` |

## Reach a Mac from anywhere

A Bonjour connection works only on the home network. To reach the Mac from anywhere, go
through an SSH server that can reach its VNC port, for example the Mac itself behind a
router port forward to its SSH port. The server must run a shell command (`sleep`): a
forwarding-only key or a server with no `sleep` closes the tunnel before Screen Sharing
connects.

1. Check that key-only SSH works, and accept the host key:
   `ssh -o BatchMode=yes -p <ssh port> <user>@<fqdn> true`.
2. Start a tunnel by hand: `ssh -N -L 5901:localhost:5900 -p <ssh port> <user>@<fqdn>`.
3. In Screen Sharing, connect to `localhost:5901` and let it remember the password. In All
   Connections, rename the new entry to the name the app should use. If the home-network entry
   has that name, rename or delete that one first. Stop the tunnel (Ctrl-C).
4. Add the tunnel to the entry in `config/local.yaml`, then run `make screenshare-app` again:

   ```yaml
   screen_share:
     apps:
       - connection: "Studio Mac"   # the localhost:5901 entry from step 3
         ssh_tunnel:
           host: vnc.example.com    # FQDN or IP of the SSH server
           port: 2222               # default 22
           user: alex               # default: ~/.ssh/config, then your login name
           # remote_port: 5900      # VNC port as seen from the SSH server
         fallback_app: "Splashtop Personal"
   ```

The local port comes from the saved connection (`5901` above). On launch the app starts
`ssh -L` in the background, unless that port already listens, which means a tunnel is up. The
tunnel closes when the session ends, or about 30 s after its link dies. If SSH fails, or no session shows within 90 s, the app
says why and offers `fallback_app`.

The fit needs no setting: from Actual Size the app zooms in until a scroll bar appears, then
zooms out one step. A remote larger than this screen gets scaling instead.
`make screenshare-app DEST=<dir>` installs elsewhere;
`ScreenShare/build_app.py` also takes `--no-dock`.
