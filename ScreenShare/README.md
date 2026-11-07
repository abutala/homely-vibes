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

The app starts the tunnel itself. Setup is config only:

1. Check that key-only SSH works, which also saves the host key:
   `ssh -p <ssh port> <user>@<fqdn> true` (answer `yes` to the host key once).
2. Add `ssh_tunnel` to the entry in `config/local.yaml`. `connection` stays the home-network
   entry: the app takes its name, user and screen sharing type from it.

   ```yaml
   screen_share:
     apps:
       - connection: "Studio Mac"
         ssh_tunnel:
           host: vnc.example.com    # FQDN or IP of the SSH server
           port: 2222               # default 22
           user: alex               # default: ~/.ssh/config, then your login name
           # remote_port: 5900      # VNC port as seen from the SSH server
           # local_port: 5901       # tunnel end on this Mac
         fallback_app: "Splashtop Personal"
   ```

3. Run `make screenshare-app 2>&1 | tee /tmp/screenshare-app.log`.
4. Launch the app. The first launch asks for the remote password once: tick "Remember this
   password in my keychain". Screen Sharing then saves a `localhost` entry with the same name.

On launch the app reuses a tunnel only if the server's VNC answers through it. Otherwise it
stops the old tunnel and starts `ssh -L <local_port>:localhost:<remote_port>` in the
background, then checks that VNC answers. The tunnel closes when the session ends, about 30 s
after its link dies, or after 5 minutes unused.

A connect that fails (SSH error, VNC does not answer, "Connection failed") is cleaned up and
tried again, up to 3 times while at least 10 s of the launch's 30 s is left. A connect that hangs on "Connecting…" is cancelled when the
launch reaches 30 s. Then the app says why and offers `fallback_app`, so a dead link reaches
the fallback in about 30 s. A password prompt stops the clock: the app waits up to 90 s
for it. If you click Cancel, the app stops and does not retry.

The fit needs no setting: from Actual Size the app zooms in until a scroll bar appears, then
zooms out one step. A remote larger than this screen gets scaling instead.
`make screenshare-app DEST=<dir>` installs elsewhere;
`ScreenShare/build_app.py` also takes `--no-dock`.
