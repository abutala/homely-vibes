# ScreenShare — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Landmines

### Never open a hand-built `vnc://<hostname>`

When the address differs from the saved one (Screen Sharing saves Bonjour names such as
`Name._rfb._tcp.local`), Screen Sharing makes a **new** saved connection with no username, and
every launch asks more questions. The builder reads `connectionsStore` from
`defaults export com.apple.ScreenSharing -` and opens the saved entry's own
`vnc://user@address:port`. The session window title is then the entry's `displayName`.

### The URL must carry the screen sharing type

Without it, every launch asks "Select Screen Sharing Type" (Standard or High Performance).
The Connect button in All Connections does not ask. Standard is saved as
`displayType.compatibilityMode` and maps to `?numVirtualDisplays=0`, the same query Screen
Sharing writes itself. Only that key is sent, so the saved quality is untouched. Other types
still get the prompt.

### Scale to fit only shrinks

When the remote screen is smaller than this one (2048×1332 on 2624×1646), scaling shows it
at 1:1 with black borders, and the full-screen window itself is capped at the remote size.
Dynamic Resolution would fix it, but it needs High Performance (more load on the remote,
and a virtual display that starts at the lock screen). View → Actual Size plus Zoom In
fills the screen in Standard mode; zoom turns scaling off.

### Scroll bars tell when the zoom is one step too far

The `AXSharedScreen` element in the session window gets `AXScrollBar` children only while the
picture is larger than the window, on either axis. The launcher zooms in from Actual Size
until one appears, then zooms out once. This replaced a per-host `zoom_in_steps` setting. It
needs no screenshot, so no Screen Recording permission. System Events `entire contents`
returns nothing for this window; walk `UI elements` instead.

### Accessibility permission does not survive a rebuild

`osacompile` signs ad hoc, so each rebuild has a new signature and the old Accessibility entry
no longer matches. Remove it and add the app again. `osacompile` also writes no
`CFBundleIdentifier`; without one the app never appeared in the list, so the builder sets
`com.homelyvibes.screenshare.<name>` and re-signs.

### `Assets.car` hides a custom icon

`osacompile` ships the stock applet icon twice: `applet.icns` and an `Assets.car` named by
`CFBundleIconName`. Modern macOS prefers the asset catalog, so replacing only `applet.icns`
changes nothing. The builder deletes `Assets.car` and the `CFBundleIconName` key, writes its
own `applet.icns`, then signs. After a rebuild, `touch` the app and `killall Dock` if the old
icon is cached.

### The Accessibility list moved in macOS 27

It is under **System Settings → Device Control and Data Access**, not Privacy & Security. The
old deep link still opens it:
`x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility`.

### System Events cannot see a window on another full-screen Space

With the session in full screen and another Space active, `windows of process
"Screen Sharing"` is empty while the connection is up (`lsof -i` shows port 5900
established). `open location` switches to the session's Space, so the launcher then finds it.

A new "Connecting…" window opened while another Space was in front was also invisible (0
windows) until Screen Sharing was activated. The launcher activates it after `open location`
and whenever it sees 0 windows, through `NSRunningApplication`: `tell application "Screen
Sharing" to activate` launches it when it is not running, and left an empty instance. 0
windows is never read as the user's Cancel.

### `do shell script` hangs on `ssh -f`

`do shell script` returns only when the command's stdout and stderr close. `ssh -f` goes to the
background and keeps them open, so the launcher would wait until the tunnel closes. The tunnel
command sends ssh's stdout to `/dev/null` and its stderr to a temp file, then prints that file,
so an SSH error still reaches the dialog. `BatchMode=yes` stops a password prompt that nobody
can answer, and `ExitOnForwardFailure=yes` makes ssh fail, not go to the background, when the
local port cannot be bound. ssh does not check the far side, so the script reads the VNC
banner through the tunnel after ssh starts (next landmine). `ServerAliveInterval` ends a
tunnel whose link died, but only after about 30 s: until then a stale ssh holds the port.

### A tunnel saves its own connection on first use

A hand-built `vnc://user@localhost:5901?numVirtualDisplays=0` makes a new saved entry, as the
first landmine says, but with the user in the URL that is harmless. Screen Sharing asks for the
password once, then saves `localhost:5901` with that user and with the **remote Mac's own
name** as `displayName`. The session window gets that name too, so the launcher's window title
is the home-network entry's name. The second launch connected with no prompt. The new entry
does not save the screen sharing type, so the builder takes the user and type from the
home-network entry and only moves the address. Two entries now share a name:
`find_connection` prefers the one that is not `localhost`.

A first launch can sit on the password prompt for a while, so an unused tunnel lasts
5 minutes (`sleep 300`), not the launcher's 90 s wait.

### Each View menu click must settle before the next

In full screen with scaling on, the window is capped at the remote size (2048 wide). Actual
Size grows it to the screen (2624). A Zoom In sent at once stacked on that resize, so one step
zoomed twice and cropped the remote menu bar and Dock. A click during the full-screen
animation was lost. Measured on one host, from the click until the change shows:

| Step | Shows after |
|---|---|
| Full screen | 0.8 s; the window is unreadable from 0.15 s until then |
| Actual Size | 0.5 s |
| Zoom In / Zoom Out | 0.1 s (scroll bars) |

Fixed waits of 2 s and 1 s per click made the fit about 6 s. The launcher now polls the
window size every `pollSeconds` until it changes (full screen, Actual Size), then waits
`drawSeconds`; zoom clicks wait only `drawSeconds`. Reproduced and tuned by running the
rendered script with `osascript`, which needs no rebuild.

### Probe the VNC banner, not the port

On 2026-11-06 a tunnel app hung on "Connecting…", left the window and a stale ssh, and
the next launch reused the dead tunnel and hung again: `nc -z` saw the stale ssh listen. A
VNC server sends `RFB 003.008` before the client sends anything, so the tunnel script opens
the port and reads 3 bytes. Measured through the real tunnel: banner in 0.21 s; a closed
remote port reads down in 0.04 s; a frozen ssh reads down at the 5 s timeout. The script
probes twice before it stops a tunnel (a slow host must not lose a working session), so a
stale tunnel costs about 12 s, then a new one starts.

- `nc` cannot read it: with stdin at EOF it quits before a slow banner arrives.
- Bash's `/dev/tcp/localhost` tries only `::1`; ssh may listen on `127.0.0.1` alone. Probe
  `127.0.0.1`, and run the script with `/bin/bash -c`: `do shell script` runs `/bin/sh`.
- `exec 3<>/dev/tcp/… 2>/dev/null` makes the `2>/dev/null` permanent, so ssh's error never
  reached the dialog. The probe wraps the `exec` in braces. A test caught it.
- `stop` kills only a process named exactly `ssh` (`lsof -c '/^ssh$/'`; a bare `-c ssh` is a
  prefix match) that listens on the port and has `-L <port>:` in its arguments. A frozen ssh
  ignores TERM until KILL, 2 s later.

### Hung and failed connects, by shape

Measured on macOS 27 against local listeners:

| Case | What Screen Sharing shows |
|---|---|
| Nothing listens | An `AXDialog` "Connection failed to “localhost”." with one button (OK), within 2 s |
| Listens, says nothing | An untitled `AXStandardWindow` with an `AXBusyIndicator` and one button. Its name is missing value; its description is "Cancel". Unchanged at 20 s |
| Cancel or OK clicked | The window closes; Screen Sharing quits when it has no other window |

The launcher matches these by shape (busy indicator and one button; a dialog with one button
and no text field), not by English text. A window with a text field is taken for a password
prompt and never touched: its shape is not measured yet, because a fake RFB server with VNC
auth got only "Unable to communicate". `exists process "Screen Sharing"` in System Events
takes 2.4 s when it is not running (6 ms when it is); `NSRunningApplication` answers at once.

### Retry, cleanup and the 30 s deadline

The state machine is [formal/screenshare_connect.qnt](../formal/screenshare_connect.qnt),
proved with TLC; each fix in it is needed (its ablation is in
[formal/Logbook.md](../formal/Logbook.md)). The owner chose one 30 s deadline for the whole
launch (2026-11-06): a connect slower than that gets the fallback. What the model taught:

- Look for the session before cleanup and again after the clear: a session can come up after
  the timer fires, and a stop would end it.
- After a stop under a session window, wait for that window to turn into its alert, then
  clear: it keeps the session's title for a moment and was taken for success.
- Clear leftovers before `open location` too: an old session's alert can show after cleanup.
- A Connecting window that goes with nothing in its place (or Screen Sharing quits) for 2 s
  is the user's Cancel: leave, do not reopen.
- Retry only after a known failure. A launch that reaches 30 s with no known window offers
  the fallback and leaves the window and the tunnel (the model has no unknown window).
- The tunnel script's time counts against the 30 s: replacing a stale tunnel takes about
  12 s, which leaves about 18 s for the connect.
- A password prompt keeps the "Connecting window gone" timer fresh: after the password, the
  prompt goes before the session shows, and that gap is not a Cancel.
- Each window is read on its own `try`, and a partial read is read again: a window that
  closes mid-read would hide a session from cleanup (found in review, not seen live).

Accepted: cleanup touches any Screen Sharing window, so it assumes one tunnel app (revisit
with a second `screen_share.apps` entry that uses a tunnel). A stopped tunnel leaves the
remote `sleep 300`; at most three per bad launch, gone in 5 minutes. A remote VNC daemon that
hangs after its banner still looks live to the probe.

Not checked yet: a probe during a live session (RFB servers drop a client that leaves after
the banner; the session should stay).

### Check Accessibility before connecting

Without the grant, the old launcher opened the session and then failed, which left a
windowed session and a dialog. It now probes System Events (`count UI elements of process
"Dock"`) first.

The warning dialog hid behind System Settings: `open location` returns before Settings comes
forward. The launcher now waits for the Settings window, lays out Settings and Finder side by
side through their own scripting (Automation, not Accessibility), then activates itself and
shows the dialog. System Settings caps its own width, so the layout reads it back before it
centers the pair. The main screen's usable area comes from `NSScreen` (AppleScriptObjC):
Finder's desktop bounds span every display.

### Relaunch on a live session only switches to it

A new session always opens windowed, so `AXFullScreen` already true after `open location`
means the session was up. The launcher raises it and stops: it does not redo the zoom. A check
before `open location` cannot do this, because of the Space landmine above.

### The Dock rewrites its tiles

The builder appends a minimal `persistent-apps` entry (`file-data` → `_CFURLString` = the
app's `file://…/` URL, `_CFURLStringType` 15), then `killall Dock`. After a restart the Dock
rewrites the entries, and a check on the URL alone once missed the existing tile. The
duplicate check matches the URL or the `file-label`.

---

## Dead ends

### Full screen without System Events

Screen Sharing's AppleScript dictionary has only `GetURL`. `sessionMetadatas` stores
`isFullScreen` and `scalingMode` per connection, but opening the connection does not restore
full screen. Hand-made `.vncloc` files with `restorationAttributes.isFullScreen` opened no
window, and the app deletes its own `.vncloc` when the session closes.
