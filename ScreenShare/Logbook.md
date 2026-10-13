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
