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
and a virtual display that starts at the lock screen). View → Actual Size plus one Zoom In
fills the screen in Standard mode; zoom turns scaling off. The click count is
`zoom_in_steps` in config.

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

---

## Dead ends

### Full screen without System Events

Screen Sharing's AppleScript dictionary has only `GetURL`. `sessionMetadatas` stores
`isFullScreen` and `scalingMode` per connection, but opening the connection does not restore
full screen. Hand-made `.vncloc` files with `restorationAttributes.isFullScreen` opened no
window, and the app deletes its own `.vncloc` when the session closes.

### Dock tile format

Not a dead end, for reference: the builder appends a minimal `persistent-apps` entry
(`file-data` → `_CFURLString` = the app's `file://…/` URL, `_CFURLStringType` 15), then
`killall Dock`. It checks for the URL first, so a rebuild keeps one tile.
