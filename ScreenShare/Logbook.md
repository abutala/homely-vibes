# ScreenShare — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Open the saved connection, never a hand-built `vnc://host` (2026-10)

`open location "vnc://<hostname>"` makes a **new** saved connection when the saved one uses
another address (Screen Sharing saves Bonjour names such as `Name._rfb._tcp.local`). The new
entry has no username, so every launch asks more questions. The builder now reads
`connectionsStore` from `defaults export com.apple.ScreenSharing -` and opens the saved entry's
own `vnc://user@address:port`. Screen Sharing then reuses that entry, and its window title is
the entry's `displayName`, which the launcher waits for.

A per-connection `sessionMetadatas` record holds `isFullScreen` and `scalingMode`, but opening
the connection does not restore full screen. Screen Sharing's AppleScript dictionary has only
`GetURL`, so full screen still goes through System Events.

## `.vncloc` files are not a launcher (2026-10)

Screen Sharing writes a `.vncloc` file per open session under its container
(`~/Library/Containers/com.apple.ScreenSharing/Data/Library/Application Support/Screen Sharing/`).
Its `restorationAttributes` hold `isFullScreen`, `scalingMode` and `dynamicResolution`.
These keys are not documented. A hand-made file with them opened no window, and the app
deletes its own copy when the session closes. Do not build on them.

## System Events cannot see a window on another full-screen Space

When the session is in full screen and a different Space is active, `windows of process
"Screen Sharing"` is empty, but the connection is still up (`lsof -i` shows port 5900
established). `open location` switches to the session's Space, so the launcher then finds it.

## Accessibility permission does not survive a rebuild

`osacompile` signs the app ad hoc. Each rebuild gives a new signature, so the Accessibility
entry no longer matches and the app cannot set full screen. Remove the entry and add the app
again.

The builder also sets `CFBundleIdentifier` (`com.homelyvibes.screenshare.<name>`).
`osacompile` writes none, and an app without one did not show up in the Accessibility list.

## The Accessibility list moved in macOS 27

It is under **System Settings → Device Control and Data Access**, not Privacy & Security. The
old deep link still opens it:
`x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility`.
