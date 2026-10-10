# ScreenShare — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## The window title is the remote display name, not the hostname

A session window is titled with the remote Mac's display name (it can hold characters such as
`ñ`), not with the hostname in the `vnc://` URL. A title match built from `HOST` misses. The
launcher reads the window's `AXDocument` attribute instead. It points to a `.vncloc` file
whose `URL` key holds the `vnc://` address.

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
entry no longer matches and full screen silently fails. Remove the entry and add the app
again.
