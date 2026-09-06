# AppleNotesBackup — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Landmines

### Why this design

- **AppleScript, not `NoteStore.sqlite`.** Notes are stored as gzip-compressed
  protobuf blobs in a private schema that changes across macOS versions. We go
  through Notes.app's scripting interface (`export_notes.applescript`) and read
  each note's rendered **HTML `body`** — lossless for text, lists, tables, and
  checklists, and stable across OS upgrades.
- **One HTML file per note, mirrored into git.** Each run makes the working tree
  match Notes exactly (deleting files for notes that vanished), then commits.
  Deleting the working file is safe — every past version stays in git history.
- **Hybrid filenames** `‹slug›__‹short_id›.html`. The `short_id` (an 8-hex-char
  fingerprint of the note's stable id) anchors identity, so renaming a note in
  Notes.app shows up as a git **edit**, not delete+add. Without it, every rename
  would look like an accidental delete and bury the real ones.

### Limitations (v1)

- **Attachments: metadata only.** Images, drawings, and scanned PDFs are recorded
  by count in each note's header comment but not exported as files. Full
  attachment export is future work.
- Runs on the Mac where Notes.app lives (notes are local); not a prod-host job.

---

## Error reference

### AppleScript error `-1728` on `container`

We read only *downward*; reading a folder/note's parent via `container` errors
(-1728) on items reached through a top-level collection.
