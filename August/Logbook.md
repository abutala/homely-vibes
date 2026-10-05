# August — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-10-04 — A failed save tore the state file, and the reset was silent

`_save_state` opened the state file with `open(path, "w")`, which truncates before a
byte is written. A save that died part-way left invalid JSON; reproduced in a test with
an unserializable value, which left `{"unlock_start_times": {"Lock A": ` on disk. Not
observed in production.

`_load_state` then treated the corrupt file like a missing one, at debug level. Every
unlock and ajar timer restarted from zero, so a door already open alerted up to a full
threshold late, the alert cooldowns were forgotten too, and nothing said why.

Fix: the save goes through `lib.secure_io.write_secret_atomic` (temp file, then rename),
and a state file that cannot be read as a JSON object logs a warning naming the path. A missing file stays quiet: that is a
first run.

---

## Landmines

### A crash between sending an alert and saving state repeats the alert

The cooldown timestamp is persisted at the end of the check cycle, after the alert is
sent. A crash in between sends the same alert again after restart. Left as is on purpose:
the other order (save, then send) can lose an alert, and for a door left open a
duplicate is the cheaper failure.

### A failed Pushover send still starts the cooldown

The unlock and ajar cooldown timestamps are set when the alert is queued, and
`_send_consolidated_alerts` logs a send failure without raising. The cooldown is saved
anyway, so that alert is not retried until the cooldown has passed. Open.
