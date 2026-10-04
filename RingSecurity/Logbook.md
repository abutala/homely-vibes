# RingSecurity — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Landmines

### `auth` runs without the token lock

`ring_manager.py auth` writes the token file outside `acquire_lock`, so an interactive
login that overlaps a cron run can race its refresh. Left open on purpose: holding the
lock across a 2FA prompt would time out the cron jobs. Run `auth` away from the daily
runs. Model and the unconfirmed assumption behind it: [formal/Logbook.md](../formal/Logbook.md).
