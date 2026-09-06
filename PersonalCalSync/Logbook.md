# PersonalCalSync — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Design rationale

### Why this module exists

Enterprise Google Workspace often blocks external calendar access via `CalendarApp`, so built-in calendar sharing doesn't work for scheduling visibility. This script fetches your personal calendar's private iCal feed over HTTP and creates real blocker events on your enterprise calendar that show up in coworkers' "Find a time" / scheduling assistant.

### Why the advanced Calendar service

> Because free/busy transparency and tentative status can't be set via the classic `CalendarApp` API, the script uses the **advanced Calendar service** (`Calendar.Events`). It's declared in `appsscript.json`, so a `clasp push` enables it automatically. If you paste the code in manually, add it via **Services (+)** → **Calendar API** in the Apps Script editor.

---

## Landmines

- Timezone: `TZID`-qualified timestamps are parsed as local (Apps Script server) timezone. Events on personal calendars in different timezones may be off by one hour during DST transitions.
- Sync window: only the next `SYNC_DAYS_AHEAD` (180) days are checked. Events beyond that window that were previously synced will not be cleaned up until they fall within the window.
- "Free" events are still created as blocker events (so you see them on your work calendar) but marked transparent, so coworkers **can** book over them — they don't reserve the time.
