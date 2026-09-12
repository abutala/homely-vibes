# RachioFlume — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-09-12 — the weekly report showed Z9 watering for three days

The 2026-09-05 → 09-12 report listed Z9 at 4336 minutes. It ran for eight minutes
on 2026-09-08, as the Rachio app said. Our DB was missing Z9's `ZONE_COMPLETED`.

- **The lost event.** Each poll asked Rachio for exactly `[last poll, now]`. The
  07:03:02 COMPLETED was not yet published when the 07:03:19 poll ran, and the next
  poll's window began after it, so nothing ever asked again. Rachio's API still
  returns the event.
- **The amplifier.** `compute_zone_sessions` paired a START with the next end event
  for that zone however far away. One lost end became a three-day session that
  absorbed three days of whole-house Flume usage. Earlier weeks had carried the same
  failure at a week long.
- **The quieter loss beside it.** Flume's newest minute or two read short at poll
  time. Back-to-back windows plus a "newer than `MAX(timestamp)`" filter froze those
  short values, so every irrigation run was undercounted.
- **The signal that would have caught it was hidden.** The report's `Alrt` column
  read `avg_flow_rate` off per-session rows, a name only the aggregate query
  produces (`AVG(average_flow_rate) AS avg_flow_rate`). Controller zones never
  showed an alert count, even while runs crossed their thresholds.

Fix: every poll re-fetches `FETCH_OVERLAP` of both feeds; events dedup on a unique
key and readings upsert. A START is now closed by the next controller event, since
the controller runs one zone at a time. When that event isn't the zone's own end,
the end was lost and is read off Flume flow: contiguous flow from the START, one dry
minute tolerated, capped. A run with no visible flow is kept as zero-length rather
than dropped, because the stale-zone monitor reads `MAX(start_time)` from sessions.

Prod repair: re-fetched Rachio's event history and inserted the missing rows. The
collector rebuilds sessions from events every cycle, so reports healed on the next
poll, and the report was re-sent. One end (Z11, 2026-08-12) is missing from Rachio's
API too, during a Flume data gap the same morning; only the estimate covers it.

### Deployment runbook — the one-time `rachio_flume.alerts` schema migration

This is the ritual that landed the structured `rachio_flume.alerts` config on
the Linux prod host. It is a record of that migration, not a procedure to
repeat on every deploy.

Production lives on the Linux prod host. The collector runs from cron's `@reboot` wrapped in
`run-one-constantly` (auto-restarts on exit), so deploying new code is a
staged ritual.

Before any production deploy that changes the `rachio_flume.alerts` schema,
**migrate the prod host's `local.yaml` first**. The new structured-config loader is
strict — an outdated schema crashes on startup.

```bash
# 1) Backup the prod host's local.yaml (gitignored, host-specific)
ssh <user>@<prod-host> 'cp ~/bin/Common-configs/Code_config_local.yaml \
    ~/bin/Common-configs/Code_config_local.yaml.bak-$(date +%Y%m%d-%H%M%S)'

# 2) Migrate the rachio_flume block to the new shape — easiest is:
#    a. scp it down, edit locally, scp back
#    b. or edit in place via ssh + python script
scp <user>@<prod-host>:~/bin/Common-configs/Code_config_local.yaml /tmp/prod_local.yaml
# (edit /tmp/prod_local.yaml to match new schema — keep host-specific blocks like node_check, prod_controller unchanged)
scp /tmp/prod_local.yaml <user>@<prod-host>:~/bin/Common-configs/Code_config_local.yaml

# 3) Pull new code on the prod host
ssh <user>@<prod-host> 'cd ~/Code && git fetch origin && git pull origin main'

# 4) Verify new config loads cleanly before restart
ssh <user>@<prod-host> 'cd ~/Code && uv run python -c "
from lib.config import reset_config, get_config; reset_config()
cfg = get_config()
print(\"zone_anomaly:\", cfg.rachio_flume.alerts.zone_anomaly.absolute_gpm)
print(\"flow rules:\", [r.name for r in cfg.rachio_flume.alerts.default_flow_rules])
print(\"stale days:\", cfg.rachio_flume.alerts.stale_zone_days)
"'

# 5) Kill the python collector process; run-one-constantly auto-restarts with new code
ssh <user>@<prod-host> 'pkill -f ".venv/bin/python3 RachioFlume/rfmanager.py"'
sleep 12
ssh <user>@<prod-host> 'ps auxf | grep ".venv/bin/python3 RachioFlume/rfmanager.py" | grep -v grep'

# 6) Tail logs to confirm a clean cycle
ssh <user>@<prod-host> 'tail -25 ~/logs/rfmanager.py.log' 2>&1 | tee /tmp/rfmanager-deploy.log
```

The first post-restart cycle should show: zones saved, Flume readings
saved, hose-timer valves listed (if any), and (if any zones are stale
beyond the threshold) the very first `Stale-zone alert sent: ...` message
— that's expected on new code or fresh DB.

---

## Landmines

### Never poll a back-to-back window from an API that publishes late

Rachio and Flume both publish late. A `[last poll, now]` window loses anything that
lands after the poll that covered its timestamp, and a "newer than what's stored"
filter turns a value that hadn't settled yet into a permanent one. Re-fetch an
overlap and let the table's unique key dedup: ignore for events, which never change,
upsert for readings, which settle.

### Zone baselines are measurements of the ingestion, not of the pipes

Per-zone `avg_gpm` baselines were tuned on readings that undercounted flow. Any change
to how readings are ingested moves every zone's measured GPM, and with it which runs
cross the P2 anomaly threshold. Re-derive baselines against the new ingestion before
deploying it, or normal runs page as anomalies.

### The minute in progress reads short, so never count it

At poll time Flume reports the current minute at a fraction of its real flow; the
minute before it has already settled. Anything that reads a trailing window ending at
"now" must drop that minute: sustained-flow rules, the zone-end estimate, the status
rate. Counting it pulled the mean down and inflated CV past the tight caps, so Pipe
Break and High Flow almost never matched live and household Mid Flow draws never did.
Hose runs are totalled once their last minute has closed rather than dropping it,
because that minute is part of the run.

### Hose threshold keys must survive a prefix change

Config keys and Rachio's valve names both carry a zone prefix, and prefixes drift.
Z13's key said "Z13 FS - ..." while Rachio reported "Z13 BUD - ...", so the valve ran
with no baseline in the alert path and the report alike, for as long as the logs go
back. Matching compares the valve's own name (after " - ") on both sides, exact match
first, and the report uses the same resolver as the alert path. Two valves sharing an
own name under different prefixes would be ambiguous; the resolver warns and takes
the first.

### The CV variance gate is what keeps the low-flow rules quiet

**Final detector logic for sustained-flow rules** — implemented in
[`AlertEngine._rule_matches`](alert_engine.py). A rule fires when both
conditions hold across the trailing `duration_minutes` window:

1. **Mean test** — `mean(values) ≥ rule.min_gpm`.
2. **CV variance gate** — `cv = stddev / mean ≤ max_cv(rule.min_gpm)`,
   where `max_cv = clip(0.5 − 0.04 × min_gpm, 0.15, 0.5)`. Rejects
   spiky windows where a handful of high readings drag the mean up
   past threshold but the rest are zero — Flume sensor noise has a
   larger relative footprint at low GPM, so low-threshold rules
   (Leak at 0.1 GPM) get a tighter CV cap than high-threshold rules
   (Pipe Break at 8 GPM).

Tradeoff: an *intermittent* leak (e.g. a joint that pulses) where most
per-minute readings are zero will fail the CV gate and stay silent.
This is a deliberate choice: we tried removing the CV gate on this
branch (commits a672f9c → 652bb31 in PR #201) and a 7-day replay
showed 6 Leak fires/week of ambiguous origin. Restored the gate;
the proper fix for true intermittent leaks is to lower the per-rule
`duration_minutes` so a shorter window can fully encompass each
pulse, rather than weaken the noise rejection.

### An alert that is routinely ignored is not an alert

The stale-zone monitor's 10 → 15 day / P1 → P2 retune is one change, not two:
at 10 days the alert fired often enough on ordinary seasonal gaps to be
ignored, and an alert that is routinely ignored is not an alert. Widening the
window is what makes the louder priority correct rather than merely louder.

### Config keys follow what the API surfaces, not what reads nicely

**Config key convention**: Controllers key by stringified `zone_number`
(`"1"`, `"2"`, …) because that's what the Rachio API surfaces per run.
Hose valves key by their raw API name (e.g. `"Z13 FS - Upper Deck Planters"`)
for the same reason — the hose API has no zone number. Display strings for
both come from `compact_zone_label()` (splits on `" - "` and takes the head),
so `"Z13 FS - Upper Deck Planters"` shows as `"Z13 FS"` in the email and
Pushover header. No separate `name:` field in config.
