# RachioFlume — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

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
