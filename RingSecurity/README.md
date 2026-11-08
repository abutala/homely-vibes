# RingSecurity

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

Daily health check for Ring devices (doorbells, cameras, chimes).

- **P1 alert** — any device battery below `battery_threshold_pct` (default 25%)
- **P1 alert** — any device offline / unreachable: no wifi signal category, or either the
  signal category or Ring's `connection_status` reads `offline`
- **P1 alert** — the account lists zero devices (a broken fetch, never a healthy house)
- **P0 alert** — Ring auth rejected / re-auth needed
- **P1 alert** — Ring check failed (unexpected error)
- **P-2 ping** — `Ring Cameras: healthy` / `Devices N · Health ok` when every check passes (health = battery and online). Any finding sends only its alert, no ping

One-shot invocation designed for a daily cron. No polling loop, no state file.

## Setup

1. Add credentials to `config/local.yaml`:
   ```yaml
   ring:
     username: your@email.com
     password: your_password
   pushover:
     tokens:
       Ring Security: <your-pushover-app-token>
   ```

2. First-time 2FA login (writes token to `config/tokens/ring_auth_token.json`):
   ```bash
   uv run python RingSecurity/ring_manager.py auth
   ```
   Enter the code Ring sends via SMS/email when prompted.

## Daily run

```bash
uv run python RingSecurity/ring_manager.py check 2>&1 | tee /tmp/ring_check.log
```

Schedule via cron/launchd once per day. Exit code is non-zero on auth failure or generic Ring-check failure (which push P0 and P1 alerts respectively).

## Change a device setting

A dry run by default. Run it from the primary checkout, because the token path is relative. Get the
device id (a `per_device` key) and the setting names from `ring_dump.json`, which
`RingBeams/config_dump.py` writes.

```bash
uv run python RingSecurity/set_device_settings.py <device_id> '{"motion_settings":{"motion_detection_enabled":true}}' 2>&1 | tee /tmp/ring_set.log
```

Add `--apply` to write. It sends a partial `PATCH`, then prints every field that moved, because Ring
can move linked fields too. It fails if a requested value did not take effect, and it refuses a
setting the device does not already have. A list is sent whole and is not checked item by item, so a
bad list is caught only when it is read back, after the write.

## Tests

```bash
uv run python -m pytest RingSecurity -v
```
