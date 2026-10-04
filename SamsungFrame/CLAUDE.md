# Samsung Frame TV Module

## Playbook: "upload this photo folder to the Frame"

Amit's standing preference. Do all four steps without asking; each is the default, not a question. `HV` = the primary checkout (`dirname "$(git rev-parse --path-format=absolute --git-common-dir)"`); run from the repo root or a worktree that has `config/local.yaml` and a `config/tokens` symlink.

1. **Resize + dedup** (macOS only): `"$HV/.venv/bin/python" -m SamsungFrame.dedup_photos "<SRC>"`. Downsizes to 4K JPG, keeps ~50% (`--keep`), writes `"<SRC> - dedup"`. The source is never modified. Skip only if Amit says the folder is already curated.
2. **Upload, in the background, with the long timeout**: `"$HV/.venv/bin/python" -m SamsungFrame.batch_upload "<SRC> - dedup" 2>&1 | tee /tmp/<name>.log` via Bash `run_in_background` with `timeout: 7200000`. Roughly 10s per image, so a 10-minute timeout kills it mid-run. Purge is ON by default and is step 4, so do not pass `--no-purge`.
3. **Give Amit the tail command the moment the upload starts**, without waiting to be asked (substitute the real log name; `tr` is needed because the progress bar redraws with carriage returns):

   ```bash
   tail -f /tmp/<name>.log | tr '\r' '\n' | grep --line-buffered -E "Uploading images|ERROR|WARNING|Skipped|Complete"
   ```

4. **Cleanup = delete older art**: the end-of-upload purge removes user-uploaded art (`MY_F…` ids) older than 24h, never below `min_images`, never Samsung's pre-installed art. If the upload ran without purge (an interrupted run resumed with `--start-index`, or `--no-purge`), run `manage_samsung.py purge --days 1` once it completes: first with `< /dev/null` (logs the count, deletes nothing), then with `--force`.

Report at the end: files found, uploaded, skipped (portraits, files under `min_size_mb`), failed, and how many old items were purged.

Landmines: purge is relative to the TV's `image_date`, so finish a batch (and its purge) the same day or the next day's purge deletes the batch's own earlier uploads. `batch_upload` silently skips portraits and files under `min_size_mb`; see [Logbook.md](Logbook.md).

## Bootstrap — Centralized Connection
**All code MUST use `connect_ready()` or the context manager to connect.** Never call bare `connect()`.

```python
# Context manager (preferred for CLI handlers):
with SamsungFrameClient() as client:
    client.get_available_art()
# Calls connect_ready() on enter, close() on exit. Raises ConnectionError on failure.

# Manual (for long-running ops like batch_upload that need mid-operation reconnect):
client = SamsungFrameClient()
client.connect_ready()  # WoL + SmartThings + connect + art mode
# ... mid-operation reconnect:
client.close()
client.connect_ready()  # Same full bootstrap path
```

`connect_ready()` flow: fire WoL + SmartThings → try connect → check REST standby → wait for power → connect → ensure art mode. Config is read automatically — never hardcode IPs.

## Architecture
- `samsung_client.py` — WebSocket client wrapping `samsungtvws` (NickWaterton fork v3.0.5)
- `batch_upload.py` — Two-phase upload workflow (prepare temp dir -> upload)
- `manage_samsung.py` — CLI entry point with subcommands
- `dedup_photos.py` + `feature_prints.swift` — thin a photo folder to ~N% (macOS Vision embeddings, average-linkage clustering); output feeds `batch_upload.py`
- Config keys: `cfg.samsung_frame.ip`, `.port`, `.mac`, `.token_file`, `.default_matte`, `.min_images`, `.min_size_mb`, `.slideshow_delay_seconds`, `.wol_password`, `.smartthings_token`, `.smartthings_device_id`

## TV Art API
Key for this codebase:
- `image_date` available from API — usable for age-based purge directly
- No filename or file hash returned — art already on the TV cannot be deduped; dedup the source folder first with `dedup_photos.py`
- Art channel only responds when TV is in art mode

## Stability Features
- `ping()` — `art().supported()` as health check
- `get_available_art_strict()` — raises on error (vs `get_available_art()` returns `[]`)
- `_reconnect()` — close + sleep(2) + reconnect
- `_reboot_and_reconnect()` — reboot TV + exponential backoff (30s→5min, 5 attempts) + reconnect
- Upload loop: 3 consecutive failures → reboot TV → backoff reconnect → resume; abort if reboot fails
- Post-timeout verification: checks TV art list for new IDs when upload returns None/error
- 5s pause between uploads for TV stability
- `--timeout` CLI param (default 60s) forwarded to `SamsungTVWS`
- Purge runs even after upload abort (reconnects if needed)

## Purge Logic
- Purge is ON by default; use `--no-purge` to skip
- `get_stale_art_ids()` uses `image_date` from TV API — no local state needed for age
- `min_images` config value is safety cap against deleting everything
- Art with empty `image_date` (very old uploads) treated as stale; only `MY_F` ids are ever considered, so Samsung's pre-installed art is never purged

## CLI Commands
- `batch_upload.py <source_dir>` — `--no-purge`, `--include-portraits`, `--start-index`, `--max-files`, `--timeout`, `--matte`
- `dedup_photos.py <source_dir>` — `--keep`, `--window`, `--max-distance`, `--out`, `--work-dir`
- `manage_samsung.py status|list-art|list-mattes|delete-all|download-thumbnails|update-mattes|cycle-images|start-slideshow|reboot|purge`

## Testing
- Tests in `test_samsung_client.py`, `test_batch_upload.py` and `test_dedup_photos.py` (Vision smoke test skips off macOS)
- Must patch `SamsungFrame.samsung_client.cfg` (not `get_config`) for module-level config
- `SamsungTVWS` constructor patched via `@patch("SamsungFrame.samsung_client.SamsungTVWS")`
