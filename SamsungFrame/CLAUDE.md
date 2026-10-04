# Samsung Frame TV Module

## Playbook: "upload this photo folder to the Frame"

Amit's standing preference. Do every step below without asking; each is the default, not a question. `HV` = the primary checkout (`dirname "$(git rev-parse --path-format=absolute --git-common-dir)"`); run from the repo root or a worktree that has `config/local.yaml` and a `config/tokens` symlink. `<SRC>` may be a network mount.

1. **Ingest** (resize + filter, resumable): `"$HV/.venv/bin/python" -m SamsungFrame.ingest "<SRC>"`. Writes <=4K JPGs to a job dir under `/tmp/frame-jobs/<name>-<hash>/` (it prints the path as `<JOB>`) and records every non-hidden file in `<JOB>/manifest.json`. Videos, sidecars, thumbnails and files under `min_size_mb` are dropped by name and size without being read; portraits are dropped after the one read each original gets. The source is never modified or copied. If it dies (network blip, killed), rerun the same command: recorded photos are not read again, and unreadable files are retried. Only if Amit asks for portraits: pass `--include-portraits` to this step **and** to `batch_upload` in step 3, which filters portraits again by default.
2. **Dedup** (macOS only): `"$HV/.venv/bin/python" -m SamsungFrame.dedup_photos "<JOB>"`. There is no target fraction: frames closer than `--max-distance` (default 0.4, near-identical) within `--window` seconds (default 600) are duplicates, and the best-scoring frame by Apple's aesthetics score is kept. Reference shots Apple flags as "utility" (signs, plates, receipts, screenshots) are dropped. Every drop and its reason is in the manifest. Survivors are hard-linked into `<JOB>/deduped/`. Skip only if Amit says the folder is already curated; then upload `<JOB>/jpg`.
3. **Upload, in the background, with the long timeout**: `"$HV/.venv/bin/python" -m SamsungFrame.batch_upload "<JOB>/deduped" 2>&1 | tee /tmp/<name>.log` via Bash `run_in_background` with `timeout: 7200000`. Roughly 10s per image, so a 10-minute timeout kills it mid-run. Purge is ON by default and is step 5, so do not pass `--no-purge`. `batch_upload` re-filters the JPGs by `min_size_mb` and by orientation, and a resume needs `--start-index` computed by hand.
4. **Give Amit the tail command the moment the upload starts**, without waiting to be asked (substitute the real log name; `tr` is needed because the progress bar redraws with carriage returns):

   ```bash
   tail -f /tmp/<name>.log | tr '\r' '\n' | grep --line-buffered -E "Uploading images|ERROR|WARNING|Skipped|Complete"
   ```

5. **Cleanup = delete older art**: the end-of-upload purge removes user-uploaded art (`MY_F…` ids) older than 24h, never below `min_images`, never Samsung's pre-installed art. If the upload ran without purge (an interrupted run resumed with `--start-index`, or `--no-purge`), run `manage_samsung.py purge --days 1` once it completes: first with `< /dev/null` (logs the count, deletes nothing), then with `--force`.

Report at the end: files found, ingested, skipped with reasons (the ingest summary line), kept after dedup, uploaded, failed, and how many old items were purged.

Landmines: purge is relative to the TV's `image_date`, so finish a batch (and its purge) the same day or the next day's purge deletes the batch's own earlier uploads. A network `<SRC>` that sleeps or drops mid-ingest is safe to rerun; see [Logbook.md](Logbook.md) for the rest.

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
- `frame_job.py` — job dir (`/tmp/frame-jobs/...`) and the manifest every pipeline stage reads and writes
- `ingest.py` — stage 1: filter by name/size, read each original once, write local <=4K JPGs, manifest saved after every small batch
- `dedup_photos.py` + `vision_features.swift` — stage 2: drop near-duplicates and utility shots from an ingested job (macOS Vision: feature prints, aesthetics score, utility flag; average-linkage clustering); output feeds `batch_upload.py`
- Config keys: `cfg.samsung_frame.ip`, `.port`, `.mac`, `.token_file`, `.default_matte`, `.min_images`, `.min_size_mb`, `.slideshow_delay_seconds`, `.wol_password`, `.smartthings_token`, `.smartthings_device_id`

## TV Art API
Key for this codebase:
- `image_date` available from API — usable for age-based purge directly
- No filename or file hash returned — art already on the TV cannot be deduped; dedup the ingested job first with `dedup_photos.py`
- Art channel only responds when TV is in art mode

## Stability Features
- `ping()` — `art().supported()` as health check
- `get_available_art_strict()` — raises on error (vs `get_available_art()` returns `[]`)
- `_reconnect()` — close + sleep(2) + reconnect
- `_reboot_and_reconnect()` — reboot TV, wait up to 120s for it to power on, then up to 3 connect attempts 5s apart
- Upload loop: 3 consecutive failures → `ensure_art_mode()`; only if that fails, reboot the TV (at most once per run) and reconnect → resume; abort if that fails
- Post-timeout verification: checks TV art list for new IDs when upload returns None/error
- Adaptive pause between uploads: starts at 5s, +5s (max 30s) when the TV needs a cooldown, -1s (min 5s) as it recovers
- `--timeout` CLI param (default 60s) forwarded to `SamsungTVWS`
- Purge is skipped when the upload aborted (fewer images uploaded than discovered); finish the upload, then run `manage_samsung.py purge`

## Purge Logic
- Purge is ON by default; use `--no-purge` to skip
- `get_stale_art_ids()` uses `image_date` from TV API — no local state needed for age
- `min_images` config value is safety cap against deleting everything
- Art with empty `image_date` (very old uploads) treated as stale; only `MY_F` ids are ever considered, so Samsung's pre-installed art is never purged

## CLI Commands
- `batch_upload.py <source_dir>` — `--no-purge`, `--include-portraits`, `--start-index`, `--max-files`, `--timeout`, `--matte`
- `ingest.py <source_dir>` — `--job`, `--include-portraits`, `--workers`
- `dedup_photos.py <job_dir>` — `--window`, `--max-distance`
- `manage_samsung.py status|list-art|list-mattes|delete-all|download-thumbnails|update-mattes|cycle-images|start-slideshow|reboot|purge`

## Testing
- Tests in `test_samsung_client.py`, `test_batch_upload.py`, `test_frame_job.py`, `test_ingest.py` and `test_dedup_photos.py` (Vision smoke test skips off macOS)
- Must patch `SamsungFrame.samsung_client.cfg` (not `get_config`) for module-level config
- `SamsungTVWS` constructor patched via `@patch("SamsungFrame.samsung_client.SamsungTVWS")`
