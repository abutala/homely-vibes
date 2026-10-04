# Samsung Frame TV Module

## Playbook: "upload this photo folder to the Frame"

Amit's standing preference. Do every step below without asking; each is the default, not a question. `HV` = the primary checkout (`dirname "$(git rev-parse --path-format=absolute --git-common-dir)"`); run from the repo root or a worktree that has `config/local.yaml` and a `config/tokens` symlink. `<SRC>` may be a network mount.

1. **Run the pipeline in the background with the long timeout**: `"$HV/.venv/bin/python" -m SamsungFrame.frame_run "<SRC>" 2>&1 | tee /tmp/<name>.log` via Bash `run_in_background` with `timeout: 7200000` (a 10-minute timeout once killed an upload mid-run). It runs ingest, dedup, upload, cleanup of the old catalog and slideshow, in that order, and stops at the first stage that fails. Each stage is described in [README.md](README.md).
2. **Give Amit the tail command the moment it starts**, without waiting to be asked (substitute the real log name; `tr` is needed because the progress bar redraws with carriage returns):

   ```bash
   tail -f /tmp/<name>.log | tr '\r' '\n' | grep --line-buffered -E "=== |Ingested|Uploading images|ERROR|WARNING|Slideshow|Notification sent"
   ```

3. **If it stops, rerun the same command.** Every stage resumes from the manifest in the job dir (`/tmp/frame-jobs/<name>-<hash>/`, printed as `Job:` by ingest), and the upload stage already retries itself 3 times. Never compute start indexes or delete photos by hand. To resume or inspect one stage on its own: `"$HV/.venv/bin/python" -m SamsungFrame.<stage> "<JOB>"` with `ingest` (takes `<SRC>` too), `dedup_photos`, `frame_upload`, `frame_cleanup`, `frame_slideshow`.
4. **Report from the run's single Pushover / the manifest**: skipped and dropped by reason, uploaded of kept, old photos removed and retained, and whether the slideshow was verified. A non-zero exit or "Slideshow NOT verified" means it is NOT done: say so, do not report done.

Knobs, only when Amit asks: `--include-portraits`; `--no-dedup` with a fresh `--job` (a curated folder); `--max-distance` (lower keeps more photos); `--max-photos N` (after dedup, keep the best of each stretch of the album, N in all); `--no-cleanup` (keep the photos already on the TV); `--duration` (minutes per photo).

Landmines, the things a rerun will not tell you:

- **A full run deletes the old catalog.** Preview it with `"$HV/.venv/bin/python" -m SamsungFrame.frame_cleanup "<JOB>" --dry-run` (needs the upload stage to have finished). Never run the pipeline or cleanup against Amit's TV as a test: it removes his existing photos down to the `min_images` floor. Test with a tiny folder and `--no-cleanup`, and remove only what the manifest's `uploaded` ids name.
- **The TV cannot map a file name to a photo.** After a timeout an upload can arrive that the script cannot name (reported as "unnamed": kept, never deleted), and rerunning that file adds a duplicate. Rare, expected, and not fixable by name.
- **Order matters.** Cleanup runs before the slideshow and the slideshow is verified last, because deleting art after the slideshow starts leaves a stale playlist and no autoplay. A passing upload and cleanup do not prove the slideshow plays; only the read-back does.
- **`/tmp` jobs are scratch.** They survive a killed script, a dropped TV and a network blip. macOS clears `/tmp` on reboot and after a few idle days; a fresh run then uploads everything again and its cleanup removes the earlier copies (except any the `min_images` floor keeps, which stay as duplicates), so nothing is lost, it is just slower.
- **A sleeping or dropped network mount** fails ingest for the unreadable files only; rerun. Portrait originals are read once before they are dropped, so they still cost network time.
- **A failing Pushover never fails the run.** Read the log and the manifest instead.
- **`manage_samsung.py purge --days N` is a manual, age-based tool** and is not part of the pipeline; `delete-all` removes every user photo.
- When something unexpected happens, read [Logbook.md](Logbook.md) first, and add the new landmine there and here.

## Bootstrap — Centralized Connection
**All code MUST use `connect_ready()` or the context manager to connect.** Never call bare `connect()`.

```python
# Context manager (preferred for CLI handlers):
with SamsungFrameClient() as client:
    client.get_available_art()
# Calls connect_ready() on enter, close() on exit. Raises ConnectionError on failure.

# Manual (for long-running ops like the upload stage that need mid-operation reconnect):
client = SamsungFrameClient()
client.connect_ready()  # WoL + SmartThings + connect + art mode
# ... mid-operation reconnect:
client.close()
client.connect_ready()  # Same full bootstrap path
```

`connect_ready()` flow: fire WoL + SmartThings → try connect → check REST standby → wait for power → connect → ensure art mode. Config is read automatically — never hardcode IPs.

## Architecture
- `samsung_client.py` — WebSocket client wrapping `samsungtvws` (NickWaterton fork v3.0.5)
- `manage_samsung.py` — CLI entry point with subcommands
- `frame_job.py` — job dir (`/tmp/frame-jobs/...`) and the manifest every pipeline stage reads and writes
- `ingest.py` — stage 1: filter by name/size, read each original once, write local <=4K JPGs, manifest saved after every small batch
- `frame_album.py` + `album_queue.py` — the monthly album: a queue of library albums (`index.tsv`), which pictures of an album to show (labelled files, else its picks CSV, else dedup, which writes that CSV into the album folder), skip-if-small, split-if-big, then `frame_run` with cleanup on. Usage and rules: README, "A New Album Every Month"
- `frame_run.py` — the driver: runs the stages as separate processes, retries the upload stage, sends one Pushover built from the manifest
- `frame_upload.py` / `frame_cleanup.py` / `frame_slideshow.py` — stages 3 to 5: checkpointed upload, snapshot-based cleanup with the minimum-photo floor, slideshow with read-back verification
- `dedup_photos.py` + `vision_features.swift` — stage 2: drop near-duplicates and utility shots from an ingested job (macOS Vision: feature prints, aesthetics score, utility flag; average-linkage clustering); output feeds `frame_upload.py`
- Config keys (read once into `client.cfg`; there is no module-level config): `cfg.samsung_frame.ip`, `.port`, `.mac`, `.token_file`, `.default_matte`, `.min_images`, `.min_size_mb`, `.max_image_size_mb`, `.slideshow_delay_seconds`, `.albums.*` (the album queue), `.wol_password`, `.smartthings_token`, `.smartthings_device_id`

## TV Art API
Key for this codebase:
- `image_date` available from API — used to order old photos for the minimum-photo floor and by the manual age-based purge. It is the TV's local wall-clock time with no zone (measured against a fresh upload), so it is compared with naive local time, never UTC
- No filename or file hash returned — art already on the TV cannot be deduped; dedup the ingested job first with `dedup_photos.py`
- Art channel only responds when TV is in art mode

## Stability Features
- `ping()` — `art().supported()` as health check
- `get_available_art_strict()` — raises on error (vs `get_available_art()` returns `[]`)
- `_reconnect()` — close + sleep(2) + reconnect
- `reboot_and_reconnect()` — reboot TV, wait up to 120s for it to power on, then up to 3 connect attempts 5s apart
- Upload loop: a successful upload is followed only by the pause, with no health check (the TV has just answered). A failed one → `ensure_art_mode()`; only if that fails, reboot the TV (at most once per run) and reconnect → resume; stop if that fails. A TV that stays in art mode never stops the run: each failed image is recorded and the next is tried
- An error raised by the per-image checkpoint callback propagates and stops the run
- Post-timeout verification: when an upload returns nothing, the TV art list is read and the image counts as uploaded only if exactly one new id appeared
- Adaptive pause between uploads: starts at 5s, +5s (max 30s) when the TV needs a cooldown, -1s (min 5s) as it recovers
- `--timeout` CLI param (default 60s) forwarded to `SamsungTVWS`

## Cleanup Logic
- Stage 3 records the TV's user photos (`MY_F` ids and `image_date`) in the manifest before its first upload; stage 4 deletes exactly those that are still on the TV, never "older than N hours"
- Floor: if fewer than `min_images` photos would remain, the newest old photos by `image_date` are retained (an empty date counts as oldest)
- Refuses unless the snapshot exists, every kept photo is recorded as uploaded and is on the TV, at least one new photo is on the TV, and no id is both old and new; only `MY_F` ids are ever candidates, so Samsung's pre-installed art is never deleted
- Deletes that fail are retried by rerunning: the plan is recomputed from the TV each time
- `manage_samsung.py purge --days N` is the separate manual tool: `plan_purge()` takes user art older than N days by `image_date`, oldest first, and never goes below `min_images`; not used by the pipeline

## CLI Commands
- `frame_run.py <source_dir>` — `--job`, `--include-portraits`, `--no-dedup`, `--window`, `--max-distance`, `--max-photos`, `--upload-attempts`, `--no-cleanup`, `--duration`, `--no-notify`
- `ingest.py <source_dir>` — `--job`, `--include-portraits`, `--workers`
- `dedup_photos.py <job_dir>` — `--window`, `--max-distance`, `--max-photos`
- `frame_upload.py <job_dir>` — `--matte`, `--timeout`
- `frame_cleanup.py <job_dir>` — `--dry-run`, `--min-images`, `--timeout`
- `frame_slideshow.py <job_dir>` — `--duration`, `--no-shuffle`, `--timeout`
- `frame_album.py run|scan|classify|shuffle|table` — `run --scheduled` does nothing unless today is a first Monday; `scan --full` recounts every album
- `manage_samsung.py status|list-art|list-mattes|delete-all|download-thumbnails|update-mattes|cycle-images|start-slideshow|reboot|purge`

## Testing
- Tests in `test_samsung_client.py`, `test_manage_samsung.py`, `test_frame_job.py`, `test_ingest.py`, `test_dedup_photos.py`, `test_frame_upload.py`, `test_frame_cleanup.py`, `test_frame_slideshow.py`, `test_frame_run.py`, `test_album_queue.py` and `test_frame_album.py` (real-Vision tests skip off macOS). Stage tests pass hand-written fake TV clients into the stage functions: no `patch()`
- No test uses `patch()`. The client takes its config and a `TvIo` (TV constructor, REST client, HTTP post, UDP socket, sleep) as parameters; `test_samsung_client.py` passes fakes for those and uses the `Scripted` subclass to answer the client's own methods (`connect`, `ensure_art_mode`, ...) from a script. `manage_samsung.run_command` takes a client factory, and the confirm prompts take an `ask` callable
