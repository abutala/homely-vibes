# Samsung Frame TV Art Manager — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-04-23 — Validated batch upload session

| Date | TV Model | Firmware | Images | Success | Runtime | Notes |
|------|----------|----------|--------|---------|---------|-------|
| 2026-04-23 | QN55LS03FADXZA (55" Frame) | unknown | 474 | 472 (99.6%) | 1h 38m | 2 WebSocket timeout failures; Art API toggled ×2; `ms.channel.timeOut` retry bug fixed same day |

**Observed failure modes (all auto-recovered except where noted):**
- `ms.channel.timeOut` on initial connect → retry with backoff (requires fix in `connect()`)
- Mid-upload WebSocket timeout → 10s cooldown, skip image, continue *(image lost)*
- Art API unresponsive mid-run → `KEY_POWER` toggle, reconnect, resume *(no image loss)*
- `ms.channel.clientDisconnect` response → treated as failure, next image normal

### 2026-10-04 — Trip folder: dedup, then upload

593 photos from a trip (539 HEIC, 47 JPG, 7 PNG, plus 8 MOV and 17 AAE the uploader ignores) thinned to 296 with `dedup_photos.py`, then uploaded with `--no-purge`.

- **Uploader sees fewer than you give it**: of the 296, 251 cleared `min_size_mb`, and 174 were landscape. The 45 small files were dropped at debug log level; the 77 portraits with one INFO line.
- **The folder was 43% portrait** (253 of 593). The Frame is landscape, so the default skip is right, but it makes the real upload count far lower than the file count.
- **Pace**: about 10s per image, so 174 images take roughly 30 minutes. Watch it with `tail -f <log> | tr '\r' '\n'`; the progress bar redraws with carriage returns.
- **Art has no label or caption**: the client sends image bytes and a matte only. Unlabeled, camera-named files (`IMG_1234.jpg`) upload fine and the TV never shows a filename.

---

## Landmines

### Image Validation

Before upload, each image is validated:
1. File exists and is readable
2. Extension matches supported formats
3. File size is within limits
4. PIL can successfully open and verify the image

Invalid images are skipped with logged errors.

### Connection Retry Logic

Connection attempts use exponential backoff:
- Max 3 attempts
- Initial retry delay: 2 seconds
- Delay doubles on each retry (2s, 4s)

### Token Security

- Token file stored at `samsung_frame.token_file` (default `config/tokens/samsung_frame_token.txt`) with 600 permissions (owner read/write only)
- Token automatically saved on first successful pairing
- No credentials stored in code or logs

### Photo Dedup (`dedup_photos.py`)

Choices that took trial to find, so they are not re-litigated:

- **Perceptual hashes (dHash) fail on handheld bursts.** Photos taken seconds apart differed by a median 124 of 256 bits (unrelated images average 128; the 10th percentile was 87), so no threshold separates duplicates from neighbours. Apple Vision feature prints do: adjacent-in-time pairs had median distance 0.6 and a 10th percentile of 0.24. No install needed, but it makes the tool macOS-only.
- **Single linkage chains.** One photo bridging two scenes merges both. With a 300s window, threshold 0.8 collapsed 593 photos to 174 clusters, and with no window to 27. Average linkage inside a time window, plus a `--max-distance` cap, keeps clusters tight.
- **A fixed target fraction is the wrong control.** Forcing 50% needed an average merge distance of 0.58, which merges the same place with different people; it also kept every reference shot. The distance limit is now the only control (default 0.4), so a folder keeps whatever is genuinely different. On one 332-photo trip folder, limits of 0.3 / 0.4 / 0.5 kept 278 / 242 / 199, against 166 for a forced 50%.
- **Pick the best frame with Apple's aesthetics score, not sharpness.** Laplacian variance favours harsh contrast and HDR-looking frames, and the two picks differed in 30 of 49 multi-photo clusters; on a sampled sheet the aesthetics pick was the better composed frame (a visual check, not a blind test). Sharpness now only breaks ties.
- **Apple's "utility" flag finds reference shots.** It flagged 8 photos on that trip (car wheels and bumpers, licence plates, park signs, a napkin on a tray) and all 8 were reference shots that do not belong on a TV, so they are dropped and recorded as such. It is Apple's model, so an odd miss in either direction is possible; the manifest lists every drop.
- **Landscape beats portrait** within a cluster by a small aesthetics bonus. Ingest already drops portraits by default, so this only matters with `--include-portraits`.

### Fresh Worktrees Have No Token Dir

`config/tokens` is gitignored, so a fresh worktree does not carry it, and the uploader would find no token file and start a new TV pairing prompt. Symlink it before running from a worktree:

```bash
ln -s ~/bin/Common-configs/tokens config/tokens
```

### Ingest and the Job Dir

- **A network folder is read once per candidate original.** Name and size filtering costs no bytes, but a portrait is only recognisable after its file is read (HEIC metadata is not reliably in the first bytes), so portrait originals still cross the network once. Each candidate is read whole into memory and decoded from there, which avoids the many small seeks a decode straight off an SMB mount makes.
- **State is scratch under `/tmp/frame-jobs`**, keyed by folder name plus a hash of the full path so two `Trip` folders never share a job. It survives a killed script, a dropped TV or a network blip; macOS clears `/tmp` on reboot and after a few idle days, and the stages then redo their work.
- **Name and size skips are recomputed every run and never cached**, otherwise a file that was too small once (or a video renamed) would stay skipped after it changed. Only content-derived skips (portrait, unreadable) are cached, and unreadable ones always retry.
- **The size floor applies to the original only**, so a 4K JPG is never filtered by size a second time and a low-detail photo is not silently dropped before upload.

### The Staged Pipeline (what replaced `batch_upload.py`)

`batch_upload.py` did discovery, conversion, upload, an age-based purge, the slideshow and the notification in one run with no memory, so every failure meant hand-computed `--start-index` retries, a notification that described only the last attempt, and a purge keyed to "older than 24h". The decisions behind the replacement, so they are not re-litigated:

- **State is a manifest, stages are separate scripts.** Any stage can be rerun alone and resumes. The driver only orders them and sends the notification.
- **Cleanup deletes a recorded snapshot, not an age.** Stage 3 records the TV's user photos before its first upload; stage 4 deletes exactly those. An age cut-off breaks on a retry the next day (it deletes yesterday's half-uploaded batch) and on photos with no date.
- **The minimum-photo floor stays.** If fewer than `min_images` would remain, the newest old photos are retained. Nothing is deleted unless every kept photo is on the TV (the TV is checked, not just the manifest).
- **Unnamed uploads are expected.** The existing upload loop recovers a timed-out upload by diffing the TV's art list, but when that list read also times out the photo arrives with no recorded id. Such photos are listed as "unnamed", counted in the slideshow check, never deleted, and a rerun of that file duplicates it. Seen once (one of 86 in a top-up), and the TV offers no way to map a name.
- **The notification reads the manifest.** Its totals cover every attempt; the old one reported only the last run (116 of 174) and was sent before the slideshow step, so a failure there still read "Complete".
- **Dropped without a replacement:** `--start-index` and `--max-files` (a resume is just a rerun), the 24h purge inside the upload run, tracking by upload order, and the direct copy of JPG/PNG sources (ingest re-encodes every photo to a <=4K JPG, stepping quality down from 90 until the file fits `max_image_size_mb`).
- **Removed on purpose:** nothing that decides which photos reach the TV lives in the uploader any more; ingest and dedup decide, the manifest records.

### Dedup Scaling

`dedup_photos.py` holds a dense n×n distance matrix and scans it once per merge, so cost grows roughly with n³. A few hundred photos take seconds; a folder of several thousand needs splitting first.

### Slideshow Behavior

The interval is set by `start-slideshow --duration` (minutes, default 3) and the pipeline's slideshow stage uses `--duration` (default 3) with shuffle on. The TV then cycles on its own after the command exits.

---

## Error reference

### Cannot Connect to TV

**Symptoms**: `Failed to connect to TV at 192.168.x.x`

**Solutions**:
- Verify TV is powered on (not fully off)
- Check TV is on same network as computer running script
- Verify IP address in `config/local.yaml` (samsung_frame.ip) is correct
- Check firewall isn't blocking port 8002

### Authentication Failed

**Symptoms**: Connection works but commands fail with auth errors

**Solutions**:
- Delete token file: `rm config/tokens/samsung_frame_token.txt`
- Run status command again and accept pairing prompt on TV
- Ensure token file has correct permissions (600)

### Image Upload Fails

**Symptoms**: Some or all images fail to upload

**Common causes**:
- **Unsupported format**: Only JPG and PNG supported
- **File too large**: Images must be < 10MB
- **Corrupted file**: File cannot be opened by PIL
- **Network timeout**: TV connection unstable

**Check logs** for specific error messages about failed images.

### Art Mode Not Supported

**Symptoms**: `Art mode: Not supported or unavailable`

**Solutions**:
- Verify you have a Samsung Frame TV (or other model with art mode)
- Ensure TV firmware is up to date
- Try restarting the TV

### Token File Permissions

If you see permission errors, ensure token file has restrictive permissions:

```bash
chmod 600 config/tokens/samsung_frame_token.txt
```
