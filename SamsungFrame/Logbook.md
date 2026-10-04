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

- Token file stored in `~/logs/` with 600 permissions (owner read/write only)
- Token automatically saved on first successful pairing
- No credentials stored in code or logs

### Photo Dedup (`dedup_photos.py`)

Choices that took trial to find, so they are not re-litigated:

- **Perceptual hashes (dHash) fail on handheld bursts.** Photos taken seconds apart differed by a median 124 of 256 bits (unrelated images average 128; the 10th percentile was 87), so no threshold separates duplicates from neighbours. Apple Vision feature prints do: adjacent-in-time pairs had median distance 0.6 and a 10th percentile of 0.24. No install needed, but it makes the tool macOS-only.
- **Single linkage chains.** One photo bridging two scenes merges both. With a 300s window, threshold 0.8 collapsed 593 photos to 174 clusters, and with no window to 27. Average linkage inside a time window, plus a `--max-distance` cap, keeps clusters tight.
- **A wider window merges less distant things.** Reaching 50% took an average merge distance of 0.58 with a 600s window but 0.73 with 120s, because the larger window offers more close pairs to merge first.
- **Sharpness is a tie-breaker, not a quality score.** Laplacian variance favours harsh contrast and HDR-looking frames, so it is only meaningful between frames of the same cluster.
- **50% means "same scene", not "exact duplicate".** Frames of the same spot with different people can be dropped. Raise `--keep` if that matters more than a short slideshow.
- **Landscape beats portrait** within a cluster (unless the portrait is 2x sharper), because `batch_upload.py` skips portraits by default and the scene would otherwise vanish from the TV.

### Fresh Worktrees Have No Token Dir

`config/tokens` is gitignored, so a fresh worktree does not carry it, and the uploader would find no token file and start a new TV pairing prompt. Symlink it before running from a worktree:

```bash
ln -s ~/bin/Common-configs/tokens config/tokens
```

### Purge After the Slideshow Started Leaves No Autoplay

After a `--no-purge` upload and a separate `purge`, the TV did not start cycling although the upload log said "Slideshow started". Re-running `start-slideshow` fixed it and the TV then read back a playlist of exactly the uploaded photos. Deleting art after the slideshow is configured is the likely cause (not proven; the playlist was not read before the restart). `batch_upload` is unaffected because it purges first and starts the slideshow after. Both `batch_upload` and `start-slideshow` now read the slideshow back from the TV and fail when it does not match.

### Dedup Scaling

`dedup_photos.py` holds a dense n×n distance matrix and scans it once per merge, so cost grows roughly with n³. A few hundred photos take seconds; a folder of several thousand needs splitting first.

### Slideshow Behavior

The interval is set by `start-slideshow --duration` (minutes, default 3) and `batch_upload` always uses 3 minutes with shuffle on. The TV then cycles on its own after the command exits.

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
