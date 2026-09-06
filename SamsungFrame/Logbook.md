# Samsung Frame TV Art Manager — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Incidents

### 2026-04-23 — Validated batch upload session

Cross-reference with `~/bin/_claude/shared-memory/skills/samsung.md` for full protocol notes.

| Date | TV Model | Firmware | Images | Success | Runtime | Notes |
|------|----------|----------|--------|---------|---------|-------|
| 2026-04-23 | QN55LS03FADXZA (55" Frame) | unknown | 474 | 472 (99.6%) | 1h 38m | 2 WebSocket timeout failures; Art API toggled ×2; `ms.channel.timeOut` retry bug fixed same day |

**Observed failure modes (all auto-recovered except where noted):**
- `ms.channel.timeOut` on initial connect → retry with backoff (requires fix in `connect()`)
- Mid-upload WebSocket timeout → 10s cooldown, skip image, continue *(image lost)*
- Art API unresponsive mid-run → `KEY_POWER` toggle, reconnect, resume *(no image loss)*
- `ms.channel.clientDisconnect` response → treated as failure, next image normal

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

### Slideshow Behavior

The slideshow uses the TV's configured rotation interval (fastest available). The interval cannot be customized via the API - adjust it directly on the TV's art mode settings.

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
- Delete token file: `rm lib/tokens/samsung_frame_token.txt`
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
chmod 600 lib/tokens/samsung_frame_token.txt
```
