# Samsung Frame TV Art Manager

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

A Python client for managing art mode on Samsung Frame TVs. Upload images, configure display settings, and control slideshow playback remotely.

## Features

- **One-command pipeline**: `frame_run.py` ingests, dedups, uploads, removes the old catalog, starts and verifies the slideshow, and sends one Pushover
- **Ingest + Photo Dedup**: `ingest.py` turns a local or network folder (HEIC, JPG, PNG; recursive) into checkpointed <=4K JPGs; `dedup_photos.py` drops near-duplicates and reference shots (signs, plates, receipts), keeping the best-scored frame of each cluster
- **Checkpointed upload**: every image is recorded the moment the TV has it, filenames are capped to 50 characters, and a rerun uploads only what is missing
- **Safe cleanup**: deletes exactly the photos that were on the TV before the batch, never below a minimum photo count, and only once the whole batch is on the TV
- **Verified slideshow**: reads the slideshow back from the TV (art mode, category, interval, shuffle, playlist) and fails if it is not really playing
- **Connection Health Checks**: After a failed upload the client restores art mode, reboots the TV only if that fails (at most once per run), and stops only if that fails too
- **Matte Configuration**: Apply black borders (or other matte styles) to uploaded images
- **Art Mode Control**: Enable art mode and start automatic slideshow
- **TV Status**: Check connection and art mode support
- **Art Inventory**: List all available art on TV
- **Pushover Notifications**: Get notified of upload results and errors
- **Token-based Authentication**: Secure WebSocket connection with persistent token storage

## Setup

### Configuration

Add your Samsung Frame TV settings to `config/local.yaml`:

```yaml
samsung_frame:
  ip: "192.168.XX.YY"  # Your TV's IP address
  port: 8002  # WebSocket port (default: 8002)
  token_file: config/tokens/samsung_frame_token.txt
  default_matte: shadowbox_black  # Black border style
  supported_formats: [jpg, jpeg, png]
  max_image_size_mb: 10

# Add to pushover tokens for notifications
pushover:
  tokens:
    SamsungFrame: your-pushover-token
```

### Installation

Install dependencies from the project root:

```bash
uv sync
```

### First-Time Authentication

On first run, any command that connects to the TV will display a pairing prompt:

```bash
# Option 1: Use status command to pair without uploading
uv run python SamsungFrame/manage_samsung.py status

# Option 2: Pair during the first pipeline run
uv run python -m SamsungFrame.frame_run /path/to/images
```

**Pairing Steps:**
1. Run any command that connects to TV (status, the pipeline, list-art, etc.)
2. Check your TV screen for the pairing prompt
3. Accept the connection on your TV
4. The authentication token will be automatically saved to `config samsung_frame.token_file`
5. Subsequent operations will use the saved token without requiring TV approval

**To re-pair:** Delete the token file and run any connection command:

```bash
rm config/tokens/samsung_frame_token.txt
uv run python SamsungFrame/manage_samsung.py status
```

## Usage

All commands should be run from the project root directory.

### Upload a Photo Folder (the pipeline)

One command takes a folder of photos (a local folder or a network mount) to a verified slideshow on the TV:

```bash
# Ingest, dedup, upload, remove the old catalog, start and verify the slideshow, one Pushover
uv run python -m SamsungFrame.frame_run "/Volumes/share/Trip" 2>&1 | tee /tmp/frame-run.log

# Keep the photos already on the TV
uv run python -m SamsungFrame.frame_run "/Volumes/share/Trip" --no-cleanup

# Include portraits / skip dedup (use a fresh --job) / stricter dedup
uv run python -m SamsungFrame.frame_run ~/Photos/Trip --include-portraits
uv run python -m SamsungFrame.frame_run ~/Photos/Curated --no-dedup --job /tmp/frame-jobs/curated
uv run python -m SamsungFrame.frame_run ~/Photos/Trip --max-distance 0.3

# A big album: keep the best 300, spread across the whole trip
uv run python -m SamsungFrame.frame_run ~/Photos/Trip --max-photos 300
```

Stages run as separate processes, in this order, and the run stops at the first one that fails. The state lives in the job dir (`/tmp/frame-jobs/<name>-<hash>/manifest.json`), so after any failure **rerun the same command** and every stage resumes. The upload stage is also retried automatically (`--upload-attempts`, default 3).

| Stage | Script | What it does | Checkpoint |
|---|---|---|---|
| 1 ingest | `ingest.py` | Filters by name and size, reads each original once, drops portraits, writes local <=4K JPGs | Manifest saved per small batch |
| 2 dedup | `dedup_photos.py` | Drops near-duplicates and utility shots, keeps the best frame of each cluster | Kept and dropped lists |
| 3 upload | `frame_upload.py` | Records the TV's current user photos, then uploads the kept set | Each image recorded as it lands |
| 4 cleanup | `frame_cleanup.py` | Deletes the recorded old catalog, once every kept photo is on the TV | Idempotent: deletes what is still there |
| 5 slideshow | `frame_slideshow.py` | Starts the slideshow, reads it back from the TV | Exit code and manifest |

Each stage is also a CLI on a job dir, for example `python -m SamsungFrame.frame_upload <job>` to resume just the upload, or `python -m SamsungFrame.frame_cleanup <job> --dry-run` to see what cleanup would delete without deleting anything.

**Cleanup** removes exactly the user photos that were on the TV before the first upload (not "older than 24h", so a retry on another day cannot delete the batch). `samsung_frame.min_images` (default 100) is a floor: if fewer photos than that would remain, the newest old photos are retained. Samsung's own art is never touched, and nothing is deleted unless every kept photo is uploaded and still on the TV.

**Notification:** exactly one Pushover per run, built from the manifest so its totals cover every attempt: uploaded of kept, skipped and dropped by reason, upload failures, photos on the TV the batch added but could not name, old photos removed and retained, and whether the slideshow was verified. A clean, verified run is silent (priority -1); a failed stage, an upload failure or an unverified slideshow is high priority.

**Art carries no label or caption**: the uploader sends image bytes and a matte only, so filenames are never shown on the TV.

**Supported formats**: HEIC, JPG, JPEG, PNG. Videos, `.AAE` sidecars and other files are ignored.

### Stages 1 and 2 in Detail: Ingest and Dedup

A trip folder is full of near-identical bursts, videos and portraits. Ingest and dedup prepare it, and ingest is resumable; the source (a local folder or a network mount) is never modified, and the originals are never copied. Dedup is macOS only (Apple Vision via `swiftc`).

```bash
# Stage 1: filter and downsize to local <=4K JPGs; prints the job dir (under /tmp/frame-jobs)
uv run python -m SamsungFrame.ingest "/Volumes/share/Trip" 2>&1 | tee /tmp/ingest.log

# Stage 2: drop duplicates and utility shots; survivors are hard-linked into <job>/deduped
uv run python -m SamsungFrame.dedup_photos /tmp/frame-jobs/Trip-ab12cd

# Stricter: only near-exact repeats within 2 minutes of each other count as duplicates
uv run python -m SamsungFrame.dedup_photos /tmp/frame-jobs/Trip-ab12cd --max-distance 0.3 --window 120
```

**Ingest** (`ingest.py`):

1. Lists the folder recursively and drops, by name and size alone and without reading a byte, videos, `.AAE` sidecars, other non-images, thumbnails and files under `samsung_frame.min_size_mb`
2. Reads each remaining original once, into memory, and decodes from there; portraits are dropped after that read unless `--include-portraits`
3. Writes an EXIF-rotated JPG of at most 3840x2160 into the job dir and records it, with capture time and sharpness, in `manifest.json`, saved after every small batch of files
4. Rerun after any interruption: files already in the manifest are not read again, unreadable ones are retried, and name/size skips are recomputed from the folder each time

**Dedup** (`dedup_photos.py`), working only on the local JPGs and the manifest:

1. Apple Vision gives each photo a feature print (similarity: ~0 identical, ~0.4 near-identical, ~0.5 same scene, >0.8 unrelated), an aesthetics score and a "utility" flag; utility photos (signs, plates, receipts, screenshots) are dropped first
2. Average-linkage clustering merges the closest pairs until none is within `--max-distance` (default 0.4); photos more than `--window` seconds apart never merge. There is no target fraction: how much is dropped depends on how many near-duplicates the folder has
3. Per cluster, the frame with the best aesthetics score is kept (a landscape frame gets a small bonus, since the TV is landscape; sharpness only breaks ties), and the manifest records why every other photo was dropped
4. With `--max-photos N`, the survivors are cut into N runs in capture order and the best-scored photo of each run is kept, so the selection still spans the whole album; the rest are recorded as "over the limit"

The job dir lives in `/tmp` because it is scratch: if macOS clears it, the stages redo their work. The next stages (upload, cleanup, slideshow) are described above; the step-by-step routine is in [AGENTS.md](AGENTS.md).

### A New Album Every Month (the album queue)

`frame_album` picks the next album from a photo library laid out `<root>/<year>/<month>/<album>`, decides which of its pictures to show, and hands them to the pipeline above with cleanup on, so the TV ends up showing that album.

```bash
uv run python -m SamsungFrame.frame_album run            # this month's album
uv run python -m SamsungFrame.frame_album run --scheduled # the same, but only on a first Monday
uv run python -m SamsungFrame.frame_album scan            # index new albums; prints those needing a kind
uv run python -m SamsungFrame.frame_album classify < kinds.tsv   # path<TAB>kind<TAB>region per line
uv run python -m SamsungFrame.frame_album shuffle         # re-deal the queue
uv run python -m SamsungFrame.frame_album table           # rewrite and print upcoming.md
```

**The queue** is `index.tsv` in `samsung_frame.albums.data_dir`: one row per album, and line order is play order. Edit it by hand to move an album up or set its `status` to `skip`. An album is eligible when it has more than `min_pictures` pictures and its kind is `park` or `city`; the two kinds alternate. New albums found by a run are dropped at a random slot near the top. `upcoming.md` beside the index shows the next months and the pool, and is rewritten by every command.

**Which pictures of an album are shown**, first match wins:

1. **Its labelled files**, when at least `labelled_album_min` files carry a caption someone typed (`IMG_1234-Sunset.jpg`; camera and export names do not count). Those captions are the curation, so nothing else is uploaded and dedup is skipped.
2. **The files listed in its picks CSV** (`picks_csv`, default `frame_picks.csv`, inside the album folder), if an earlier visit wrote one.
3. **Whatever dedup keeps**: the album is ingested and deduplicated, and the picks CSV is written into the album folder with one row per kept photo: `file` and `recommended_name` (the camera name plus Apple Vision's top labels, such as `IMG_1234-People adult outdoor.HEIC`). Nothing is renamed; the CSV is a recommendation and the record that makes the next visit skip dedup.

Portraits are dropped in every case. Then:

- fewer than `min_on_tv` usable pictures: the album is marked `small`, never retried, and the next album in the queue is tried in the same run;
- more than `max_on_tv`: the album is cut into equal parts in capture order and plays one part a month; alternation resumes after its last part.

**Exit codes**: 0 done; 1 failed (one Pushover says why; run again to resume the same album and part); 2 the library is not mounted; 3 new albums need a kind (they are printed; classify them and run again). A success is one terse Pushover line; the pipeline's own notification is switched off for these runs.

**Config** (`samsung_frame.albums` in `config/default.yaml`; set `root`, `data_dir` and `home_region` in `config/local.yaml`): the limits above, plus `away_weight` and `recency_half_life_years`, which bias `shuffle` towards albums from outside the home region and newer ones.

### Check TV Status

Check TV connection and display comprehensive information:

```bash
uv run python SamsungFrame/manage_samsung.py status
```

Example output:
```
Model: QN55LS03FADXZA
Name: 55" The Frame
Firmware: Unknown
Resolution: 3840x2160
Power State: on
OS: Tizen
Network Type: wireless
Frame TV Support: true
Available Art: 42 items
Art Mode: Supported and working
```

**Note:** The status command connects over the WebSocket like any other command, so on a fresh token it triggers the TV's pairing prompt (accept it on the TV).

### List Available Art

List all art currently on the TV:

```bash
uv run python SamsungFrame/manage_samsung.py list-art
```

### List Available Matte Styles

See what matte (border) styles your TV supports:

```bash
uv run python SamsungFrame/manage_samsung.py list-mattes
```

Common options include: `shadowbox`, `none`, `modern`, `flexible`, `panoramic`

### Download Thumbnails

Download thumbnail images for your uploaded photos:

```bash
# Download only user-uploaded photos
uv run python SamsungFrame/manage_samsung.py download-thumbnails ~/Downloads/samsung_thumbnails

# Download all art (including Samsung's pre-installed art)
uv run python SamsungFrame/manage_samsung.py download-thumbnails ~/Downloads/samsung_thumbnails --all
```

### Update Mattes for Existing Art

Change the matte (border) style for all art already on the TV:

```bash
# Update all art to default black border
uv run python SamsungFrame/manage_samsung.py update-mattes

# Update with base style only
uv run python SamsungFrame/manage_samsung.py update-mattes --matte shadowbox

# Update with style and color (e.g., shadowbox with black color)
uv run python SamsungFrame/manage_samsung.py update-mattes --matte shadowbox_black
uv run python SamsungFrame/manage_samsung.py update-mattes --matte modern_warm
uv run python SamsungFrame/manage_samsung.py update-mattes --matte flexible_polar
```

**Matte Format**: `<base_style>` or `<base_style>_<color>`

Valid colors: seafoam, black, neutral, antique, warm, polar, sand, sage, burgandy, navy, apricot, byzantine, lavender, redorange, skyblue, turqoise

This command:

- Retrieves all art currently on the TV
- Validates matte style and optional color
- Updates each art item to use the specified matte style
- Reports success/failure/skipped counts

### Start Slideshow

Enable the TV's automatic slideshow feature (recommended for normal use):

```bash
# Start slideshow with default settings (3 min interval)
uv run python SamsungFrame/manage_samsung.py start-slideshow

# Custom interval (30 minutes between images)
uv run python SamsungFrame/manage_samsung.py start-slideshow --duration 30

# Sequential mode (no shuffle)
uv run python SamsungFrame/manage_samsung.py start-slideshow --no-shuffle
```

This command:

- Enables art mode on the TV
- Starts the TV's built-in slideshow for user-uploaded photos
- Configures the interval between image changes (in minutes)
- Optionally enables shuffle or sequential mode
- Reads the slideshow back from the TV and exits non-zero unless it is really playing: art mode on, My Pictures, interval and shuffle as requested, and a playlist that is exactly the photos on the TV
- Returns after verifying (TV continues cycling independently)

**Note**: This uses the TV's native slideshow feature, which continues running even after the command exits. The TV will cycle through images automatically based on the configured interval.

### Cycle Through Images

Manually cycle through your photos with a specified period (useful for testing or presentations):

```bash
# Cycle through user photos every 15 seconds (default)
uv run python SamsungFrame/manage_samsung.py cycle-images

# Custom period (30 seconds)
uv run python SamsungFrame/manage_samsung.py cycle-images --period 30

# Cycle through all art (including Samsung's pre-installed art)
uv run python SamsungFrame/manage_samsung.py cycle-images --all --period 10
```

This command:

- Enables art mode on the TV
- Retrieves all available art (or only user-uploaded photos)
- Cycles through each image with the specified period
- Continues indefinitely until you press Ctrl+C
- Logs each image change for monitoring

**Note**: This is different from the TV's built-in slideshow. The cycle-images command gives you precise control over timing (in seconds) and which images to display, but requires the script to keep running.

## Architecture

### Core Components

- **`samsung_client.py`**: Core client class (`SamsungFrameClient`)
  - Connection management with retry logic
  - Image validation and upload, with art-mode recovery after a failed image
  - Art mode control
  - Slideshow management

- **`frame_run.py`**: The driver: runs the stages as separate processes, retries the upload stage, sends one Pushover from the manifest

- **`frame_upload.py`**, **`frame_cleanup.py`**, **`frame_slideshow.py`**: Stages 3 to 5: checkpointed upload, snapshot-based cleanup with the minimum-photo floor, slideshow with read-back verification

- **`frame_job.py`**: Job dir (`/tmp/frame-jobs/...`) and the manifest shared by the pipeline stages

- **`ingest.py`**: Stage 1, name/size filtering, single read per original, local <=4K JPGs, manifest saved per batch

- **`dedup_photos.py`** + **`vision_features.swift`**: Stage 2, photo dedup (macOS only)
  - Scores the ingested JPGs with Apple Vision, clusters near-duplicates, keeps the best-scored frame of each, drops utility shots

- **`manage_samsung.py`**: CLI entry point
  - Argparse-based command interface for TV management

- **`test_frame_*.py`**, **`test_ingest.py`**, **`test_dedup_photos.py`**: Manifest, every pipeline stage (against hand-written fake TV clients), the driver and its notification, ingest filtering and resume, clustering and best-pick; real-Vision tests are skipped off macOS

### Data Models (Pydantic)

- **`ImageUploadSummary`**: Batch upload summary with counts and error list

### Dependencies

- **`samsungtvws`**: Samsung TV WebSocket API library (using [NickWaterton fork v3.0.5+](https://github.com/NickWaterton/samsung-tv-ws-api) for improved upload reliability)
- **`Pillow`**: Image validation and processing
- **`pydantic`**: Data validation and modeling

**Note**: This project uses the NickWaterton fork of samsungtvws which includes critical fixes for image uploads, particularly for TVs with `support_myshelf: FALSE`. The official pypi package (v2.7.2) has known issues with large file uploads.

## Supported Matte Styles

Use the `list-mattes` command to see what your TV supports. Common options:

- `shadowbox_black` - Black border (default); `shadowbox` accepts other colors via a suffix
- `none` - No border
- `modern`, `modernthin`, `modernwide` - Modern border styles
- `flexible` - Flexible border
- `panoramic` - Panoramic layout
- `triptych` - Three-panel layout
- `mix` - Mixed layout
- `squares` - Square grid layout

Run `uv run python SamsungFrame/manage_samsung.py list-mattes` to see your TV's exact options.

## Development

### Running Tests

```bash
# Run all SamsungFrame tests
uv run python -m pytest SamsungFrame/ -v

# Run specific test
uv run python -m pytest SamsungFrame/test_samsung_client.py::TestSamsungFrameClient::test_upload_image_success -v
```

### Linting

```bash
# Run all linters
make lint

# Auto-fix issues
make lint-fix
```

## References

- [NickWaterton samsung-tv-ws-api fork](https://github.com/NickWaterton/samsung-tv-ws-api) (v3.0.5+ used by this project)
- [Original samsung-tv-ws-api](https://github.com/xchwarze/samsung-tv-ws-api) (official upstream)
- Samsung Frame TV User Manual
- [Pushover API Documentation](https://pushover.net/api)
