# Samsung Frame TV Art Manager

Gotchas, incidents and error reference: [Logbook.md](Logbook.md).

A Python client for managing art mode on Samsung Frame TVs. Upload images, configure display settings, and control slideshow playback remotely.

## Features

- **Batch Upload with HEIC Conversion**: Convert iPhone/iOS HEIC images to 4K JPG and upload
- **Recursive Directory Scanning**: Process images from nested subdirectories
- **Smart Filtering**: Exclude thumbnails, small files and portraits automatically
- **Photo Dedup**: `dedup_photos.py` thins a folder to a fraction of its size by dropping near-duplicates
- **Filename Trimming**: Automatically trims filenames to <50 chars (preserves extension, handles collisions)
- **Start Index / Pagination**: Skip first N files with `--start-index` for resuming interrupted uploads
- **Smart Purge**: Delete stale art (uploaded >24h ago or with no upload date) while respecting minimum image count
- **Connection Health Checks**: After 3 consecutive failures, reboots the TV and reconnects; aborts the upload only if that fails
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

# Option 2: Pair during first upload
uv run python SamsungFrame/batch_upload.py /path/to/images
```

**Pairing Steps:**
1. Run any command that connects to TV (status, batch upload, list-art, etc.)
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

### Batch Upload with HEIC Conversion

For iPhone/iOS users with HEIC photos, use the batch upload script which handles conversion automatically:

```bash
# Basic batch upload with HEIC conversion
uv run python SamsungFrame/batch_upload.py ~/Photos/Favorites 2>&1 | tee /tmp/samsung-batch-upload.log

# Keep older art on the TV (purge of art >24h old is ON by default)
uv run python SamsungFrame/batch_upload.py ~/Photos/Vacation --no-purge

# Include portrait photos (skipped by default; the TV is landscape)
uv run python SamsungFrame/batch_upload.py ~/Photos/Vacation --include-portraits

# Custom matte
uv run python SamsungFrame/batch_upload.py ~/Photos --matte shadowbox_black

# Skip first 20 files (resume interrupted upload)
uv run python SamsungFrame/batch_upload.py ~/Photos --start-index 20

# Upload at most 50 files starting from index 10
uv run python SamsungFrame/batch_upload.py ~/Photos --start-index 10 --max-files 50
```

**What the batch upload script does:**

1. **Recursive Discovery**: Scans directory and all subdirectories for images
2. **Smart Filtering**: Excludes files below `samsung_frame.min_size_mb` (default 0.75MB), thumbnail patterns (*_thumb*, *_thumbnail*, *_small*) and, unless `--include-portraits`, portrait photos. Small-file skips are logged at debug level only
3. **Start Index / Max Files**: Optionally skip first N files and/or cap total uploads
4. **Phase 1 — Prepare**: Converts HEIC to high-quality JPG at 4K (max 3840×2160), copies JPG/PNG, trims all filenames to <50 chars
5. **Quality Compression**: Reduces JPG quality (95→90→85→80→75→70) if needed to meet 10MB TV limit
6. **Phase 2 — Upload**: Uploads all prepared images with health checking (3 consecutive failures reboot the TV and reconnect; the upload aborts only if that fails)
7. **Smart Purge**: Deletes art uploaded >24h ago or with no upload date, using the TV's own `image_date` (respects minimum image count); skip with `--no-purge`
8. **Enable Art Mode**: Automatically enables slideshow after upload

**Command Options:**

- `source_dir` - Directory to scan (required)
- `--matte` - Matte style (default: shadowbox_black)
- `--no-purge` - Skip purging stale art (>24h old) after upload
- `--include-portraits` - Upload portrait photos too (default: skipped)
- `--start-index N` - Skip first N discovered files (applied before --max-files)
- `--max-files N` - Maximum number of files to upload (0 = all)

**Note**: Pushover notifications sent automatically. Files below `min_size_mb` are filtered as thumbnails. Art carries no label or caption: the uploader sends image bytes and a matte only, so filenames are never shown on the TV.

**Supported Formats**: HEIC, JPG, JPEG, PNG

### Dedup Photos Before Uploading

A trip folder is full of near-identical bursts. `dedup_photos.py` thins it to a fraction of its size and writes the survivors, as 4K JPGs, to a new folder. The source is never modified. macOS only (uses Apple Vision via `swiftc`).

```bash
# Keep ~50%; writes "~/Photos/Trip - dedup"
uv run python SamsungFrame/dedup_photos.py ~/Photos/Trip 2>&1 | tee /tmp/dedup.log

# Keep ~30%, only treat photos within 2 minutes of each other as duplicates
uv run python SamsungFrame/dedup_photos.py ~/Photos/Trip --keep 0.3 --window 120 --out ~/Photos/Trip-small
```

How it chooses:

1. Every HEIC/JPG/PNG in the folder's top level (no subfolders, unlike `batch_upload.py`) is downsized to <=3840x2160 JPG (EXIF-rotated), so the rest runs on small files
2. Apple Vision feature prints give a distance per pair (~0 identical, ~0.5 same scene, >0.8 unrelated)
3. Average-linkage clustering merges the closest pairs until `--keep` is reached; photos more than `--window` seconds apart never merge, and nothing merges past `--max-distance` even if `--keep` is not reached
4. Per cluster, the sharpest frame is kept; a landscape frame beats a portrait one unless the portrait is 2x sharper

Videos (`.MOV`) and sidecars (`.AAE`) are ignored. Upload the result with `batch_upload.py "<out>"`; it then purges user art older than 24h (add `--no-purge` to keep it). The step-by-step routine is in [CLAUDE.md](CLAUDE.md).

### Check TV Status

Check TV connection and display comprehensive information:

```bash
uv run python SamsungFrame/manage_samsung.py status
```

Example output:
```
Connecting to Samsung Frame TV at 192.168.x.x...
==================================================
TV STATUS
==================================================
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

**Note:** Status command uses REST API only, so it won't trigger the pairing prompt. Run an upload command first to establish authentication.

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
- Returns after starting the slideshow (TV continues cycling independently)

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
  - Image validation and upload with health checking (consecutive failure detection)
  - Art mode control
  - Slideshow management

- **`batch_upload.py`**: Batch upload with two-phase architecture
  - Phase 1: Prepare images (HEIC conversion, filename trimming, copy to temp dir)
  - Phase 2: Upload via `upload_images_from_folder()` with automatic health checks
  - Smart purge using the TV's `image_date`

- **`dedup_photos.py`** + **`feature_prints.swift`**: Photo dedup (macOS only)
  - Downsizes to 4K JPG, embeds with Apple Vision, clusters, keeps the sharpest of each cluster

- **`manage_samsung.py`**: CLI entry point
  - Argparse-based command interface for TV management
  - Pushover notification integration

- **`test_batch_upload.py`**: Comprehensive test suite
  - Tests for discovery, conversion, deletion, filename trimming, start-index

- **`test_dedup_photos.py`**: Clustering, best-pick and image-prep tests; one real-Vision smoke test (skipped off macOS)

### Data Models (Pydantic)

- **`UploadResult`**: Single image upload result with success/error details
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
