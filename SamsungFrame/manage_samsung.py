#!/usr/bin/env python3
"""Main entry point for Samsung Frame TV art mode management."""

import argparse
import sys
from typing import Callable

from lib.config import get_config
from lib.logger import get_logger
from SamsungFrame.samsung_client import (
    SamsungFrameClient,
    delete_all_art,
    delete_art_by_ids,
    plan_purge,
)

logger = get_logger(__name__)

Handler = Callable[[SamsungFrameClient, argparse.Namespace], int]

DEVICE_FIELDS = [
    ("Model", "modelName"),
    ("Name", "name"),
    ("Firmware", "firmwareVersion"),
    ("Resolution", "resolution"),
    ("Power State", "PowerState"),
    ("OS", "OS"),
    ("Network Type", "networkType"),
    ("Frame TV Support", "FrameTVSupport"),
]


def show_status(client: SamsungFrameClient, _args: argparse.Namespace) -> int:
    device = (client.get_device_info() or {}).get("device")
    if device is None:
        logger.warning("Could not retrieve device info")
    else:
        for label, key in DEVICE_FIELDS:
            logger.info(f"{label}: {device.get(key, 'Unknown')}")
        if device.get("FrameTVSupport") == "true":
            logger.info(f"Available Art: {len(client.get_available_art())} items")

    if client.check_art_support():
        logger.info("Art Mode: Supported and working")
    else:
        logger.warning("Art Mode: Not supported or unavailable")
    return 0


def list_art(client: SamsungFrameClient, _args: argparse.Namespace) -> int:
    art_list = client.get_available_art()
    logger.info(f"Available art ({len(art_list)} items):")
    for i, art in enumerate(art_list, 1):
        logger.info(f"  {i}. ID: {art.get('content_id', 'Unknown ID')}")
    return 0


def list_mattes(client: SamsungFrameClient, _args: argparse.Namespace) -> int:
    mattes = client.get_available_mattes()
    logger.info(f"Available matte styles ({len(mattes)} options):")
    for i, matte in enumerate(mattes, 1):
        logger.info(f"  {i}. {matte}")
    return 0


def _report(result: dict[str, int]) -> int:
    """Log an operation's counts; non-zero when any item failed."""
    logger.info("Results: " + ", ".join(f"{count} {name}" for name, count in result.items()))
    return 0 if result["failed"] == 0 else 1


def download_thumbnails(client: SamsungFrameClient, args: argparse.Namespace) -> int:
    return _report(client.download_thumbnails(args.output_dir, user_photos_only=not args.all))


def update_mattes(client: SamsungFrameClient, args: argparse.Namespace) -> int:
    return _report(
        client.update_all_mattes(args.matte, user_photos_only=not args.include_preinstalled)
    )


def cycle_images(client: SamsungFrameClient, args: argparse.Namespace) -> int:
    client.cycle_images(
        period=args.period, user_photos_only=not args.all, shuffle=not args.no_shuffle
    )
    return 0


def start_slideshow(client: SamsungFrameClient, args: argparse.Namespace) -> int:
    shuffle = not args.no_shuffle
    if not client.start_slideshow(duration=args.duration, shuffle=shuffle):
        logger.error("Failed to start slideshow")
        return 1
    problems = client.verify_slideshow(args.duration, shuffle)
    for problem in problems:
        logger.error(f"Slideshow not verified: {problem}")
    if problems:
        return 1
    logger.info("Slideshow started and verified on the TV")
    return 0


def delete_all(client: SamsungFrameClient, args: argparse.Namespace) -> int:
    return _report(delete_all_art(client, force=args.force))


def purge_art(
    client: SamsungFrameClient,
    args: argparse.Namespace,
    ask: Callable[[str], str] = input,
    min_images: int | None = None,
) -> int:
    if min_images is None:
        min_images = get_config().samsung_frame.min_images
    ids = plan_purge(client.get_available_art(), args.days * 24, min_images)
    if not ids:
        logger.info(f"Nothing to purge older than {args.days} day(s) (minimum kept: {min_images})")
        return 0

    logger.info(f"{len(ids)} art items older than {args.days} day(s) (minimum kept: {min_images})")
    if not args.force and ask(f"Delete {len(ids)} items? [y/N] ").lower() != "y":
        logger.info("Purge cancelled")
        return 0
    return _report(delete_art_by_ids(client, ids))


def reboot_tv(client: SamsungFrameClient, _args: argparse.Namespace) -> int:
    if client.reboot_and_reconnect():
        logger.info("TV rebooted and in art mode")
        return 0
    logger.error("Failed to reboot TV into art mode")
    return 1


COMMANDS: dict[str, Handler] = {
    "status": show_status,
    "list-art": list_art,
    "list-mattes": list_mattes,
    "download-thumbnails": download_thumbnails,
    "update-mattes": update_mattes,
    "cycle-images": cycle_images,
    "start-slideshow": start_slideshow,
    "reboot": reboot_tv,
    "delete-all": delete_all,
    "purge": purge_art,
}


def run_command(
    name: str,
    args: argparse.Namespace,
    client_factory: Callable[[], SamsungFrameClient] = SamsungFrameClient,
) -> int:
    """Connect, run one command, close; any failure is logged and becomes exit code 1."""
    try:
        with client_factory() as client:
            return COMMANDS[name](client, args)
    except Exception as e:
        logger.error(f"Error running {name}: {e}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Samsung Frame TV Art Mode Manager")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("status", help="Check TV connection and art mode support")
    subparsers.add_parser("list-art", help="List available art on TV")
    subparsers.add_parser("list-mattes", help="List available matte styles")
    subparsers.add_parser("reboot", help="Reboot the TV")

    purge_parser = subparsers.add_parser("purge", help="Delete user art older than N days")
    purge_parser.add_argument(
        "--days",
        type=int,
        default=1,
        help="Delete art older than this many days (default: %(default)s)",
    )
    purge_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")

    delete_parser = subparsers.add_parser("delete-all", help="Delete all user-uploaded art from TV")
    delete_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")

    download_parser = subparsers.add_parser(
        "download-thumbnails", help="Download thumbnails for art on TV"
    )
    download_parser.add_argument("output_dir", type=str, help="Directory to save thumbnails")
    download_parser.add_argument(
        "--all", action="store_true", help="Download all art (not just user photos)"
    )

    matte_parser = subparsers.add_parser(
        "update-mattes", help="Update matte style for user-uploaded art"
    )
    matte_parser.add_argument(
        "--matte",
        type=str,
        default=get_config().samsung_frame.default_matte,
        help="Matte style (default: %(default)s)",
    )
    matte_parser.add_argument(
        "--include-preinstalled", action="store_true", help="Include Samsung pre-installed art"
    )

    cycle_parser = subparsers.add_parser(
        "cycle-images", help="Cycle through images with specified period"
    )
    cycle_parser.add_argument(
        "--period",
        type=int,
        default=15,
        help="Time in seconds between image changes (default: 15)",
    )
    cycle_parser.add_argument(
        "--all", action="store_true", help="Cycle through all art (not just user photos)"
    )
    cycle_parser.add_argument(
        "--no-shuffle",
        action="store_true",
        help="Disable randomization (cycle in sequential order)",
    )

    slideshow_parser = subparsers.add_parser(
        "start-slideshow", help="Start automatic slideshow on TV"
    )
    slideshow_parser.add_argument(
        "--duration",
        type=int,
        default=3,
        help="Time in minutes between image changes (default: 3)",
    )
    slideshow_parser.add_argument(
        "--no-shuffle", action="store_true", help="Disable shuffle mode (sequential order)"
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1
    return run_command(args.command, args)


if __name__ == "__main__":
    sys.exit(main())
