#!/usr/bin/env python3
import asyncio
import argparse
import json
import sys
from typing import Optional
import logging

from August.august_client import AugustMonitor, AugustClient, battery_summary
from lib.logger import get_logger
from lib.config import get_config
from lib.MyPushover import Pushover
from August.validate_2fa import complete_2fa

cfg = get_config()
pushover = Pushover(cfg.pushover.user, cfg.pushover.tokens["August"])


async def _test(battery_pct: int) -> None:
    cfg = get_config()
    client = AugustClient(cfg.august.email, cfg.august.password)
    try:
        statuses = await client.get_all_lock_statuses()
        message, priority = battery_summary(statuses.values(), battery_pct)
        pushover.send_message(message, title="August Battery Status", priority=priority)
    except Exception as e:
        pushover.send_message(
            f"Error initializing August client: {e}",
            title="August Battery Status",
            priority=1,
        )
    finally:
        await client.close()


async def _details() -> None:
    cfg = get_config()
    client = AugustClient(cfg.august.email, cfg.august.password)
    try:
        for summary in await client.get_lock_summaries():
            print(json.dumps(summary))
    finally:
        await client.close()


async def _run_command(
    args: argparse.Namespace,
    email: str,
    password: str,
    phone: Optional[str],
    logger: logging.Logger,
) -> None:
    if args.command == "monitor":
        monitor = AugustMonitor(
            email=email,
            password=password,
            phone=phone,
            unlock_threshold_minutes=args.lock_mins,
            ajar_threshold_minutes=args.ajar_mins,
            battery_threshold_pct=args.battery_pct,
        )

        logger.info(
            f"Starting continuous monitoring (interval: {args.poll_secs}s, "
            f"threshold: {args.lock_mins}min)"
        )
        await monitor.run_continuous_monitoring(args.poll_secs)

    elif args.command == "validate":
        logger.info("Starting 2FA validation process...")

        await complete_2fa()

    elif args.command == "test":
        await _test(args.battery_pct)

    elif args.command == "details":
        await _details()


def main() -> None:
    logger = get_logger(__name__)
    cfg = get_config()
    logger.info("=" * 50)
    logger.info("Starting August Smart Lock Monitoring")

    parser = argparse.ArgumentParser(description="August Smart Lock monitoring and alerting")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Monitor commands
    monitor_parser = subparsers.add_parser("monitor", help="Continuous lock monitoring")
    monitor_parser.add_argument(
        "--poll-secs",
        type=int,
        default=60,
        help="Check interval in seconds (default: 60)",
    )
    monitor_parser.add_argument(
        "--lock-mins",
        type=int,
        default=5,
        help="Unlock alert threshold in minutes (default: 5)",
    )
    monitor_parser.add_argument(
        "--ajar-mins",
        type=int,
        default=10,
        help="Door ajar alert threshold in minutes (default: 10)",
    )
    monitor_parser.add_argument(
        "--battery-pct",
        type=int,
        default=20,
        help="Low battery alert threshold percentage (default: 20)",
    )

    # Validate command
    _ = subparsers.add_parser("validate", help="Complete 2FA validation")

    # Test command
    test_parser = subparsers.add_parser("test", help="Battery report (P-1 unless a lock is low)")
    test_parser.add_argument(
        "--battery-pct",
        type=int,
        default=20,
        help="Below this a lock is low and the report goes out at P1 (default: 20)",
    )

    # Details command
    _ = subparsers.add_parser("details", help="Each lock's model, serial, MAC and bridge")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Get August credentials from config
    cfg = get_config()
    if not cfg.august.email or not cfg.august.password:
        logger.error("August credentials not found in config")
        logger.error("Please add august.email and august.password to config/local.yaml")
        sys.exit(1)

    email = cfg.august.email
    password = cfg.august.password
    phone = cfg.august.phone

    try:
        asyncio.run(_run_command(args, email, password, phone, logger))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.command == "test":
            pushover.send_message(f"August test failed: {e}", title="August Error", priority=1)
        sys.exit(1)


if __name__ == "__main__":
    main()
