"""Data collection service that polls Rachio and Flume APIs."""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from RachioFlume.alert_engine import CONTROLLER_STATUS_KEY, AlertEngine
from RachioFlume.hose_timer_processor import HoseTimerProcessor
from RachioFlume.rachio_client import RachioClient
from RachioFlume.flume_client import FlumeClient
from RachioFlume.data_storage import WaterTrackingDB
from RachioFlume.stale_zone_checker import StaleZoneChecker
from lib.logger import get_logger

# Both APIs publish late: a Rachio event can appear well after it happened, and
# Flume's newest minutes read short until the bridge finishes uploading. Each poll
# re-fetches this much history; unique keys drop repeated events and upsert readings.
FETCH_OVERLAP = timedelta(hours=1)


class WaterTrackingCollector:
    """Service that collects data from Rachio and Flume APIs."""

    def __init__(
        self,
        db_path: str,
        poll_interval_seconds: int = 300,  # 5 minutes default
        alert_engine: Optional[AlertEngine] = None,
        hose_processors: Optional[List[HoseTimerProcessor]] = None,
        stale_zone_checker: Optional[StaleZoneChecker] = None,
        rachio_client: Optional[RachioClient] = None,
        flume_client: Optional[FlumeClient] = None,
    ):
        self.logger = get_logger(__name__)

        self.db = WaterTrackingDB(db_path)
        self.rachio_client = rachio_client or RachioClient()
        self.flume_client = flume_client or FlumeClient()
        self.poll_interval = poll_interval_seconds
        self.alert_engine = alert_engine
        self.hose_processors = hose_processors or []
        self.stale_zone_checker = stale_zone_checker

        # Initialize last collection times from database to avoid duplicates
        self.last_rachio_collection: Optional[datetime] = self.db.get_last_collection_timestamp(
            "rachio"
        )
        self.last_flume_collection: Optional[datetime] = self.db.get_last_collection_timestamp(
            "flume"
        )

        if self.last_rachio_collection:
            self.logger.info(
                f"Initialized with last Rachio collection: {self.last_rachio_collection}"
            )
        if self.last_flume_collection:
            self.logger.info(
                f"Initialized with last Flume collection: {self.last_flume_collection}"
            )

    async def collect_rachio_data(self) -> None:
        """Collect data from Rachio API."""
        try:
            # Collect zone information
            zones = self.rachio_client.get_zones()
            self.db.save_zones(zones)
            self.logger.info(f"Collected {len(zones)} zones from Rachio")

            # Record controller online/offline status for the device-offline
            # check (status rides along on the device payload get_zones fetched).
            if self.rachio_client.last_device_status is not None:
                self.db.set_metadata(
                    CONTROLLER_STATUS_KEY,
                    json.dumps(
                        {
                            "status": self.rachio_client.last_device_status,
                            "observed_at": datetime.now().isoformat(),
                        }
                    ),
                )

            if not self.last_rachio_collection:
                # First run - get last 7 days of events
                events = self.rachio_client.get_recent_events(days=7)
            else:
                events = self.rachio_client.get_events(
                    self.last_rachio_collection - FETCH_OVERLAP, datetime.now()
                )

            if events:
                inserted = self.db.save_watering_events(events)
                self.logger.info(
                    f"Collected {inserted} new watering events from Rachio "
                    f"({len(events) - inserted} already stored)"
                )

            collection_time = datetime.now()
            self.last_rachio_collection = collection_time
            # Save collection timestamp to database for persistence
            self.db.set_last_collection_timestamp("rachio", collection_time)

        except Exception as e:
            self.logger.error(f"Error collecting Rachio data: {e}")

    async def collect_flume_data(self) -> None:
        """Collect data from Flume API."""
        try:
            if not self.last_flume_collection:
                # First run - get last 24 hours
                start_time = datetime.now() - timedelta(hours=24)
            else:
                start_time = self.last_flume_collection - FETCH_OVERLAP

            end_time = datetime.now()
            readings = self.flume_client.get_usage(start_time, end_time, bucket="MIN")

            if readings:
                self.db.save_water_readings(readings)
                self.logger.info(f"Saved {len(readings)} water readings from Flume")

            self.last_flume_collection = end_time
            # Save collection timestamp to database for persistence
            self.db.set_last_collection_timestamp("flume", end_time)

        except Exception as e:
            self.logger.error(f"Error collecting Flume data: {e}")

    async def process_collected_data(self) -> None:
        """Process collected data to compute zone sessions and statistics."""
        try:
            estimated = self.db.compute_zone_sessions()
            self.logger.info(
                f"Computed zone sessions from watering events ({estimated} estimated from Flume)"
            )

        except Exception as e:
            self.logger.error(f"Error processing collected data: {e}")

    async def collect_once(self) -> None:
        """Run one collection cycle."""
        self.logger.info("Starting data collection cycle")

        # Collect from both APIs concurrently
        await asyncio.gather(
            self.collect_rachio_data(),
            self.collect_flume_data(),
            return_exceptions=True,
        )

        # Process the collected data
        await self.process_collected_data()

        # Evaluate hose-timer processors (one per Smart Hose Timer base station).
        # Synchronous calls — each issues 1-2 HTTP requests per valve, well
        # under the 5-minute poll cadence even with several base stations.
        for proc in self.hose_processors:
            try:
                proc.evaluate()
            except Exception as e:
                self.logger.error(f"Hose-timer processor '{proc.client.label}' failed: {e}")

        # Evaluate usage alerts (no-op if engine not configured)
        if self.alert_engine is not None:
            try:
                await self.alert_engine.evaluate()
            except Exception as e:
                self.logger.error(f"Error evaluating alerts: {e}")

        # Stale-zone check (gated to once per hour internally)
        if self.stale_zone_checker is not None:
            try:
                self.stale_zone_checker.maybe_evaluate()
            except Exception as e:
                self.logger.error(f"Error checking stale zones: {e}")

        self.logger.info("Data collection cycle completed")

    async def run_continuous(self) -> None:
        """Run continuous data collection."""
        self.logger.info(f"Starting continuous collection every {self.poll_interval} seconds")

        while True:
            try:
                await self.collect_once()

                # Wait for next collection cycle
                await asyncio.sleep(self.poll_interval)

            except KeyboardInterrupt:
                self.logger.info("Collection stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Error in collection cycle: {e}")
                # Wait a bit before retrying
                await asyncio.sleep(60)

    def get_current_status(self) -> Dict[str, Any]:
        """Get current status of water tracking system."""
        try:
            # Get current active zone from Rachio
            active_zone = self.rachio_client.get_active_zone()

            # Get current water usage rate from Flume
            current_usage_rate = self.flume_client.get_current_usage_rate()

            # Get recent sessions from database
            recent_sessions = self.db.get_zone_sessions(
                datetime.now() - timedelta(hours=24), datetime.now()
            )

            return {
                "active_zone": {
                    "zone_number": active_zone.zone_number if active_zone else None,
                    "zone_name": active_zone.name if active_zone else None,
                },
                "current_usage_rate_gpm": current_usage_rate,
                "recent_sessions_count": len(recent_sessions),
                "last_rachio_collection": (
                    self.last_rachio_collection.isoformat() if self.last_rachio_collection else None
                ),
                "last_flume_collection": (
                    self.last_flume_collection.isoformat() if self.last_flume_collection else None
                ),
            }

        except Exception as e:
            self.logger.error(f"Error getting current status: {e}")
            return {"error": str(e)}
