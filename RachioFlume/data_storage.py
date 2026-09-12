"""Data storage for water tracking integration."""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator, Tuple
from contextlib import contextmanager

from RachioFlume.rachio_client import WateringEvent, Zone
from RachioFlume.flume_client import WaterReading
from lib.logger import get_logger

# A per-minute Flume reading at or below this is meter noise, not irrigation.
ACTIVE_FLOW_GPM = 0.05
# A run whose end event was lost is over once flow has been absent this long.
# One dry minute is tolerated: Flume minute buckets can read short.
MAX_FLOW_GAP = timedelta(minutes=2)
# Cap on how far past a lost-end START to look for its flow.
ORPHAN_MAX_WINDOW = timedelta(hours=3)

RUN_END_EVENTS = ("ZONE_COMPLETED", "ZONE_STOPPED")
# The controller runs one zone at a time: any of these after a START closes that run.
RUN_BOUNDARY_EVENTS = (
    "ZONE_STARTED",
    *RUN_END_EVENTS,
    "SCHEDULE_COMPLETED",
    "SCHEDULE_STOPPED",
    "COLD_REBOOT",
)


def estimate_run_end(
    start: datetime, bound: datetime, readings: List[Tuple[datetime, float]]
) -> datetime:
    """End of a zone run whose end event was lost, read off per-minute Flume flow.

    The run lasts through the contiguous flow that begins at `start`, clamped to
    `bound`. No flow at all yields a zero-length run.
    """
    last_active: Optional[datetime] = None
    for timestamp, gpm in readings:
        if gpm <= ACTIVE_FLOW_GPM:
            continue
        if timestamp - (last_active or start) > MAX_FLOW_GAP:
            break
        last_active = timestamp
    if last_active is None:
        return start
    return min(last_active + timedelta(minutes=1), bound)


class WaterTrackingDB:
    """SQLite database for storing water tracking data."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.logger = get_logger(__name__)
        self.logger.info(f"Initializing water tracking database at {self.db_path}")
        self.init_database()

    def init_database(self) -> None:
        """Create database tables if they don't exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Zones table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS zones (
                    id TEXT PRIMARY KEY,
                    zone_number INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Watering events table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS watering_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_date TIMESTAMP NOT NULL,
                    zone_name TEXT NOT NULL,
                    zone_number INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    duration_seconds INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Water readings table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS water_readings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT DEFAULT 'GAL',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Zone sessions table (computed from events)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS zone_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zone_name TEXT NOT NULL,
                    zone_number INTEGER NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    duration_seconds INTEGER,
                    total_water_used REAL DEFAULT 0.0,
                    average_flow_rate REAL DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Collection metadata table (for tracking last collection timestamps)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS collection_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # === Hose-timer tables (Rachio Smart Hose Timer / cloud-rest.rach.io) ===
            # Kept in separate tables from the controller schema so multiple
            # Bluetooth valves under one or more base stations can coexist
            # without zone_number collisions or schema migrations.
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS hose_valves (
                    id TEXT PRIMARY KEY,                    -- valveId
                    base_station_id TEXT NOT NULL,
                    base_station_label TEXT NOT NULL,       -- human label (e.g. "Hose Drip Jasmine")
                    name TEXT NOT NULL,                     -- valve name (e.g. "Upper Deck Planters")
                    default_runtime_seconds INTEGER,
                    detect_flow BOOLEAN DEFAULT 0,
                    battery_status TEXT,
                    connected BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS hose_watering_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    valve_id TEXT NOT NULL,
                    base_station_id TEXT NOT NULL,
                    event_date TIMESTAMP NOT NULL,          -- run start time
                    event_type TEXT NOT NULL,               -- ZONE_STARTED | ZONE_COMPLETED
                    duration_seconds INTEGER,               -- planned (start) or actual (complete)
                    reason TEXT,                            -- QUICK_RUN | SCHEDULE | etc.
                    flow_detected INTEGER,                  -- 0/1, NULL if not reported
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(valve_id, event_date, event_type)
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS hose_zone_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    valve_id TEXT NOT NULL,
                    base_station_id TEXT NOT NULL,
                    valve_name TEXT NOT NULL,
                    base_station_label TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    duration_seconds INTEGER,
                    flow_detected INTEGER,
                    total_water_used REAL DEFAULT 0.0,
                    average_flow_rate REAL DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(valve_id, start_time)
                )
            """
            )
            self._ensure_hose_session_flow_columns(cursor)

            # Create indexes for better query performance
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_watering_events_date ON watering_events(event_date)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_watering_events_zone ON watering_events(zone_number)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_zone_sessions_times ON zone_sessions(start_time, end_time)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_hose_events_valve ON hose_watering_events(valve_id, event_date)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_hose_sessions_times ON hose_zone_sessions(start_time, end_time)"
            )
            self._ensure_watering_events_unique_key(cursor)

            conn.commit()

        # Pre-2026-06-28, the Flume collector saved one row per (timestamp,
        # device), so each minute had two rows: the real meter value and a
        # 0.0 from the bridge. Dedup by keeping MAX value per timestamp —
        # since the bridge always read 0, MAX preserves the meter's reading
        # for every minute that ever had real flow.
        self._ensure_water_readings_unique_key()

    def _ensure_hose_session_flow_columns(self, cursor: Any) -> None:
        """Add total_water_used / average_flow_rate to legacy hose_zone_sessions."""
        cursor.execute("PRAGMA table_info(hose_zone_sessions)")
        cols = {row["name"] for row in cursor.fetchall()}
        if "total_water_used" not in cols:
            cursor.execute(
                "ALTER TABLE hose_zone_sessions ADD COLUMN total_water_used REAL DEFAULT 0.0"
            )
        if "average_flow_rate" not in cols:
            cursor.execute(
                "ALTER TABLE hose_zone_sessions ADD COLUMN average_flow_rate REAL DEFAULT 0.0"
            )

    def _ensure_watering_events_unique_key(self, cursor: Any) -> None:
        """Give watering_events a natural key so re-fetched events are ignored on insert.

        The collector re-fetches an overlapping window every poll because Rachio
        publishes events late. DBs from before the key existed get duplicates
        dropped (first row kept) before the index is created.
        """
        cursor.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_watering_events_unique'"
        )
        if cursor.fetchone():
            return
        cursor.execute(
            """
            DELETE FROM watering_events
            WHERE id NOT IN (
                SELECT MIN(id) FROM watering_events
                GROUP BY event_date, zone_number, event_type
            )
            """
        )
        if cursor.rowcount:
            self.logger.info(f"Dropped {cursor.rowcount} duplicate watering_events rows")
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_watering_events_unique "
            "ON watering_events(event_date, zone_number, event_type)"
        )

    def _ensure_water_readings_unique_key(self) -> None:
        """Collapse duplicate-per-timestamp rows, then key water_readings on timestamp.

        The key lets the collector upsert: each poll re-fetches recent minutes
        because Flume's newest minutes read short until the bridge finishes
        uploading, and the settled value must replace the short one.

        Uses an atomic DML transaction (UPDATE-then-DELETE) rather than a
        DDL table-swap. sqlite3's `executescript` auto-commits between
        statements, so a failure mid-script between DROP and RENAME would
        leave the table missing; UPDATE+DELETE inside one BEGIN/COMMIT can
        be cleanly rolled back on error.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' "
                "AND name = 'idx_water_readings_unique'"
            )
            if cursor.fetchone():
                return
            cursor.execute(
                "SELECT COUNT(*) - COUNT(DISTINCT timestamp) AS dupes FROM water_readings"
            )
            row = cursor.fetchone()
            dupes = (row["dupes"] if row else 0) or 0
            try:
                cursor.execute("BEGIN")
                if dupes:
                    self.logger.info(
                        f"Deduping {dupes} duplicate-per-timestamp water_readings rows"
                    )
                    # Promote every duplicate row's value to the max for its timestamp,
                    # so legacy bridge=0 / meter=N pairs all carry the meter's reading
                    # before we delete duplicates.
                    cursor.execute(
                        """
                        UPDATE water_readings
                        SET value = (
                            SELECT MAX(value) FROM water_readings AS w2
                            WHERE w2.timestamp = water_readings.timestamp
                        )
                        """
                    )
                    # Keep lowest-id row per timestamp; delete the rest.
                    cursor.execute(
                        """
                        DELETE FROM water_readings
                        WHERE id NOT IN (
                            SELECT MIN(id) FROM water_readings GROUP BY timestamp
                        )
                        """
                    )
                cursor.execute("DROP INDEX IF EXISTS idx_water_readings_timestamp")
                cursor.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_water_readings_unique "
                    "ON water_readings(timestamp)"
                )
                cursor.execute("COMMIT")
            except Exception:
                cursor.execute("ROLLBACK")
                raise

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with automatic cleanup."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
        try:
            yield conn
        finally:
            conn.close()

    def save_zones(self, zones: List[Zone]) -> None:
        """Save or update zones in database."""
        self.logger.info(f"Saving {len(zones)} zones to database")
        with self.get_connection() as conn:
            cursor = conn.cursor()

            for zone in zones:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO zones (id, zone_number, name, enabled, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        zone.id,
                        zone.zone_number,
                        zone.name,
                        zone.enabled,
                        datetime.now(),
                    ),
                )

            conn.commit()
            self.logger.debug(f"Successfully saved {len(zones)} zones")

    def save_watering_events(self, events: List[WateringEvent]) -> int:
        """Save watering events, ignoring ones already stored. Returns how many were new."""
        if not events:
            return 0

        inserted = 0
        with self.get_connection() as conn:
            cursor = conn.cursor()

            for event in events:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO watering_events 
                    (event_date, zone_name, zone_number, event_type, duration_seconds)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        event.event_date,
                        event.zone_name,
                        event.zone_number,
                        event.event_type,
                        event.duration_seconds,
                    ),
                )
                inserted += cursor.rowcount

            conn.commit()
        return inserted

    def save_water_readings(self, readings: List[WaterReading]) -> None:
        """Save water readings; a re-fetched minute replaces the stored value."""
        if not readings:
            return

        with self.get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO water_readings (timestamp, value, unit)
                VALUES (?, ?, ?)
                ON CONFLICT(timestamp) DO UPDATE SET value = excluded.value, unit = excluded.unit
                """,
                [(reading.timestamp, reading.value, reading.unit) for reading in readings],
            )
            conn.commit()

    def get_zone_sessions(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get zone watering sessions for a date range."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM zone_sessions 
                WHERE start_time >= ? AND start_time <= ?
                ORDER BY start_time
            """,
                (start_date, end_date),
            )

            return [dict(row) for row in cursor.fetchall()]

    def compute_zone_sessions(self) -> int:
        """Rebuild zone_sessions from watering events.

        Returns how many sessions had no end event and were estimated from Flume.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM zone_sessions")

            cursor.execute(
                "SELECT event_date, zone_name, zone_number, event_type "
                "FROM watering_events ORDER BY event_date"
            )
            boundaries = [
                (datetime.fromisoformat(row["event_date"]), row)
                for row in cursor.fetchall()
                if row["event_type"] in RUN_BOUNDARY_EVENTS
            ]

            estimated = 0
            for index, (start_time, start_event) in enumerate(boundaries):
                if start_event["event_type"] != "ZONE_STARTED":
                    continue
                run_end = self._find_run_end(cursor, boundaries, index)
                if run_end is None:
                    continue
                end_time, from_flume = run_end
                if from_flume:
                    estimated += 1
                self._insert_zone_session(cursor, start_event, start_time, end_time)

            conn.commit()
        return estimated

    def _find_run_end(
        self,
        cursor: Any,
        boundaries: List[Tuple[datetime, sqlite3.Row]],
        start_index: int,
    ) -> Optional[Tuple[datetime, bool]]:
        """End of the run started at boundaries[start_index], and whether it was estimated.

        The first boundary event after a START closes that run. When it isn't the
        zone's own end event, that end event was lost, so the end is read off Flume
        flow up to the boundary instead. None: nothing has happened since the START,
        so the zone is still running.
        """
        start_time, start_event = boundaries[start_index]
        boundary: Optional[datetime] = None
        for index in range(start_index + 1, len(boundaries)):
            event_time, event = boundaries[index]
            if event_time == start_time:
                continue
            if boundary is not None and event_time > boundary:
                break
            if (
                event["zone_number"] == start_event["zone_number"]
                and event["event_type"] in RUN_END_EVENTS
            ):
                return event_time, False
            if boundary is None:
                boundary = event_time

        if boundary is None:
            return None
        window_end = min(boundary, start_time + ORPHAN_MAX_WINDOW)
        cursor.execute(
            "SELECT timestamp, value FROM water_readings "
            "WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp",
            (start_time, window_end),
        )
        readings = [(datetime.fromisoformat(r["timestamp"]), r["value"]) for r in cursor.fetchall()]
        return estimate_run_end(start_time, window_end, readings), True

    def _insert_zone_session(
        self, cursor: Any, start_event: sqlite3.Row, start_time: datetime, end_time: datetime
    ) -> None:
        duration = int((end_time - start_time).total_seconds())
        water_used = self._get_water_usage_for_period(start_time, end_time)
        avg_flow_rate = (water_used / (duration / 60)) if duration > 0 else 0.0
        cursor.execute(
            """
            INSERT INTO zone_sessions
            (zone_name, zone_number, start_time, end_time, duration_seconds,
             total_water_used, average_flow_rate)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                start_event["zone_name"],
                start_event["zone_number"],
                start_time,
                end_time,
                duration,
                water_used,
                avg_flow_rate,
            ),
        )

    def _get_water_usage_for_period(self, start_time: datetime, end_time: datetime) -> float:
        """Get total water usage for a time period."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT SUM(value) as total FROM water_readings
                WHERE timestamp >= ? AND timestamp <= ?
            """,
                (start_time, end_time),
            )

            result = cursor.fetchone()
            return result["total"] or 0.0

    def get_period_zone_stats(
        self, start_date: datetime, end_date: datetime
    ) -> List[Dict[str, Any]]:
        """Get period statistics by zone for a custom date range."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT 
                    zone_name,
                    zone_number,
                    COUNT(*) as session_count,
                    SUM(duration_seconds) as total_duration_seconds,
                    AVG(duration_seconds) as avg_duration_seconds,
                    SUM(total_water_used) as total_water_used,
                    AVG(average_flow_rate) as avg_flow_rate
                FROM zone_sessions
                WHERE start_time >= ? AND start_time < ?
                GROUP BY zone_name, zone_number
                ORDER BY zone_number
            """,
                (start_date, end_date),
            )

            return [dict(row) for row in cursor.fetchall()]

    def get_raw_data_intervals(
        self,
        start_time: datetime,
        end_time: datetime,
        interval_minutes: int = 5,
    ) -> List[Dict[str, Any]]:
        """Get raw data aggregated into time intervals."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Create intervals by rounding timestamps to the specified interval
            cursor.execute(
                """
                SELECT 
                    datetime(
                        (strftime('%s', timestamp) / (? * 60)) * (? * 60),
                        'unixepoch'
                    ) as interval_start,
                    AVG(value) as avg_flow_rate,
                    MAX(value) as max_flow_rate,
                    MIN(value) as min_flow_rate,
                    COUNT(*) as data_points,
                    AVG(CASE WHEN value > 0.1 THEN value END) as avg_active_flow_rate
                FROM water_readings
                WHERE timestamp >= ? AND timestamp <= ?
                GROUP BY interval_start
                ORDER BY interval_start
            """,
                (interval_minutes, interval_minutes, start_time, end_time),
            )

            return [dict(row) for row in cursor.fetchall()]

    def get_last_collection_timestamp(self, source: str) -> Optional[datetime]:
        """Get the last collection timestamp for a source (rachio or flume)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM collection_metadata WHERE key = ?",
                (f"last_{source}_collection",),
            )
            result = cursor.fetchone()
            if result:
                return datetime.fromisoformat(result["value"])
            return None

    def set_last_collection_timestamp(self, source: str, timestamp: datetime) -> None:
        """Set the last collection timestamp for a source."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO collection_metadata (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """,
                (f"last_{source}_collection", timestamp.isoformat()),
            )
            conn.commit()

    def get_metadata(self, key: str) -> Optional[str]:
        """Get a raw value from collection_metadata, or None if missing."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM collection_metadata WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else None

    def set_metadata(self, key: str, value: str) -> None:
        """Upsert a value into collection_metadata."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO collection_metadata (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """,
                (key, value),
            )
            conn.commit()

    def delete_metadata(self, key: str) -> None:
        """Remove a metadata key (no-op if missing)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM collection_metadata WHERE key = ?", (key,))
            conn.commit()

    # =====================================================================
    # Hose-timer storage (separate from controller schema)
    # =====================================================================

    def save_hose_valves(self, valves: List[Dict[str, Any]]) -> None:
        """Upsert hose-timer valves (one row per (base_station, valve))."""
        if not valves:
            return
        self.logger.info(f"Saving {len(valves)} hose-timer valves")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for v in valves:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO hose_valves (
                        id, base_station_id, base_station_label, name,
                        default_runtime_seconds, detect_flow, battery_status,
                        connected, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        v["id"],
                        v["base_station_id"],
                        v["base_station_label"],
                        v["name"],
                        v.get("default_runtime_seconds"),
                        1 if v.get("detect_flow") else 0,
                        v.get("battery_status"),
                        1 if v.get("connected", True) else 0,
                        datetime.now(),
                    ),
                )
            conn.commit()

    def get_hose_valves(self) -> List[Dict[str, Any]]:
        """All known hose-timer valve roster rows (connected or not)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM hose_valves ORDER BY base_station_label, name")
            return [dict(row) for row in cursor.fetchall()]

    def save_hose_watering_event(self, event: Dict[str, Any]) -> None:
        """Insert a hose-timer event (idempotent on (valve_id, event_date, event_type))."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO hose_watering_events (
                    valve_id, base_station_id, event_date, event_type,
                    duration_seconds, reason, flow_detected
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["valve_id"],
                    event["base_station_id"],
                    event["event_date"],
                    event["event_type"],
                    event.get("duration_seconds"),
                    event.get("reason"),
                    None
                    if event.get("flow_detected") is None
                    else (1 if event["flow_detected"] else 0),
                ),
            )
            conn.commit()

    def save_hose_zone_session(self, session: Dict[str, Any]) -> None:
        """Insert a finalized hose-timer session row."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO hose_zone_sessions (
                    valve_id, base_station_id, valve_name, base_station_label,
                    start_time, end_time, duration_seconds, flow_detected,
                    total_water_used, average_flow_rate
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["valve_id"],
                    session["base_station_id"],
                    session["valve_name"],
                    session["base_station_label"],
                    session["start_time"],
                    session["end_time"],
                    session["duration_seconds"],
                    None
                    if session.get("flow_detected") is None
                    else (1 if session["flow_detected"] else 0),
                    float(session.get("total_water_used") or 0.0),
                    float(session.get("average_flow_rate") or 0.0),
                ),
            )
            conn.commit()

    def get_hose_zone_sessions(
        self, start_date: datetime, end_date: datetime
    ) -> List[Dict[str, Any]]:
        """Get hose-timer sessions for a date range."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM hose_zone_sessions
                WHERE start_time >= ? AND start_time <= ?
                ORDER BY start_time
                """,
                (start_date, end_date),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_last_data_timestamp(self, source: str) -> Optional[datetime]:
        """Get the actual last timestamp from data tables."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            if source != "flume":
                raise ValueError(f"Unknown source: {source}")
            cursor.execute("SELECT MAX(timestamp) as last_timestamp FROM water_readings")

            result = cursor.fetchone()
            if result and result["last_timestamp"]:
                return datetime.fromisoformat(result["last_timestamp"])
            return None
