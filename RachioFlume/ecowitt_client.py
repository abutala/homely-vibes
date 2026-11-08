"""Read soil moisture probes from an Ecowitt gateway's local HTTP API.

The gateway serves `GET /get_livedata_info` on the LAN with no key. Soil probes
(WH51, WH51L) appear under `ch_soil`, one entry per channel, with moisture as a
string such as "80%".
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, List

import requests

from lib.logger import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class SoilReading:
    channel: int
    name: str  # set in the Ecowitt app; "" until someone names the channel
    moisture_pct: float
    read_at: datetime


def parse_soil(payload: dict[str, Any], read_at: datetime) -> List[SoilReading]:
    """Soil readings from a `get_livedata_info` payload. A channel whose value does
    not parse (a probe that lost contact reads "--") is left out."""
    readings: List[SoilReading] = []
    for row in payload.get("ch_soil") or []:
        try:
            pct = float(str(row["humidity"]).rstrip("%"))
            channel = int(row["channel"])
        except (KeyError, ValueError):
            logger.warning(f"Skipping unreadable Ecowitt soil entry: {row}")
            continue
        readings.append(SoilReading(channel, row.get("name") or "", pct, read_at))
    return readings


class EcowittClient:
    """Local-API client for one Ecowitt gateway."""

    def __init__(
        self,
        host: str,
        get: Callable[..., Any] = requests.get,
        timeout: float = 10,
    ) -> None:
        self.host = host
        self._get = get
        self.timeout = timeout

    def soil_readings(self, now: datetime) -> List[SoilReading]:
        response = self._get(f"http://{self.host}/get_livedata_info", timeout=self.timeout)
        response.raise_for_status()
        return parse_soil(response.json(), now)
