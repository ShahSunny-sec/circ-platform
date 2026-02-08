from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
    )


@dataclass
class StageTimer:
    stage: str
    extra: dict[str, Any]

    def __post_init__(self) -> None:
        self._start = time.perf_counter()

    def finish(self, **kwargs: Any) -> dict[str, Any]:
        duration_ms = int((time.perf_counter() - self._start) * 1000)
        payload = {"stage": self.stage, "duration_ms": duration_ms, **self.extra, **kwargs}
        logging.info(json.dumps(payload, default=str))
        return payload
