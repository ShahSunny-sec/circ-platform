from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from .models import Alert, Incident, RawEvent
from .utils import ensure_dir, to_jsonl


def write_events_parquet(events: list[RawEvent], path: Path) -> None:
    rows: list[dict[str, Any]] = []
    for e in events:
        rows.append(
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "source": e.source,
                "source_ip": e.source_ip,
                "dest_ip": e.dest_ip,
                "hostname": e.hostname,
                "username": e.username,
                "action": e.action,
                "direction": e.direction,
                "src_port": e.src_port,
                "dst_port": e.dst_port,
                "protocol": e.protocol,
                "bytes": e.bytes,
                "entities": [x for x in e.entities],
                "iocs": [ioc.model_dump() for ioc in e.iocs],
                "raw": e.raw,
            }
        )
    df = pd.DataFrame(rows)
    df.to_parquet(path, index=False)


def write_alerts_parquet(alerts: list[Alert], path: Path) -> None:
    rows: list[dict[str, Any]] = []
    for a in alerts:
        rows.append(
            {
                "alert_id": a.alert_id,
                "event_id": a.event_id,
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity.value,
                "timestamp": a.timestamp,
                "source": a.source,
                "entities": [x for x in a.entities],
                "iocs": [ioc.model_dump() for ioc in a.iocs],
                "mitre": [m.model_dump() for m in a.mitre],
                "tags": [t for t in a.tags],
                "raw_event": a.raw_event,
            }
        )
    pd.DataFrame(rows).to_parquet(path, index=False)


def write_incidents_parquet(incidents: list[Incident], path: Path) -> None:
    rows: list[dict[str, Any]] = []
    for inc in incidents:
        rows.append(
            {
                "incident_id": inc.incident_id,
                "created_at": inc.created_at,
                "severity": inc.severity.value,
                "alert_count": inc.alert_count,
                "time_window_start": inc.time_window_start,
                "time_window_end": inc.time_window_end,
                "shared_entities": inc.shared_entities,
                "shared_iocs": [ioc.model_dump() for ioc in inc.shared_iocs],
                "mitre_techniques": [m.model_dump() for m in inc.mitre_techniques],
                "tags": inc.tags,
                "summary": inc.summary,
                "rationale": inc.rationale,
                "recommendations": inc.recommendations,
            }
        )
    pd.DataFrame(rows).to_parquet(path, index=False)


def write_incidents_json(incidents: list[Incident], path: Path) -> None:
    path.write_text(
        json.dumps([i.model_dump() for i in incidents], indent=2, default=str),
        encoding="utf-8",
    )


def write_dead_letter(dead: list[dict[str, Any]], path: Path) -> None:
    # write JSONL to keep file size reasonable
    to_jsonl(dead, path)


def write_run_summary(summary: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")


def new_run_dir(output_root: Path, run_id: str) -> Path:
    run_dir = output_root / run_id
    ensure_dir(run_dir)
    return run_dir
