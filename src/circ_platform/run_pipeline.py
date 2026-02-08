from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import AppConfig
from .correlate import correlate_alerts
from .detect import load_rules, run_detection
from .enrich import enrich_events
from .ingest import ingest_dir
from .logging_utils import StageTimer
from .normalize import normalize_record
from .storage import (
    new_run_dir,
    write_alerts_parquet,
    write_dead_letter,
    write_events_parquet,
    write_incidents_json,
    write_incidents_parquet,
    write_run_summary,
)


def iso_run_id() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H-%M-%SZ")


def run_pipeline(
    cfg: AppConfig, input_dir: Path | None = None, output_root: Path | None = None
) -> Path:
    input_dir = input_dir or cfg.input_dir
    output_root = output_root or cfg.output_root

    run_id = iso_run_id()
    run_dir = new_run_dir(output_root, run_id)

    summary: dict[str, Any] = {"run_id": run_id, "outputs": {}, "counts": {}, "stages": []}

    # Ingest + Normalize
    dead_letter: list[dict[str, Any]] = []
    events = []
    t = StageTimer("ingest_normalize", {"input_dir": str(input_dir)})
    ingested = 0
    for source, raw, origin_file in ingest_dir(input_dir):
        ingested += 1
        try:
            ev = normalize_record(source, raw)
            ev.tags.append(f"origin:{origin_file}")
            events.append(ev)
        except Exception as e:
            dead_letter.append(
                {"origin_file": origin_file, "source": source, "error": str(e), "raw": raw}
            )
    summary["stages"].append(
        t.finish(records_in=ingested, records_out=len(events), dead=len(dead_letter))
    )

    # Enrich
    t = StageTimer("enrich", {})
    events = enrich_events(events)
    summary["stages"].append(t.finish(records_in=len(events), records_out=len(events)))

    # Detect
    t = StageTimer("detect", {"rules_dir": str(cfg.rules_dir)})
    rules = load_rules(cfg.rules_dir)
    alerts = run_detection(events, rules)
    summary["stages"].append(t.finish(events=len(events), rules=len(rules), alerts=len(alerts)))

    # Correlate
    t = StageTimer("correlate", {"window_min": cfg.correlation_window_minutes})
    incidents = correlate_alerts(
        alerts,
        correlation_window_minutes=cfg.correlation_window_minutes,
        min_shared_entities=cfg.min_shared_entities,
        max_alerts_per_incident=cfg.max_alerts_per_incident,
        severity_escalation_threshold=cfg.severity_escalation_threshold,
    )
    summary["stages"].append(t.finish(alerts=len(alerts), incidents=len(incidents)))

    # Write outputs (append-only + sidecars per spec guarantees)
    t = StageTimer("write", {"run_dir": str(run_dir)})
    events_pq = run_dir / "events.parquet"
    alerts_pq = run_dir / "alerts.parquet"
    inc_pq = run_dir / "incidents.parquet"
    inc_json = run_dir / "incidents.json"
    dead_path = run_dir / "dead_letter.jsonl"
    run_summary_path = run_dir / "run_summary.json"

    write_events_parquet(events, events_pq)
    write_alerts_parquet(alerts, alerts_pq)
    write_incidents_parquet(incidents, inc_pq)
    write_incidents_json(incidents, inc_json)
    write_dead_letter(dead_letter, dead_path)
    summary["stages"].append(t.finish())

    summary["counts"] = {
        "events": len(events),
        "alerts": len(alerts),
        "incidents": len(incidents),
        "dead_letter": len(dead_letter),
    }
    summary["outputs"] = {
        "run_dir": str(run_dir),
        "events_parquet": str(events_pq),
        "alerts_parquet": str(alerts_pq),
        "incidents_parquet": str(inc_pq),
        "incidents_json": str(inc_json),
        "dead_letter_jsonl": str(dead_path),
    }
    write_run_summary(summary, run_summary_path)

    return run_dir
