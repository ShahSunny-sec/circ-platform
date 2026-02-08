from __future__ import annotations

import argparse
from pathlib import Path

from cir.config import AppConfig, load_config_from_env
from cir.correlate import correlate_alerts_to_incidents
from cir.detect import run_detection
from cir.enrich import enrich_events
from cir.ingest import discover_inputs
from cir.normalize import normalize_all
from cir.storage import (
    ensure_output_dir,
    write_alerts_parquet,
    write_events_parquet,
    write_incidents_json,
    write_rule_report_json,
)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Cloud Incident Response & Event Correlation Platform (MVP)"
    )
    p.add_argument("--input", type=str, default=None, help="Input directory (overrides env)")
    p.add_argument("--output", type=str, default=None, help="Output directory (overrides env)")
    p.add_argument("--rules", type=str, default=None, help="Rules YAML path (overrides env)")
    p.add_argument(
        "--window-minutes",
        type=int,
        default=None,
        help="Correlation time window in minutes (overrides env)",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing processed files",
    )
    return p


def main() -> int:
    args = build_arg_parser().parse_args()
    cfg: AppConfig = load_config_from_env()

    if args.input:
        cfg.input_dir = Path(args.input)
    if args.output:
        cfg.output_dir = Path(args.output)
    if args.rules:
        cfg.rules_path = Path(args.rules)
    if args.window_minutes is not None:
        cfg.correlation_window_minutes = args.window_minutes
    if args.overwrite:
        cfg.overwrite = True

    ensure_output_dir(cfg.output_dir)

    inputs = discover_inputs(cfg.input_dir)
    if not inputs.cloudtrail_files and not inputs.vpcflow_files:
        raise SystemExit(
            f"No supported log files found in {cfg.input_dir}. "
            "Expected CloudTrail *.jsonl and/or VPC Flow *.csv."
        )

    # 1) Normalize
    events_df = normalize_all(inputs)

    # 2) Enrich
    enriched_df = enrich_events(events_df)

    # 3) Detect
    alerts_df, rule_report = run_detection(enriched_df, cfg.rules_path)

    # 4) Correlate
    incidents = correlate_alerts_to_incidents(
        alerts_df=alerts_df,
        events_df=enriched_df,
        window_minutes=cfg.correlation_window_minutes,
    )

    # 5) Persist
    events_path = cfg.output_dir / "events_enriched.parquet"
    alerts_path = cfg.output_dir / "alerts.parquet"
    incidents_path = cfg.output_dir / "incidents.json"
    report_path = cfg.output_dir / "rule_report.json"

    if (
        events_path.exists() or alerts_path.exists() or incidents_path.exists()
    ) and not cfg.overwrite:
        raise SystemExit(
            "Processed outputs already exist. Re-run with CIR_OVERWRITE=true or --overwrite."
        )

    write_events_parquet(enriched_df, events_path)
    write_alerts_parquet(alerts_df, alerts_path)
    write_incidents_json(incidents, incidents_path)
    write_rule_report_json(rule_report, report_path)

    print("\n✅ Pipeline completed successfully.")
    print(f"- Enriched events:  {events_path}")
    print(f"- Alerts:          {alerts_path}")
    print(f"- Incidents:       {incidents_path}")
    print(f"- Rule report:     {report_path}")
    print("\nRun the UI:")
    print("  streamlit run ui/app.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
