from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_config
from .logging_utils import setup_logging
from .run_pipeline import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="circ", description="CIRC Platform (MVP) - batch pipeline"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    runp = sub.add_parser("run", help="Run ingest->normalize->enrich->detect->correlate->write")
    runp.add_argument(
        "--input", type=str, default=None, help="Input directory (default from config)"
    )
    runp.add_argument(
        "--output", type=str, default=None, help="Output root dir (default from config)"
    )
    runp.add_argument("--log-level", type=str, default="INFO")

    args = parser.parse_args()
    setup_logging(args.log_level)

    cfg = load_config()

    if args.cmd == "run":
        input_dir = Path(args.input) if args.input else None
        output_root = Path(args.output) if args.output else None
        run_dir = run_pipeline(cfg, input_dir=input_dir, output_root=output_root)
        print(json.dumps({"status": "ok", "run_dir": str(run_dir)}, indent=2))


if __name__ == "__main__":
    main()
