from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .utils import read_text_file


def iter_ndjson(path: Path) -> Iterable[dict[str, Any]]:
    for line in read_text_file(path).splitlines():
        line = line.strip()
        if not line:
            continue
        yield json.loads(line)


def iter_csv(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield dict(row)


def detect_source(record: dict[str, Any], file_hint: str) -> str:
    # File hint first
    lh = file_hint.lower()
    if "cloudtrail" in lh:
        return "cloudtrail"
    if "vpc" in lh or "flow" in lh:
        return "vpc_flow"

    # Content heuristics
    if "eventSource" in record and "eventName" in record and "eventTime" in record:
        return "cloudtrail"
    if "srcaddr" in record and "dstaddr" in record and "action" in record:
        return "vpc_flow"
    return "generic"


def ingest_dir(input_dir: Path) -> Iterable[tuple[str, dict[str, Any], str]]:
    """
    Yields (source, raw_record, origin_file)
    """
    for path in sorted(input_dir.glob("*")):
        if path.is_dir():
            continue
        suf = path.suffix.lower()
        if suf in [".ndjson", ".jsonl"]:
            for rec in iter_ndjson(path):
                yield detect_source(rec, path.name), rec, path.name
        elif suf == ".json":
            obj = json.loads(read_text_file(path))
            if isinstance(obj, list):
                for rec in obj:
                    if isinstance(rec, dict):
                        yield detect_source(rec, path.name), rec, path.name
            elif isinstance(obj, dict):
                yield detect_source(obj, path.name), obj, path.name
        elif suf == ".csv":
            for rec in iter_csv(path):
                yield detect_source(rec, path.name), rec, path.name
