from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st


DEFAULT_OUTPUT_ROOT = Path("output")


@dataclass(frozen=True)
class RunInfo:
    run_dir: Path
    run_id: str


def _is_run_dir(p: Path) -> bool:
    return p.is_dir() and (p / "incidents.json").exists()


@st.cache_data(show_spinner=False)
def list_runs(output_root: Path) -> list[RunInfo]:
    if not output_root.exists():
        return []
    runs = [p for p in output_root.iterdir() if _is_run_dir(p)]
    runs_sorted = sorted(runs, key=lambda x: x.name, reverse=True)
    return [RunInfo(run_dir=p, run_id=p.name) for p in runs_sorted]


@st.cache_data(show_spinner=False)
def load_run_summary(run_dir: Path) -> dict[str, Any]:
    p = run_dir / "run_summary.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


@st.cache_data(show_spinner=False)
def load_incidents(run_dir: Path) -> list[dict[str, Any]]:
    p = run_dir / "incidents.json"
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8"))


@st.cache_data(show_spinner=False)
def load_alerts_parquet(run_dir: Path) -> pd.DataFrame:
    p = run_dir / "alerts.parquet"
    if not p.exists():
        return pd.DataFrame()
    return pd.read_parquet(p)


def severity_rank(sev: str) -> int:
    m = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return m.get((sev or "").lower(), 0)
