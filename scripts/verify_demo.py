import json
import sys
from pathlib import Path

BASE = Path("output/demo-run")
EXPECTED = Path("data/samples/expected/expected_summary.json")


def fail(msg: str) -> None:
    print(f"[demo verify] FAIL: {msg}")
    sys.exit(1)


def newest_run_dir(base: Path) -> Path:
    if not base.exists():
        fail(f"Missing {base}. Run: circ run --input data/samples --output output/demo-run")

    run_dirs = [p for p in base.iterdir() if p.is_dir()]
    if not run_dirs:
        fail(f"No run directories found under {base}. Run the demo first.")

    return max(run_dirs, key=lambda p: p.stat().st_mtime)


def main() -> None:
    run_dir = newest_run_dir(BASE)
    summary = run_dir / "run_summary.json"

    if not summary.exists():
        fail(f"Missing {summary}. Did the pipeline write run_summary.json?")

    if not EXPECTED.exists():
        fail(f"Missing {EXPECTED}. Create expected thresholds first.")

    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    actual = json.loads(summary.read_text(encoding="utf-8"))

    # Your summary appears to include stage JSON lines + final status; we rely on run_summary.json here.
    counts = actual.get("counts", actual)
    events = counts.get("events", 0)
    alerts = counts.get("alerts", 0)
    incidents = counts.get("incidents", 0)

    if events < expected.get("min_events", 0):
        fail(f"events {events} < min_events {expected['min_events']}")
    if alerts < expected.get("min_alerts", 0):
        fail(f"alerts {alerts} < min_alerts {expected['min_alerts']}")
    if incidents < expected.get("min_incidents", 0):
        fail(f"incidents {incidents} < min_incidents {expected['min_incidents']}")

    print("[demo verify] OK")
    print(f"run_dir={run_dir}")
    print(f"events={events} alerts={alerts} incidents={incidents}")


if __name__ == "__main__":
    main()
