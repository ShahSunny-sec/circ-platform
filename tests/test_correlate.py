from datetime import UTC, datetime

from circ_platform.correlate import correlate_alerts
from circ_platform.models import IOC, Alert, MitreMapping, Severity


def test_correlate_by_shared_entity_within_window():
    t0 = datetime(2026, 2, 1, 9, 0, 0, tzinfo=UTC)
    a1 = Alert(
        alert_id="a1",
        event_id="e1",
        rule_id="CT-AUTH-001",
        rule_name="x",
        severity=Severity.medium,
        timestamp=t0,
        source="cloudtrail",
        entities=["203.0.113.10", "alice"],
        iocs=[IOC(type="ip", value="203.0.113.10")],
        mitre=[
            MitreMapping(
                technique_id="T1110", technique_name="Brute Force", tactic="initial_access"
            )
        ],
        tags=[],
        raw_event={},
    )
    a2 = Alert(
        alert_id="a2",
        event_id="e2",
        rule_id="CT-AUTH-001",
        rule_name="x",
        severity=Severity.medium,
        timestamp=t0,
        source="cloudtrail",
        entities=["203.0.113.10", "alice"],
        iocs=[IOC(type="ip", value="203.0.113.10")],
        mitre=[
            MitreMapping(
                technique_id="T1110", technique_name="Brute Force", tactic="initial_access"
            )
        ],
        tags=[],
        raw_event={},
    )

    inc = correlate_alerts(
        [a1, a2],
        correlation_window_minutes=15,
        min_shared_entities=1,
        max_alerts_per_incident=500,
        severity_escalation_threshold=3,
    )
    assert len(inc) == 1
    assert inc[0].alert_count == 2
    assert "203.0.113.10" in inc[0].shared_entities
