from pathlib import Path

from circ_platform.detect import load_rules, run_detection
from circ_platform.enrich import enrich_events
from circ_platform.normalize import normalize_cloudtrail, normalize_vpc_flow


def test_rules_fire_on_samples():
    rules = load_rules(Path("rules"))

    ct = normalize_cloudtrail(
        {
            "eventTime": "2026-02-01T09:05:00Z",
            "eventName": "AssumeRole",
            "sourceIPAddress": "198.51.100.25",
            "userIdentity": {"type": "IAMUser", "userName": "bob"},
            "requestParameters": {"roleArn": "arn:aws:iam::123:role/AdminAccess"},
        }
    )
    vpc = normalize_vpc_flow(
        {
            "start": "1769940000",
            "srcaddr": "10.0.1.10",
            "dstaddr": "203.0.113.77",
            "dstport": "4444",
            "srcport": "51544",
            "protocol": "6",
            "bytes": "12582912",
            "action": "ACCEPT",
        }
    )

    events = enrich_events([ct, vpc])
    alerts = run_detection(events, rules)
    rule_ids = {a.rule_id for a in alerts}
    assert "CT-IAM-001" in rule_ids
    assert "VPC-NET-001" in rule_ids
