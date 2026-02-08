from circ_platform.normalize import normalize_cloudtrail


def test_normalize_cloudtrail_basic():
    raw = {
        "eventTime": "2026-02-01T09:00:05Z",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": {"type": "IAMUser", "userName": "alice"},
    }
    ev = normalize_cloudtrail(raw)
    assert ev.source == "cloudtrail"
    assert ev.action == "ConsoleLogin"
    assert ev.source_ip == "203.0.113.10"
    assert ev.username == "alice"
