from circ_platform.normalize import normalize_vpc_flow


def test_normalize_vpc_flow_direction_egress():
    raw = {
        "start": "1769940000",
        "srcaddr": "10.0.1.10",
        "dstaddr": "203.0.113.77",
        "srcport": "51544",
        "dstport": "4444",
        "protocol": "6",
        "bytes": "12582912",
        "action": "ACCEPT",
    }
    ev = normalize_vpc_flow(raw)
    assert ev.source == "vpc_flow"
    assert ev.direction == "egress"
    assert ev.bytes == 12582912
    assert ev.dst_port == 4444
