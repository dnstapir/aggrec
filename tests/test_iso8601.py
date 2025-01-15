from datetime import datetime, timezone

from aggrec.helpers import parse_iso8601_interval


def test_parse_iso8601_interval():
    start, duration = parse_iso8601_interval("2025-01-15T08:56:58+00:00/PT1M")
    assert start == datetime(year=2025, month=1, day=15, hour=8, minute=56, second=58, tzinfo=timezone.utc)
    assert duration.total_seconds() == 60
