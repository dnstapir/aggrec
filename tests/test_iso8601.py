from datetime import datetime

import pytest

from aggrec.helpers import parse_iso8601_interval


def test_parse_iso8601_interval():
    # timestamp/duration
    start, duration = parse_iso8601_interval("2025-01-15T08:56:58+00:00/PT1M")
    assert start == datetime(year=2025, month=1, day=15, hour=8, minute=56, second=58, tzinfo=datetime.UTC)
    assert duration.total_seconds() == 60

    # timestamp/timestamp
    start, duration = parse_iso8601_interval("19840101T000000Z/19840115T000000Z")
    assert start == datetime(year=1984, month=1, day=1, hour=0, minute=0, second=0, tzinfo=datetime.UTC)
    assert duration.total_seconds() == 14 * 24 * 60 * 60

    # Invalid format
    with pytest.raises(ValueError):
        parse_iso8601_interval("invalid")

    # Different timezone formats
    start, duration = parse_iso8601_interval("2025-01-15T08:56:58-05:00/PT1M")
    assert start == datetime(year=2025, month=1, day=15, hour=13, minute=56, second=58, tzinfo=datetime.UTC)

    # Microsecond precision
    start, duration = parse_iso8601_interval("2025-01-15T08:56:58.123456+00:00/PT1M")
    assert start == datetime(
        year=2025, month=1, day=15, hour=8, minute=56, second=58, microsecond=123456, tzinfo=datetime.UTC
    )
    assert duration.total_seconds() == 60
