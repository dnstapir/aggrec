import pytest
from pydantic import ValidationError

from aggrec.settings import HttpSettings, size_string


@pytest.mark.parametrize(
    "value,expected",
    [
        (1234, 1234),
        (None, None),
        ("1234", 1234),
        ("10B", 10),
        ("10KB", 10 * 1024),
        ("10KiB", 10 * 1024),
        ("100MB", 100 * 1024**2),
        ("100MiB", 100 * 1024**2),
        ("2GB", 2 * 1024**3),
        ("2gib", 2 * 1024**3),
        ("1TB", 1024**4),
        ("1TiB", 1024**4),
        (" 2 GiB ", 2 * 1024**3),
    ],
)
def test_size_string(value, expected):
    assert size_string(value) == expected


@pytest.mark.parametrize("value", ["1.5GB", "GiB", "10XB"])
def test_size_string_invalid(value):
    with pytest.raises(ValueError):
        size_string(value)


@pytest.mark.parametrize("value", [0, -1, "0", "-1MB"])
def test_http_max_content_length_must_be_positive(value):
    with pytest.raises(ValidationError):
        HttpSettings(max_content_length=value)


def test_http_max_content_length_parsed():
    assert HttpSettings(max_content_length="10MiB").max_content_length == 10 * 1024**2
    assert HttpSettings().max_content_length is None
