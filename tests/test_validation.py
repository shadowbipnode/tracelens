import pytest

from backend.models.target import validate_domain


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "example.com"),
        ("sub.example.com", "sub.example.com"),
        ("EXAMPLE.COM", "example.com"),
    ],
)
def test_valid_domains(value, expected):
    assert validate_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "localhost",
        "127.0.0.1",
        "example.com/path",
        "example.com?query=1",
        "example.com#fragment",
        "example .com",
        " example.com",
        "example.com;rm -rf",
        "$(whoami).example.com",
        "example",
        "-example.com",
        "example.c",
    ],
)
def test_invalid_domains(value):
    with pytest.raises(ValueError):
        validate_domain(value)
