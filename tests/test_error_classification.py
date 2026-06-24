import json

import httpx
import pytest

from backend.collectors.base import CollectorParseError, classify_collector_error


def http_error(status_code):
    request = httpx.Request("GET", "https://source.example")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(
        "source request failed", request=request, response=response
    )


@pytest.mark.parametrize(
    ("error", "category"),
    [
        (httpx.ReadTimeout("timed out"), "timeout"),
        (TimeoutError("timed out"), "timeout"),
        (http_error(408), "timeout"),
        (http_error(401), "invalid_credentials"),
        (http_error(403), "forbidden"),
        (http_error(429), "rate_limited"),
        (http_error(503), "unavailable"),
        (http_error(404), "bad_response"),
        (httpx.ConnectError("connection failed"), "network_error"),
        (CollectorParseError("unexpected payload"), "parse_error"),
        (
            json.JSONDecodeError("invalid JSON", "not-json", 0),
            "parse_error",
        ),
        (RuntimeError("unknown failure"), "unexpected_error"),
    ],
)
def test_error_classification(error, category):
    detail = classify_collector_error(error)

    assert detail["category"] == category
    assert detail["message"]
    assert detail["recoverable"] is True
