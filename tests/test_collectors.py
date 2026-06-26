from datetime import datetime, timezone

import httpx
import pytest

from backend.collectors import (
    censys,
    crtsh,
    dns,
    shodan,
    urlscan,
    wayback,
    whois,
)
from backend.config import Settings
from backend.models.report import CollectorResult


def assert_structure(result, source):
    parsed = CollectorResult.model_validate(result)
    assert parsed.source == source
    assert parsed.completed_at


class Response:
    def __init__(self, payload):
        self.payload = payload
        self.status_code = 200
        self.text = "response"

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_dns_collector_structure(monkeypatch):
    class Resolver:
        def resolve(self, target, record_type, lifetime):
            if record_type == "A":
                return ["93.184.216.34"]
            raise dns.dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.dns.resolver, "Resolver", Resolver)
    result = dns.collect_dns("example.com")

    assert_structure(result, "dns")
    assert result["data"]["records"]["A"] == ["93.184.216.34"]


def test_whois_collector_structure(monkeypatch):
    payload = {
        "registrar": "Registrar",
        "creation_date": datetime(1995, 8, 14, tzinfo=timezone.utc),
        "expiration_date": None,
        "updated_date": None,
        "name_servers": ["NS1.EXAMPLE.COM"],
        "emails": "hostmaster@example.com",
    }
    monkeypatch.setattr(whois.whois, "whois", lambda target: payload)
    result = whois.collect_whois("example.com")

    assert_structure(result, "whois")
    assert result["data"]["creation_date"] == "1995-08-14T00:00:00+00:00"


def test_crtsh_collector_structure(monkeypatch):
    payload = [
        {
            "common_name": "www.example.com",
            "name_value": "www.example.com\n*.api.example.com",
            "issuer_name": "Example CA",
            "not_before": "2025-01-01T00:00:00",
            "not_after": "2025-04-01T00:00:00",
            "serial_number": "01",
        }
    ]
    monkeypatch.setattr(crtsh.httpx, "get", lambda *args, **kwargs: Response(payload))
    result = crtsh.collect_crtsh("example.com", Settings())

    assert_structure(result, "crtsh")
    assert result["data"]["subdomains"] == ["api.example.com", "www.example.com"]


def test_wayback_collector_structure(monkeypatch):
    payload = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20010101000000", "http://example.com/", "200", "text/html"],
    ]
    monkeypatch.setattr(
        wayback.httpx, "get", lambda *args, **kwargs: Response(payload)
    )
    result = wayback.collect_wayback("example.com", Settings())

    assert_structure(result, "wayback")
    assert result["data"]["first_seen"] == "20010101000000"


def test_collector_failure_is_structured(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("source unavailable")

    monkeypatch.setattr(crtsh.httpx, "get", fail)
    result = crtsh.collect_crtsh("example.com", Settings())

    assert_structure(result, "crtsh")
    assert result["status"] == "error"
    assert result["errors"] == ["source unavailable"]
    assert result["error"] == {
        "category": "unexpected_error",
        "message": "source unavailable",
        "recoverable": True,
    }


def test_wayback_unexpected_payload_is_parse_error(monkeypatch):
    monkeypatch.setattr(
        wayback.httpx,
        "get",
        lambda *args, **kwargs: Response({"unexpected": "payload"}),
    )

    result = wayback.collect_wayback("example.com", Settings())

    assert result["status"] == "error"
    assert result["error"]["category"] == "parse_error"


def test_shodan_skips_when_api_key_is_missing():
    result = shodan.collect_shodan(
        "example.com", Settings(SHODAN_API_KEY="", _env_file=None)
    )

    assert_structure(result, "shodan")
    assert result["status"] == "skipped"
    assert result["errors"] == ["SHODAN_API_KEY not configured"]
    assert result["error"] == {
        "category": "not_configured",
        "message": "SHODAN_API_KEY not configured",
        "recoverable": True,
    }


def test_shodan_parses_passive_domain_response(monkeypatch):
    payload = {
        "domain": "example.com",
        "tags": ["cdn", "ipv6"],
        "subdomains": ["api", "www.example.com"],
        "data": [
            {
                "subdomain": "api",
                "type": "A",
                "value": "192.0.2.10",
                "last_seen": "2026-06-20",
            },
            {
                "subdomain": "mail",
                "type": "MX",
                "value": "mx.example.net",
                "last_seen": "2026-06-21",
            },
        ],
        "more": False,
    }
    monkeypatch.setattr(
        shodan.httpx,
        "get",
        lambda *args, **kwargs: Response(payload),
    )

    result = shodan.collect_shodan(
        "example.com", Settings(SHODAN_API_KEY="test-key", _env_file=None)
    )

    assert_structure(result, "shodan")
    assert result["status"] == "ok"
    assert result["data"]["subdomains"] == [
        "api.example.com",
        "mail.example.com",
        "www.example.com",
    ]
    assert result["data"]["records"][0] == {
        "subdomain": "api",
        "fqdn": "api.example.com",
        "type": "A",
        "value": "192.0.2.10",
        "last_seen": "2026-06-20",
    }
    assert result["data"]["tags"] == ["cdn", "ipv6"]
    assert result["data"]["subdomain_count"] == 3
    assert result["data"]["record_count"] == 2
    assert result["data"]["source_metadata"] == {
        "endpoint": "dns/domain",
        "domain": "example.com",
        "more": False,
    }


@pytest.mark.parametrize(
    ("status_code", "category"),
    [
        (401, "invalid_credentials"),
        (403, "forbidden"),
        (429, "rate_limited"),
        (500, "unavailable"),
        (503, "unavailable"),
    ],
)
def test_shodan_http_errors_are_structured(monkeypatch, status_code, category):
    def fail(*args, **kwargs):
        request = httpx.Request("GET", "https://api.shodan.io/dns/domain/example.com")
        response = httpx.Response(status_code, request=request)
        raise httpx.HTTPStatusError(
            f"Shodan returned {status_code}",
            request=request,
            response=response,
        )

    monkeypatch.setattr(shodan.httpx, "get", fail)

    result = shodan.collect_shodan(
        "example.com", Settings(SHODAN_API_KEY="test-key", _env_file=None)
    )

    assert_structure(result, "shodan")
    assert result["status"] == "error"
    assert result["error"]["category"] == category
    assert result["error"]["recoverable"] is True


def test_shodan_timeout_is_structured(monkeypatch):
    def fail(*args, **kwargs):
        raise httpx.ReadTimeout("Shodan timed out")

    monkeypatch.setattr(shodan.httpx, "get", fail)

    result = shodan.collect_shodan(
        "example.com", Settings(SHODAN_API_KEY="test-key", _env_file=None)
    )

    assert result["status"] == "error"
    assert result["error"]["category"] == "timeout"


def test_censys_skips_when_token_is_missing():
    result = censys.collect_censys(
        "example.com",
        Settings(CENSYS_API_TOKEN="", _env_file=None),
        context={"dns": {"data": {"records": {"A": ["192.0.2.10"]}}}},
    )

    assert_structure(result, "censys")
    assert result["status"] == "skipped"
    assert result["data"]["reason"] == "not_configured"
    assert result["error"]["category"] == "not_configured"


def test_censys_skips_when_dns_has_no_addresses():
    result = censys.collect_censys(
        "example.com",
        Settings(CENSYS_API_TOKEN="token", _env_file=None),
        context={"dns": {"data": {"records": {"MX": []}}}},
    )

    assert_structure(result, "censys")
    assert result["status"] == "skipped"
    assert result["data"]["reason"] == "no_ip_addresses"
    assert result["error"]["category"] == "no_ip_addresses"


def test_censys_parses_host_response(monkeypatch):
    payload = {
        "result": {
            "resource": {
                "ip": "192.0.2.10",
                "location": {
                    "country": "Italy",
                    "country_code": "IT",
                    "city": "Rome",
                },
                "autonomous_system": {
                    "asn": 64500,
                    "name": "Example Cloud",
                    "description": "Example Cloud Network",
                    "bgp_prefix": "192.0.2.0/24",
                    "country_code": "IT",
                },
                "whois": {
                    "organization": "Example Hosting",
                    "network": {"name": "EXAMPLE-NET"},
                },
                "services": [
                    {
                        "port": 443,
                        "protocol": "HTTP",
                        "transport_protocol": "TCP",
                        "scan_time": "2026-06-20T10:00:00Z",
                        "service_name": "HTTPS",
                        "software": [
                            {
                                "vendor": "nginx",
                                "product": "nginx",
                                "version": "1.25",
                            }
                        ],
                        "http": {
                            "response": {
                                "html_title": "Example",
                                "headers": {"Server": ["nginx"]},
                            }
                        },
                        "tls": {
                            "certificates": {
                                "leaf_data": {
                                    "names": [
                                        "example.com",
                                        "www.example.com",
                                    ],
                                    "issuer_dn": "CN=Example CA",
                                    "serial_number": "01",
                                    "not_before": "2026-01-01T00:00:00Z",
                                    "not_after": "2026-04-01T00:00:00Z",
                                }
                            }
                        },
                    }
                ],
            }
        }
    }
    monkeypatch.setattr(
        censys.httpx,
        "get",
        lambda *args, **kwargs: Response(payload),
    )

    result = censys.collect_censys(
        "example.com",
        Settings(CENSYS_API_TOKEN="token", _env_file=None),
        context={"dns": {"data": {"records": {"A": ["192.0.2.10"]}}}},
    )

    assert_structure(result, "censys")
    assert result["status"] == "ok"
    assert result["data"]["host_count"] == 1
    assert result["data"]["service_count"] == 1
    assert result["data"]["ports"] == [443]
    assert result["data"]["protocols"] == ["HTTP"]
    assert result["data"]["asns"] == [64500]
    assert result["data"]["hosts"][0]["services"][0][
        "tls_certificate_names"
    ] == ["example.com", "www.example.com"]
    assert result["data"]["observed_technologies"] == ["nginx 1.25"]
    assert result["data"]["certificates"][0]["issuer"] == "CN=Example CA"
    assert result["data"]["hosts"][0]["services"][0]["title"] == "Example"


@pytest.mark.parametrize(
    ("status_code", "category"),
    [
        (401, "invalid_credentials"),
        (403, "plan_restricted"),
        (429, "rate_limited"),
        (500, "unavailable"),
        (503, "unavailable"),
    ],
)
def test_censys_http_errors_are_structured(
    monkeypatch, status_code, category
):
    def fail(*args, **kwargs):
        request = httpx.Request(
            "GET",
            "https://api.platform.censys.io/v3/global/asset/host/192.0.2.10",
        )
        response = httpx.Response(status_code, request=request)
        raise httpx.HTTPStatusError(
            f"Censys returned {status_code}",
            request=request,
            response=response,
        )

    monkeypatch.setattr(censys.httpx, "get", fail)
    result = censys.collect_censys(
        "example.com",
        Settings(CENSYS_API_TOKEN="token", _env_file=None),
        context={"dns": {"data": {"records": {"A": ["192.0.2.10"]}}}},
    )

    assert result["status"] == "error"
    assert result["error"]["category"] == category
    assert result["error"]["ip"] == "192.0.2.10"


def test_censys_timeout_is_structured(monkeypatch):
    monkeypatch.setattr(
        censys.httpx,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            httpx.ReadTimeout("Censys timed out")
        ),
    )

    result = censys.collect_censys(
        "example.com",
        Settings(CENSYS_API_TOKEN="token", _env_file=None),
        context={"dns": {"data": {"records": {"A": ["192.0.2.10"]}}}},
    )

    assert result["status"] == "error"
    assert result["error"]["category"] == "timeout"


@pytest.mark.parametrize("payload", [["unexpected"], {"result": {"total": 1}}])
def test_censys_invalid_payload_is_parse_error(monkeypatch, payload):
    monkeypatch.setattr(
        censys.httpx,
        "get",
        lambda *args, **kwargs: Response(payload),
    )

    result = censys.collect_censys(
        "example.com",
        Settings(CENSYS_API_TOKEN="token", _env_file=None),
        context={"dns": {"data": {"records": {"A": ["192.0.2.10"]}}}},
    )

    assert result["status"] == "error"
    assert result["error"]["category"] == "parse_error"


def test_urlscan_skips_when_api_key_is_missing():
    result = urlscan.collect_urlscan(
        "example.com", Settings(URLSCAN_API_KEY="", _env_file=None)
    )

    assert_structure(result, "urlscan")
    assert result["status"] == "skipped"
    assert result["data"]["reason"] == "not_configured"
    assert result["error"]["category"] == "not_configured"


def test_urlscan_parses_search_response(monkeypatch):
    payload = {
        "total": 2,
        "results": [
            {
                "task": {"time": "2026-06-20T10:00:00Z"},
                "page": {
                    "url": "https://example.com/",
                    "domain": "example.com",
                    "ip": "192.0.2.10",
                    "asn": "AS64500",
                    "asnname": "Example Network",
                    "country": "IT",
                    "server": "cloudflare",
                    "mimeType": "text/html",
                    "title": "Example Domain",
                    "faviconHash": "12345",
                },
                "technologies": ["React", "Cloudflare"],
                "frameworks": ["React"],
                "resourceDomains": ["cdn.example.net"],
                "linkedDomains": ["docs.example.net"],
                "scriptDomains": ["scripts.example.net"],
                "analytics": ["Google Analytics"],
                "tracking": ["Google Tag Manager"],
                "verdicts": {"overall": {"malicious": False}},
                "screenshot": "https://urlscan.io/screenshots/example.png",
            },
            {
                "task": {"time": "2026-06-21T10:00:00Z"},
                "page": {
                    "url": "https://www.example.com/",
                    "domain": "www.example.com",
                    "ip": "192.0.2.11",
                    "country": "US",
                },
            },
        ],
    }
    monkeypatch.setattr(
        urlscan.httpx, "get", lambda *args, **kwargs: Response(payload)
    )

    result = urlscan.collect_urlscan(
        "example.com", Settings(URLSCAN_API_KEY="key", _env_file=None)
    )

    assert result["status"] == "ok"
    assert result["data"]["result_count"] == 2
    assert result["data"]["domains"] == ["example.com", "www.example.com"]
    assert result["data"]["ips"] == ["192.0.2.10", "192.0.2.11"]
    assert result["data"]["screenshot_count"] == 1
    assert result["data"]["titles"] == ["Example Domain"]
    assert result["data"]["technologies"] == ["Cloudflare", "React"]
    assert result["data"]["frameworks"] == ["React"]
    assert result["data"]["resource_domains"] == ["cdn.example.net"]
    assert result["data"]["linked_domains"] == ["docs.example.net"]
    assert result["data"]["script_domains"] == ["scripts.example.net"]
    assert result["data"]["favicon_hashes"] == ["12345"]
    assert result["data"]["cdn"] == ["Cloudflare"]


def test_urlscan_errors_are_structured(monkeypatch):
    monkeypatch.setattr(
        urlscan.httpx,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            httpx.ReadTimeout("URLScan timed out")
        ),
    )

    result = urlscan.collect_urlscan(
        "example.com", Settings(URLSCAN_API_KEY="key", _env_file=None)
    )

    assert result["status"] == "error"
    assert result["error"]["category"] == "timeout"
