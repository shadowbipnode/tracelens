from backend.config import Settings
from backend.collectors import collect_censys, collect_shodan, collect_urlscan
from backend.orchestrator import COLLECTORS, run_passive_scan


def test_orchestrator_continues_after_collector_failure(monkeypatch):
    calls = []

    def broken(target, settings):
        calls.append("broken")
        raise RuntimeError("collector failed")

    def healthy(target, settings):
        calls.append("healthy")
        return {
            "source": "wayback",
            "status": "ok",
            "data": {"captures": [], "first_seen": None},
            "errors": [],
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:01+00:00",
        }

    monkeypatch.setattr("backend.orchestrator.COLLECTORS", [broken, healthy])
    report = run_passive_scan(
        "example.com", Settings(SHODAN_API_KEY="", _env_file=None)
    )

    assert calls == ["broken", "healthy"]
    assert report["status"] == "partial"
    assert report["collectors"]["broken"]["status"] == "error"
    assert report["collectors"]["wayback"]["status"] == "ok"
    assert report["collectors"]["wayback"]["data"] == {
        "captures": [],
        "first_seen": None,
    }
    assert report["collectors"]["broken"]["error"]["recoverable"] is True
    assert report["summary"]["wayback_capture_count"] == 0


def test_orchestrator_orders_censys_after_dns_and_includes_shodan():
    assert COLLECTORS.index(collect_urlscan) < COLLECTORS.index(collect_shodan)
    assert COLLECTORS.index(collect_shodan) < COLLECTORS.index(collect_censys)


def test_orchestrator_passes_dns_context_to_censys(monkeypatch):
    received = {}

    def dns_collector(target, settings):
        return {
            "source": "dns",
            "status": "ok",
            "data": {"records": {"A": ["192.0.2.10"]}},
            "errors": [],
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:01+00:00",
        }

    def context_collector(target, settings, context=None):
        received.update(context or {})
        return {
            "source": "censys",
            "status": "skipped",
            "data": {"reason": "not_configured"},
            "errors": ["CENSYS_API_TOKEN not configured"],
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:01+00:00",
        }

    monkeypatch.setattr(
        "backend.orchestrator.COLLECTORS",
        [dns_collector, context_collector],
    )
    run_passive_scan("example.com", Settings(_env_file=None))

    assert received["dns"]["data"]["records"]["A"] == ["192.0.2.10"]


def test_missing_shodan_key_does_not_make_scan_partial(monkeypatch):
    monkeypatch.setattr("backend.orchestrator.COLLECTORS", [collect_shodan])

    report = run_passive_scan(
        "example.com", Settings(SHODAN_API_KEY="", _env_file=None)
    )

    assert report["status"] == "completed"
    assert report["collector_statuses"] == {"shodan": "skipped"}
    assert report["collectors"]["shodan"]["errors"] == [
        "SHODAN_API_KEY not configured"
    ]


def test_missing_censys_token_does_not_make_scan_partial(monkeypatch):
    monkeypatch.setattr("backend.orchestrator.COLLECTORS", [collect_censys])

    report = run_passive_scan(
        "example.com", Settings(CENSYS_API_TOKEN="", _env_file=None)
    )

    assert report["status"] == "completed"
    assert report["collector_statuses"] == {"censys": "skipped"}


def test_missing_urlscan_key_does_not_make_scan_partial(monkeypatch):
    monkeypatch.setattr("backend.orchestrator.COLLECTORS", [collect_urlscan])

    report = run_passive_scan(
        "example.com", Settings(URLSCAN_API_KEY="", _env_file=None)
    )

    assert report["status"] == "completed"
    assert report["collector_statuses"] == {"urlscan": "skipped"}
    assert report["progress"]["skipped_collectors"] == 1


def test_censys_error_makes_scan_partial(monkeypatch):
    def failed_censys(target, settings, context=None):
        return {
            "source": "censys",
            "status": "error",
            "data": {"hosts": []},
            "errors": ["rate limited"],
            "error_details": [
                {
                    "category": "rate_limited",
                    "message": "rate limited",
                    "recoverable": True,
                }
            ],
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:01+00:00",
        }

    monkeypatch.setattr(
        "backend.orchestrator.COLLECTORS", [failed_censys]
    )
    report = run_passive_scan("example.com", Settings(_env_file=None))

    assert report["status"] == "partial"


def test_timeline_limits_censys_service_events(monkeypatch):
    services = [
        {
            "port": 1000 + index,
            "protocol": "HTTP",
            "scan_time": f"2026-06-{index + 1:02d}T00:00:00Z",
        }
        for index in range(25)
    ]

    def censys_collector(target, settings, context=None):
        return {
            "source": "censys",
            "status": "ok",
            "data": {
                "hosts": [
                    {
                        "ip": "192.0.2.10",
                        "services": services,
                    }
                ]
            },
            "errors": [],
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:01+00:00",
        }

    monkeypatch.setattr(
        "backend.orchestrator.COLLECTORS", [censys_collector]
    )
    report = run_passive_scan("example.com", Settings(_env_file=None))
    events = [
        event
        for event in report["timeline"]
        if event["type"] == "censys_service_observed"
    ]

    assert len(events) == 20
