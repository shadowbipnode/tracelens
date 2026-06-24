from backend.config import Settings
from backend.collectors import collect_shodan
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


def test_orchestrator_includes_shodan_after_m1_collectors():
    assert COLLECTORS[-1] is collect_shodan


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
