from backend.config import Settings
from backend.orchestrator import run_passive_scan


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
    report = run_passive_scan("example.com", Settings())

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
