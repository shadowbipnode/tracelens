from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch) -> Iterator[TestClient]:
    settings = Settings(db_path=str(tmp_path / "tracelens.sqlite3"))

    def collector(source, data):
        def run(target, settings):
            return {
                "source": source,
                "status": "ok",
                "data": data,
                "errors": [],
                "started_at": "2026-01-01T00:00:00+00:00",
                "completed_at": "2026-01-01T00:00:01+00:00",
            }

        return run

    monkeypatch.setattr(
        "backend.orchestrator.COLLECTORS",
        [
            collector("dns", {"records": {"A": ["93.184.216.34"]}}),
            collector(
                "whois",
                {
                    "registrar": "Example Registrar",
                    "creation_date": "1995-08-14T00:00:00+00:00",
                    "updated_date": None,
                },
            ),
            collector("crtsh", {"certificates": [], "subdomains": []}),
            collector("wayback", {"captures": [], "first_seen": None}),
        ],
    )

    with TestClient(create_app(settings)) as test_client:
        yield test_client
