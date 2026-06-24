def test_health(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_invalid_scan_target_returns_422(client):
    response = client.post("/api/scans", json={"target": "https://example.com"})

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "target"]


def test_create_list_and_retrieve_scan(client):
    created = client.post("/api/scans", json={"target": "example.com"})

    assert created.status_code == 201
    assert created.json() == {"scan_id": 1, "status": "completed"}

    scans = client.get("/api/scans")
    assert scans.status_code == 200
    assert len(scans.json()) == 1
    assert scans.json()[0]["target"] == "example.com"
    assert scans.json()[0]["status"] == "completed"

    metadata = client.get("/api/scans/1")
    assert metadata.status_code == 200
    assert metadata.json()["collector_statuses"] == {
        "dns": "ok",
        "whois": "ok",
        "crtsh": "ok",
        "wayback": "ok",
    }

    report = client.get("/api/scans/1/report")
    assert report.status_code == 200
    assert report.json()["scan_id"] == 1
    assert report.json()["collectors"]["dns"]["data"]["records"]["A"] == [
        "93.184.216.34"
    ]
    assert any(
        event["type"] == "whois_created" for event in report.json()["timeline"]
    )


def test_missing_scan_returns_404(client):
    assert client.get("/api/scans/99").status_code == 404
    assert client.get("/api/scans/99/report").status_code == 404
