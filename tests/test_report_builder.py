from backend.report_builder import build_dns_insights, build_summary, enrich_report


def test_summary_builder_derives_normalized_metrics():
    collectors = {
        "dns": {
            "data": {
                "records": {
                    "A": ["192.0.2.1"],
                    "AAAA": ["2001:db8::1"],
                    "MX": [{"preference": 10, "exchange": "mx.example.com"}],
                    "NS": ["ns1.example.com", "ns2.example.com"],
                    "TXT": ["v=spf1 include:example.net -all"],
                }
            }
        },
        "whois": {
            "data": {
                "registrar": "Example Registrar",
                "creation_date": "2020-07-01T00:00:00+00:00",
                "updated_date": "2025-02-01T00:00:00+00:00",
            }
        },
        "crtsh": {
            "data": {
                "certificates": [{}, {}],
                "subdomains": ["a.example.com"],
            }
        },
        "wayback": {"data": {"captures": [{}, {}, {}]}},
    }
    timeline = [
        {
            "type": "whois_created",
            "timestamp": "2020-07-01T00:00:00+00:00",
        },
        {"type": "wayback_first_seen", "timestamp": "20210101000000"},
    ]

    summary = build_summary(
        "example.com",
        "completed",
        "2026-06-24T00:00:00+00:00",
        collectors,
        timeline,
    )

    assert summary == {
        "target": "example.com",
        "status": "completed",
        "domain_age_years": 5,
        "registrar": "Example Registrar",
        "nameserver_count": 2,
        "mx_count": 1,
        "txt_count": 1,
        "a_count": 1,
        "aaaa_count": 1,
        "certificate_count": 2,
        "subdomain_count": 1,
        "wayback_capture_count": 3,
        "first_seen": "2020-07-01T00:00:00+00:00",
        "last_updated": "2025-02-01T00:00:00+00:00",
    }


def test_dns_insights_are_evidence_backed():
    collectors = {
        "dns": {
            "data": {
                "records": {
                    "MX": [
                        {
                            "preference": 10,
                            "exchange": "aspmx.l.google.com",
                        }
                    ],
                    "NS": [
                        "ada.ns.cloudflare.com",
                        "ns1-01.azure-dns.com",
                    ],
                    "TXT": [
                        "v=spf1 include:_spf.google.com ~all",
                        "v=DMARC1; p=reject",
                        "google-site-verification=one",
                        "atlassian-domain-verification=two",
                        "facebook-domain-verification=three",
                    ],
                    "CAA": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}],
                }
            }
        }
    }

    insights = build_dns_insights(collectors)
    titles = {insight["title"] for insight in insights}

    assert {
        "Google Workspace detected",
        "Azure DNS detected",
        "Cloudflare detected",
        "SPF configured",
        "DMARC configured",
        "CAA configured",
        "Large SaaS footprint",
    }.issubset(titles)
    assert all(insight["evidence"] for insight in insights)


def test_enrich_report_upgrades_existing_report_shape():
    report = {
        "target": "example.com",
        "status": "completed",
        "completed_at": "2026-06-24T00:00:00+00:00",
        "collectors": {},
        "timeline": [
            {
                "type": "scan_completed",
                "timestamp": "2026-06-24T00:00:00+00:00",
                "source": "scan",
            }
        ],
    }

    enriched = enrich_report(report)

    assert enriched["summary"]["target"] == "example.com"
    assert enriched["insights"] == []
    assert enriched["timeline"][0]["label"] == "Scan completed"
