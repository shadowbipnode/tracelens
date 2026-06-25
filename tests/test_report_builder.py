from backend.report_builder import (
    build_censys_insights,
    build_dns_insights,
    build_graph,
    build_infrastructure,
    build_progress,
    build_shodan_insights,
    build_summary,
    enrich_report,
)


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
        "shodan": {
            "data": {
                "subdomains": ["api.example.com", "mail.example.com"],
                "records": [{}, {}, {}],
            }
        },
        "censys": {
            "data": {
                "host_count": 2,
                "service_count": 4,
                "asns": [64500, 64501],
                "ports": [80, 443],
            }
        },
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
        "shodan_subdomain_count": 2,
        "shodan_record_count": 3,
        "censys_host_count": 2,
        "censys_service_count": 4,
        "censys_asn_count": 2,
        "censys_port_count": 2,
        "urlscan_result_count": 0,
        "urlscan_domain_count": 0,
        "urlscan_ip_count": 0,
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


def test_shodan_insights_cover_available_skipped_and_error_states():
    available = build_shodan_insights(
        {
            "shodan": {
                "status": "ok",
                "data": {
                    "subdomain_count": 2,
                    "record_count": 3,
                    "tags": ["cdn"],
                },
            }
        }
    )
    skipped = build_shodan_insights(
        {
            "shodan": {
                "status": "skipped",
                "data": {},
                "errors": ["SHODAN_API_KEY not configured"],
            }
        }
    )
    unavailable = build_shodan_insights(
        {
            "shodan": {
                "status": "error",
                "data": {},
                "errors": ["rate limited"],
                "error": {
                    "category": "rate_limited",
                    "message": "rate limited",
                    "recoverable": True,
                },
            }
        }
    )

    assert available[0]["title"] == "Shodan passive data available"
    assert skipped == []
    assert unavailable == []


def test_censys_insights_are_evidence_backed():
    insights = build_censys_insights(
        {
            "censys": {
                "status": "ok",
                "data": {
                    "host_count": 2,
                    "service_count": 3,
                    "ports": [80, 443],
                    "protocols": ["HTTP"],
                    "asns": [13335, 64500],
                    "organizations": ["Cloudflare, Inc.", "Example Net"],
                    "locations": ["Rome, IT"],
                    "hosts": [{}, {}],
                },
            }
        }
    )
    titles = {insight["title"] for insight in insights}

    assert {
        "Censys host intelligence available",
        "Exposed services observed by Censys",
        "Multiple ASNs observed",
    }.issubset(titles)
    assert "Cloud/CDN infrastructure detected" not in titles
    assert all(insight["evidence"] for insight in insights)


def test_censys_skip_insights_distinguish_reason():
    no_token = build_censys_insights(
        {
            "censys": {
                "status": "skipped",
                "data": {"reason": "not_configured"},
                "errors": ["CENSYS_API_TOKEN not configured"],
            }
        }
    )
    no_ips = build_censys_insights(
        {
            "censys": {
                "status": "skipped",
                "data": {"reason": "no_ip_addresses"},
                "errors": ["No DNS addresses were available"],
            }
        }
    )

    assert "no token" in no_token[0]["title"]
    assert "no IPs" in no_ips[0]["title"]


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
    assert enriched["summary"]["shodan_subdomain_count"] == 0
    assert enriched["summary"]["shodan_record_count"] == 0
    assert enriched["summary"]["censys_host_count"] == 0
    assert enriched["progress"]["state"] == "idle"
    assert enriched["graph"]["stats"]["node_count"] == 1
    assert enriched["infrastructure"]["ips"] == []
    assert enriched["insights"][0]["title"] == "Relationship graph available"
    assert enriched["verdict"]["target"] == "example.com"
    assert enriched["verdict"]["risk_level"] == "Informational"
    assert enriched["verdict"]["narrative"].endswith("Confidence: Limited.")
    assert enriched["timeline"][0]["label"] == "Scan completed"


def test_verdict_uses_only_collected_evidence():
    report = {
        "target": "example.com",
        "status": "completed",
        "completed_at": "2026-06-24T00:00:00+00:00",
        "collectors": {
            "dns": {
                "source": "dns",
                "status": "ok",
                "data": {
                    "records": {
                        "NS": ["ada.ns.cloudflare.com"],
                        "MX": [{"exchange": "aspmx.l.google.com"}],
                    }
                },
                "errors": [],
                "started_at": "2026-06-24T00:00:00+00:00",
                "completed_at": "2026-06-24T00:00:01+00:00",
            },
            "whois": {
                "source": "whois",
                "status": "ok",
                "data": {
                    "registrar": "Example Registrar",
                    "creation_date": "2020-01-01T00:00:00+00:00",
                },
                "errors": [],
                "started_at": "2026-06-24T00:00:01+00:00",
                "completed_at": "2026-06-24T00:00:02+00:00",
            },
            "shodan": {
                "source": "shodan",
                "status": "skipped",
                "data": {},
                "errors": ["not configured"],
                "started_at": "2026-06-24T00:00:02+00:00",
                "completed_at": "2026-06-24T00:00:02+00:00",
            },
        },
        "timeline": [],
    }

    verdict = enrich_report(report)["verdict"]

    assert verdict["coverage_status"] == "High"
    assert verdict["infrastructure_providers"] == ["Cloudflare"]
    assert verdict["email_providers"] == ["Google Workspace"]
    assert verdict["sources_used"] == ["DNS", "WHOIS"]
    assert "Cloudflare infrastructure was observed." in verdict["narrative"]


def test_progress_builder_reports_final_collector_state():
    collectors = {
        "dns": {
            "status": "ok",
            "started_at": "2026-06-24T10:00:00Z",
            "completed_at": "2026-06-24T10:00:01Z",
        },
        "urlscan": {
            "status": "skipped",
            "started_at": "2026-06-24T10:00:01Z",
            "completed_at": "2026-06-24T10:00:01Z",
        },
        "censys": {
            "status": "error",
            "started_at": "2026-06-24T10:00:01Z",
            "completed_at": "2026-06-24T10:00:02Z",
        },
    }

    progress = build_progress("partial", collectors)

    assert progress["percent"] == 100
    assert progress["state"] == "partial"
    assert progress["successful_collectors"] == 1
    assert progress["skipped_collectors"] == 1
    assert progress["failed_collectors"] == 1
    assert [step["label"] for step in progress["steps"]] == [
        "DNS",
        "URLScan",
        "Censys",
    ]


def test_graph_builder_deduplicates_and_caps_entities():
    collectors = {
        "dns": {
            "status": "ok",
            "data": {
                "records": {
                    "A": ["192.0.2.10", "192.0.2.10"],
                    "NS": ["ada.ns.cloudflare.com"],
                    "MX": [{"exchange": "mx.example.com"}],
                }
            },
        },
        "crtsh": {
            "status": "ok",
            "data": {
                "subdomains": [
                    f"host-{index}.example.com" for index in range(110)
                ],
                "certificates": [
                    {
                        "serial_number": str(index),
                        "common_name": f"host-{index}.example.com",
                    }
                    for index in range(60)
                ],
            },
        },
        "censys": {
            "status": "ok",
            "data": {
                "hosts": [
                    {
                        "ip": "192.0.2.10",
                        "autonomous_system": {
                            "asn": 13335,
                            "name": "Cloudflare, Inc.",
                        },
                        "services": [{"port": 443, "protocol": "HTTP"}],
                    }
                ]
            },
        },
    }

    graph = build_graph("example.com", collectors)

    assert graph["stats"]["type_counts"]["subdomain"] == 100
    assert graph["stats"]["type_counts"]["certificate"] == 50
    assert graph["stats"]["type_counts"]["ip"] == 1
    assert len({node["id"] for node in graph["nodes"]}) == len(graph["nodes"])
    assert len({edge["id"] for edge in graph["edges"]}) == len(graph["edges"])


def test_infrastructure_builder_combines_passive_sources_and_providers():
    collectors = {
        "dns": {
            "data": {
                "records": {
                    "A": ["192.0.2.10"],
                    "AAAA": ["2001:db8::10"],
                    "NS": ["ada.ns.cloudflare.com"],
                }
            }
        },
        "shodan": {
            "data": {
                "records": [
                    {"type": "A", "value": "192.0.2.11"},
                    {"type": "TXT", "value": "ignored"},
                ]
            }
        },
        "censys": {
            "data": {
                "host_count": 1,
                "service_count": 2,
                "ports": [80, 443],
                "protocols": ["HTTP"],
                "asns": [13335],
                "organizations": ["Cloudflare, Inc."],
                "hosts": [
                    {
                        "ip": "192.0.2.10",
                        "location": {"country_code": "IT"},
                        "services": [
                            {"port": 443, "protocol": "HTTP"},
                            {"port": 53, "protocol": "DNS"},
                        ],
                    }
                ],
            }
        },
    }

    infrastructure = build_infrastructure(collectors)

    assert infrastructure["ipv4_count"] == 2
    assert infrastructure["ipv6_count"] == 1
    assert infrastructure["ports"] == [53, 80, 443]
    assert infrastructure["countries"] == ["IT"]
    assert infrastructure["providers"] == ["Cloudflare"]
    assert infrastructure["cloud_or_cdn_detected"] is True
