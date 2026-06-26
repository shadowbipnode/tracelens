from backend.intelligence import (
    build_certificate_intelligence,
    build_correlations,
    build_executive_summary,
    build_findings,
    build_organization_intelligence,
    build_technology_intelligence,
    build_timeline,
)
from backend.report_builder import build_graph, build_infrastructure, build_summary


def collectors():
    return {
        "dns": {
            "status": "ok",
            "data": {
                "records": {
                    "A": ["192.0.2.10"],
                    "MX": [
                        {
                            "preference": 10,
                            "exchange": "aspmx.l.google.com",
                        }
                    ],
                    "NS": ["ada.ns.cloudflare.com"],
                    "CAA": [
                        {
                            "flags": 0,
                            "tag": "issue",
                            "value": "letsencrypt.org",
                        }
                    ],
                }
            },
        },
        "whois": {
            "status": "ok",
            "data": {
                "registrar": "Example Registrar",
                "creation_date": "2020-01-01T00:00:00Z",
                "updated_date": "2025-01-01T00:00:00Z",
                "expiration_date": "2027-01-01T00:00:00Z",
            },
        },
        "crtsh": {
            "status": "ok",
            "data": {
                "subdomains": ["www.example.com"],
                "certificates": [
                    {
                        "common_name": "example.com",
                        "name_value": "example.com\nwww.example.com",
                        "issuer_name": "Let's Encrypt",
                        "not_before": "2025-01-01T00:00:00Z",
                        "not_after": "2025-04-01T00:00:00Z",
                        "serial_number": "01",
                    }
                ],
            },
        },
        "wayback": {
            "status": "ok",
            "data": {
                "captures": [
                    {
                        "timestamp": "20210101000000",
                        "url": "https://example.com/",
                    }
                ]
            },
        },
        "urlscan": {
            "status": "ok",
            "data": {
                "result_count": 1,
                "ips": ["192.0.2.10"],
                "domains": ["example.com"],
                "servers": ["cloudflare"],
                "technologies": ["React", "nginx"],
                "frameworks": ["React"],
                "resource_domains": ["cdn.example.net"],
                "script_domains": ["scripts.example.net"],
                "results": [
                    {
                        "task": {"time": "2026-01-01T00:00:00Z"},
                        "page": {
                            "url": "https://example.com/",
                            "domain": "example.com",
                            "server": "cloudflare",
                            "title": "Example",
                        },
                    }
                ],
            },
        },
        "censys": {
            "status": "ok",
            "data": {
                "host_count": 1,
                "service_count": 1,
                "ports": [443],
                "protocols": ["HTTP"],
                "asns": [13335],
                "organizations": ["Cloudflare, Inc."],
                "hosts": [
                    {
                        "ip": "192.0.2.10",
                        "autonomous_system": {
                            "asn": 13335,
                            "name": "Cloudflare, Inc.",
                            "description": "Cloudflare network",
                        },
                        "services": [
                            {
                                "port": 443,
                                "protocol": "HTTP",
                                "server": "nginx",
                                "software": ["nginx 1.25"],
                                "scan_time": "2026-01-02T00:00:00Z",
                                "tls_certificate_names": [
                                    "example.com",
                                    "www.example.com",
                                ],
                            }
                        ],
                    }
                ],
            },
        },
    }


def test_technology_fingerprinting_requires_and_retains_evidence():
    intelligence = build_technology_intelligence(collectors())
    values = {item["value"] for item in intelligence["fingerprints"]}

    assert {"Cloudflare", "React", "nginx", "Google Workspace"}.issubset(values)
    assert all(item["evidence"] for item in intelligence["fingerprints"])
    assert all(item["reasoning"] for item in intelligence["fingerprints"])


def test_technology_normalization_merges_sources_and_scales_confidence():
    data = collectors()
    data["urlscan"]["data"]["servers"] = ["nginx/1.25", "cloudflare"]
    data["urlscan"]["data"]["technologies"] = ["React", "nginx"]
    data["censys"]["data"]["hosts"][0]["services"][0]["server"] = "nginx"
    data["censys"]["data"]["hosts"][0]["services"][0]["banner"] = "OpenSSH_9.6"
    data["censys"]["data"]["hosts"][0]["services"][0]["http_headers"] = {
        "server": "nginx",
        "x-powered-by": "PHP/8.2",
    }

    intelligence = build_technology_intelligence(data)
    by_value = {item["value"]: item for item in intelligence["fingerprints"]}

    assert by_value["nginx"]["category"] == "Web Server"
    assert by_value["nginx"]["confidence"] in {"moderate", "high"}
    assert len(
        {
            item["source"]
            for item in by_value["nginx"]["evidence"]
        }
    ) > 1
    assert by_value["OpenSSH"]["category"] == "SSH"
    assert len(
        [
            item
            for item in intelligence["fingerprints"]
            if item["value"] == "nginx"
        ]
    ) == 1


def test_certificate_intelligence_normalizes_validity_and_relationships():
    intelligence = build_certificate_intelligence(
        "example.com", collectors(), "2026-06-25T00:00:00Z"
    )

    assert intelligence["certificate_count"] == 1
    assert intelligence["expired_count"] == 1
    assert intelligence["certificates"][0]["sans"] == [
        "example.com",
        "www.example.com",
    ]
    assert {
        item["domain"] for item in intelligence["relationships"]
    } == {"example.com", "www.example.com"}


def test_correlation_engine_only_emits_supported_relationships():
    data = collectors()
    technology = build_technology_intelligence(data)
    certificates = build_certificate_intelligence(
        "example.com", data, "2026-06-25T00:00:00Z"
    )
    correlations = build_correlations(
        "example.com", data, certificates, technology
    )
    types = set(correlations["type_counts"])

    assert {
        "certificate_domain",
        "certificate_organization",
        "ip_asn",
        "asn_organization",
        "mx_mail_provider",
        "caa_certificate_authority",
        "wayback_urlscan",
        "urlscan_technology",
        "dns_infrastructure",
    }.issubset(types)
    assert all(item["evidence"] for item in correlations["items"])
    assert all(item["reasoning"] for item in correlations["items"])


def test_organization_intelligence_unifies_network_and_domain_entities():
    data = collectors()
    technology = build_technology_intelligence(data)
    certificates = build_certificate_intelligence(
        "example.com", data, "2026-06-25T00:00:00Z"
    )
    correlations = build_correlations(
        "example.com", data, certificates, technology
    )
    organization = build_organization_intelligence(
        "example.com", data, certificates, correlations
    )

    assert organization["stats"]["organization_count"] >= 1
    assert organization["asns"][0]["asn"] == "AS13335"
    assert "www.example.com" in organization["domains"]
    assert organization["cloud_providers"][0]["evidence"]


def test_organization_normalization_merges_equivalent_names_without_raw_objects():
    data = collectors()
    host = data["censys"]["data"]["hosts"][0]
    host["autonomous_system"]["name"] = "KELIWEB - Keliweb S.R.L"
    host["autonomous_system"]["description"] = "Keliweb S.R.L"
    host["whois"] = {
        "organization": {"name": "Keliweb S.R.L"},
        "network_name": "KELIWEB - Keliweb S.R.L",
    }
    certificates = build_certificate_intelligence(
        "example.com", data, "2026-06-25T00:00:00Z"
    )
    technology = build_technology_intelligence(data)
    correlations = build_correlations(
        "example.com", data, certificates, technology
    )

    organization = build_organization_intelligence(
        "example.com", data, certificates, correlations
    )

    names = [item["name"] for item in organization["organizations"]]
    assert names.count("Keliweb S.R.L") == 1
    assert all(not name.startswith("{") for name in names)
    assert organization["organizations"][0]["role"]
    assert organization["organizations"][0]["evidence_source"] == "censys"


def test_global_organization_and_asn_normalization_for_report_surfaces():
    data = collectors()
    host = data["censys"]["data"]["hosts"][0]
    host["autonomous_system"] = {
        "asn": "AS202675",
        "name": "KELIWEB - Keliweb S.R.L",
        "description": "Keliweb S.R.L",
    }
    host["whois"] = {
        "organization": {"handle": "ORG-KS87-RIPE", "name": "Keliweb S.R.L"},
        "network_name": "KELIWEB - Keliweb S.R.L",
    }
    data["censys"]["data"]["asns"] = [202675, "AS202675"]
    data["censys"]["data"]["organizations"] = [
        "KELIWEB - Keliweb S.R.L",
        "Keliweb S.R.L",
        {"handle": "ORG-KS87-RIPE", "name": "Keliweb S.R.L"},
    ]

    technology = build_technology_intelligence(data)
    certificates = build_certificate_intelligence(
        "laspeziameteo.com", data, "2026-06-25T00:00:00Z"
    )
    correlations = build_correlations(
        "laspeziameteo.com", data, certificates, technology
    )
    organization = build_organization_intelligence(
        "laspeziameteo.com", data, certificates, correlations
    )
    findings = build_findings([], correlations, technology, certificates, data)
    timeline = build_timeline(data, [])
    infrastructure = build_infrastructure(data)
    summary = build_summary(
        "laspeziameteo.com",
        "completed",
        "2026-06-25T00:00:00Z",
        data,
        timeline,
    )
    executive = build_executive_summary(
        "completed",
        data,
        infrastructure,
        technology,
        organization,
        findings,
        timeline,
        summary,
    )
    graph = build_graph(
        "laspeziameteo.com", data, correlations, technology, certificates
    )

    assert infrastructure["organizations"] == ["Keliweb S.R.L"]
    assert infrastructure["asns"] == ["AS202675"]
    assert executive["infrastructure_overview"]["organizations"] == [
        "Keliweb S.R.L"
    ]
    assert executive["infrastructure_overview"]["asns"] == ["AS202675"]
    assert [item["name"] for item in organization["organizations"]] == [
        "Keliweb S.R.L"
    ]
    assert [item["asn"] for item in organization["asns"]] == ["AS202675"]

    correlation_values = [
        side["value"]
        for item in correlations["items"]
        for side in (item["left"], item["right"])
    ]
    assert "KELIWEB - Keliweb S.R.L" not in correlation_values
    assert "{'handle': 'ORG-KS87-RIPE', 'name': 'Keliweb S.R.L'}" not in (
        str(value) for value in correlation_values
    )
    assert "Keliweb S.R.L" in correlation_values
    assert "AS202675" in correlation_values

    finding_text = " ".join(
        item["description"] for item in findings["all"]
    )
    assert "Keliweb S.R.L" in finding_text
    assert "KELIWEB - Keliweb S.R.L" not in finding_text
    assert "ORG-KS87-RIPE" not in finding_text

    node_ids = {node["id"] for node in graph["nodes"]}
    organization_nodes = [
        node for node in graph["nodes"] if node["type"] == "organization"
    ]
    asn_nodes = [node for node in graph["nodes"] if node["type"] == "asn"]
    assert "organization:keliweb s.r.l" in node_ids
    assert all("{" not in node["label"] for node in organization_nodes)
    assert [node["id"] for node in asn_nodes] == ["asn:as202675"]
    assert [node["label"] for node in asn_nodes] == ["AS202675"]
    assert all(
        edge["source"] in node_ids and edge["target"] in node_ids
        for edge in graph["edges"]
    )


def test_timeline_merges_historical_sources_chronologically():
    timeline = build_timeline(
        collectors(),
        [],
        "2026-06-25T00:00:00Z",
        "2026-06-25T00:01:00Z",
    )
    event_types = {event["type"] for event in timeline}

    assert {
        "whois_created",
        "whois_updated",
        "certificate_issued",
        "certificate_expires",
        "wayback_capture",
        "urlscan_observed",
        "censys_service_observed",
    }.issubset(event_types)
    assert timeline[0]["type"] == "whois_created"
    assert timeline == sorted(timeline, key=lambda item: item["timestamp"])


def test_timeline_groups_repetitive_wayback_events():
    data = collectors()
    data["wayback"]["data"]["captures"] = [
        {"timestamp": "20210101000000", "url": "https://example.com/"},
        {"timestamp": "20210101010000", "url": "https://example.com/"},
        {"timestamp": "20210101020000", "url": "https://example.com/"},
    ]

    timeline = build_timeline(data, [])
    grouped = [
        event
        for event in timeline
        if event["type"] == "wayback_capture"
    ]

    assert len(grouped) == 1
    assert grouped[0]["grouped_count"] == 3


def test_findings_engine_separates_facts_correlations_and_notes():
    data = collectors()
    technology = build_technology_intelligence(data)
    certificates = build_certificate_intelligence(
        "example.com", data, "2026-06-25T00:00:00Z"
    )
    correlations = build_correlations(
        "example.com", data, certificates, technology
    )
    findings = build_findings(
        [
            {
                "type": "dns",
                "severity": "info",
                "title": "DNS evidence available",
                "description": "DNS returned records.",
                "evidence": [
                    {"source": "dns", "field": "A", "value": "192.0.2.10"}
                ],
            }
        ],
        correlations,
        technology,
        certificates,
        data,
    )

    assert findings["observed_facts"]
    assert findings["correlated_findings"]
    assert findings["analyst_notes"] == []
    assert all(item["confidence"] for item in findings["all"])


def test_relationship_graph_contains_intelligence_entities_and_metadata():
    data = collectors()
    technology = build_technology_intelligence(data)
    certificates = build_certificate_intelligence(
        "example.com", data, "2026-06-25T00:00:00Z"
    )
    correlations = build_correlations(
        "example.com", data, certificates, technology
    )
    graph = build_graph(
        "example.com", data, correlations, technology, certificates
    )

    assert graph["stats"]["type_counts"]["technology"] >= 1
    assert graph["stats"]["type_counts"]["external_domain"] == 2
    assert graph["groups"]
    assert any(edge["metadata"] for edge in graph["edges"])


def test_executive_summary_reports_quality_and_supported_stack():
    data = collectors()
    technology = build_technology_intelligence(data)
    certificates = build_certificate_intelligence(
        "example.com", data, "2026-06-25T00:00:00Z"
    )
    correlations = build_correlations(
        "example.com", data, certificates, technology
    )
    organization = build_organization_intelligence(
        "example.com", data, certificates, correlations
    )
    findings = build_findings([], correlations, technology, certificates, data)
    timeline = build_timeline(data, [])
    infrastructure = build_infrastructure(data)
    summary = build_summary(
        "example.com",
        "completed",
        "2026-06-25T00:00:00Z",
        data,
        timeline,
    )
    executive = build_executive_summary(
        "completed",
        data,
        infrastructure,
        technology,
        organization,
        findings,
        timeline,
        summary,
    )

    assert executive["collection_quality"]["coverage"] in {"moderate", "high"}
    assert executive["collection_quality"]["evidence_reference_count"] > 0
    assert "React" in executive["technology_stack"]
    assert executive["high_level_observations"]
