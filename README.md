# TraceLens

[![Status](https://img.shields.io/badge/status-v0.7.0--alpha1-brightgreen)](https://github.com/shadowbipnode/tracelens)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688)
![React](https://img.shields.io/badge/frontend-React-61dafb)
![OSINT](https://img.shields.io/badge/OSINT-passive--first-purple)

TraceLens is a passive-first investigation workspace for domain intelligence. It collects public evidence, normalizes source results, performs deterministic correlations, and presents infrastructure, organization, certificate, technology, timeline, and finding views without actively probing target services.

## Core principles

- Passive-first collection
- No port scanning, vulnerability scanning, brute forcing, exploitation, or authenticated probing
- Evidence attached to every derived fingerprint and correlation
- Deterministic, explainable conclusions
- Graceful degradation when optional sources fail
- Backward-compatible enrichment of stored reports

## Current capabilities

- DNS, WHOIS, crt.sh, and Wayback collection
- Optional URLScan search of existing public observations
- Optional Shodan passive DNS collection
- Optional Censys enrichment for IPs already returned by DNS
- Structured timeout, rate-limit, credential, plan, network, and parse errors
- Passive technology fingerprinting for supported servers, proxies, CDN, cloud, frameworks, CMS, mail providers, analytics, tracking, and programming hints
- Organization profiles correlating domains, subdomains, IPs, ASNs, organizations, MX, NS, certificate issuers, and providers
- Certificate investigation covering issuers, validity, SANs, wildcards, duplicates, reuse, shared names, expiration, and domain relationships
- Unified chronological timeline across registration, certificate, archive, URLScan, Shodan, Censys, and scan events
- Findings separated into Observed Facts, Correlated Findings, and Analyst Notes
- Executive collection-quality assessment with coverage, confidence, evidence completeness, passive exposure, infrastructure, mail, and technology summaries
- Interactive relationship graph with dragging, panning, wheel zoom, fit/reset, category collapse, search, selection, connected-node highlighting, relationship highlighting, and entity inspection
- SQLite report history and JSON export

## Requirements

- Python 3.11 or newer
- Node.js 20 or newer
- npm

## Installation

```bash
git clone https://github.com/shadowbipnode/tracelens.git
cd tracelens

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cd frontend
npm install
cd ..
cp .env.example .env
```

## Configuration

```dotenv
TRACELENS_DB_PATH=.tracelens/tracelens.sqlite3
TRACELENS_HTTP_TIMEOUT=20
TRACELENS_USER_AGENT=TraceLens/0.7

SHODAN_API_KEY=
CENSYS_API_TOKEN=
URLSCAN_API_KEY=
```

Optional integrations are skipped when credentials are absent and do not make the investigation partial. Invalid credentials, unsupported plans, rate limits, timeouts, and temporary outages are retained as structured source errors while successful evidence remains usable.

URLScan only searches existing public observations. TraceLens does not submit a new URLScan job.

Censys only receives IP addresses already found in DNS A or AAAA records. Lookups are bounded to ten IPs and fifty normalized services per host.

## Run locally

Backend:

```bash
source .venv/bin/activate
uvicorn backend.main:app --reload
```

Frontend:

```bash
cd frontend
npm run dev
```

Open `http://localhost:5173`.

## Docker Compose

```bash
docker compose up --build
```

The workspace is served at `http://localhost:5173`; the API is served at `http://localhost:8000`.

## API

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` | Service health |
| `POST` | `/api/scans` | Run and store a passive investigation |
| `GET` | `/api/scans` | List stored investigations |
| `GET` | `/api/scans/{scan_id}` | Investigation metadata and collector status |
| `GET` | `/api/scans/{scan_id}/report` | Current schema-2.0 enriched report |

```bash
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'
```

Collection is synchronous and sequential to keep source usage bounded and predictable.

## Investigation workflow

1. Executive Summary: review coverage, confidence, completeness, exposure, and high-level observations.
2. Infrastructure: inspect addresses, ownership, providers, countries, ports, protocols, and source health.
3. Technology: review fingerprints, reasoning, and exact passive evidence references.
4. Organization: correlate ownership, network, domain, mail, nameserver, certificate, and provider entities.
5. Certificates: inspect validity, SANs, wildcards, duplicates, reuse, and relationships.
6. Relationships: explore the interactive entity graph.
7. Timeline: filter and review chronological historical observations.
8. Findings: separate observed facts from cross-source correlations and analyst notes.
9. Raw Evidence: inspect, copy, or download normalized collector payloads and the complete report.

## Report compatibility

Raw collector payloads and API routes remain compatible with earlier reports. `enrich_report()` rebuilds current derived sections when a stored report is read. Schema 2.0 adds:

- `technology`
- `organization`
- `certificates`
- `correlations`
- `findings`
- `executive_summary`
- graph groups, relationship counts, and edge metadata
- timeline evidence references
- `derivation_errors`

See [docs/REPORT_SCHEMA.md](docs/REPORT_SCHEMA.md).

## Verification

```bash
python -m compileall backend
pytest -q

cd frontend
npm run build
npm run lint
```

External services are mocked in the test suite.

## Security and privacy

TraceLens stores public source responses and derived report sections in local SQLite. It does not store optional API credentials in reports. Keep `.env` private and comply with source terms and applicable law.

See [docs/SECURITY.md](docs/SECURITY.md) and [private-docs/SECURITY_MODEL.md](private-docs/SECURITY_MODEL.md).

## License

MIT License
