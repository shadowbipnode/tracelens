# TraceLens

[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/shadowbipnode)
![Status](https://img.shields.io/badge/status-v0.6.0--alpha6-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688)
![React](https://img.shields.io/badge/frontend-React-61dafb)
![OSINT](https://img.shields.io/badge/OSINT-passive--first-purple)
![SQLite](https://img.shields.io/badge/database-SQLite-lightgrey)

TraceLens is a passive-first domain intelligence application. It collects public information, normalizes source results, derives evidence-backed insights, builds an investigation timeline, and stores reports for later review.

## v0.6.0-alpha6 capabilities

- Validate and scan one domain at a time
- Collect DNS records without subdomain brute forcing
- Collect public WHOIS registration metadata
- Query certificate transparency data from crt.sh
- Query archived URL metadata from the Wayback Machine
- Optionally query Shodan passive DNS data for subdomains, records, and tags
- Optionally query Censys host intelligence for IP addresses already found in DNS A and AAAA records
- Optionally search existing URLScan observations without submitting a new scan
- Continue scans when an individual collector fails
- Store scan reports in SQLite
- Review a deterministic relationship graph across domains, subdomains, IPs, network ownership, certificates, services, and sources
- Review a correlated infrastructure dashboard covering addresses, ASNs, organizations, providers, countries, ports, and protocols
- Follow synchronous scan progress through collector steps and a final completion summary
- Review summary metrics for registration, DNS, certificate, archive, URLScan, Shodan, and Censys evidence
- Review deterministic DNS and host intelligence insights with supporting evidence
- Use the Professional Analyst Workspace with section-based report navigation
- Review Executive Summary, Infrastructure, Relationships, Timeline, Findings, and Raw Evidence as dedicated views
- Start with an evidence-derived Investigation Verdict covering status, coverage, risk, confidence, providers, timeline coverage, and sources used
- Read compact Critical, Warning, Notice, and Info findings while keeping full payloads isolated in Raw Evidence
- Filter and summarize timeline events, control the hierarchical relationship graph, and collapse noisy infrastructure detail
- Search, expand, collapse, copy, and download collector JSON from the Raw Evidence workspace
- Review Censys hosts, services, ports, protocols, ASN metadata, organizations, and locations
- Browse, search, and filter recent scans
- See user-friendly collector error categories while retaining raw details
- Review a chronological timeline with certificate and Censys service observations
- Download the complete current report as JSON
- Access scan metadata and normalized reports through FastAPI

TraceLens does not perform port scanning, vulnerability scanning, brute forcing, credential collection, exploitation, or authenticated probing.

## Requirements

- Python 3.11 or newer
- Node.js 20 or newer
- npm

Docker Compose is optional.

## Installation

```bash
git clone https://github.com/shadowbipnode/tracelens.git
cd tracelens

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cd frontend
npm install
```

Copy the example environment file if you want to override defaults:

```bash
cd ..
cp .env.example .env
```

Available settings:

```text
TRACELENS_DB_PATH=.tracelens/tracelens.sqlite3
TRACELENS_HTTP_TIMEOUT=20
TRACELENS_USER_AGENT=TraceLens/0.5
SHODAN_API_KEY=
CENSYS_API_TOKEN=
URLSCAN_API_KEY=
```

## Optional API Integrations

TraceLens works without API keys. Shodan, Censys, and URLScan integrations are optional. A missing key or token causes the related collector to be skipped without making the scan partial.

Create or sign in to a Shodan account at https://account.shodan.io, then copy the API key shown in the account overview. Add it to your local `.env` file:

```dotenv
SHODAN_API_KEY=
```

For Censys host intelligence, create a Personal Access Token and add it to your local `.env` file:

```dotenv
CENSYS_API_TOKEN=
```

The Censys collector only looks up IP addresses already discovered through the scan's DNS A and AAAA records. It does not resolve additional targets, connect to target services, or scan ports. Lookups are limited to 10 IP addresses per scan and normalized service data is kept compact.

For URLScan search, configure:

```dotenv
URLSCAN_API_KEY=
```

This release only uses URLScan's search endpoint for existing public observations. It does not submit the target or any URL for a new scan.

`CENSYS_API_ID` and `CENSYS_API_SECRET` remain available as legacy configuration fields, but v0.5.0-alpha5 uses `CENSYS_API_TOKEN`.

Do not commit `.env` or share credentials. Account access and API limits depend on each provider's plan.

## Run locally

Start the backend from the repository root:

```bash
source .venv/bin/activate
uvicorn backend.main:app --reload
```

Start the frontend in another terminal:

```bash
cd frontend
npm run dev
```

Open `http://localhost:5173`. The Vite development server proxies API requests to `http://localhost:8000`.

## Run with Docker Compose

```bash
docker compose up --build
```

The dashboard is available at `http://localhost:5173` and the API at `http://localhost:8000`.

## API

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` | Return service health |
| `POST` | `/api/scans` | Run and store a passive domain scan |
| `GET` | `/api/scans` | List stored scans |
| `GET` | `/api/scans/{scan_id}` | Return scan metadata and collector statuses |
| `GET` | `/api/scans/{scan_id}/report` | Return the normalized report and timeline |

Create a scan:

```bash
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'
```

Collectors execute sequentially. Depending on source response times, creating a scan can take up to several collector timeout periods.

## Analyst workflow

The workspace is organized as an evidence-review sequence:

1. **Executive Summary** presents the Investigation Verdict and the highest-priority findings.
2. **Infrastructure** correlates passive addresses, ownership, providers, locations, services, ports, and DNS records.
3. **Relationships** groups entities into a bounded hierarchical graph with zoom, fit, and layout controls.
4. **Timeline** provides source filtering, event counts, repeated-event grouping, and chronological context.
5. **Findings** separates Critical, Warning, Notice, and Info observations with concise evidence summaries.
6. **Raw Evidence** contains full collector output with search, collapse/expand, copy, and JSON download controls.

Verdict text and findings are deterministic. They only reference evidence present in the stored report; TraceLens does not infer vulnerabilities or make unsupported attribution claims.

## Tests

```bash
python -m compileall backend
pytest -q

cd frontend
npm run build
npm run lint
```

External services are mocked in the test suite.

## Passive-first security model

The current release only uses public DNS, WHOIS, certificate transparency, web archive, optional URLScan search, optional Shodan passive DNS, and optional Censys host intelligence sources. URLScan queries existing observations only, and Censys requests are limited to addresses already present in DNS results. TraceLens does not connect to target web services or enumerate target infrastructure through active probes. Each collector has a timeout, returns classified structured errors, and cannot terminate the remaining collection sequence.

Use TraceLens only for lawful research and analysis.

## Data storage

The default database is `.tracelens/tracelens.sqlite3`. The directory and schema are created automatically. Database files, local environment files, caches, build output, and logs are excluded from Git.

## Support TraceLens

GitHub Sponsors: https://github.com/sponsors/shadowbipnode

Lightning: `zap@shadowbip.com`

Bitcoin: `bc1qgppvys2e0zx3r87fvtdytwped3xft385sj9800`

## License

MIT License
