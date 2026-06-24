# TraceLens

[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/shadowbipnode)
![Status](https://img.shields.io/badge/status-M1%20complete-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688)
![React](https://img.shields.io/badge/frontend-React-61dafb)
![OSINT](https://img.shields.io/badge/OSINT-passive--first-purple)
![SQLite](https://img.shields.io/badge/database-SQLite-lightgrey)

TraceLens is a passive-first domain intelligence application. It collects public information, normalizes source results, builds a basic timeline, and stores reports for later review.

## M1 capabilities

- Validate and scan one domain at a time
- Collect DNS records without subdomain brute forcing
- Collect public WHOIS registration metadata
- Query certificate transparency data from crt.sh
- Query archived URL metadata from the Wayback Machine
- Continue scans when an individual collector fails
- Store scan reports in SQLite
- Browse recent scans and reports in a React dashboard
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
TRACELENS_USER_AGENT=TraceLens/0.1
```

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

M1 executes collectors sequentially. Depending on source response times, creating a scan can take up to several collector timeout periods.

## Tests

```bash
python -m compileall backend
pytest -q

cd frontend
npm run build
```

External services are mocked in the test suite.

## Passive-first security model

M1 only uses public DNS, WHOIS, certificate transparency, and web archive sources. It does not connect to target web services or enumerate target infrastructure through active probes. Each collector has a timeout, returns structured errors, and cannot terminate the remaining collection sequence.

Use TraceLens only for lawful research and analysis.

## Data storage

The default database is `.tracelens/tracelens.sqlite3`. The directory and schema are created automatically. Database files, local environment files, caches, build output, and logs are excluded from Git.

## Support TraceLens

GitHub Sponsors: https://github.com/sponsors/shadowbipnode

Lightning: `zap@shadowbip.com`

Bitcoin: `bc1qgppvys2e0zx3r87fvtdytwped3xft385sj9800`

## License

MIT License
