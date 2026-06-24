# TraceLens

[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/shadowbipnode)
![Status](https://img.shields.io/badge/status-M1%20development-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688)
![React](https://img.shields.io/badge/frontend-React-61dafb)
![OSINT](https://img.shields.io/badge/OSINT-passive--first-purple)
![SQLite](https://img.shields.io/badge/database-SQLite-lightgrey)

> Passive-first OSINT intelligence platform for analysts, researchers, journalists, security teams, and infrastructure operators.

TraceLens collects, normalizes, correlates, timelines, and visualizes publicly available intelligence while maintaining an evidence-first and explainable approach.

The goal is not to become another data aggregator.

The goal is to help investigators transform scattered public information into structured intelligence.

---

## Why TraceLens?

Most OSINT tools focus on data collection.

TraceLens focuses on:

* Passive-first intelligence gathering
* Evidence preservation
* Timeline reconstruction
* Relationship discovery
* Investigation workflows
* Professional reporting
* Future AI-assisted correlation with explainable evidence

---

## Current Status

Current milestone:

**M1 — Passive Recon Core**

Implemented sources planned for M1:

* DNS
* WHOIS
* Certificate Transparency (crt.sh)
* Wayback Machine

Planned outputs:

* Structured JSON report
* Timeline view
* Web dashboard

---

## Architecture

### Backend

* Python
* FastAPI
* SQLAlchemy
* SQLite

### Frontend

* React
* TypeScript
* Zustand
* Axios

### Future Components

* PostgreSQL
* Neo4j
* AI Correlation Engine
* Professional PDF Reporting

---

## Roadmap

### M1 — Passive Recon Core

* Domain intelligence
* DNS collection
* WHOIS collection
* crt.sh integration
* Wayback integration
* Timeline generation
* SQLite storage
* FastAPI backend
* React dashboard

### M2 — External Intelligence Sources

* Shodan
* Censys
* Historical search
* PostgreSQL support

### M3 — Graph Intelligence

* Neo4j integration
* Relationship mapping
* Entity graph explorer

### M4 — AI Correlation Engine

* Confidence scoring
* Anomaly detection
* Executive briefing
* Investigation summaries

### M5 — Professional Reporting

* PDF export
* CSV export
* JSON export
* Investigation workspaces
* Multi-target investigations

---

## Design Principles

TraceLens follows a strict set of principles:

* Passive-first
* Evidence-based
* Explainable findings
* Auditable collection
* Safe defaults
* Professional workflows
* Incremental architecture

---

## Security Model

TraceLens is not a vulnerability scanner.

M1 does not include:

* Port scanning
* Vulnerability scanning
* Brute forcing
* Credential attacks
* Exploitation modules
* Authentication bypass

Only public and passive intelligence sources are used.

---

## Development

Clone the repository:

```bash
git clone https://github.com/shadowbipnode/tracelens.git
cd tracelens
```

Create Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Start backend:

```bash
uvicorn backend.main:app --reload
```

Start frontend:

```bash
cd frontend
npm install
npm run dev
```

---

## Project Structure

```text
tracelens/
├── backend/
├── frontend/
├── tests/
├── private-docs/
├── requirements.txt
├── docker-compose.yml
└── README.md
```

---

## Support TraceLens

If TraceLens helps you, consider supporting development.

### GitHub Sponsors

https://github.com/sponsors/shadowbipnode

### Lightning

```text
zap@shadowbip.com
```

### Bitcoin

```text
bc1qgppvys2e0zx3r87fvtdytwped3xft385sj9800
```

Every contribution helps fund:

* Development
* Infrastructure
* Testing
* Documentation
* Future features

---

## License

MIT License
