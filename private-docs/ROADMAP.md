# TraceLens Roadmap

## Vision

TraceLens aims to become a professional passive-first OSINT intelligence platform.

The project will evolve through small, releasable milestones.

Every milestone must produce a usable application.

No milestone should depend on future features.

---

# M1 - Passive Recon Core

Status:
Planned

Goal:

Produce a structured intelligence report for a domain using passive public sources.

Input:

- domain

Collectors:

- DNS
- WHOIS
- crt.sh
- Wayback Machine

Backend:

- FastAPI
- SQLite
- scan orchestration
- report generation

Frontend:

- React dashboard
- scan submission form
- result viewer

Output:

- JSON report
- dashboard view
- timeline

Storage:

- SQLite

Features:

- create scan
- list scans
- retrieve scan
- retrieve report
- collector status tracking

Definition of Done:

- user can submit a domain
- collectors execute successfully
- results are stored
- report can be viewed later
- timeline is generated
- failed collectors do not stop the scan
- frontend displays results
- tests pass

---

# M2 - External Intelligence Sources

Status:
Planned

Goal:

Expand passive intelligence coverage.

New Collectors:

- Shodan
- Censys
- SecurityTrails

Storage:

- PostgreSQL support

Features:

- scan filtering
- scan history
- source metadata
- API key management

Definition of Done:

- application works without API keys
- collectors disable gracefully if keys are missing
- PostgreSQL supported
- historical searches available

---

# M3 - Graph Intelligence

Status:
Planned

Goal:

Represent investigations as entities and relationships.

Technology:

- Neo4j

Entities:

- Domain
- Subdomain
- IP
- Email
- Organization
- Certificate
- Nameserver

Relationships:

- resolves_to
- owns
- covers
- uses
- references

Features:

- graph API
- graph UI
- relationship explorer

Definition of Done:

- graph can be generated from findings
- graph can be queried
- graph view available in UI

---

# M4 - AI Correlation Engine

Status:
Planned

Goal:

Transform raw intelligence into analyst-friendly insights.

Features:

- confidence scoring
- anomaly detection
- semantic grouping
- executive briefing

Rules:

- AI must never invent evidence
- AI must reference collected findings
- confidence must be explainable

Definition of Done:

- analyst receives correlated findings
- AI output references evidence
- confidence scores generated

---

# M5 - Professional Reporting

Status:
Planned

Goal:

Support investigation sharing and export.

Features:

- PDF export
- CSV export
- JSON export
- investigation notes
- workspace support

Definition of Done:

- reports can be exported
- reports are reproducible
- exports preserve evidence references

---

# Explicit Non-Goals Before v1.0

Do not implement:

- active scanning
- vulnerability scanning
- exploitation modules
- credential collection
- brute force modules
- Kubernetes
- distributed microservices
- dark web automation
- login-required scraping

These items may be evaluated after v1.0 but must not delay core functionality.

