# TraceLens Architecture

## Overview

TraceLens is a passive-first OSINT intelligence platform.

The architecture is intentionally designed to evolve through multiple milestones without requiring disruptive rewrites.

M1 uses a simple monolithic architecture:

- FastAPI backend
- SQLite database
- local collector modules
- React frontend
- Docker Compose for development

Future releases may introduce PostgreSQL, Redis, Neo4j, and AI correlation services.

Those future components must not complicate M1.

---

## High-Level Components

### Frontend

Location:

frontend/

Responsibilities:

- collect user input
- display scan results
- render timeline
- render future graph views
- export reports

Technology:

- React
- TypeScript
- React Router
- Zustand
- Axios

M1 UI:

- Scan page
- Results page
- Timeline section
- Collector status section

---

### Backend

Location:

backend/

Responsibilities:

- validate targets
- orchestrate collectors
- normalize data
- store scans
- expose APIs

Technology:

- Python
- FastAPI
- Pydantic
- SQLAlchemy

Expected M1 endpoints:

GET /health

POST /api/scans

GET /api/scans

GET /api/scans/{scan_id}

GET /api/scans/{scan_id}/report

---

### Collectors

Location:

backend/collectors/

Collectors are independent modules.

Each collector must:

- receive a target
- perform passive collection
- normalize results
- return structured output
- handle failures internally

A collector failure must never crash the entire scan.

M1 collectors:

- DNS
- WHOIS
- crt.sh
- Wayback Machine

Future collectors:

- Shodan
- Censys
- SecurityTrails
- HaveIBeenPwned
- IntelX

---

### Storage

M1 storage:

SQLite

Suggested path:

.tracelens/tracelens.sqlite3

Core entities:

Scan
Target
Finding
TimelineEvent
CollectorResult

Future migration path:

SQLite → PostgreSQL

API contracts must remain stable after migration.

---

### Timeline Engine

Timeline is one of the differentiating features of TraceLens.

M1 timeline sources:

- domain registration date
- WHOIS update date
- certificate issuance dates
- first archived Wayback entries
- scan execution timestamp

Future timeline sources:

- breaches
- social events
- infrastructure changes
- ownership changes

---

### Graph Engine

Not included in M1.

Planned for M3.

Technology:

Neo4j

Entity examples:

- Domain
- Subdomain
- IP
- Email
- Organization
- Certificate
- Nameserver

Relationship examples:

Domain -> resolves_to -> IP

Certificate -> covers -> Domain

Domain -> uses -> Nameserver

Organization -> owns -> Domain

---

### AI Correlation Engine

Not included in M1.

Planned for M4.

Responsibilities:

- correlation
- confidence scoring
- anomaly detection
- executive briefing

AI must never replace evidence.

Every conclusion must remain traceable to collected data.

---

### Configuration

Configuration source:

environment variables

Never store secrets in source code.

Example variables:

TRACELENS_ENV=development

TRACELENS_DB_PATH=.tracelens/tracelens.sqlite3

TRACELENS_HTTP_TIMEOUT=20

TRACELENS_USER_AGENT=TraceLens/0.1

Future variables:

SHODAN_API_KEY

CENSYS_API_ID

CENSYS_API_SECRET

OPENAI_API_KEY

ANTHROPIC_API_KEY

DATABASE_URL

REDIS_URL

NEO4J_URI

---

### Docker Strategy

Docker is used for:

- local development
- optional deployment

M1 must work both:

with Docker Compose

and

directly from Python virtual environments.

Example:

uvicorn backend.main:app --reload

Docker must remain optional.

---

### Design Principles

Passive-first

Evidence-based

API-first

Modular collectors

Stable data contracts

Simple deployments

Incremental evolution

No premature microservices

No Kubernetes before it becomes necessary

No active scanning in M1
