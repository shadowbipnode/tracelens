# TraceLens AI Handover

TraceLens is a passive-first OSINT intelligence platform focused on domain-based investigations.

The project must grow incrementally through small releasable milestones.

The objective is not to build another OSINT data aggregator. The objective is to help analysts collect, normalize, correlate, timeline, and export intelligence from public sources.

Default mode is passive-first.

No active scanning should be introduced before the passive intelligence pipeline is stable and tested.

## Product Vision

TraceLens should become an investigation platform capable of:

- collecting public intelligence
- normalizing heterogeneous data sources
- correlating findings
- building timelines
- generating professional reports
- supporting graph-based investigations

Target users:

- security analysts
- blue teams
- journalists
- researchers
- infrastructure operators
- compliance teams

## M1 Scope

Input:
- single domain

Collectors:
- DNS
- WHOIS
- crt.sh
- Wayback Machine

Storage:
- SQLite

Backend:
- FastAPI

Frontend:
- React

Output:
- JSON report
- simple dashboard

AI:
- not included

## Future Milestones

M2:
- Shodan
- Censys
- scan history
- PostgreSQL

M3:
- graph model
- Neo4j

M4:
- AI correlation engine
- confidence scoring
- anomaly detection

M5:
- professional reporting
- PDF export
- multi-target investigations

## Code Quality Rules

Never mention:
- AI generated
- ChatGPT
- Codex
- Claude
- Gemini
- Copilot
- Cursor
- LLM

Comments should only provide technical value.

Code must look human-maintained and production-oriented.

## Development Philosophy

Prefer:
- simple modules
- typed Python
- deterministic tests
- explicit error handling
- documented APIs

Avoid:
- premature abstractions
- microservices
- Kubernetes
- unnecessary dependencies
- hidden side effects
