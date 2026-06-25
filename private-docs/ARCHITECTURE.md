# TraceLens Architecture

## Current Release

v0.6.0-alpha6 remains a monolithic passive-first application:

- FastAPI backend
- sequential local collectors
- SQLite persistence
- React and TypeScript dashboard
- deterministic report enrichment

The API runs scans synchronously. Collector failures are isolated and successful evidence is retained.

## Collection Pipeline

Collectors execute in this order:

1. DNS
2. WHOIS
3. crt.sh
4. Wayback Machine
5. URLScan search
6. Shodan
7. Censys

URLScan, Shodan, and Censys are optional. Missing credentials produce a skipped result and do not make the scan partial. URLScan only searches existing observations. Censys only enriches addresses already returned by DNS.

Every collector returns normalized data, status, timestamps, and structured error details.

## Report Model

Stored reports contain the normalized collector outputs plus deterministic derived sections:

- `summary`: investigation counts and dates
- `progress`: collector order, final step states, and completion totals
- `infrastructure`: addresses, network ownership, providers, locations, ports, and protocols
- `graph`: deduplicated entities, relationships, and type counts
- `timeline`: chronological source observations
- `insights`: compact evidence-backed findings
- `verdict`: deterministic investigation status, coverage, confidence, risk, provider, timeline, and source-use summary

Graph entities are stored in the report JSON rather than a separate graph database. Node limits keep reports and visualization responsive.

`enrich_report()` remains the compatibility boundary for old stored reports. Derived workspace fields are rebuilt at read time, so reports created before the analyst-workstation changes receive the current summary, verdict, infrastructure, graph, progress, and findings shape without a database migration. Existing collector payloads and scan API routes are unchanged.

## Frontend

The Professional Analyst Workspace separates reports into Executive Summary, Infrastructure, Relationships, Timeline, Findings, and Raw Evidence views. The persistent left navigation follows the analyst workflow: assess, inspect, correlate, sequence, review, and verify.

The Executive Summary leads with an evidence-derived Investigation Verdict. Findings retain only a short explanation and bounded evidence summary; full collector objects are rendered only in Raw Evidence. Infrastructure and host detail use collapsible sections. Timeline filtering and repeated-event grouping are client-side presentation operations and do not alter stored evidence.

The scan request remains synchronous. While the request is pending, the UI shows indeterminate collection progress without claiming an exact collector state. After completion, it renders the report's final collector steps and totals.

The graph uses a fixed-height hierarchical SVG layout, category columns, zoom/fit/reset controls, and a visible-node limit while preserving the complete graph in JSON evidence. Long source values and JSON are contained within wrapping or internally scrollable elements so the application does not create page-level horizontal overflow.

Raw Evidence owns full collector JSON. Search and expand/collapse state are local UI state; copy and per-section download operate directly on the loaded report and do not mutate it.

## Storage and Evolution

SQLite remains the only database for this release. API and report contracts should remain stable as investigation history, richer correlation, exports, and multi-target workflows are developed for beta.
