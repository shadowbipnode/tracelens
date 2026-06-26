# TraceLens architecture

## Release

v0.7.0-alpha1 is a passive-first monolith:

- FastAPI API
- sequential collectors
- SQLite persistence
- deterministic report enrichment
- React and TypeScript investigation workspace

## Collection pipeline

Collectors execute in this order:

1. DNS
2. WHOIS
3. crt.sh
4. Wayback
5. URLScan search
6. Shodan passive DNS
7. Censys host metadata

URLScan, Shodan, and Censys are optional. Missing credentials return `skipped`. Collector errors are isolated and produce structured error details.

## Data boundaries

Collector payloads are raw normalized evidence. Derived sections never replace collector data.

`enrich_report()` is the compatibility boundary. It upgrades old stored reports at read time and writes schema-2.0 derived sections:

- progress
- infrastructure
- summary
- technology
- certificates
- correlations
- organization
- graph
- timeline
- findings
- executive summary
- verdict

Each derived builder is isolated. A failure is recorded in `derivation_errors` and does not remove raw evidence or prevent other sections from rendering.

## Intelligence modules

`backend/intelligence/` contains focused deterministic builders:

- `technology.py`: passive fingerprint extraction and evidence merging
- `certificates.py`: validity, SAN, wildcard, duplicate, reuse, and relationship analysis
- `correlations.py`: typed cross-source relationships
- `organization.py`: unified organization and infrastructure profile
- `timeline.py`: chronological historical event construction
- `findings.py`: fact/correlation separation and deduplication
- `executive.py`: coverage, confidence, completeness, exposure, and overview

## Graph

Graph entities remain embedded in report JSON. Nodes and edges are deduplicated and bounded by source-specific limits. Edges may include confidence, reasoning, and evidence counts.

The frontend renders at most 180 filtered nodes at once. The complete graph remains downloadable. Native SVG interactions provide node dragging, pan, wheel zoom, fit/reset, category collapse, search, selection, neighbor highlighting, edge highlighting, and side-panel inspection.

## Storage

SQLite stores scan metadata and report JSON. No schema migration is required for derived report evolution because current sections are regenerated when reports are read.
