# Report schema 2.0

Stored reports retain raw collector results under `collectors`. Derived sections are rebuilt when reports are read.

## Collector result

Each source returns:

- `source`
- `status`: `ok`, `error`, or `skipped`
- `data`
- `errors`
- `error` and `error_details`
- `started_at`
- `completed_at`

## Derived sections

### `technology`

Contains evidence-backed fingerprints grouped by category. Every fingerprint includes `confidence`, `reasoning`, and `evidence`.

### `organization`

Contains organizations, ASNs, certificate issuers, domains, subdomains, MX, nameservers, IPs, provider evidence, relationships, and counts.

### `certificates`

Contains normalized certificate records, issuers, SANs, wildcard names, validity, expiration state, duplicates, shared certificates, reuse groups, and certificate-domain relationships.

### `correlations`

Contains deterministic entity pairs. Each correlation includes typed left and right entities, confidence, reasoning, and source evidence.

### `timeline`

Contains chronological WHOIS, certificate, Wayback, URLScan, Shodan, Censys, and scan events. Events may include `entity` and `evidence_ref`.

### `findings`

Separates `observed_facts`, `correlated_findings`, and `analyst_notes`. Each finding includes severity, confidence, reasoning, evidence, and sources.

### `executive_summary`

Contains infrastructure, hosting, cloud, mail, technology, passive exposure, collection quality, evidence completeness, and high-level observations.

### `graph`

Contains nodes, edges, category groups, node counts, relationship counts, and optional edge metadata. The complete graph remains in the report even when the UI renders a bounded filtered subset.

### `derivation_errors`

Records recoverable errors from derived-section construction. Raw collector evidence remains available when a derived view cannot be built.

## Compatibility

Schema-1 reports do not require a database migration. The API passes stored reports through `enrich_report()`, which regenerates current derived sections from available collector evidence.
