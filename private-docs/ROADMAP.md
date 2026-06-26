# TraceLens roadmap

## Current: v0.7.0-alpha1

Implemented:

- professional investigation workspace
- interactive relationship graph
- passive technology fingerprinting
- organization intelligence
- certificate intelligence
- unified timeline
- deterministic correlation engine
- findings separation and deduplication
- expanded URLScan and Censys normalization
- executive quality and completeness assessment
- derived-view error isolation
- schema-2.0 backward-compatible report enrichment

## Beta priorities

- persisted analyst notes with evidence references
- report contract validation and migration fixtures
- investigation tagging and larger history controls
- CSV and structured sharing exports
- graph layout profiling on larger reports
- additional passive providers with bounded collectors
- background execution without changing collection semantics

## Deferred

- active infrastructure probing
- port or vulnerability scanning
- exploitation and credential workflows
- multi-user access controls
- separate graph storage
- PDF export

New collectors must remain optional, bounded, mock-testable, and unable to terminate the remaining pipeline.
