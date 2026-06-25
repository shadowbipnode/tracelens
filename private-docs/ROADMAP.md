# TraceLens Roadmap

## Current: v0.6.0-alpha6

Status: implemented

Focus:

- Professional Analyst Workspace
- section-based report navigation
- viewport-contained responsive layout without page-level horizontal scrolling
- compact executive summary, collector health, and scan progress
- evidence-derived Investigation Verdict with coverage and confidence
- dedicated infrastructure, relationships, timeline, findings, and raw evidence views
- hierarchical graph controls and source-filtered timeline summaries
- Critical, Warning, Notice, and Info finding hierarchy
- searchable, collapsible, copyable, downloadable raw JSON
- bounded evidence and JSON presentation with noisy detail collapsed by default

The release remains passive-first, monolithic, and SQLite-backed.

## Beta Direction

The next beta milestones should focus on:

- graph entity filtering and entity inspection
- stronger cross-source correlation
- report contract versioning and migrations
- larger investigation history controls
- reusable investigation notes and evidence references
- CSV and structured sharing workflows
- performance profiling for larger passive datasets

## Deferred

The following remain outside the current architecture:

- active infrastructure probing
- port or vulnerability scanning
- exploitation and credential workflows
- background worker infrastructure
- multi-user access controls
- separate graph storage
- PDF export

New collectors must remain optional, bounded, testable with mocks, and unable to terminate the rest of a scan.
