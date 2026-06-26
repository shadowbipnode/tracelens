# TraceLens engineering handover

TraceLens is a passive-first domain investigation platform.

## Current implementation

The current release is v0.7.0-alpha1 with report schema 2.0.

The product collects public evidence, normalizes source payloads, performs deterministic correlations, builds chronological history, and presents investigation-specific views.

## Non-negotiable constraints

- no active target scanning
- no unsupported attribution
- every fingerprint and correlation cites evidence
- raw evidence remains authoritative
- optional sources fail independently
- stored reports remain readable
- dependencies remain minimal

## Key files

- `backend/orchestrator.py`: sequential collection and report assembly
- `backend/report_builder.py`: compatibility and derived-section orchestration
- `backend/intelligence/`: focused intelligence builders
- `backend/collectors/`: source-specific normalization
- `frontend/src/App.tsx`: workspace views and interactions
- `frontend/src/App.css`: dark professional interface
- `tests/test_intelligence.py`: schema-2.0 intelligence coverage

## Report evolution

Do not mutate or remove raw collector fields. Add new derived fields through the enrichment boundary. Builders must return deterministic output for identical input and must include exact evidence references for conclusions.

## Verification

```bash
python -m compileall backend
pytest -q

cd frontend
npm run build
npm run lint
```

Remote services are mocked in tests.
