# Contributing to TraceLens

TraceLens accepts changes that preserve passive-first, evidence-backed behavior.

## Requirements

- Do not add active target probing.
- Do not emit findings without collected evidence.
- Keep correlations deterministic and explainable.
- Preserve raw collector data and report compatibility.
- Keep optional integrations bounded and failure-isolated.
- Avoid dependencies when the standard library or existing stack is sufficient.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cd frontend
npm install
```

## Verification

```bash
python -m compileall backend
pytest -q

cd frontend
npm run build
npm run lint
```

Collector tests must mock remote services. New derived conclusions require tests proving their evidence and reasoning fields are populated.
