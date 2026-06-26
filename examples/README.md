# Examples

Run a passive investigation:

```bash
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'
```

List stored investigations:

```bash
curl http://localhost:8000/api/scans
```

Retrieve a report after replacing `SCAN_ID` with an ID returned by the API:

```bash
curl http://localhost:8000/api/scans/SCAN_ID/report \
  -o tracelens-report.json
```

Inspect schema-2.0 sections:

```bash
jq '{
  executive_summary,
  technology,
  organization,
  certificates,
  correlations,
  findings
}' tracelens-report.json
```
