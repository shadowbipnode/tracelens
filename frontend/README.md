# TraceLens frontend

The React workspace renders schema-2.0 investigation reports from the TraceLens API.

Views:

- Executive Summary
- Infrastructure
- Technology
- Organization
- Certificates
- Relationships
- Timeline
- Findings
- Raw Evidence

The relationship graph uses native SVG and React state for dragging, panning, wheel zoom, category filtering, search, selection, and entity inspection. No graph dependency is required.

```bash
npm install
npm run dev
npm run build
npm run lint
```

The development server proxies `/api` and `/health` to `http://localhost:8000`. Set `VITE_API_URL` when the API is hosted on another origin.
