# TraceLens frontend

The M1 dashboard submits domains to the TraceLens API, lists stored scans, and renders collector results and timeline events.

Install and run:

```bash
npm install
npm run dev
```

The development server proxies `/api` and `/health` to `http://localhost:8000`.

Create a production build:

```bash
npm run build
```

Set `VITE_API_URL` when the API is hosted on a different origin.
