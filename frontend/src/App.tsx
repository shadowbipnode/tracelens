import axios from 'axios'
import { useCallback, useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

type CollectorStatus = 'ok' | 'error' | 'skipped'

type CollectorError = {
  category: string
  message: string
  recoverable: boolean
}

type CollectorResult = {
  source: string
  status: CollectorStatus
  data: Record<string, unknown>
  errors: string[]
  error?: CollectorError | null
  error_details?: CollectorError[]
  started_at: string
  completed_at: string
}

type TimelineEvent = {
  type: string
  label: string
  timestamp: string
  source: string
  detail?: string
}

type ReportSummary = {
  target: string
  status: string
  domain_age_years: number | null
  registrar: string | null
  nameserver_count: number
  mx_count: number
  txt_count: number
  a_count: number
  aaaa_count: number
  certificate_count: number
  subdomain_count: number
  wayback_capture_count: number
  first_seen: string | null
  last_updated: string | null
}

type Insight = {
  type: string
  severity: 'info' | 'notice' | 'warning'
  title: string
  description: string
  evidence: unknown[]
}

type Report = {
  scan_id: number
  target: string
  status: string
  started_at: string
  completed_at: string
  collectors: Record<string, CollectorResult>
  timeline: TimelineEvent[]
  summary: ReportSummary
  insights: Insight[]
}

type ScanSummary = {
  scan_id: number
  target: string
  status: string
  created_at: string
  completed_at: string | null
}

type DisplayTimelineEvent = TimelineEvent & {
  count?: number
  endTimestamp?: string
}

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL ?? '' })

const errorLabels: Record<string, string> = {
  timeout: 'Timeout',
  rate_limited: 'Rate limited',
  unavailable: 'Source temporarily unavailable',
  bad_response: 'Unexpected response',
  parse_error: 'Unexpected response',
  network_error: 'Network error',
  unexpected_error: 'Unexpected error',
}

function formatDate(value: string | null) {
  if (!value) return 'Not available'
  const date = new Date(normalizeTimestamp(value))
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function normalizeTimestamp(value: string) {
  return /^\d{14}$/.test(value)
    ? `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(8, 10)}:${value.slice(10, 12)}:${value.slice(12, 14)}Z`
    : value
}

function summaryCards(summary: ReportSummary) {
  return [
    ['Domain age', summary.domain_age_years === null ? 'Unknown' : `${summary.domain_age_years} years`],
    ['Registrar', summary.registrar ?? 'Unknown'],
    ['DNS addresses', `${summary.a_count} IPv4 · ${summary.aaaa_count} IPv6`],
    ['Mail and nameservers', `${summary.mx_count} MX · ${summary.nameserver_count} NS`],
    ['Certificates', summary.certificate_count.toLocaleString()],
    ['Subdomains', summary.subdomain_count.toLocaleString()],
    ['Wayback captures', summary.wayback_capture_count.toLocaleString()],
    ['First seen', formatDate(summary.first_seen)],
  ]
}

function simplifyTimeline(events: TimelineEvent[]): DisplayTimelineEvent[] {
  const certificateEvents = events.filter((event) => event.type === 'certificate_observed')
  if (certificateEvents.length <= 5) return events

  const otherEvents = events.filter((event) => event.type !== 'certificate_observed')
  return [
    ...otherEvents,
    {
      ...certificateEvents[0],
      label: 'Certificates observed',
      detail: `${certificateEvents.length} certificate observations`,
      count: certificateEvents.length,
      endTimestamp: certificateEvents.at(-1)?.timestamp,
    },
  ].sort(
    (left, right) =>
      new Date(normalizeTimestamp(left.timestamp)).getTime() -
      new Date(normalizeTimestamp(right.timestamp)).getTime(),
  )
}

function downloadReport(report: Report) {
  const safeTarget = report.target.replace(/[^a-z0-9.-]/gi, '-')
  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `tracelens-${safeTarget}-${report.scan_id}.json`
  link.click()
  URL.revokeObjectURL(url)
}

function DataSection({
  title,
  collector,
}: {
  title: string
  collector?: CollectorResult
}) {
  const detail = collector?.error ?? collector?.error_details?.[0]
  return (
    <details className="panel report-section">
      <summary>
        <span>{title}</span>
        <span className={`status ${collector?.status ?? 'skipped'}`}>
          {collector?.status ?? 'not run'}
        </span>
      </summary>
      {detail ? (
        <div className="source-error">
          <strong>{errorLabels[detail.category] ?? 'Collector error'}</strong>
          <span>Raw details are included below.</span>
        </div>
      ) : null}
      <pre>{JSON.stringify(collector ?? {}, null, 2)}</pre>
    </details>
  )
}

function App() {
  const [target, setTarget] = useState('')
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [scanFilter, setScanFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  const visibleScans = useMemo(() => {
    const query = scanFilter.trim().toLowerCase()
    return scans.filter(
      (scan) =>
        (!query || scan.target.toLowerCase().includes(query)) &&
        (statusFilter === 'all' || scan.status === statusFilter),
    )
  }, [scanFilter, scans, statusFilter])

  const displayTimeline = useMemo(
    () => simplifyTimeline(report?.timeline ?? []),
    [report],
  )

  const loadScans = useCallback(async () => {
    const response = await api.get<ScanSummary[]>('/api/scans')
    setScans(response.data)
  }, [])

  const loadReport = useCallback(async (scanId: number) => {
    setLoading(true)
    setError('')
    try {
      const response = await api.get<Report>(`/api/scans/${scanId}/report`)
      setReport(response.data)
    } catch {
      setError('The scan report could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadScans().catch(() => setError('Recent scans could not be loaded.'))
  }, [loadScans])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setLoading(true)
    setError('')
    try {
      const response = await api.post<{ scan_id: number }>('/api/scans', {
        target,
      })
      await Promise.all([loadReport(response.data.scan_id), loadScans()])
      setTarget('')
    } catch (requestError) {
      if (axios.isAxiosError(requestError) && requestError.response?.status === 422) {
        setError('Enter a valid domain such as example.com.')
      } else {
        setError('The passive scan could not be completed.')
      }
      setLoading(false)
    }
  }

  return (
    <main>
      <header className="masthead">
        <div>
          <p className="eyebrow">Passive domain intelligence</p>
          <h1>TraceLens</h1>
        </div>
        <span className="version">v0.2.0-alpha2</span>
      </header>

      <section className="panel scan-form">
        <div>
          <h2>Start a scan</h2>
          <p>Collect public DNS, registration, certificate, and archive data.</p>
        </div>
        <form onSubmit={submit}>
          <label htmlFor="target">Domain</label>
          <div className="input-row">
            <input
              id="target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="example.com"
              autoComplete="off"
              required
            />
            <button type="submit" disabled={loading}>
              {loading ? 'Collecting…' : 'Run passive scan'}
            </button>
          </div>
        </form>
        {error ? <p className="notice">{error}</p> : null}
      </section>

      <div className="layout">
        <aside className="panel recent">
          <div className="recent-heading">
            <h2>Recent scans</h2>
            <span>{visibleScans.length} visible</span>
          </div>
          <label htmlFor="scan-search">Search</label>
          <input
            id="scan-search"
            type="search"
            value={scanFilter}
            onChange={(event) => setScanFilter(event.target.value)}
            placeholder="Filter by target"
          />
          <label htmlFor="status-filter">Status</label>
          <select
            id="status-filter"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="all">All statuses</option>
            <option value="completed">Completed</option>
            <option value="partial">Partial</option>
            <option value="failed">Failed</option>
            <option value="running">Running</option>
          </select>
          {scans.length === 0 ? <p>No scans stored yet.</p> : null}
          {scans.length > 0 && visibleScans.length === 0 ? (
            <p>No scans match the current filters.</p>
          ) : null}
          <ul>
            {visibleScans.map((scan) => (
              <li key={scan.scan_id}>
                <button type="button" onClick={() => loadReport(scan.scan_id)}>
                  <strong>{scan.target}</strong>
                  <span>
                    {scan.status} · {formatDate(scan.created_at)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <div className="results">
          {report ? (
            <>
              <section className="panel report-header">
                <div>
                  <p className="eyebrow">Scan #{report.scan_id}</p>
                  <h2>{report.target}</h2>
                </div>
                <div className="report-actions">
                  <span className={`status ${report.status}`}>{report.status}</span>
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => downloadReport(report)}
                  >
                    Download JSON
                  </button>
                </div>
              </section>

              {report.status === 'partial' ? (
                <p className="partial-explanation">
                  Some external sources were unavailable. Existing results are still valid.
                </p>
              ) : null}

              <section className="summary-grid" aria-label="Report summary">
                {summaryCards(report.summary).map(([label, value]) => (
                  <article className="panel summary-card" key={label}>
                    <span>{label}</span>
                    <strong>{value}</strong>
                  </article>
                ))}
              </section>

              <section className="panel report-section">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Source status</p>
                    <h2>Collector health</h2>
                  </div>
                </div>
                <div className="collector-grid">
                  {Object.values(report.collectors).map((collector) => {
                    const detail = collector.error ?? collector.error_details?.[0]
                    return (
                      <div key={collector.source}>
                        <span>{collector.source}</span>
                        <span className={`status ${collector.status}`}>
                          {collector.status}
                        </span>
                        {detail ? (
                          <small>{errorLabels[detail.category] ?? 'Collector error'}</small>
                        ) : (
                          <small>Source completed normally</small>
                        )}
                      </div>
                    )
                  })}
                </div>
              </section>

              <section className="panel report-section">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Evidence-backed findings</p>
                    <h2>DNS insights</h2>
                  </div>
                  <span>{report.insights.length} findings</span>
                </div>
                {report.insights.length ? (
                  <div className="insight-list">
                    {report.insights.map((insight) => (
                      <article className={`insight ${insight.severity}`} key={insight.title}>
                        <span>{insight.severity}</span>
                        <div>
                          <h3>{insight.title}</h3>
                          <p>{insight.description}</p>
                          <details>
                            <summary>View evidence</summary>
                            <pre>{JSON.stringify(insight.evidence, null, 2)}</pre>
                          </details>
                        </div>
                      </article>
                    ))}
                  </div>
                ) : (
                  <p className="muted">No deterministic DNS insights were identified.</p>
                )}
              </section>

              <section className="panel report-section">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Chronology</p>
                    <h2>Timeline</h2>
                  </div>
                  <span>{report.timeline.length} events</span>
                </div>
                <ol className="timeline">
                  {displayTimeline.map((event, index) => (
                    <li key={`${event.type}-${event.timestamp}-${index}`}>
                      <time>
                        {formatDate(event.timestamp)}
                        {event.endTimestamp ? ` – ${formatDate(event.endTimestamp)}` : ''}
                      </time>
                      <strong>{event.label}</strong>
                      <span>{event.detail ?? event.source}</span>
                    </li>
                  ))}
                </ol>
              </section>

              <section className="raw-sections">
                <div className="section-heading raw-heading">
                  <div>
                    <p className="eyebrow">Source evidence</p>
                    <h2>Detailed data</h2>
                  </div>
                </div>
                <DataSection title="DNS" collector={report.collectors.dns} />
                <DataSection title="WHOIS" collector={report.collectors.whois} />
                <DataSection
                  title="Certificate Transparency"
                  collector={report.collectors.crtsh}
                />
                <DataSection
                  title="Wayback Machine"
                  collector={report.collectors.wayback}
                />
                <details className="panel report-section">
                  <summary>
                    <span>Raw report</span>
                    <span className="status">JSON</span>
                  </summary>
                  <pre>{JSON.stringify(report, null, 2)}</pre>
                </details>
              </section>
            </>
          ) : (
            <section className="panel empty-state">
              <h2>No report selected</h2>
              <p>Run a passive scan or choose a stored scan.</p>
            </section>
          )}
        </div>
      </div>
    </main>
  )
}

export default App
