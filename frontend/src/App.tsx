import axios from 'axios'
import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

type CollectorStatus = 'ok' | 'error' | 'skipped'

type CollectorResult = {
  source: string
  status: CollectorStatus
  data: Record<string, unknown>
  errors: string[]
  started_at: string
  completed_at: string
}

type TimelineEvent = {
  type: string
  timestamp: string
  source: string
  detail?: string
}

type Report = {
  scan_id: number
  target: string
  status: string
  started_at: string
  completed_at: string
  collectors: Record<string, CollectorResult>
  timeline: TimelineEvent[]
}

type ScanSummary = {
  scan_id: number
  target: string
  status: string
  created_at: string
  completed_at: string | null
}

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL ?? '' })

function DataSection({
  title,
  collector,
}: {
  title: string
  collector?: CollectorResult
}) {
  return (
    <section className="panel report-section">
      <div className="section-heading">
        <h2>{title}</h2>
        <span className={`status ${collector?.status ?? 'skipped'}`}>
          {collector?.status ?? 'not run'}
        </span>
      </div>
      {collector?.errors.length ? (
        <ul className="errors">
          {collector.errors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      ) : null}
      <pre>{JSON.stringify(collector?.data ?? {}, null, 2)}</pre>
    </section>
  )
}

function App() {
  const [target, setTarget] = useState('')
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

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
        <span className="version">M1</span>
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
          <h2>Recent scans</h2>
          {scans.length === 0 ? <p>No scans stored yet.</p> : null}
          <ul>
            {scans.map((scan) => (
              <li key={scan.scan_id}>
                <button type="button" onClick={() => loadReport(scan.scan_id)}>
                  <strong>{scan.target}</strong>
                  <span>
                    {scan.status} · {new Date(scan.created_at).toLocaleString()}
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
                <span className={`status ${report.status}`}>{report.status}</span>
              </section>

              <section className="panel collector-grid">
                {Object.values(report.collectors).map((collector) => (
                  <div key={collector.source}>
                    <span>{collector.source}</span>
                    <span className={`status ${collector.status}`}>
                      {collector.status}
                    </span>
                  </div>
                ))}
              </section>

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

              <section className="panel report-section">
                <h2>Timeline</h2>
                <ol className="timeline">
                  {report.timeline.map((event, index) => (
                    <li key={`${event.type}-${event.timestamp}-${index}`}>
                      <time>{event.timestamp}</time>
                      <strong>{event.type.replaceAll('_', ' ')}</strong>
                      <span>{event.detail ?? event.source}</span>
                    </li>
                  ))}
                </ol>
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
