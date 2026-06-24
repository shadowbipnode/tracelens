import axios from 'axios'
import { useCallback, useEffect, useMemo, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
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
  shodan_subdomain_count: number
  shodan_record_count: number
  censys_host_count: number
  censys_service_count: number
  censys_asn_count: number
  censys_port_count: number
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

type CensysService = {
  port?: number
  protocol?: string
  transport_protocol?: string
  service_name?: string
  scan_time?: string
  tls_certificate_names?: string[]
}

type CensysHost = {
  ip: string
  location?: {
    country?: string
    country_code?: string
    city?: string
  }
  autonomous_system?: {
    asn?: number | string
    name?: string
    description?: string
    bgp_prefix?: string
    country_code?: string
  }
  whois?: {
    organization?: string
    network_name?: string
  }
  services: CensysService[]
  service_count: number
  services_truncated?: boolean
}

type DisplayTimelineEvent = TimelineEvent & {
  count?: number
  endTimestamp?: string
}

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL ?? '' })

const errorLabels: Record<string, string> = {
  timeout: 'Request timed out',
  rate_limited: 'Rate limited',
  unavailable: 'Source unavailable',
  bad_response: 'Unexpected response',
  parse_error: 'Response could not be parsed',
  network_error: 'Network error',
  invalid_credentials: 'Invalid credentials',
  forbidden: 'Access forbidden',
  plan_restricted: 'Plan restricted',
  unexpected_error: 'Unexpected error',
}

function normalizeTimestamp(value: string) {
  return /^\d{14}$/.test(value)
    ? `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(8, 10)}:${value.slice(10, 12)}:${value.slice(12, 14)}Z`
    : value
}

function formatDate(value: string | null, compact = false) {
  if (!value) return 'Not available'
  const date = new Date(normalizeTimestamp(value))
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: compact ? 'medium' : 'long',
    timeStyle: compact ? undefined : 'short',
  }).format(date)
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : []
}

function asObjects(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is Record<string, unknown> =>
          typeof item === 'object' && item !== null,
      )
    : []
}

function evidenceLabel(value: unknown) {
  if (typeof value === 'string' || typeof value === 'number') return String(value)
  if (typeof value === 'object' && value !== null) {
    return Object.entries(value)
      .map(([key, item]) => `${key.replaceAll('_', ' ')}: ${String(item)}`)
      .join(' · ')
  }
  return String(value)
}

function simplifyTimeline(events: TimelineEvent[]): DisplayTimelineEvent[] {
  const groupedTypes = new Set(['certificate_observed', 'censys_service_observed'])
  const grouped = [...groupedTypes].flatMap((type) => {
    const matches = events.filter((event) => event.type === type)
    if (matches.length <= 5) return matches
    return [
      {
        ...matches[0],
        label:
          type === 'certificate_observed'
            ? 'Certificates observed'
            : 'Censys services observed',
        detail: `${matches.length} observations`,
        count: matches.length,
        endTimestamp: matches.at(-1)?.timestamp,
      },
    ]
  })
  const other = events.filter((event) => !groupedTypes.has(event.type))
  return [...other, ...grouped].sort(
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

function StatusBadge({
  status,
  children,
}: {
  status: string
  children?: ReactNode
}) {
  return <span className={`status ${status}`}>{children ?? status}</span>
}

function Section({
  eyebrow,
  title,
  meta,
  children,
  className = '',
}: {
  eyebrow: string
  title: string
  meta?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`panel report-section ${className}`}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">{eyebrow}</p>
          <h2>{title}</h2>
        </div>
        {meta}
      </div>
      {children}
    </section>
  )
}

function SourceState({ collector }: { collector?: CollectorResult }) {
  const detail = collector?.error ?? collector?.error_details?.[0]
  if (collector?.status === 'skipped') {
    const reason =
      typeof collector.data.reason === 'string'
        ? collector.data.reason
        : 'not_configured'
    return (
      <div className="source-state skipped-state">
        <strong>Optional source skipped</strong>
        <span>
          {reason === 'no_ip_addresses'
            ? 'No DNS A or AAAA addresses were available.'
            : collector.errors[0] ?? 'This integration is not configured.'}
        </span>
      </div>
    )
  }
  if (collector?.status === 'error') {
    return (
      <div className="source-state error-state">
        <strong>{errorLabels[detail?.category ?? ''] ?? 'Collector error'}</strong>
        <span>{detail?.message ?? collector.errors[0]}</span>
      </div>
    )
  }
  return null
}

function ChipList({
  values,
  empty = 'No observations returned.',
  limit = 16,
}: {
  values: Array<string | number>
  empty?: string
  limit?: number
}) {
  if (!values.length) return <p className="muted">{empty}</p>
  return (
    <div className="chips">
      {values.slice(0, limit).map((value) => (
        <span key={String(value)}>{value}</span>
      ))}
      {values.length > limit ? <span>+{values.length - limit} more</span> : null}
    </div>
  )
}

function DomainOverview({ report }: { report: Report }) {
  const summary = report.summary
  return (
    <Section
      eyebrow="Investigation profile"
      title="Domain Overview"
      meta={<StatusBadge status={report.status} />}
    >
      <div className="overview-grid">
        <div>
          <span>Registrar</span>
          <strong>{summary.registrar ?? 'Unknown'}</strong>
        </div>
        <div>
          <span>Domain age</span>
          <strong>
            {summary.domain_age_years === null
              ? 'Unknown'
              : `${summary.domain_age_years} years`}
          </strong>
        </div>
        <div>
          <span>First evidence</span>
          <strong>{formatDate(summary.first_seen, true)}</strong>
        </div>
        <div>
          <span>WHOIS updated</span>
          <strong>{formatDate(summary.last_updated, true)}</strong>
        </div>
      </div>
    </Section>
  )
}

function DnsSection({ collector }: { collector?: CollectorResult }) {
  const records =
    typeof collector?.data.records === 'object' && collector.data.records !== null
      ? (collector.data.records as Record<string, unknown>)
      : {}
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'CAA']
  return (
    <Section
      eyebrow="Resolution evidence"
      title="DNS Intelligence"
      meta={<StatusBadge status={collector?.status ?? 'skipped'} />}
    >
      <SourceState collector={collector} />
      <div className="record-grid">
        {types.map((type) => {
          const values = Array.isArray(records[type]) ? records[type] : []
          return (
            <article key={type}>
              <div>
                <strong>{type}</strong>
                <span>{values.length}</span>
              </div>
              <ChipList
                values={values.slice(0, 8).map((value) =>
                  typeof value === 'object' ? JSON.stringify(value) : String(value),
                )}
                empty={`No ${type} records`}
                limit={8}
              />
            </article>
          )
        })}
      </div>
    </Section>
  )
}

function WhoisSection({ collector }: { collector?: CollectorResult }) {
  const data = collector?.data ?? {}
  const fields = [
    ['Registrar', data.registrar],
    ['Created', data.creation_date],
    ['Updated', data.updated_date],
    ['Expires', data.expiration_date],
  ]
  return (
    <Section
      eyebrow="Registration metadata"
      title="WHOIS"
      meta={<StatusBadge status={collector?.status ?? 'skipped'} />}
    >
      <SourceState collector={collector} />
      <dl className="definition-grid">
        {fields.map(([label, value]) => (
          <div key={String(label)}>
            <dt>{String(label)}</dt>
            <dd>
              {String(label) === 'Registrar'
                ? String(value ?? 'Not available')
                : formatDate(typeof value === 'string' ? value : null, true)}
            </dd>
          </div>
        ))}
      </dl>
      <div className="subsection">
        <h3>Nameservers</h3>
        <ChipList values={asStrings(data.name_servers)} />
      </div>
    </Section>
  )
}

function CertificateSection({ collector }: { collector?: CollectorResult }) {
  const data = collector?.data ?? {}
  const subdomains = asStrings(data.subdomains)
  const certificates = asObjects(data.certificates)
  return (
    <Section
      eyebrow="Public certificate records"
      title="Certificate Transparency"
      meta={
        <span className="section-count">
          {certificates.length.toLocaleString()} certificates
        </span>
      }
    >
      <SourceState collector={collector} />
      <div className="split-content">
        <div>
          <h3>Observed subdomains</h3>
          <ChipList values={subdomains} limit={24} />
        </div>
        <div>
          <h3>Recent certificate sample</h3>
          <div className="compact-list">
            {certificates.slice(0, 6).map((certificate, index) => (
              <div key={`${String(certificate.serial_number)}-${index}`}>
                <strong>
                  {String(certificate.common_name ?? 'Unnamed certificate')}
                </strong>
                <span>{formatDate(String(certificate.not_before ?? ''), true)}</span>
              </div>
            ))}
            {!certificates.length ? <p className="muted">No certificates returned.</p> : null}
          </div>
        </div>
      </div>
    </Section>
  )
}

function WaybackSection({ collector }: { collector?: CollectorResult }) {
  const data = collector?.data ?? {}
  const captures = asObjects(data.captures)
  return (
    <Section
      eyebrow="Historical web evidence"
      title="Wayback"
      meta={
        <span className="section-count">
          {captures.length.toLocaleString()} captures
        </span>
      }
    >
      <SourceState collector={collector} />
      <div className="compact-list capture-list">
        {captures.slice(0, 8).map((capture, index) => (
          <div key={`${String(capture.timestamp)}-${index}`}>
            <strong>{String(capture.url ?? 'Archived URL')}</strong>
            <span>
              {formatDate(String(capture.timestamp ?? ''), true)} ·{' '}
              {String(capture.mime_type ?? 'unknown type')}
            </span>
          </div>
        ))}
        {!captures.length ? <p className="muted">No archived captures returned.</p> : null}
      </div>
    </Section>
  )
}

function ShodanSection({ collector }: { collector?: CollectorResult }) {
  const data = collector?.data ?? {}
  const subdomains = asStrings(data.subdomains)
  const tags = asStrings(data.tags)
  return (
    <Section
      eyebrow="Optional passive source"
      title="Shodan"
      meta={<StatusBadge status={collector?.status ?? 'skipped'} />}
    >
      <SourceState collector={collector} />
      {collector?.status === 'ok' ? (
        <>
          <div className="mini-metrics">
            <div>
              <span>Subdomains</span>
              <strong>{subdomains.length.toLocaleString()}</strong>
            </div>
            <div>
              <span>DNS records</span>
              <strong>{Number(data.record_count ?? 0).toLocaleString()}</strong>
            </div>
            <div>
              <span>Tags</span>
              <strong>{tags.length.toLocaleString()}</strong>
            </div>
          </div>
          <div className="subsection">
            <h3>Observed names</h3>
            <ChipList values={subdomains} />
          </div>
        </>
      ) : null}
    </Section>
  )
}

function CensysSection({ collector }: { collector?: CollectorResult }) {
  const data = collector?.data ?? {}
  const hosts = Array.isArray(data.hosts) ? (data.hosts as CensysHost[]) : []
  const ports = Array.isArray(data.ports) ? (data.ports as number[]) : []
  const protocols = asStrings(data.protocols)
  const organizations = asStrings(data.organizations)
  const locations = asStrings(data.locations)
  return (
    <Section
      eyebrow="DNS-derived host intelligence"
      title="Censys Host Intelligence"
      meta={<StatusBadge status={collector?.status ?? 'skipped'} />}
      className="censys-section"
    >
      <SourceState collector={collector} />
      {collector?.status === 'ok' || hosts.length ? (
        <>
          <div className="mini-metrics four">
            <div>
              <span>Hosts</span>
              <strong>{Number(data.host_count ?? hosts.length).toLocaleString()}</strong>
            </div>
            <div>
              <span>Services</span>
              <strong>{Number(data.service_count ?? 0).toLocaleString()}</strong>
            </div>
            <div>
              <span>Ports</span>
              <strong>{ports.length.toLocaleString()}</strong>
            </div>
            <div>
              <span>ASNs</span>
              <strong>
                {(Array.isArray(data.asns) ? data.asns.length : 0).toLocaleString()}
              </strong>
            </div>
          </div>
          <div className="censys-facts">
            <div>
              <h3>Observed ports</h3>
              <ChipList values={ports} />
            </div>
            <div>
              <h3>Protocols</h3>
              <ChipList values={protocols} />
            </div>
            <div>
              <h3>ASN and organizations</h3>
              <ChipList values={organizations} />
            </div>
            <div>
              <h3>Locations</h3>
              <ChipList values={locations} />
            </div>
          </div>
          <div className="host-grid">
            {hosts.map((host) => {
              const location = [host.location?.city, host.location?.country_code]
                .filter(Boolean)
                .join(', ')
              return (
                <article className="host-card" key={host.ip}>
                  <div className="host-heading">
                    <div>
                      <span>Host</span>
                      <h3>{host.ip}</h3>
                    </div>
                    <span>{host.service_count} services</span>
                  </div>
                  <dl>
                    <div>
                      <dt>Network</dt>
                      <dd>
                        {host.autonomous_system?.name ??
                          host.whois?.organization ??
                          'Unknown'}
                      </dd>
                    </div>
                    <div>
                      <dt>ASN</dt>
                      <dd>
                        {host.autonomous_system?.asn
                          ? `AS${host.autonomous_system.asn}`
                          : 'Unknown'}
                      </dd>
                    </div>
                    <div>
                      <dt>Location</dt>
                      <dd>{location || 'Unknown'}</dd>
                    </div>
                  </dl>
                  <div className="service-list">
                    {host.services.slice(0, 8).map((service, index) => (
                      <div key={`${service.port}-${service.protocol}-${index}`}>
                        <strong>{service.port ?? '—'}</strong>
                        <span>
                          {service.service_name ?? service.protocol ?? 'Unknown service'}
                        </span>
                        <small>{service.transport_protocol ?? '—'}</small>
                      </div>
                    ))}
                    {!host.services.length ? (
                      <p className="muted">No services returned.</p>
                    ) : null}
                  </div>
                </article>
              )
            })}
          </div>
        </>
      ) : null}
    </Section>
  )
}

function RawEvidence({ report }: { report: Report }) {
  return (
    <Section eyebrow="Normalized source output" title="Raw Evidence">
      <div className="raw-evidence">
        {Object.values(report.collectors).map((collector) => (
          <details key={collector.source}>
            <summary>
              <span>{collector.source}</span>
              <StatusBadge status={collector.status} />
            </summary>
            <pre>{JSON.stringify(collector, null, 2)}</pre>
          </details>
        ))}
        <details>
          <summary>
            <span>Complete report</span>
            <StatusBadge status="json">JSON</StatusBadge>
          </summary>
          <pre>{JSON.stringify(report, null, 2)}</pre>
        </details>
      </div>
    </Section>
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
      setError('The selected report could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadScans().catch(() => setError('Recent scans could not be loaded.'))
  }, [loadScans])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const normalizedTarget = target.trim().toLowerCase()
    if (!normalizedTarget) {
      setError('Enter a domain such as example.com.')
      return
    }
    setLoading(true)
    setError('')
    try {
      const response = await api.post<{ scan_id: number }>('/api/scans', {
        target: normalizedTarget,
      })
      await Promise.all([loadReport(response.data.scan_id), loadScans()])
      setTarget('')
    } catch (requestError) {
      if (axios.isAxiosError(requestError) && requestError.response?.status === 422) {
        setError('Enter a valid domain without a URL path or protocol.')
      } else {
        setError('The passive scan could not be completed.')
      }
      setLoading(false)
    }
  }

  const summaryMetrics = report
    ? [
        ['DNS addresses', report.summary.a_count + report.summary.aaaa_count, 'A + AAAA'],
        ['Certificates', report.summary.certificate_count, 'public records'],
        ['Subdomains', report.summary.subdomain_count, 'CT observations'],
        ['Archive captures', report.summary.wayback_capture_count, 'historical URLs'],
        ['Censys hosts', report.summary.censys_host_count ?? 0, 'DNS-derived'],
        ['Censys services', report.summary.censys_service_count ?? 0, 'observed'],
      ]
    : []

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">TL</span>
          <div>
            <strong>TraceLens</strong>
            <span>Intelligence Console</span>
          </div>
        </div>
        <div className="system-status">
          <span />
          Passive collection ready
        </div>
        <nav aria-label="Report sections">
          <a href="#overview">Overview</a>
          <a href="#intelligence">Intelligence</a>
          <a href="#timeline">Timeline</a>
          <a href="#evidence">Raw evidence</a>
        </nav>
        <div className="recent-header">
          <div>
            <span>Investigation history</span>
            <strong>Recent scans</strong>
          </div>
          <span>{visibleScans.length}</span>
        </div>
        <div className="scan-filters">
          <input
            aria-label="Search scans by target"
            type="search"
            value={scanFilter}
            onChange={(event) => setScanFilter(event.target.value)}
            placeholder="Search target"
          />
          <select
            aria-label="Filter scans by status"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="all">All statuses</option>
            <option value="completed">Completed</option>
            <option value="partial">Partial</option>
            <option value="failed">Failed</option>
            <option value="running">Running</option>
          </select>
        </div>
        <div className="scan-list">
          {visibleScans.map((scan) => (
            <button
              type="button"
              className={report?.scan_id === scan.scan_id ? 'active' : ''}
              key={scan.scan_id}
              onClick={() => loadReport(scan.scan_id)}
            >
              <span className={`scan-dot ${scan.status}`} />
              <span>
                <strong>{scan.target}</strong>
                <small>{formatDate(scan.created_at, true)}</small>
              </span>
              <small>#{scan.scan_id}</small>
            </button>
          ))}
          {!visibleScans.length ? (
            <p>{scans.length ? 'No scans match these filters.' : 'No scans stored yet.'}</p>
          ) : null}
        </div>
        <span className="version">v0.4.0-alpha4</span>
      </aside>

      <main className="workspace">
        <header className="workspace-header">
          <div>
            <p className="eyebrow">Passive-first domain intelligence</p>
            <h1>Investigation workspace</h1>
          </div>
          <div className="workspace-state">
            <span>{loading ? 'Collection in progress' : 'Console online'}</span>
            <i className={loading ? 'working' : ''} />
          </div>
        </header>

        <section className="scan-command panel">
          <div>
            <span className="command-icon">⌕</span>
            <div>
              <h2>Start a passive investigation</h2>
              <p>
                Collect public DNS, registration, certificate, archive, and
                optional host intelligence. No direct infrastructure scanning.
              </p>
            </div>
          </div>
          <form onSubmit={submit}>
            <input
              aria-label="Domain target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="example.com"
              autoComplete="off"
              disabled={loading}
            />
            <button type="submit" disabled={loading}>
              {loading ? <span className="spinner" /> : null}
              {loading ? 'Collecting' : 'Run scan'}
            </button>
          </form>
          {error ? <p className="form-error">{error}</p> : null}
        </section>

        {report ? (
          <div className="report">
            <section className="report-title" id="overview">
              <div>
                <div className="report-kicker">
                  <span>Scan #{report.scan_id}</span>
                  <StatusBadge status={report.status} />
                </div>
                <h2>{report.target}</h2>
                <p>
                  Completed {formatDate(report.completed_at)} ·{' '}
                  {Object.keys(report.collectors).length} sources evaluated
                </p>
              </div>
              <button
                type="button"
                className="export-button"
                onClick={() => downloadReport(report)}
              >
                <span>↓</span> Download JSON
              </button>
            </section>

            {report.status === 'partial' ? (
              <div className="partial-explanation">
                <strong>Partial source coverage</strong>
                <span>
                  One or more external sources returned an error. Successful
                  collector evidence remains available below.
                </span>
              </div>
            ) : null}

            <section className="metric-grid" aria-label="Report summary">
              {summaryMetrics.map(([label, value, note]) => (
                <article className="metric-card" key={String(label)}>
                  <span>{label}</span>
                  <strong>{Number(value).toLocaleString()}</strong>
                  <small>{note}</small>
                </article>
              ))}
            </section>

            <Section
              eyebrow="Source operations"
              title="Collector Health"
              meta={
                <span className="section-count">
                  {Object.values(report.collectors).filter(
                    (collector) => collector.status === 'ok',
                  ).length}{' '}
                  healthy
                </span>
              }
            >
              <div className="collector-grid">
                {Object.values(report.collectors).map((collector) => {
                  const detail = collector.error ?? collector.error_details?.[0]
                  return (
                    <article key={collector.source}>
                      <div>
                        <span className={`collector-icon ${collector.status}`}>
                          {collector.status === 'ok'
                            ? '✓'
                            : collector.status === 'skipped'
                              ? '–'
                              : '!'}
                        </span>
                        <strong>{collector.source}</strong>
                      </div>
                      <StatusBadge status={collector.status} />
                      <small>
                        {collector.status === 'ok'
                          ? 'Source completed normally'
                          : collector.status === 'skipped'
                            ? collector.errors[0] ?? 'Optional source skipped'
                            : errorLabels[detail?.category ?? ''] ?? 'Collector error'}
                      </small>
                    </article>
                  )
                })}
              </div>
            </Section>

            <Section
              eyebrow="Evidence-backed assessment"
              title="Analyst Notes"
              meta={
                <span className="section-count">{report.insights.length} findings</span>
              }
            >
              <div className="insight-list">
                {report.insights.map((insight, index) => (
                  <article
                    className={`insight ${insight.severity}`}
                    key={`${insight.title}-${index}`}
                  >
                    <span className="insight-marker">
                      {insight.severity === 'warning'
                        ? '!'
                        : insight.severity === 'notice'
                          ? '◆'
                          : 'i'}
                    </span>
                    <div>
                      <span className="insight-source">{insight.type}</span>
                      <h3>{insight.title}</h3>
                      <p>{insight.description}</p>
                      <div className="evidence-chips">
                        {insight.evidence.slice(0, 8).map((evidence, evidenceIndex) => (
                          <span key={`${evidenceLabel(evidence)}-${evidenceIndex}`}>
                            {evidenceLabel(evidence)}
                          </span>
                        ))}
                      </div>
                    </div>
                  </article>
                ))}
                {!report.insights.length ? (
                  <p className="muted">No deterministic insights were identified.</p>
                ) : null}
              </div>
            </Section>

            <div id="intelligence" className="intelligence-stack">
              <DomainOverview report={report} />
              <DnsSection collector={report.collectors.dns} />
              <WhoisSection collector={report.collectors.whois} />
              <CertificateSection collector={report.collectors.crtsh} />
              <WaybackSection collector={report.collectors.wayback} />
              <ShodanSection collector={report.collectors.shodan} />
              <CensysSection collector={report.collectors.censys} />
            </div>

            <div id="timeline">
              <Section
                eyebrow="Observed chronology"
                title="Timeline"
                meta={
                  <span className="section-count">
                    {report.timeline.length} events
                  </span>
                }
              >
                <ol className="timeline">
                  {displayTimeline.map((event, index) => (
                    <li key={`${event.type}-${event.timestamp}-${index}`}>
                      <span className={`timeline-node ${event.source}`} />
                      <div className="timeline-date">
                        <time>{formatDate(event.timestamp, true)}</time>
                        {event.endTimestamp ? (
                          <small>to {formatDate(event.endTimestamp, true)}</small>
                        ) : null}
                      </div>
                      <div>
                        <span className="source-badge">{event.source}</span>
                        <strong>{event.label}</strong>
                        <p>{event.detail ?? 'Source observation recorded'}</p>
                      </div>
                    </li>
                  ))}
                </ol>
              </Section>
            </div>

            <div id="evidence">
              <RawEvidence report={report} />
            </div>
          </div>
        ) : (
          <section className="empty-state panel">
            <span className="empty-mark">◎</span>
            <p className="eyebrow">Investigation workspace</p>
            <h2>No report selected</h2>
            <p>
              Run a passive domain scan or select a previous investigation from
              the sidebar.
            </p>
          </section>
        )}
      </main>
    </div>
  )
}

export default App
