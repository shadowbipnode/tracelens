import axios from 'axios'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { FormEvent, PointerEvent as ReactPointerEvent, ReactNode, WheelEvent as ReactWheelEvent } from 'react'
import './App.css'

type CollectorStatus = 'ok' | 'error' | 'skipped'
type ViewId =
  | 'summary'
  | 'infrastructure'
  | 'technology'
  | 'organization'
  | 'certificates'
  | 'relationships'
  | 'timeline'
  | 'findings'
  | 'evidence'

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
  entity?: string
  evidence_ref?: string
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
  urlscan_result_count: number
  urlscan_domain_count: number
  urlscan_ip_count: number
  first_seen: string | null
  last_updated: string | null
}

type ProgressStep = {
  source: string
  label: string
  status: 'pending' | 'running' | CollectorStatus
  started_at: string | null
  completed_at: string | null
}

type ScanProgress = {
  total_collectors: number
  completed_collectors: number
  successful_collectors: number
  skipped_collectors: number
  failed_collectors: number
  percent: number
  state: 'idle' | 'running' | 'completed' | 'partial' | 'failed'
  steps: ProgressStep[]
}

type Infrastructure = {
  ips: string[]
  ipv4_count: number
  ipv6_count: number
  asns: string[]
  organizations: string[]
  providers: string[]
  countries: string[]
  ports: number[]
  protocols: string[]
  service_count: number
  cloud_or_cdn_detected: boolean
}

type GraphNode = {
  id: string
  type: string
  label: string
  metadata: Record<string, unknown>
}

type GraphEdge = {
  id: string
  source: string
  target: string
  type: string
  metadata?: Record<string, unknown>
}

type RelationshipGraph = {
  nodes: GraphNode[]
  edges: GraphEdge[]
  stats: {
    node_count: number
    edge_count: number
    type_counts: Record<string, number>
    relationship_counts?: Record<string, number>
  }
  groups?: Array<{
    id: string
    label: string
    node_ids: string[]
    count: number
  }>
}

type EvidenceReference = {
  source: string
  field: string
  value: unknown
  context?: string
}

type Fingerprint = {
  category: string
  name: string
  value: string
  confidence: string
  reasoning: string
  evidence: EvidenceReference[]
}

type TechnologyIntelligence = {
  fingerprints: Fingerprint[]
  categories: Record<string, Fingerprint[]>
  observed_sources: string[]
  fingerprint_count: number
  evidence_count: number
}

type CertificateRecord = {
  id: string
  source: string
  common_name?: string | null
  issuer?: string | null
  not_before?: string | null
  not_after?: string | null
  sans: string[]
  wildcards: string[]
  expired: boolean
  evidence: EvidenceReference[]
}

type CertificateIntelligence = {
  certificates: CertificateRecord[]
  certificate_count: number
  issuers: string[]
  wildcard_count: number
  expired_count: number
  duplicate_certificates: Array<Record<string, unknown>>
  shared_certificates: Array<Record<string, unknown>>
  reuse_count: number
  relationships: Array<Record<string, unknown>>
}

type OrganizationIntelligence = {
  target: string
  organizations: Array<{
    name: string
    asns: string[]
    ips: string[]
    domains: string[]
    certificates: string[]
    sources: string[]
  }>
  asns: Array<Record<string, unknown>>
  certificate_issuers: Array<{ name: string; certificates: string[] }>
  domains: string[]
  subdomains: string[]
  mx: string[]
  nameservers: string[]
  ips: string[]
  cloud_providers: Array<{
    name: string
    confidence: string
    reasoning: string
    evidence: EvidenceReference[]
  }>
  relationships: Array<Record<string, unknown>>
  stats: Record<string, number>
}

type Finding = Insight & {
  id: string
  kind: 'observed_fact' | 'correlated_finding' | 'analyst_note'
  confidence: string
  reasoning: string
  sources: string[]
}

type FindingsEngine = {
  observed_facts: Finding[]
  correlated_findings: Finding[]
  analyst_notes: Finding[]
  all: Finding[]
  counts: Record<string, number>
}

type ExecutiveIntelligence = {
  investigation_status: string
  infrastructure_overview: Record<string, unknown>
  hosting: Record<string, unknown>
  cloud: string[]
  mail_infrastructure: string[]
  technology_stack: string[]
  passive_exposure: {
    ports: number[]
    protocols: string[]
    host_count: number
    service_count: number
  }
  collection_quality: {
    coverage: string
    coverage_ratio: number
    confidence: string
    evidence_completeness: string
    successful_sources: string[]
    failed_sources: string[]
    skipped_sources: string[]
    corroborated_technology_count: number
    evidence_reference_count: number
  }
  timeline_event_count: number
  high_level_observations: string[]
}

type InvestigationVerdict = {
  target: string
  investigation_status: string
  coverage_status: string
  risk_level: string
  confidence_level: string
  domain_age_years: number | null
  registrar: string | null
  infrastructure_providers: string[]
  email_providers: string[]
  host_intelligence_sources: string[]
  timeline: {
    event_count: number
    first_observation: string | null
    last_observation: string | null
  }
  sources_used: string[]
  narrative: string
}

type Insight = {
  type: string
  severity: 'info' | 'notice' | 'warning' | 'critical'
  title: string
  description: string
  evidence: unknown[]
}

type Report = {
  schema_version?: string
  scan_id: number
  target: string
  status: string
  started_at: string
  completed_at: string
  collectors: Record<string, CollectorResult>
  timeline: TimelineEvent[]
  summary: ReportSummary
  insights: Insight[]
  progress: ScanProgress
  infrastructure: Infrastructure
  graph: RelationshipGraph
  verdict?: InvestigationVerdict
  technology?: TechnologyIntelligence
  certificates?: CertificateIntelligence
  organization?: OrganizationIntelligence
  findings?: FindingsEngine
  executive_summary?: ExecutiveIntelligence
  derivation_errors?: Array<{
    section: string
    category: string
    message: string
    recoverable: boolean
  }>
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
  }
  whois?: {
    organization?: string
    network_name?: string
  }
  services?: CensysService[]
  service_count?: number
  services_truncated?: boolean
}

type DisplayTimelineEvent = TimelineEvent & {
  count: number
  endTimestamp?: string
}

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL ?? '' })

const navigation: Array<{ id: ViewId; label: string; short: string }> = [
  { id: 'summary', label: 'Executive Summary', short: 'ES' },
  { id: 'infrastructure', label: 'Infrastructure', short: 'IN' },
  { id: 'technology', label: 'Technology', short: 'TE' },
  { id: 'organization', label: 'Organization', short: 'OR' },
  { id: 'certificates', label: 'Certificates', short: 'CT' },
  { id: 'relationships', label: 'Relationships', short: 'RL' },
  { id: 'timeline', label: 'Timeline', short: 'TL' },
  { id: 'findings', label: 'Findings', short: 'FD' },
  { id: 'evidence', label: 'Raw Evidence', short: 'RE' },
]

const navigationActions: Record<ViewId, string> = {
  summary: 'Assess',
  infrastructure: 'Inspect',
  technology: 'Fingerprint',
  organization: 'Attribute',
  certificates: 'Validate',
  relationships: 'Correlate',
  timeline: 'Sequence',
  findings: 'Review',
  evidence: 'Verify',
}

const collectorLabels: Record<string, string> = {
  dns: 'DNS',
  whois: 'WHOIS',
  crtsh: 'Certificate Transparency',
  wayback: 'Wayback',
  shodan: 'Shodan',
  censys: 'Censys',
  urlscan: 'URLScan',
}

const collectorOrder = ['dns', 'whois', 'crtsh', 'wayback', 'urlscan', 'shodan', 'censys']

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
    ? value
        .filter((item) => item !== null && item !== undefined)
        .map((item) =>
          typeof item === 'object' ? JSON.stringify(item) : String(item),
        )
    : []
}

function compactValue(value: unknown, limit = 120) {
  let text: string
  if (typeof value === 'string' || typeof value === 'number') {
    text = String(value)
  } else {
    try {
      text = JSON.stringify(value)
    } catch {
      text = String(value)
    }
  }
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text
}

function evidenceSummary(evidence: unknown[]) {
  if (!evidence.length) return 'No concise evidence summary was provided.'
  const labels = evidence.slice(0, 3).map((item) => evidenceLabel(item))
  return `${labels.join(' · ')}${evidence.length > 3 ? ` · +${evidence.length - 3} more in Raw Evidence` : ''}`
}

function evidenceLabel(value: unknown) {
  if (typeof value !== 'object' || value === null) return compactValue(value)
  const text = Object.entries(value)
    .map(([key, item]) => `${key.replaceAll('_', ' ')}: ${compactValue(item, 54)}`)
    .join(' · ')
  return compactValue(text, 150)
}

function groupTimeline(events: TimelineEvent[]): DisplayTimelineEvent[] {
  const groups = new Map<string, TimelineEvent[]>()
  events.forEach((event) => {
    const key = `${event.type}:${event.source}`
    groups.set(key, [...(groups.get(key) ?? []), event])
  })

  return Array.from(groups.values())
    .flatMap((matches) => {
      const sorted = [...matches].sort(
        (left, right) =>
          new Date(normalizeTimestamp(left.timestamp)).getTime() -
          new Date(normalizeTimestamp(right.timestamp)).getTime(),
      )
      if (sorted.length < 5) {
        return sorted.map((event) => ({ ...event, count: 1 }))
      }
      return [
        {
          ...sorted[0],
          label: sorted[0].label.replace(/\bobserved\b/i, 'observations'),
          detail: `${sorted.length} repeated source events grouped`,
          count: sorted.length,
          endTimestamp: sorted.at(-1)?.timestamp,
        },
      ]
    })
    .sort(
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
  return <span className={`status status-${status}`}>{children ?? status}</span>
}

function Panel({
  eyebrow,
  title,
  meta,
  children,
  className = '',
}: {
  eyebrow?: string
  title: string
  meta?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`panel ${className}`}>
      <header className="panel-heading">
        <div>
          {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
          <h2>{title}</h2>
        </div>
        {meta}
      </header>
      {children}
    </section>
  )
}

function SourceMessage({ collector }: { collector?: CollectorResult }) {
  if (!collector || collector.status === 'ok') return null
  const detail = collector.error ?? collector.error_details?.[0]
  const reason =
    typeof collector.data.reason === 'string' ? collector.data.reason : ''
  return (
    <div className={`source-message ${collector.status}`}>
      <strong>
        {collector.status === 'skipped'
          ? 'Optional source skipped'
          : errorLabels[detail?.category ?? ''] ?? 'Collector error'}
      </strong>
      <span>
        {reason === 'no_ip_addresses'
          ? 'No DNS addresses were available for this source.'
          : detail?.message ??
            collector.errors[0] ??
            'This optional source is not configured.'}
      </span>
    </div>
  )
}

function ChipList({
  values,
  empty = 'No observations returned.',
  limit = 10,
}: {
  values: Array<string | number>
  empty?: string
  limit?: number
}) {
  if (!values.length) return <p className="empty-inline">{empty}</p>
  return (
    <div className="chip-list">
      {values.slice(0, limit).map((value, index) => {
        const full = String(value)
        return (
          <span title={full} key={`${full}-${index}`}>
            {compactValue(full, 64)}
          </span>
        )
      })}
      {values.length > limit ? (
        <span className="chip-overflow">+{values.length - limit} more</span>
      ) : null}
    </div>
  )
}

function ProgressPanel({
  progress,
  running = false,
}: {
  progress?: ScanProgress
  running?: boolean
}) {
  const percent = running ? null : Math.min(progress?.percent ?? 0, 100)
  const steps = running
    ? collectorOrder.map((source) => ({
        source,
        label: collectorLabels[source],
        status: 'pending',
      }))
    : progress?.steps ?? []
  return (
    <section className="progress-panel panel" aria-live="polite">
      <div className="progress-copy">
        <span className={`activity-dot ${running ? 'working' : ''}`} />
        <div>
          <strong>
            {running ? 'Passive collection running' : 'Passive coverage complete'}
          </strong>
          <small>
            {running
              ? 'Collectors execute sequentially; progress advances as sources return.'
              : `${progress?.successful_collectors ?? 0} healthy · ${progress?.skipped_collectors ?? 0} skipped · ${progress?.failed_collectors ?? 0} failed`}
          </small>
        </div>
      </div>
      <div className="progress-meter">
        <div className={`progress-track ${running ? 'indeterminate' : ''}`}>
          <span style={percent === null ? undefined : { width: `${percent}%` }} />
        </div>
        <span>{percent === null ? 'Active' : `${percent}%`}</span>
      </div>
      {steps.length ? (
        <div className="progress-steps">
          {steps.map((step) => (
            <span className={step.status} key={step.source}>
              <i />
              {step.label}
              <small>{running ? 'awaiting result' : step.status}</small>
            </span>
          ))}
        </div>
      ) : null}
    </section>
  )
}

function CollectorHealth({ collectors }: { collectors: Record<string, CollectorResult> }) {
  return (
    <div className="collector-row" aria-label="Collector health">
      {Object.values(collectors).map((collector) => {
        const detail = collector.error ?? collector.error_details?.[0]
        const description =
          collector.status === 'ok'
            ? 'Completed'
            : collector.status === 'skipped'
              ? collector.errors[0] ?? 'Optional source skipped'
              : errorLabels[detail?.category ?? ''] ?? 'Collector error'
        return (
          <div title={description} key={collector.source}>
            <span className={`health-dot ${collector.status}`} />
            <strong>{collectorLabels[collector.source] ?? collector.source}</strong>
            <small>{collector.status}</small>
          </div>
        )
      })}
    </div>
  )
}

function FindingCard({ insight }: { insight: Insight }) {
  const finding = insight as Partial<Finding>
  return (
    <article className={`finding-card ${insight.severity}`}>
      <span className="finding-marker">
        {insight.severity === 'warning'
          ? '!'
          : insight.severity === 'critical'
            ? '×'
          : insight.severity === 'notice'
            ? '◆'
            : 'i'}
      </span>
      <div>
        <span className="finding-source">{insight.type.replaceAll('_', ' ')}</span>
        <h3>{insight.title}</h3>
        <p>{insight.description}</p>
        {finding.reasoning ? <p className="finding-reasoning">{finding.reasoning}</p> : null}
        {finding.confidence ? <ConfidenceBadge value={finding.confidence} /> : null}
        <div className="finding-evidence">
          <strong>Evidence</strong>
          <span>{evidenceSummary(insight.evidence ?? [])}</span>
        </div>
      </div>
    </article>
  )
}

function ExecutiveSummary({ report }: { report: Report }) {
  const executive = report.executive_summary
  const verdict = report.verdict ?? {
    target: report.target,
    investigation_status: report.status,
    coverage_status: report.status === 'completed' ? 'High' : 'Moderate',
    risk_level: report.insights.some((item) => item.severity === 'warning')
      ? 'Review'
      : 'Informational',
    confidence_level: 'Moderate',
    domain_age_years: report.summary.domain_age_years,
    registrar: report.summary.registrar,
    infrastructure_providers: report.infrastructure.providers,
    email_providers: [],
    host_intelligence_sources: [],
    timeline: {
      event_count: report.timeline.length,
      first_observation: report.summary.first_seen,
      last_observation: report.completed_at,
    },
    sources_used: Object.values(report.collectors)
      .filter((collector) => collector.status === 'ok')
      .map((collector) => collectorLabels[collector.source] ?? collector.source),
    narrative: 'Evidence was collected from the available passive sources.',
  }
  const metrics = [
    ['Addresses', report.summary.a_count + report.summary.aaaa_count, 'DNS'],
    ['Subdomains', report.summary.subdomain_count, 'Observed'],
    ['Certificates', report.summary.certificate_count, 'Public CT'],
    ['Archive', report.summary.wayback_capture_count, 'Captures'],
    ['Hosts', report.summary.censys_host_count ?? 0, 'Censys'],
    ['Services', report.summary.censys_service_count ?? 0, 'Observed'],
  ]
  const topFindings = [...report.insights]
    .sort(
      (left, right) =>
        ['critical', 'warning', 'notice', 'info'].indexOf(left.severity) -
        ['critical', 'warning', 'notice', 'info'].indexOf(right.severity),
    )
    .slice(0, 5)

  return (
    <div className="view-stack executive-view">
      <ProgressPanel progress={report.progress} />
      {report.status === 'partial' || report.progress?.failed_collectors > 0 ? (
        <div className="partial-warning">
          <span>!</span>
          <div>
            <strong>Partial source coverage</strong>
            <p>
              One or more sources failed. Successful evidence is retained; review
              collector health and raw evidence before drawing conclusions.
            </p>
          </div>
        </div>
      ) : null}
      {report.derivation_errors?.length ? (
        <div className="partial-warning">
          <span>!</span>
          <div>
            <strong>Some derived views are unavailable</strong>
            <p>Raw evidence remains intact. Review the affected sections and collector payloads.</p>
          </div>
        </div>
      ) : null}
      <Panel
        eyebrow="Evidence-based assessment"
        title="Investigation Verdict"
        meta={<StatusBadge status={report.status} />}
        className="verdict-panel"
      >
        <div className="verdict-layout">
          <div className="verdict-narrative">
            <span className={`risk-indicator risk-${verdict.risk_level.toLowerCase()}`} />
            <div>
              <p>{verdict.narrative}</p>
              <small>Conclusions are limited to evidence present in this report.</small>
            </div>
          </div>
          <dl className="verdict-grid">
            <div><dt>Target</dt><dd>{verdict.target}</dd></div>
            <div><dt>Investigation status</dt><dd>{verdict.investigation_status}</dd></div>
            <div><dt>Coverage</dt><dd>{verdict.coverage_status}</dd></div>
            <div><dt>Risk level</dt><dd>{verdict.risk_level}</dd></div>
            <div><dt>Confidence</dt><dd>{verdict.confidence_level}</dd></div>
            <div><dt>Domain age</dt><dd>{verdict.domain_age_years === null ? 'Unknown' : `${verdict.domain_age_years} years`}</dd></div>
            <div><dt>Registrar</dt><dd>{verdict.registrar ?? 'Unknown'}</dd></div>
            <div><dt>Infrastructure providers</dt><dd>{verdict.infrastructure_providers.join(', ') || 'Not identified'}</dd></div>
            <div><dt>Email providers</dt><dd>{verdict.email_providers.join(', ') || 'Not identified'}</dd></div>
            <div><dt>Host intelligence</dt><dd>{verdict.host_intelligence_sources.map((source) => collectorLabels[source] ?? source).join(', ') || 'Unavailable'}</dd></div>
            <div><dt>Timeline coverage</dt><dd>{verdict.timeline.event_count} events · {formatDate(verdict.timeline.first_observation, true)}</dd></div>
            <div><dt>Sources used</dt><dd>{verdict.sources_used.join(', ') || 'None'}</dd></div>
          </dl>
        </div>
      </Panel>
      <section className="metric-grid" aria-label="Key report metrics">
        {metrics.map(([label, value, note]) => (
          <article className="metric-card" key={String(label)}>
            <span>{label}</span>
            <strong>{Number(value).toLocaleString()}</strong>
            <small>{note}</small>
          </article>
        ))}
      </section>
      {executive ? (
        <div className="summary-grid">
          <Panel eyebrow="Collection assessment" title="Coverage and evidence quality">
            <dl className="profile-grid">
              <div><dt>Coverage</dt><dd>{executive.collection_quality.coverage}</dd></div>
              <div><dt>Confidence</dt><dd>{executive.collection_quality.confidence}</dd></div>
              <div><dt>Evidence completeness</dt><dd>{executive.collection_quality.evidence_completeness}</dd></div>
              <div><dt>Evidence references</dt><dd>{executive.collection_quality.evidence_reference_count}</dd></div>
            </dl>
          </Panel>
          <Panel eyebrow="Correlated profile" title="Infrastructure and stack">
            <div className="fact-groups">
              <div><h3>Cloud and CDN</h3><ChipList values={executive.cloud} /></div>
              <div><h3>Mail infrastructure</h3><ChipList values={executive.mail_infrastructure} /></div>
              <div><h3>Technology stack</h3><ChipList values={executive.technology_stack} limit={12} /></div>
            </div>
          </Panel>
        </div>
      ) : null}
      {executive?.high_level_observations.length ? (
        <Panel eyebrow="Evidence-backed overview" title="High-level observations">
          <ul className="observation-list">
            {executive.high_level_observations.map((observation) => <li key={observation}>{observation}</li>)}
          </ul>
        </Panel>
      ) : null}
      <div className="summary-grid">
        <Panel
          eyebrow="Investigation profile"
          title="Domain profile"
          meta={<StatusBadge status={report.status} />}
          className="profile-panel"
        >
          <dl className="profile-grid">
            <div>
              <dt>Target</dt>
              <dd>{report.target}</dd>
            </div>
            <div>
              <dt>Registrar</dt>
              <dd>{report.summary.registrar ?? 'Unknown'}</dd>
            </div>
            <div>
              <dt>Domain age</dt>
              <dd>
                {report.summary.domain_age_years === null
                  ? 'Unknown'
                  : `${report.summary.domain_age_years} years`}
              </dd>
            </div>
            <div>
              <dt>First evidence</dt>
              <dd>{formatDate(report.summary.first_seen, true)}</dd>
            </div>
          </dl>
        </Panel>
        <Panel
          eyebrow="Source operations"
          title="Collector health"
          meta={
            <span className="panel-meta">
              {
                Object.values(report.collectors).filter(
                  (collector) => collector.status === 'ok',
                ).length
              }
              /{Object.keys(report.collectors).length} healthy
            </span>
          }
          className="health-panel"
        >
          <CollectorHealth collectors={report.collectors} />
        </Panel>
      </div>
      <Panel
        eyebrow="Priority assessment"
        title="Top findings"
        meta={
          report.insights.length > 5 ? (
            <span className="panel-meta">Top 5 of {report.insights.length}</span>
          ) : (
            <span className="panel-meta">{report.insights.length} total</span>
          )
        }
        className="top-findings"
      >
        <div className="finding-list compact">
          {topFindings.map((insight, index) => (
            <FindingCard insight={insight} key={`${insight.title}-${index}`} />
          ))}
          {!topFindings.length ? (
            <p className="empty-inline">No deterministic findings were identified.</p>
          ) : null}
        </div>
      </Panel>
    </div>
  )
}

function DnsSummary({ collector }: { collector?: CollectorResult }) {
  const records =
    typeof collector?.data.records === 'object' && collector.data.records !== null
      ? (collector.data.records as Record<string, unknown>)
      : {}
  const recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'CAA']
  return (
    <details className="panel collapsible-panel">
      <summary className="panel-heading">
        <div>
          <p className="eyebrow">Resolution evidence</p>
          <h2>DNS records</h2>
          <span className="panel-meta">
            {recordTypes
              .map((type) => `${type}: ${asStrings(records[type]).length}`)
              .join(' · ')}
          </span>
        </div>
        <StatusBadge status={collector?.status ?? 'skipped'} />
      </summary>
      <div className="collapsible-content">
        <SourceMessage collector={collector} />
        <div className="dns-table">
        {recordTypes.map((type) => {
          const values = asStrings(records[type])
          return (
            <div className="dns-row" key={type}>
              <div>
                <strong>{type}</strong>
                <span>{values.length}</span>
              </div>
              <ChipList
                values={values}
                empty={`No ${type} records`}
                limit={type === 'TXT' || type === 'CAA' ? 3 : 6}
              />
            </div>
          )
        })}
        </div>
      </div>
    </details>
  )
}

function SourceStatusCard({
  name,
  collector,
  metrics,
}: {
  name: string
  collector?: CollectorResult
  metrics: Array<[string, number]>
}) {
  return (
    <article className="source-card">
      <header>
        <div>
          <span>Passive source</span>
          <h3>{name}</h3>
        </div>
        <StatusBadge status={collector?.status ?? 'skipped'} />
      </header>
      <SourceMessage collector={collector} />
      <div className="source-metrics">
        {metrics.map(([label, value]) => (
          <div key={label}>
            <span>{label}</span>
            <strong>{value.toLocaleString()}</strong>
          </div>
        ))}
      </div>
    </article>
  )
}

function CensysHosts({ collector }: { collector?: CollectorResult }) {
  const hosts = Array.isArray(collector?.data.hosts)
    ? (collector.data.hosts as CensysHost[])
    : []
  return (
    <Panel
      eyebrow="DNS-derived host intelligence"
      title="Censys hosts"
      meta={<StatusBadge status={collector?.status ?? 'skipped'} />}
    >
      <SourceMessage collector={collector} />
      <div className="fact-groups">
        <div><h3>Hostnames</h3><ChipList values={asStrings(collector?.data.hostnames)} /></div>
        <div><h3>Cloud metadata</h3><ChipList values={asStrings(collector?.data.cloud_providers)} /></div>
        <div><h3>Operating hints</h3><ChipList values={asStrings(collector?.data.operating_systems)} /></div>
        <div><h3>Observed technologies</h3><ChipList values={asStrings(collector?.data.observed_technologies)} /></div>
      </div>
      {hosts.length ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Network</th>
                <th>ASN</th>
                <th>Country</th>
                <th>Services</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((host) => {
                const services = host.services ?? []
                return (
                  <tr key={host.ip}>
                    <td className="mono-cell">{host.ip}</td>
                    <td>
                      {host.autonomous_system?.name ??
                        host.whois?.organization ??
                        'Unknown'}
                    </td>
                    <td>
                      {host.autonomous_system?.asn
                        ? `AS${host.autonomous_system.asn}`
                        : '—'}
                    </td>
                    <td>
                      {host.location?.country_code ??
                        host.location?.country ??
                        '—'}
                    </td>
                    <td>
                      <div className="service-chips">
                        {services.slice(0, 5).map((service, index) => (
                          <span
                            title={`${service.service_name ?? service.protocol ?? 'service'} · ${service.transport_protocol ?? 'transport unknown'}`}
                            key={`${service.port}-${service.protocol}-${index}`}
                          >
                            {service.port ?? '—'}/
                            {service.protocol ?? service.service_name ?? 'unknown'}
                          </span>
                        ))}
                        {services.length > 5 ? (
                          <span>+{services.length - 5}</span>
                        ) : null}
                        {!services.length ? (
                          <span>{host.service_count ?? 0} observed</span>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty-inline">No Censys hosts were returned.</p>
      )}
    </Panel>
  )
}

function InfrastructureView({ report }: { report: Report }) {
  const infrastructure = report.infrastructure
  const shodan = report.collectors.shodan
  const urlscan = report.collectors.urlscan
  const censys = report.collectors.censys
  return (
    <div className="view-stack">
      <section className="metric-grid infrastructure-metrics">
        {[
          ['Observed IPs', infrastructure.ips.length, 'All passive sources'],
          ['ASNs', infrastructure.asns.length, 'Network ownership'],
          ['Organizations', infrastructure.organizations.length, 'Observed'],
          ['Countries', infrastructure.countries.length, 'Locations'],
          ['Ports', infrastructure.ports.length, 'Censys'],
          ['Services', infrastructure.service_count, 'Censys'],
        ].map(([label, value, note]) => (
          <article className="metric-card" key={String(label)}>
            <span>{label}</span>
            <strong>{Number(value).toLocaleString()}</strong>
            <small>{note}</small>
          </article>
        ))}
      </section>
      <div className="infrastructure-grid">
        <Panel
          eyebrow="Correlated footprint"
          title="Infrastructure Overview"
          meta={
            infrastructure.cloud_or_cdn_detected ? (
              <span className="status status-notice">Cloud/CDN observed</span>
            ) : null
          }
          className="facts-panel"
        >
          <div className="fact-groups">
            <div>
              <h3>IP addresses</h3>
              <ChipList values={infrastructure.ips} limit={14} />
            </div>
            <div>
              <h3>ASNs</h3>
              <ChipList values={infrastructure.asns} />
            </div>
            <div>
              <h3>Organizations</h3>
              <ChipList values={infrastructure.organizations} />
            </div>
            <div>
              <h3>Providers</h3>
              <ChipList
                values={infrastructure.providers}
                empty="No major provider matched."
              />
            </div>
            <div>
              <h3>Countries</h3>
              <ChipList values={infrastructure.countries} />
            </div>
            <div>
              <h3>Ports</h3>
              <ChipList values={infrastructure.ports} />
            </div>
            <div>
              <h3>Protocols and services</h3>
              <ChipList values={infrastructure.protocols} limit={14} />
            </div>
          </div>
        </Panel>
        <DnsSummary collector={report.collectors.dns} />
      </div>
      <div className="source-card-grid">
        <SourceStatusCard
          name="Censys"
          collector={censys}
          metrics={[
            ['Hosts', report.summary.censys_host_count ?? 0],
            ['Services', report.summary.censys_service_count ?? 0],
            ['Ports', report.summary.censys_port_count ?? 0],
          ]}
        />
        <SourceStatusCard
          name="Shodan"
          collector={shodan}
          metrics={[
            ['Subdomains', report.summary.shodan_subdomain_count ?? 0],
            ['Records', report.summary.shodan_record_count ?? 0],
          ]}
        />
        <SourceStatusCard
          name="URLScan"
          collector={urlscan}
          metrics={[
            ['Results', report.summary.urlscan_result_count ?? 0],
            ['Domains', report.summary.urlscan_domain_count ?? 0],
            ['IPs', report.summary.urlscan_ip_count ?? 0],
          ]}
        />
      </div>
      <CensysHosts collector={censys} />
    </div>
  )
}

function ConfidenceBadge({ value }: { value: string }) {
  return <span className={`confidence confidence-${value.toLowerCase()}`}>{value}</span>
}

function EvidenceRefs({ items }: { items: EvidenceReference[] }) {
  return (
    <div className="evidence-refs">
      {items.slice(0, 4).map((item, index) => (
        <span title={compactValue(item.value, 240)} key={`${item.source}-${item.field}-${index}`}>
          {collectorLabels[item.source] ?? item.source} · {item.field}
        </span>
      ))}
      {items.length > 4 ? <span>+{items.length - 4} evidence</span> : null}
    </div>
  )
}

function TechnologyView({ report }: { report: Report }) {
  const intelligence = report.technology
  const categories = intelligence?.categories ?? {}
  const urlscan = report.collectors.urlscan
  return (
    <div className="view-stack">
      <section className="graph-stats">
        <div><span>Fingerprints</span><strong>{intelligence?.fingerprint_count ?? 0}</strong></div>
        <div><span>Evidence refs</span><strong>{intelligence?.evidence_count ?? 0}</strong></div>
        <div><span>Sources</span><strong>{intelligence?.observed_sources.length ?? 0}</strong></div>
        <div><span>URLScan results</span><strong>{report.summary.urlscan_result_count}</strong></div>
      </section>
      <Panel
        eyebrow="Passive fingerprinting"
        title="Technology profile"
        meta={<span className="panel-meta">Evidence required for every fingerprint</span>}
      >
        {Object.keys(categories).length ? (
          <div className="technology-groups">
            {Object.entries(categories).map(([category, fingerprints]) => (
              <section className="technology-group" key={category}>
                <header>
                  <div><span>{category}</span><strong>{fingerprints.length}</strong></div>
                </header>
                <div>
                  {fingerprints.map((fingerprint) => (
                    <article className="intelligence-card" key={`${category}-${fingerprint.value}`}>
                      <div className="intelligence-card-heading">
                        <h3>{fingerprint.value}</h3>
                        <ConfidenceBadge value={fingerprint.confidence} />
                      </div>
                      <p>{fingerprint.reasoning}</p>
                      <EvidenceRefs items={fingerprint.evidence} />
                    </article>
                  ))}
                </div>
              </section>
            ))}
          </div>
        ) : (
          <div className="graph-empty">
            <span>◇</span>
            <strong>No supported fingerprints</strong>
            <p>The collected passive evidence did not support a technology conclusion.</p>
          </div>
        )}
      </Panel>
      <Panel
        eyebrow="Existing public observations"
        title="URLScan intelligence"
        meta={<StatusBadge status={urlscan?.status ?? 'skipped'} />}
      >
        <SourceMessage collector={urlscan} />
        <div className="fact-groups">
          {[
            ['Page titles', asStrings(urlscan?.data.titles)],
            ['Servers', asStrings(urlscan?.data.servers)],
            ['Redirect chains', asStrings(urlscan?.data.redirect_chains)],
            ['Favicon hashes', asStrings(urlscan?.data.favicon_hashes)],
            ['Resource domains', asStrings(urlscan?.data.resource_domains)],
            ['Linked domains', asStrings(urlscan?.data.linked_domains)],
            ['Script domains', asStrings(urlscan?.data.script_domains)],
            ['Analytics', asStrings(urlscan?.data.analytics)],
            ['Tracking', asStrings(urlscan?.data.tracking)],
            ['CDN', asStrings(urlscan?.data.cdn)],
            ['Cloud', asStrings(urlscan?.data.cloud)],
            ['Hosting hints', asStrings(urlscan?.data.hosting_hints)],
          ].map(([label, values]) => (
            <div key={String(label)}>
              <h3>{label}</h3>
              <ChipList values={values as string[]} limit={12} />
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}

function OrganizationView({ report }: { report: Report }) {
  const organization = report.organization
  if (!organization) {
    return <Panel title="Organization intelligence"><p className="empty-inline">Organization intelligence is unavailable for this legacy report.</p></Panel>
  }
  return (
    <div className="view-stack">
      <section className="metric-grid">
        {[
          ['Organizations', organization.stats.organization_count ?? 0, 'Observed ownership'],
          ['ASNs', organization.stats.asn_count ?? 0, 'Network attribution'],
          ['Domains', organization.stats.domain_count ?? 0, 'Correlated names'],
          ['IPs', organization.stats.ip_count ?? 0, 'Passive addresses'],
          ['Providers', organization.stats.provider_count ?? 0, 'Supported matches'],
        ].map(([label, value, note]) => (
          <article className="metric-card" key={String(label)}>
            <span>{label}</span><strong>{Number(value)}</strong><small>{note}</small>
          </article>
        ))}
      </section>
      <div className="organization-grid">
        <Panel eyebrow="Unified profile" title="Organization and network ownership">
          {organization.organizations.length ? (
            <div className="organization-list">
              {organization.organizations.map((item) => (
                <article className="intelligence-card" key={item.name}>
                  <div className="intelligence-card-heading"><h3>{item.name}</h3><span className="source-badge">{item.sources.join(', ')}</span></div>
                  <dl className="compact-dl">
                    <div><dt>ASNs</dt><dd>{item.asns.join(', ') || 'Not observed'}</dd></div>
                    <div><dt>IPs</dt><dd>{item.ips.join(', ') || 'Not observed'}</dd></div>
                    <div><dt>Domains</dt><dd>{item.domains.join(', ') || 'Not observed'}</dd></div>
                  </dl>
                </article>
              ))}
            </div>
          ) : <p className="empty-inline">No organization ownership metadata was returned.</p>}
        </Panel>
        <Panel eyebrow="Infrastructure providers" title="Cloud and hosting indicators">
          {organization.cloud_providers.length ? organization.cloud_providers.map((provider) => (
            <article className="intelligence-card" key={provider.name}>
              <div className="intelligence-card-heading"><h3>{provider.name}</h3><ConfidenceBadge value={provider.confidence} /></div>
              <p>{provider.reasoning}</p>
              <EvidenceRefs items={provider.evidence} />
            </article>
          )) : <p className="empty-inline">No provider signature was supported.</p>}
        </Panel>
      </div>
      <Panel eyebrow="Correlated entities" title="Domains, mail, nameservers, and certificates">
        <div className="fact-groups">
          <div><h3>Domains and subdomains</h3><ChipList values={organization.domains} limit={18} /></div>
          <div><h3>MX infrastructure</h3><ChipList values={organization.mx} /></div>
          <div><h3>Nameservers</h3><ChipList values={organization.nameservers} /></div>
          <div><h3>Certificate issuers</h3><ChipList values={organization.certificate_issuers.map((item) => item.name)} /></div>
        </div>
      </Panel>
    </div>
  )
}

function CertificatesView({ report }: { report: Report }) {
  const intelligence = report.certificates
  if (!intelligence) {
    return <Panel title="Certificate intelligence"><p className="empty-inline">Certificate intelligence is unavailable for this legacy report.</p></Panel>
  }
  return (
    <div className="view-stack">
      <section className="metric-grid">
        {[
          ['Certificates', intelligence.certificate_count, 'CT and host evidence'],
          ['Issuers', intelligence.issuers.length, 'Observed'],
          ['Wildcards', intelligence.wildcard_count, 'Explicit SANs'],
          ['Expired', intelligence.expired_count, 'At collection time'],
          ['Reuse groups', intelligence.reuse_count, 'Duplicate identity'],
          ['Relationships', intelligence.relationships.length, 'Certificate ↔ domain'],
        ].map(([label, value, note]) => (
          <article className="metric-card" key={String(label)}>
            <span>{label}</span><strong>{Number(value)}</strong><small>{note}</small>
          </article>
        ))}
      </section>
      <Panel eyebrow="Certificate investigation" title="Observed certificates" meta={<span className="panel-meta">{intelligence.certificates.length} normalized records</span>}>
        {intelligence.certificates.length ? (
          <div className="certificate-list">
            {intelligence.certificates.map((certificate, index) => (
              <article className={`certificate-card ${certificate.expired ? 'expired' : ''}`} key={`${certificate.id}-${certificate.source}-${index}`}>
                <header>
                  <div><span>{certificate.source}</span><h3>{certificate.common_name ?? certificate.id}</h3></div>
                  <StatusBadge status={certificate.expired ? 'error' : 'ok'}>{certificate.expired ? 'Expired' : 'Observed'}</StatusBadge>
                </header>
                <dl className="compact-dl">
                  <div><dt>Issuer</dt><dd>{certificate.issuer ?? 'Not available'}</dd></div>
                  <div><dt>Valid from</dt><dd>{formatDate(certificate.not_before ?? null, true)}</dd></div>
                  <div><dt>Valid until</dt><dd>{formatDate(certificate.not_after ?? null, true)}</dd></div>
                </dl>
                <ChipList values={certificate.sans} empty="No SAN names were normalized." limit={14} />
              </article>
            ))}
          </div>
        ) : <p className="empty-inline">No certificate evidence was collected.</p>}
      </Panel>
      <div className="organization-grid">
        <Panel eyebrow="Identity reuse" title="Duplicate certificates">
          <ChipList values={intelligence.duplicate_certificates.map((item) => compactValue(item))} empty="No duplicate certificate identity was observed." />
        </Panel>
        <Panel eyebrow="Shared names" title="Shared certificates">
          <ChipList values={intelligence.shared_certificates.map((item) => compactValue(item))} empty="No certificate covered unrelated names in collected evidence." />
        </Panel>
      </div>
    </div>
  )
}

const graphTypeOrder = [
  'domain',
  'subdomain',
  'ip',
  'asn',
  'organization',
  'nameserver',
  'mx',
  'certificate',
  'technology',
  'service',
  'external_domain',
  'source',
]

function RelationshipsView({ graph }: { graph: RelationshipGraph }) {
  const width = 1400
  const height = 760
  const [zoom, setZoom] = useState(0.9)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [layoutVersion, setLayoutVersion] = useState(0)
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set(['source']))
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({})
  const interaction = useRef<{
    mode: 'pan' | 'drag'
    id?: string
    startX: number
    startY: number
    originX: number
    originY: number
  } | null>(null)
  const nodeTypes = useMemo(
    () => graphTypeOrder.filter((type) => graph.stats.type_counts[type]),
    [graph.stats.type_counts],
  )
  const visibleNodes = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    const matches = graph.nodes.filter(
      (node) =>
        !hiddenTypes.has(node.type) &&
        (!normalized ||
          node.label.toLowerCase().includes(normalized) ||
          node.type.toLowerCase().includes(normalized)),
    )
    if (normalized) return matches.slice(0, 180)
    const counts = new Map<string, number>()
    return matches
      .filter((node) => {
        const count = counts.get(node.type) ?? 0
        counts.set(node.type, count + 1)
        return count < 24
      })
      .slice(0, 180)
  }, [graph.nodes, hiddenTypes, query])
  const visibleIds = useMemo(
    () => new Set(visibleNodes.map((node) => node.id)),
    [visibleNodes],
  )
  const visibleEdges = useMemo(
    () =>
      graph.edges.filter(
        (edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target),
      ),
    [graph.edges, visibleIds],
  )
  const connectedIds = useMemo(() => {
    if (!selectedId) return new Set<string>()
    const ids = new Set([selectedId])
    visibleEdges.forEach((edge) => {
      if (edge.source === selectedId) ids.add(edge.target)
      if (edge.target === selectedId) ids.add(edge.source)
    })
    return ids
  }, [selectedId, visibleEdges])
  const selectedNode = graph.nodes.find((node) => node.id === selectedId) ?? null
  const selectedEdges = selectedId
    ? graph.edges.filter((edge) => edge.source === selectedId || edge.target === selectedId)
    : []

  useEffect(() => {
    const grouped = nodeTypes
      .map((type) => [type, visibleNodes.filter((node) => node.type === type)] as const)
      .filter(([, nodes]) => nodes.length)
    const next: Record<string, { x: number; y: number }> = {}
    grouped.forEach(([, nodes], columnIndex) => {
      const sectionColumns = Math.min(4, Math.max(grouped.length, 1))
      const sectionRows = Math.ceil(grouped.length / sectionColumns)
      const sectionColumn = columnIndex % sectionColumns
      const sectionRow = Math.floor(columnIndex / sectionColumns)
      const sectionWidth = (width - 100) / sectionColumns
      const sectionHeight = (height - 80) / Math.max(sectionRows, 1)
      const columnCount = Math.min(4, Math.max(1, Math.ceil(Math.sqrt(nodes.length))))
      const rowCount = Math.ceil(nodes.length / columnCount)
      const spreadX = Math.min(92, (sectionWidth - 30) / Math.max(columnCount, 1))
      const spreadY = Math.min(58, (sectionHeight - 35) / Math.max(rowCount, 1))
      nodes.forEach((node, index) => {
        const localColumn = index % columnCount
        const row = Math.floor(index / columnCount)
        next[node.id] = {
          x: 50 + sectionColumn * sectionWidth + sectionWidth / 2 +
            (localColumn - (columnCount - 1) / 2) * spreadX,
          y: 50 + sectionRow * sectionHeight + sectionHeight / 2 +
            (row - (rowCount - 1) / 2) * spreadY +
            ((columnIndex + layoutVersion) % 2) * 8,
        }
      })
    })
    setPositions(next)
  }, [layoutVersion, nodeTypes, visibleNodes])

  function fitView() {
    setZoom(0.9)
    setPan({ x: 0, y: 0 })
  }

  function pointerMove(event: ReactPointerEvent<SVGSVGElement>) {
    const active = interaction.current
    if (!active) return
    const dx = event.clientX - active.startX
    const dy = event.clientY - active.startY
    if (active.mode === 'pan') {
      setPan({ x: active.originX + dx, y: active.originY + dy })
    } else if (active.id) {
      setPositions((current) => ({
        ...current,
        [active.id as string]: {
          x: active.originX + dx / zoom,
          y: active.originY + dy / zoom,
        },
      }))
    }
  }

  function wheel(event: ReactWheelEvent<SVGSVGElement>) {
    event.preventDefault()
    setZoom((value) => Math.min(2.4, Math.max(0.35, value * (event.deltaY > 0 ? 0.9 : 1.1))))
  }

  return (
    <div className="view-stack graph-view">
      <section className="graph-stats">
        <div>
          <span>Nodes</span>
          <strong>{graph.stats.node_count.toLocaleString()}</strong>
        </div>
        <div>
          <span>Edges</span>
          <strong>{graph.stats.edge_count.toLocaleString()}</strong>
        </div>
        {Object.entries(graph.stats.type_counts)
          .slice(0, 6)
          .map(([type, count]) => (
            <div key={type}>
              <span>{type}</span>
              <strong>{count.toLocaleString()}</strong>
            </div>
          ))}
      </section>
      <Panel
        eyebrow="Entity correlation"
        title="Relationship graph"
        meta={<span className="panel-meta">{visibleNodes.length} nodes · {visibleEdges.length} edges shown</span>}
        className="graph-panel"
      >
        {!graph.nodes.length ? (
          <div className="graph-empty">
            <span>◎</span>
            <strong>No relationships available</strong>
            <p>The report did not contain correlated graph entities.</p>
          </div>
        ) : (
          <>
            <div className="graph-legend">
              {Object.entries(graph.stats.type_counts).map(([type, count]) => (
                <button
                  type="button"
                  className={`graph-type ${type} ${hiddenTypes.has(type) ? 'disabled' : ''}`}
                  key={type}
                  onClick={() => setHiddenTypes((current) => {
                    const next = new Set(current)
                    if (next.has(type)) next.delete(type)
                    else next.add(type)
                    return next
                  })}
                >
                  <i />
                  {type} {count}
                </button>
              ))}
            </div>
            <div className="graph-toolbar" aria-label="Graph controls">
              <button type="button" onClick={() => setZoom((value) => Math.min(1.8, value + 0.2))}>Zoom in</button>
              <button type="button" onClick={() => setZoom((value) => Math.max(0.35, value - 0.2))}>Zoom out</button>
              <button type="button" onClick={fitView}>Fit view</button>
              <button type="button" onClick={() => { fitView(); setLayoutVersion((value) => value + 1) }}>Reset layout</button>
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search nodes" aria-label="Search graph nodes" />
              <span>{Math.round(zoom * 100)}%</span>
            </div>
            <div className="graph-workspace">
            <div className="graph-canvas">
              <svg
                viewBox={`0 0 ${width} ${height}`}
                role="img"
                aria-label="Report relationship graph"
                preserveAspectRatio="xMidYMid meet"
                onWheel={wheel}
                onPointerDown={(event) => {
                  if (event.target !== event.currentTarget) return
                  event.currentTarget.setPointerCapture(event.pointerId)
                  interaction.current = {
                    mode: 'pan',
                    startX: event.clientX,
                    startY: event.clientY,
                    originX: pan.x,
                    originY: pan.y,
                  }
                }}
                onPointerMove={pointerMove}
                onPointerUp={() => { interaction.current = null }}
                onPointerCancel={() => { interaction.current = null }}
              >
                <g transform={`translate(${pan.x + width * (1 - zoom) / 2} ${pan.y + height * (1 - zoom) / 2}) scale(${zoom})`}>
                <g className="graph-edges">
                  {visibleEdges.map((edge) => {
                    const source = positions[edge.source]
                    const target = positions[edge.target]
                    const active = selectedId && (edge.source === selectedId || edge.target === selectedId)
                    return source && target ? (
                      <line
                        className={active ? 'active' : selectedId ? 'muted' : ''}
                        key={edge.id}
                        x1={source.x}
                        y1={source.y}
                        x2={target.x}
                        y2={target.y}
                      />
                    ) : null
                  })}
                </g>
                <g className="graph-nodes">
                  {visibleNodes.map((node) => {
                    const position = positions[node.id]
                    if (!position) return null
                    const label =
                      node.label.length > 24
                        ? `${node.label.slice(0, 22)}…`
                        : node.label
                    return (
                      <g
                        className={`graph-node ${node.type} ${selectedId === node.id ? 'selected' : ''} ${selectedId && !connectedIds.has(node.id) ? 'muted' : ''}`}
                        key={node.id}
                        transform={`translate(${position.x} ${position.y})`}
                        onPointerDown={(event) => {
                          event.stopPropagation()
                          event.currentTarget.setPointerCapture(event.pointerId)
                          interaction.current = {
                            mode: 'drag',
                            id: node.id,
                            startX: event.clientX,
                            startY: event.clientY,
                            originX: position.x,
                            originY: position.y,
                          }
                        }}
                        onPointerUp={(event) => {
                          event.stopPropagation()
                          interaction.current = null
                          setSelectedId(node.id)
                        }}
                      >
                        <title>{node.label}</title>
                        <circle r={node.type === 'domain' ? 11 : 7} />
                        <text y={-13} textAnchor="middle">
                          {label}
                        </text>
                      </g>
                    )
                  })}
                </g>
                </g>
              </svg>
            </div>
            <aside className="graph-inspector">
              {selectedNode ? (
                <>
                  <span className={`graph-type ${selectedNode.type}`}><i />{selectedNode.type}</span>
                  <h3>{selectedNode.label}</h3>
                  <p className="mono-cell">{selectedNode.id}</p>
                  <dl className="compact-dl">
                    <div><dt>Connections</dt><dd>{selectedEdges.length}</dd></div>
                    {Object.entries(selectedNode.metadata ?? {}).map(([key, value]) => (
                      <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{compactValue(value, 180)}</dd></div>
                    ))}
                  </dl>
                  <div className="relationship-list">
                    {selectedEdges.slice(0, 12).map((edge) => (
                      <button type="button" key={edge.id} onClick={() => setSelectedId(edge.source === selectedId ? edge.target : edge.source)}>
                        <span>{edge.type.replaceAll('_', ' ')}</span>
                        <strong>{graph.nodes.find((node) => node.id === (edge.source === selectedId ? edge.target : edge.source))?.label ?? 'Entity'}</strong>
                      </button>
                    ))}
                  </div>
                </>
              ) : (
                <div className="graph-empty"><span>◎</span><strong>Select a node</strong><p>Connected entities and relationship evidence appear here.</p></div>
              )}
            </aside>
            </div>
            {graph.nodes.length > visibleNodes.length ? (
              <p className="graph-note">
                {visibleNodes.length} of {graph.nodes.length} nodes are rendered. Use category filters and search to inspect large graphs.
              </p>
            ) : null}
          </>
        )}
      </Panel>
    </div>
  )
}

function TimelineView({ events }: { events: TimelineEvent[] }) {
  const [sourceFilter, setSourceFilter] = useState('all')
  const sources = [...new Set(events.map((event) => event.source))].sort()
  const filtered = sourceFilter === 'all'
    ? events
    : events.filter((event) => event.source === sourceFilter)
  const grouped = groupTimeline(filtered)
  const first = grouped.at(0)
  const last = grouped.at(-1)
  return (
    <div className="view-stack">
      <section className="timeline-summary panel">
        <div><span>Events</span><strong>{filtered.length}</strong></div>
        <div><span>Grouped entries</span><strong>{grouped.length}</strong></div>
        <div><span>First observation</span><strong>{formatDate(first?.timestamp ?? null, true)}</strong></div>
        <div><span>Latest observation</span><strong>{formatDate(last?.endTimestamp ?? last?.timestamp ?? null, true)}</strong></div>
        <label>
          <span>Source filter</span>
          <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
            <option value="all">All sources</option>
            {sources.map((source) => <option value={source} key={source}>{collectorLabels[source] ?? source}</option>)}
          </select>
        </label>
      </section>
      <Panel
        eyebrow="Observed chronology"
        title="Investigation timeline"
        meta={<span className="panel-meta">{events.length} total source events</span>}
        className="timeline-panel"
      >
      {grouped.length ? (
        <ol className="timeline">
          {grouped.map((event, index) => (
            <li key={`${event.type}-${event.timestamp}-${index}`}>
              <span className={`timeline-node source-${event.source}`} />
              <div className="timeline-date">
                <time>{formatDate(event.timestamp, true)}</time>
                {event.endTimestamp ? (
                  <small>to {formatDate(event.endTimestamp, true)}</small>
                ) : null}
              </div>
              <article>
                <div>
                  <span className="source-badge">{event.source}</span>
                  {event.count > 1 ? (
                    <span className="event-count">{event.count} grouped</span>
                  ) : null}
                </div>
                <h3>{event.label}</h3>
                <p>{event.detail ?? 'Source observation recorded.'}</p>
              </article>
            </li>
          ))}
        </ol>
      ) : (
        <p className="empty-inline">No timeline events were available.</p>
      )}
      </Panel>
    </div>
  )
}

function FindingsView({ report }: { report: Report }) {
  const engine = report.findings
  const sections = engine
    ? [
        {
          key: 'observed',
          label: 'Observed Facts',
          description: 'Direct observations and deterministic single-source conclusions.',
          findings: engine.observed_facts,
        },
        {
          key: 'correlated',
          label: 'Correlated Findings',
          description: 'Cross-source relationships with evidence and reasoning.',
          findings: engine.correlated_findings,
        },
        {
          key: 'notes',
          label: 'Analyst Notes',
          description: 'Reserved for explicit analyst-authored context.',
          findings: engine.analyst_notes,
        },
      ]
    : [
        {
          key: 'legacy',
          label: 'Observed Facts',
          description: 'Evidence-backed report observations.',
          findings: report.insights as Finding[],
        },
      ]
  return (
    <div className="view-stack findings-view">
      {sections.map((section) => (
        <Panel
          eyebrow={section.description}
          title={section.label}
          meta={<span className="panel-meta">{section.findings.length}</span>}
          className="findings-group"
          key={section.key}
        >
          <div className="finding-list">
            {section.findings.map((finding, index) => (
              <FindingCard insight={finding} key={`${finding.title}-${index}`} />
            ))}
            {!section.findings.length ? (
              <p className="empty-inline">
                {section.key === 'notes'
                  ? 'No analyst notes are stored in this report.'
                  : `No ${section.label.toLowerCase()}.`}
              </p>
            ) : null}
          </div>
        </Panel>
      ))}
    </div>
  )
}

function RawEvidenceView({ report }: { report: Report }) {
  const [query, setQuery] = useState('')
  const [openSections, setOpenSections] = useState<Set<string>>(new Set())
  const [copyState, setCopyState] = useState('')
  const detailsRefs = useRef<Record<string, HTMLDetailsElement | null>>({})
  const sections = [
    ['DNS', 'dns'],
    ['WHOIS', 'whois'],
    ['Certificate Transparency', 'crtsh'],
    ['Wayback', 'wayback'],
    ['Shodan', 'shodan'],
    ['Censys', 'censys'],
    ['URLScan', 'urlscan'],
  ] as const
  const normalizedQuery = query.trim().toLowerCase()
  const visibleSections = sections.filter(([label, source]) => {
    if (!normalizedQuery) return true
    const value = JSON.stringify(report.collectors[source] ?? null).toLowerCase()
    return label.toLowerCase().includes(normalizedQuery) || value.includes(normalizedQuery)
  })

  function setAll(open: boolean) {
    const next = new Set(open ? visibleSections.map(([, source]) => source) : [])
    setOpenSections(next)
    Object.values(detailsRefs.current).forEach((element) => {
      if (element) element.open = open
    })
  }

  async function copyJson(source: string, value: unknown) {
    await navigator.clipboard.writeText(JSON.stringify(value, null, 2))
    setCopyState(source)
    window.setTimeout(() => setCopyState(''), 1200)
  }

  function downloadJson(source: string, value: unknown) {
    const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `tracelens-${report.target}-${source}.json`
    link.click()
    URL.revokeObjectURL(url)
  }
  return (
    <Panel
      eyebrow="Normalized source output"
      title="Raw evidence"
      meta={<span className="panel-meta">JSON is isolated to this view</span>}
      className="raw-panel"
    >
      <div className="evidence-toolbar">
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search collector evidence"
          aria-label="Search raw evidence"
        />
        <button type="button" onClick={() => setAll(false)}>Collapse all</button>
        <button type="button" onClick={() => setAll(true)}>Expand all</button>
        <span>{visibleSections.length} of {sections.length} sources</span>
      </div>
      <div className="raw-evidence">
        {visibleSections.map(([label, source]) => {
          const collector = report.collectors[source]
          return (
            <details
              key={source}
              ref={(element) => { detailsRefs.current[source] = element }}
              open={openSections.has(source)}
              onToggle={(event) => {
                const open = event.currentTarget.open
                setOpenSections((current) => {
                  const next = new Set(current)
                  if (open) next.add(source)
                  else next.delete(source)
                  return next
                })
              }}
            >
              <summary>
                <span>{label}</span>
                <StatusBadge status={collector?.status ?? 'skipped'} />
              </summary>
              <div className="json-actions">
                <button type="button" onClick={() => copyJson(source, collector ?? null)}>
                  {copyState === source ? 'Copied' : 'Copy JSON'}
                </button>
                <button type="button" onClick={() => downloadJson(source, collector ?? null)}>Download JSON</button>
              </div>
              <div className="json-container">
                <pre>{JSON.stringify(collector ?? null, null, 2)}</pre>
              </div>
            </details>
          )
        })}
        {!visibleSections.length ? <p className="empty-inline">No collector evidence matches this search.</p> : null}
        <details ref={(element) => { detailsRefs.current.report = element }}>
          <summary>
            <span>Complete Report JSON</span>
            <StatusBadge status="json">JSON</StatusBadge>
          </summary>
          <div className="json-actions">
            <button type="button" onClick={() => copyJson('report', report)}>
              {copyState === 'report' ? 'Copied' : 'Copy JSON'}
            </button>
            <button type="button" onClick={() => downloadJson('report', report)}>Download JSON</button>
          </div>
          <div className="json-container complete-json">
            <pre>{JSON.stringify(report, null, 2)}</pre>
          </div>
        </details>
      </div>
    </Panel>
  )
}

function App() {
  const [target, setTarget] = useState('')
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [report, setReport] = useState<Report | null>(null)
  const [loadingReport, setLoadingReport] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState('')
  const [scanFilter, setScanFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [activeView, setActiveView] = useState<ViewId>('summary')

  const visibleScans = useMemo(() => {
    const query = scanFilter.trim().toLowerCase()
    return scans.filter(
      (scan) =>
        (!query || scan.target.toLowerCase().includes(query)) &&
        (statusFilter === 'all' || scan.status === statusFilter),
    )
  }, [scanFilter, scans, statusFilter])

  const loadScans = useCallback(async () => {
    const response = await api.get<ScanSummary[]>('/api/scans')
    setScans(response.data)
  }, [])

  const loadReport = useCallback(async (scanId: number) => {
    setLoadingReport(true)
    setError('')
    try {
      const response = await api.get<Report>(`/api/scans/${scanId}/report`)
      setReport(response.data)
      setActiveView('summary')
    } catch {
      setError('The selected report could not be loaded.')
    } finally {
      setLoadingReport(false)
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
    setScanning(true)
    setError('')
    try {
      const response = await api.post<{ scan_id: number }>('/api/scans', {
        target: normalizedTarget,
      })
      await Promise.all([loadReport(response.data.scan_id), loadScans()])
      setTarget('')
    } catch (requestError) {
      if (
        axios.isAxiosError(requestError) &&
        requestError.response?.status === 422
      ) {
        setError('Enter a valid domain without a URL path or protocol.')
      } else {
        setError('The passive scan could not be completed.')
      }
    } finally {
      setScanning(false)
    }
  }

  const busy = scanning || loadingReport
  const currentView =
    navigation.find((item) => item.id === activeView)?.label ?? 'Executive Summary'

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">TL</span>
          <div>
            <strong>TraceLens</strong>
            <span>Analyst Workspace</span>
          </div>
        </div>
        <div className="system-status">
          <span />
          Passive collection ready
        </div>
        <nav className="primary-nav" aria-label="Report navigation">
          <p>Report navigation</p>
          {navigation.map((item) => (
            <button
              type="button"
              className={activeView === item.id ? 'active' : ''}
              key={item.id}
              onClick={() => setActiveView(item.id)}
              disabled={!report}
              aria-current={activeView === item.id ? 'page' : undefined}
            >
              <span>{item.short}</span>
              <span className="nav-copy">
                <strong>{item.label}</strong>
                <small>
                  {navigationActions[item.id]}
                </small>
              </span>
            </button>
          ))}
        </nav>
        <section className="recent-scans">
          <header>
            <div>
              <span>History</span>
              <strong>Recent scans</strong>
            </div>
            <span>{visibleScans.length}</span>
          </header>
          <div className="scan-filters">
            <input
              aria-label="Search scans by target"
              type="search"
              value={scanFilter}
              onChange={(event) => setScanFilter(event.target.value)}
              placeholder="Filter target"
            />
            <select
              aria-label="Filter scans by status"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
            >
              <option value="all">All</option>
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
                  <strong title={scan.target}>{scan.target}</strong>
                  <small>{formatDate(scan.created_at, true)}</small>
                </span>
                <small>#{scan.scan_id}</small>
              </button>
            ))}
            {!visibleScans.length ? (
              <p>
                {scans.length
                  ? 'No scans match these filters.'
                  : 'No scans stored yet.'}
              </p>
            ) : null}
          </div>
        </section>
        <span className="version">v0.7.0-alpha1 · schema 2.0</span>
      </aside>

      <main className="workspace">
        <header className="workspace-header">
          <div>
            <p className="eyebrow">Passive-first domain intelligence</p>
            <h1>{report ? currentView : 'Professional Analyst Workspace'}</h1>
          </div>
          <div className="workspace-state">
            <span>{scanning ? 'Collection running' : 'Console online'}</span>
            <i className={busy ? 'working' : ''} />
          </div>
        </header>

        <section className="scan-command panel">
          <div>
            <span className="command-icon">⌕</span>
            <div>
              <h2>Run passive investigation</h2>
              <p>Public-source collection only. No direct infrastructure scanning.</p>
            </div>
          </div>
          <form onSubmit={submit}>
            <input
              aria-label="Domain target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="example.com"
              autoComplete="off"
              disabled={busy}
            />
            <button type="submit" disabled={busy}>
              {busy ? <span className="spinner" /> : null}
              {scanning ? 'Collecting' : loadingReport ? 'Loading' : 'Run scan'}
            </button>
          </form>
          {error ? <p className="form-error">{error}</p> : null}
        </section>

        {scanning ? <ProgressPanel running /> : null}

        {report ? (
          <section className="report-workspace">
            <header className="report-header">
              <div>
                <div>
                  <span>Scan #{report.scan_id}</span>
                  <StatusBadge status={report.status} />
                </div>
                <h2 title={report.target}>{report.target}</h2>
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
                <span>↓</span>
                Download JSON
              </button>
            </header>

            <nav className="mobile-report-nav" aria-label="Mobile report navigation">
              {navigation.map((item) => (
                <button
                  type="button"
                  className={activeView === item.id ? 'active' : ''}
                  key={item.id}
                  onClick={() => setActiveView(item.id)}
                >
                  {item.label}
                </button>
              ))}
            </nav>

            <div className="view-container">
              {activeView === 'summary' ? (
                <ExecutiveSummary report={report} />
              ) : null}
              {activeView === 'infrastructure' ? (
                <InfrastructureView report={report} />
              ) : null}
              {activeView === 'technology' ? (
                <TechnologyView report={report} />
              ) : null}
              {activeView === 'organization' ? (
                <OrganizationView report={report} />
              ) : null}
              {activeView === 'certificates' ? (
                <CertificatesView report={report} />
              ) : null}
              {activeView === 'relationships' ? (
                <RelationshipsView graph={report.graph} />
              ) : null}
              {activeView === 'timeline' ? (
                <TimelineView events={report.timeline} />
              ) : null}
              {activeView === 'findings' ? (
                <FindingsView report={report} />
              ) : null}
              {activeView === 'evidence' ? (
                <RawEvidenceView report={report} />
              ) : null}
            </div>
          </section>
        ) : (
          <section className="empty-state panel">
            <span>◎</span>
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
