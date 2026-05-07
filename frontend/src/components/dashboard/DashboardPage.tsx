'use client'
import { useEffect, useState, useCallback } from 'react'
import {
  FiRefreshCw, FiAlertCircle, FiAlertTriangle, FiCheckCircle,
  FiPlay, FiLoader, FiGitBranch, FiLock, FiGlobe, FiSearch,
  FiLink, FiPlus,
} from 'react-icons/fi'
import { orgApi, Organization, ImportedProject, OrgStats, ScanJob } from '@/lib/api'
import { api } from '@/lib/api'
import type { Page } from '@/app/page'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'

const MODELS = [
  { value: 'claude-3-5-sonnet-20241022', label: 'Claude 3.5 Sonnet' },
  { value: 'claude-3-haiku-20240307',    label: 'Claude 3 Haiku' },
  { value: 'gpt-4o',                     label: 'GPT-4o' },
  { value: 'gpt-4o-mini',               label: 'GPT-4o Mini' },
  { value: 'deepseek-chat',             label: 'DeepSeek V3' },
]

function timeAgo(s: string) {
  if (!s) return '—'
  const d = Math.floor((Date.now() - new Date(s).getTime()) / 1000)
  if (d < 60) return 'just now'
  if (d < 3600) return `${Math.floor(d / 60)}m ago`
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`
  return `${Math.floor(d / 86400)}d ago`
}

function StatCard({ label, value, color, sub }: { label: string; value: number | string; color?: string; sub?: string }) {
  return (
    <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, padding: '16px 20px', flex: 1 }}>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text)', lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 12, color: 'var(--faint)', marginTop: 4 }}>{label}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 3 }}>{sub}</div>}
    </div>
  )
}

interface Props {
  orgId: string
  org: Organization
  onNavigate: (p: Page) => void
  onScanComplete: (scanId: string) => void
}

export default function DashboardPage({ orgId, org, onNavigate, onScanComplete }: Props) {
  const oApi = orgApi(orgId)
  const [stats, setStats]     = useState<OrgStats | null>(null)
  const [projects, setProjects] = useState<ImportedProject[]>([])
  const [scans, setScans]     = useState<ScanJob[]>([])
  const [scanning, setScanning] = useState<string | null>(null)
  const [model, setModel]     = useState('claude-3-5-sonnet-20241022')
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      oApi.getStats().then(setStats).catch(() => {}),
      oApi.listProjects().then(setProjects).catch(() => {}),
      oApi.listScans().then(s => setScans(s.slice(0, 10))).catch(() => {}),
    ]).finally(() => setLoading(false))
  }, [orgId])

  useEffect(() => { load() }, [load])

  const startScan = async (project: ImportedProject) => {
    setScanning(project.id)
    try {
      const res = await oApi.createScan({
        repo_url: project.http_url_to_repo,
        branch: project.default_branch || 'main',
        source: 'gitlab',
        ai_model: model,
      })
      const poll = setInterval(async () => {
        try {
          const s = await api.getScan(res.id)
          if (s.status === 'completed' || s.status === 'failed') {
            clearInterval(poll)
            setScanning(null)
            load()
            onScanComplete(res.id)
          }
        } catch { clearInterval(poll); setScanning(null) }
      }, 3000)
    } catch { setScanning(null) }
  }

  const claudeConnected = true // optimistic; integrations page shows real status

  return (
    <div style={{ padding: '32px 40px', maxWidth: 1100, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 600, marginBottom: 4 }}>{org.name}</h1>
          <p style={{ fontSize: 13, color: 'var(--muted)' }}>Overview of your organization&apos;s security posture</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="outline" size="sm" onClick={load}>
            <FiRefreshCw size={13} /> Refresh
          </Button>
          <Button size="sm" onClick={() => onNavigate('projects')}>
            <FiPlus size={13} /> Add project
          </Button>
        </div>
      </div>

      {/* Scan in progress banner */}
      {scanning && (
        <div style={{
          marginBottom: 20, padding: '12px 16px',
          background: 'var(--blue-bg)', border: '1px solid rgba(47,129,247,0.3)',
          borderRadius: 8, display: 'flex', alignItems: 'center', gap: 10, fontSize: 13,
        }}>
          <FiLoader size={16} className="spin" style={{ color: 'var(--blue)', flexShrink: 0 }} />
          <span style={{ fontWeight: 500, color: 'var(--blue)' }}>Scan in progress</span>
          <span style={{ color: 'var(--muted)' }}>— you&apos;ll be taken to findings when complete.</span>
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div style={{ display: 'flex', gap: 10, marginBottom: 28 }}>
          <StatCard label="Projects" value={stats.project_count} />
          <StatCard label="Total scans" value={stats.scan_count} />
          <StatCard label="Open secrets" value={stats.open_findings} color={stats.open_findings > 0 ? 'var(--red)' : undefined} />
          <StatCard label="Critical" value={stats.critical} color={stats.critical > 0 ? 'var(--red)' : undefined} sub={stats.high > 0 ? `${stats.high} high` : undefined} />
        </div>
      )}

      {/* Projects */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600 }}>Projects</h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 12, color: 'var(--muted)' }}>Model</span>
            <select
              value={model}
              onChange={e => setModel(e.target.value)}
              style={{
                fontSize: 12, padding: '4px 8px', borderRadius: 6,
                background: 'var(--card)', border: '1px solid var(--border)',
                color: 'var(--text)', cursor: 'pointer',
              }}
            >
              {MODELS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
            </select>
          </div>
        </div>

        <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
          {loading ? (
            <div style={{ padding: 48, textAlign: 'center', color: 'var(--muted)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
              <FiLoader size={20} className="spin" />
              <span style={{ fontSize: 13 }}>Loading...</span>
            </div>
          ) : projects.length === 0 ? (
            <div style={{ padding: 48, textAlign: 'center' }}>
              <FiSearch size={28} style={{ color: 'var(--faint)', margin: '0 auto 12px', display: 'block' }} />
              <div style={{ fontWeight: 500, marginBottom: 6, fontSize: 14 }}>No projects yet</div>
              <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 16 }}>
                Import repositories from your GitLab to start scanning for secrets.
              </div>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
                <Button size="sm" onClick={() => onNavigate('projects')}>
                  <FiPlus size={13} /> Add project
                </Button>
                <Button variant="outline" size="sm" onClick={() => onNavigate('integrations')}>
                  <FiLink size={13} /> Set up integrations
                </Button>
              </div>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Project', 'Visibility', 'Last scanned', 'Secrets', ''].map(h => (
                    <th key={h} style={{ padding: '9px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {projects.map(p => {
                  const isScanning = scanning === p.id
                  return (
                    <tr key={p.id}
                      style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.1s' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--hover)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                    >
                      <td style={{ padding: '11px 16px' }}>
                        <div style={{ fontWeight: 500 }}>{p.name}</div>
                        <div style={{ fontSize: 11, color: 'var(--faint)', fontFamily: 'monospace', marginTop: 1 }}>{p.path_with_namespace}</div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--faint)', marginTop: 2 }}>
                          <FiGitBranch size={10} /> {p.default_branch || 'main'}
                        </div>
                      </td>
                      <td style={{ padding: '11px 16px' }}>
                        {p.visibility === 'private'
                          ? <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--orange)' }}><FiLock size={11} /> Private</span>
                          : <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--faint)' }}><FiGlobe size={11} /> Public</span>}
                      </td>
                      <td style={{ padding: '11px 16px', fontSize: 12 }}>
                        {p.last_scan_status ? (
                          <div>
                            <Badge variant={p.last_scan_status === 'completed' ? 'success' : p.last_scan_status === 'failed' ? 'destructive' : 'warning'}>
                              {p.last_scan_status}
                            </Badge>
                            <div style={{ fontSize: 11, color: 'var(--faint)', marginTop: 3 }}>
                              {timeAgo(p.imported_at)}
                            </div>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--faint)', fontSize: 12 }}>Never</span>
                        )}
                      </td>
                      <td style={{ padding: '11px 16px' }}>
                        {p.last_scan_status === 'completed' ? (
                          <button
                            onClick={() => p.last_scan_id && onScanComplete(p.last_scan_id)}
                            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                          >
                            <span style={{
                              fontSize: 13, fontWeight: 700,
                              color: p.last_finding_count > 0 ? 'var(--red)' : 'var(--green)',
                              fontFamily: 'monospace',
                            }}>
                              {p.last_finding_count}
                            </span>
                            {p.last_finding_count > 0 && (
                              <span style={{ fontSize: 11, color: 'var(--blue)', marginLeft: 4 }}>view</span>
                            )}
                          </button>
                        ) : (
                          <span style={{ color: 'var(--faint)', fontSize: 12 }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: '11px 16px', textAlign: 'right' }}>
                        <Button
                          size="sm"
                          variant={isScanning ? 'secondary' : 'default'}
                          disabled={scanning !== null}
                          onClick={() => startScan(p)}
                        >
                          {isScanning
                            ? <><FiLoader size={11} className="spin" /> Scanning</>
                            : <><FiPlay size={11} /> Scan</>}
                        </Button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Recent scans */}
      {scans.length > 0 && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <h2 style={{ fontSize: 14, fontWeight: 600 }}>Recent scans</h2>
            <button onClick={() => onNavigate('findings')} style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 12, color: 'var(--blue)' }}>
              View all findings →
            </button>
          </div>
          <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Repository', 'Status', 'Secrets', 'Date'].map(h => (
                    <th key={h} style={{ padding: '9px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.map(s => (
                  <tr key={s.id}
                    style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer', transition: 'background 0.1s' }}
                    onClick={() => onScanComplete(s.id)}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--hover)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                  >
                    <td style={{ padding: '11px 16px', fontWeight: 500 }}>{s.repo_name}</td>
                    <td style={{ padding: '11px 16px' }}>
                      <Badge variant={s.status === 'completed' ? 'success' : s.status === 'failed' ? 'destructive' : 'warning'}>
                        {s.status}
                      </Badge>
                    </td>
                    <td style={{ padding: '11px 16px', fontWeight: 600, fontFamily: 'monospace', color: s.finding_count > 0 ? 'var(--red)' : 'var(--muted)' }}>
                      {s.finding_count}
                    </td>
                    <td style={{ padding: '11px 16px', fontSize: 12, color: 'var(--faint)' }}>{timeAgo(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
