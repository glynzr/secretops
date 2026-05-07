'use client'
import { useEffect, useState, useCallback } from 'react'
import {
  FiRefreshCw, FiAlertCircle, FiAlertTriangle,
  FiCheckCircle, FiXCircle, FiLoader, FiCode, FiCpu,
  FiChevronUp, FiChevronDown, FiZap, FiCheck, FiX, FiClock,
} from 'react-icons/fi'
import { orgApi, api, Finding, ScanJob } from '@/lib/api'
import type { Page } from '@/app/page'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select'

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: '#e3b341', low: 'var(--green)',
}

type SevVariant = 'critical' | 'high' | 'medium' | 'low'
const sevVariant = (s: string): SevVariant =>
  (['critical', 'high', 'medium', 'low'].includes(s) ? s : 'low') as SevVariant

function StatCard({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div style={{
      background: 'var(--card)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '14px 18px', flex: 1,
    }}>
      <div style={{ fontSize: 22, fontWeight: 700, color: color || 'var(--text)', lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 12, color: 'var(--faint)', marginTop: 4 }}>{label}</div>
    </div>
  )
}

export default function FindingsPage({ orgId, scanId, onNavigate }: { orgId: string; scanId: string; onNavigate: (p: Page) => void }) {
  const oApi = orgApi(orgId)
  const [findings, setFindings]       = useState<Finding[]>([])
  const [scan, setScan]               = useState<ScanJob | null>(null)
  const [loading, setLoading]         = useState(true)
  const [expanded, setExpanded]       = useState<string | null>(null)
  const [remediating, setRemediating] = useState<string | null>(null)
  const [filterStatus, setFilterStatus] = useState('open')
  const [filterSev, setFilterSev]     = useState('')

  const load = useCallback(() => {
    setLoading(true)
    const ps: Promise<any>[] = []
    if (scanId) {
      ps.push(api.getScan(scanId).then(setScan).catch(() => {}))
      ps.push(api.getScanFindings(scanId).then(setFindings).catch(() => {}))
    } else {
      ps.push(oApi.listFindings({ status: filterStatus || undefined, severity: filterSev || undefined }).then(setFindings).catch(() => {}))
    }
    Promise.all(ps).finally(() => setLoading(false))
  }, [orgId, scanId, filterStatus, filterSev])

  useEffect(() => { load() }, [load])

  const remediate = async (f: Finding) => {
    setRemediating(f.id)
    try {
      await api.remediate(f.id)
      setTimeout(() => { load(); onNavigate('remediation') }, 1500)
    } catch (e: any) { alert('Remediation error: ' + e.message) }
    finally { setRemediating(null) }
  }

  const displayed = [...findings]
    .filter(f => (!filterStatus || f.status === filterStatus) && (!filterSev || f.severity === filterSev))
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))

  const secrets  = findings.filter(f => f.is_secret)
  const critical = secrets.filter(f => f.severity === 'critical').length
  const high     = secrets.filter(f => f.severity === 'high').length
  const medium   = secrets.filter(f => f.severity === 'medium').length
  const openCount = findings.filter(f => f.status === 'open' && f.is_secret).length

  return (
    <div style={{ padding: '32px 40px', maxWidth: 1100, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 3 }}>
            <h1 style={{ fontSize: 20, fontWeight: 600 }}>Findings</h1>
            {scan && <span style={{ fontSize: 12, color: 'var(--faint)', fontFamily: 'monospace' }}>{scan.repo_name}</span>}
          </div>
          <p style={{ fontSize: 13, color: 'var(--muted)' }}>
            {openCount > 0 ? `${openCount} open secret${openCount !== 1 ? 's' : ''} need attention` : 'All findings reviewed'}
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load}>
          <FiRefreshCw size={13} /> Refresh
        </Button>
      </div>

      {/* Stats */}
      {findings.length > 0 && (
        <div style={{ display: 'flex', gap: 10, marginBottom: 24 }}>
          <StatCard label="Total secrets" value={secrets.length} />
          <StatCard label="Critical" value={critical} color={critical > 0 ? 'var(--red)' : undefined} />
          <StatCard label="High" value={high} color={high > 0 ? 'var(--orange)' : undefined} />
          <StatCard label="Medium / Low" value={medium + (secrets.length - critical - high - medium)} />
        </div>
      )}

      {/* Filters */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <Select value={filterStatus || '__all__'} onValueChange={v => setFilterStatus(v === '__all__' ? '' : v)}>
          <SelectTrigger className="w-40 text-xs h-8">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all__">All statuses</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="remediated">Remediated</SelectItem>
            <SelectItem value="false_positive">False positive</SelectItem>
            <SelectItem value="closed">Closed</SelectItem>
          </SelectContent>
        </Select>

        {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
          const count = findings.filter(f => f.severity === sev && f.is_secret).length
          if (!count) return null
          const active = filterSev === sev
          return (
            <button key={sev} onClick={() => setFilterSev(active ? '' : sev)} style={{
              padding: '3px 11px', borderRadius: 20, fontSize: 12, fontWeight: 500, cursor: 'pointer',
              background: active ? SEV_COLOR[sev] : 'transparent',
              color: active ? 'white' : SEV_COLOR[sev],
              border: `1px solid ${SEV_COLOR[sev]}`,
            }}>
              {sev} · {count}
            </button>
          )
        })}
        {filterSev && (
          <button onClick={() => setFilterSev('')} style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 12, color: 'var(--muted)', display: 'flex', alignItems: 'center', gap: 3 }}>
            <FiX size={11} /> Clear
          </button>
        )}
        <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--faint)' }}>
          {displayed.length} result{displayed.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Body */}
      {loading ? (
        <div style={{ padding: 60, textAlign: 'center', color: 'var(--muted)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
          <FiCpu size={24} className="spin" />
          <span>Scanning...</span>
        </div>
      ) : displayed.length === 0 ? (
        <div style={{ padding: 60, textAlign: 'center' }}>
          <FiCheckCircle size={32} style={{ color: 'var(--green)', margin: '0 auto 12px', display: 'block' }} />
          <div style={{ fontWeight: 500, marginBottom: 4 }}>No findings</div>
          <div style={{ color: 'var(--muted)', fontSize: 13 }}>
            {filterStatus === 'open' ? 'All findings reviewed.' : 'No findings match this filter.'}
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {displayed.map(f => {
            const isOpen = expanded === f.id
            const sc = SEV_COLOR[f.severity] || 'var(--faint)'

            return (
              <div key={f.id} style={{
                background: 'var(--card)', border: '1px solid var(--border)',
                borderLeft: `3px solid ${sc}`, borderRadius: 8, overflow: 'hidden',
              }}>
                <div
                  onClick={() => setExpanded(isOpen ? null : f.id)}
                  style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '11px 16px', cursor: 'pointer' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.02)'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 3 }}>
                      <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--muted)' }}>
                        {f.file_path}:{f.line_number}
                      </span>
                      <Badge variant="secondary" className="font-mono text-[10px]">{f.secret_type}</Badge>
                      <Badge variant={sevVariant(f.severity)}>{f.severity}</Badge>
                      {f.status !== 'open' && <Badge variant="secondary">{f.status}</Badge>}
                      {f.days_in_history > 7 && (
                        <Badge variant={f.history_alert_level === 'CRITICAL' ? 'critical' : 'warning'}>
                          <FiClock size={10} /> {f.days_in_history}d exposed
                        </Badge>
                      )}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--faint)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.reasoning}
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: f.confidence > 0.9 ? sc : 'var(--muted)' }}>
                      {(f.confidence * 100).toFixed(0)}%
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--faint)' }}>confidence</div>
                  </div>
                  <span style={{ color: 'var(--faint)', marginLeft: 4, flexShrink: 0 }}>
                    {isOpen ? <FiChevronUp size={15} /> : <FiChevronDown size={15} />}
                  </span>
                </div>

                {isOpen && (
                  <div style={{ borderTop: '1px solid var(--border)', padding: 16 }}>
                    {f.days_in_history > 0 && (
                      <div style={{
                        marginBottom: 14, padding: '10px 13px', borderRadius: 6, fontSize: 13,
                        display: 'flex', alignItems: 'flex-start', gap: 8,
                        background: f.history_alert_level === 'CRITICAL' ? 'var(--red-bg)' : 'var(--orange-bg)',
                        border: `1px solid ${f.history_alert_level === 'CRITICAL' ? 'rgba(248,81,73,0.3)' : 'rgba(210,153,34,0.3)'}`,
                        color: f.history_alert_level === 'CRITICAL' ? 'var(--red)' : 'var(--orange)',
                      }}>
                        {f.history_alert_level === 'CRITICAL'
                          ? <FiAlertCircle size={14} style={{ marginTop: 1, flexShrink: 0 }} />
                          : <FiAlertTriangle size={14} style={{ marginTop: 1, flexShrink: 0 }} />}
                        <span>
                          In Git history for <strong>{f.days_in_history} days</strong>
                          {f.first_seen_date && ` since ${f.first_seen_date}`}
                          {f.commit_author && ` — introduced by ${f.commit_author}`}.
                          {f.history_alert_level === 'CRITICAL' && ' Credential may already be compromised.'}
                        </span>
                      </div>
                    )}

                    {f.context_code && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 600, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 7 }}>
                          <FiCode size={11} /> Source
                        </div>
                        <pre style={{
                          background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
                          padding: 12, fontSize: 12, fontFamily: 'monospace', color: 'var(--text)',
                          overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                          maxHeight: 160, overflow: 'auto', lineHeight: 1.6,
                        }}>
                          {f.context_code}
                        </pre>
                      </div>
                    )}

                    <div style={{
                      background: 'var(--blue-bg)', border: '1px solid rgba(47,129,247,0.2)',
                      borderRadius: 6, padding: '11px 13px', marginBottom: 14,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 600, color: 'var(--blue)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 7 }}>
                        <FiCpu size={11} /> AI Analysis
                        <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>— {f.ai_model}</span>
                      </div>
                      <div style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.6 }}>{f.reasoning}</div>
                      {f.env_var_suggestion && (
                        <div style={{ fontSize: 12, color: 'var(--green)', marginTop: 6, fontFamily: 'monospace' }}>
                          Suggested env var: <strong>{f.env_var_suggestion}</strong>
                        </div>
                      )}
                      {f.vault_path_suggestion && (
                        <div style={{ fontSize: 12, color: 'var(--purple)', marginTop: 3, fontFamily: 'monospace' }}>
                          Vault path: <strong>{f.vault_path_suggestion}</strong>
                        </div>
                      )}
                    </div>

                    {f.status === 'open' && (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <Button size="sm" onClick={() => remediate(f)} disabled={remediating === f.id}>
                          {remediating === f.id
                            ? <><FiLoader size={12} className="spin" /> Starting...</>
                            : <><FiZap size={12} /> Auto-remediate</>}
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => api.updateFindingStatus(f.id, 'false_positive').then(load)}>
                          False positive
                        </Button>
                        <Button size="sm" variant="ghost" style={{ color: 'var(--faint)' }} onClick={() => api.updateFindingStatus(f.id, 'ignored').then(load)}>
                          Ignore
                        </Button>
                      </div>
                    )}

                    {f.status === 'remediated' && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--green)' }}>
                        <FiCheck size={13} /> Remediated —
                        <button onClick={() => onNavigate('remediation')} style={{ background: 'none', border: 'none', color: 'var(--blue)', cursor: 'pointer', fontSize: 13, textDecoration: 'underline' }}>
                          view pipeline
                        </button>
                      </div>
                    )}

                    {f.status === 'false_positive' && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--faint)' }}>
                        <FiXCircle size={13} /> Marked as false positive
                        <button onClick={() => api.updateFindingStatus(f.id, 'open').then(load)} style={{ background: 'none', border: 'none', color: 'var(--blue)', cursor: 'pointer', fontSize: 12 }}>Undo</button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
