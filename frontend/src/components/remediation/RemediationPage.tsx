'use client'
import { useEffect, useState, useCallback } from 'react'
import {
  FiRefreshCw, FiShield, FiGitMerge, FiFileText, FiBell, FiMail,
  FiSlash, FiCheckCircle, FiAlertTriangle, FiLoader, FiCheck,
  FiExternalLink, FiChevronLeft, FiChevronRight, FiTool,
} from 'react-icons/fi'
import { orgApi, api, Remediation, HistoryAlert } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'

const STAGES: { key: string; label: string; Icon: React.ComponentType<{ size?: number }>; desc: string }[] = [
  { key: 'vault',  label: 'Vault Poison',   Icon: FiShield,      desc: 'Poison placeholder injected at Vault path' },
  { key: 'mr',     label: 'GitLab MR',      Icon: FiGitMerge,    desc: 'MR created with AI patch and rotation guide' },
  { key: 'issue',  label: 'GitLab Issue',   Icon: FiFileText,    desc: 'Issue created and assigned to commit author' },
  { key: 'slack',  label: 'Slack',          Icon: FiBell,        desc: 'Alert sent to security channel' },
  { key: 'email',  label: 'Email',          Icon: FiMail,        desc: 'HTML email sent to security team' },
  { key: 'revoke', label: 'Revocation',     Icon: FiSlash,       desc: 'Direct API revocation (AWS/GitLab/GitHub)' },
  { key: 'verify', label: 'Post-Merge',     Icon: FiCheckCircle, desc: 'Verify Vault value updated after MR merge' },
]

function stageStatus(job: Remediation, key: string): { ok: boolean; warn: boolean; info: string; link?: string } {
  switch (key) {
    case 'vault':  return { ok: job.vault_status === 'poisoned',                warn: job.vault_status === 'unavailable_fallback', info: job.vault_status || '—' }
    case 'mr':     return { ok: !!job.mr_url,                                   warn: false, info: job.mr_url ? `#${job.mr_number}` : '—', link: job.mr_url }
    case 'issue':  return { ok: !!job.issue_url,                                warn: false, info: job.issue_url ? `#${job.issue_number}` : '—', link: job.issue_url }
    case 'slack':  return { ok: job.slack_status === 'sent',                    warn: job.slack_status === 'not_configured', info: job.slack_status || '—' }
    case 'email':  return { ok: job.email_status === 'sent',                    warn: job.email_status === 'not_configured', info: job.email_status || '—' }
    case 'revoke': return { ok: job.revocation_status === 'revoked',            warn: job.revocation_status === 'not_applicable', info: job.revocation_status || '—' }
    case 'verify': return { ok: job.post_merge_status === 'rotation_confirmed', warn: job.post_merge_status === 'not_rotated' || job.post_merge_status === 'pending_choice', info: job.post_merge_status || 'pending' }
    default: return { ok: false, warn: false, info: '—' }
  }
}

function timeAgo(s: string) {
  const d = Math.floor((Date.now() - new Date(s).getTime()) / 1000)
  if (d < 60) return 'just now'
  if (d < 3600) return `${Math.floor(d / 60)}m ago`
  return `${Math.floor(d / 3600)}h ago`
}

export default function RemediationPage({ orgId }: { orgId: string }) {
  const oApi = orgApi(orgId)
  const [jobs, setJobs]           = useState<Remediation[]>([])
  const [alerts, setAlerts]       = useState<HistoryAlert[]>([])
  const [selected, setSelected]   = useState<Remediation | null>(null)
  const [loading, setLoading]     = useState(true)
  const [verifying, setVerifying] = useState<string | null>(null)
  const [tab, setTab]             = useState<'pipeline' | 'history'>('pipeline')

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      oApi.listRemediations().then(setJobs),
      oApi.listHistoryAlerts().then(setAlerts),
    ]).catch(() => {}).finally(() => setLoading(false))
  }, [orgId])

  useEffect(() => { load(); const t = setInterval(load, 8000); return () => clearInterval(t) }, [load])

  const verify = async (job: Remediation) => {
    setVerifying(job.id)
    try { await api.postMergeVerify(job.id); setTimeout(load, 3000) }
    catch (e: any) { alert('Verify error: ' + e.message) }
    finally { setVerifying(null) }
  }

  return (
    <div style={{ padding: '32px 40px', maxWidth: 1200, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 600, marginBottom: 4 }}>Remediation</h1>
          <p style={{ fontSize: 13, color: 'var(--muted)' }}>Automated pipeline: Vault Poison → MR → Issue → Notifications → Revocation → Verification</p>
        </div>
        <Button variant="outline" size="sm" onClick={load}>
          <FiRefreshCw size={13} /> Refresh
        </Button>
      </div>

      <Tabs value={tab} onValueChange={v => setTab(v as 'pipeline' | 'history')}>
        <TabsList>
          <TabsTrigger value="pipeline">Pipeline ({jobs.length})</TabsTrigger>
          <TabsTrigger value="history">History alerts ({alerts.length})</TabsTrigger>
        </TabsList>

        {/* Pipeline tab */}
        <TabsContent value="pipeline">
          <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 340px' : '1fr', gap: 16, alignItems: 'start' }}>

            {/* Jobs table */}
            <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
              {loading && jobs.length === 0 ? (
                <div style={{ padding: 60, textAlign: 'center', color: 'var(--muted)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
                  <FiLoader size={22} className="spin" />
                  <span>Loading...</span>
                </div>
              ) : jobs.length === 0 ? (
                <div style={{ padding: 60, textAlign: 'center', color: 'var(--muted)' }}>
                  <FiTool size={28} style={{ margin: '0 auto 10px', display: 'block', color: 'var(--faint)' }} />
                  <div style={{ fontWeight: 500, marginBottom: 4 }}>No remediations yet</div>
                  <div style={{ fontSize: 13, color: 'var(--faint)' }}>Trigger remediation from an open finding.</div>
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['Finding', 'Vault', 'MR', 'Status', 'Verify', 'Time', ''].map(h => (
                        <th key={h} style={{ padding: '9px 14px', textAlign: 'left', color: 'var(--faint)', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.map(j => {
                      const vaultSt  = stageStatus(j, 'vault')
                      const mrSt     = stageStatus(j, 'mr')
                      const verifySt = stageStatus(j, 'verify')
                      const isSel    = selected?.id === j.id
                      return (
                        <tr key={j.id}
                          style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer', background: isSel ? 'var(--hover)' : 'transparent', transition: 'background 0.1s' }}
                          onClick={() => setSelected(isSel ? null : j)}
                          onMouseEnter={e => { if (!isSel) (e.currentTarget as HTMLElement).style.background = 'var(--hover)' }}
                          onMouseLeave={e => { if (!isSel) (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                        >
                          <td style={{ padding: '11px 14px' }}>
                            <div style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'monospace' }}>{j.id.slice(0, 8)}</div>
                            {j.env_var_name && <div style={{ fontSize: 11, color: 'var(--purple)', marginTop: 2, fontFamily: 'monospace' }}>{j.env_var_name}</div>}
                          </td>
                          <td style={{ padding: '11px 14px', fontSize: 12 }}>
                            {vaultSt.ok
                              ? <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--green)' }}><FiShield size={12} /> Poisoned</span>
                              : vaultSt.warn
                                ? <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--orange)' }}><FiFileText size={12} /> Fallback</span>
                                : <span style={{ color: 'var(--faint)' }}>—</span>}
                          </td>
                          <td style={{ padding: '11px 14px' }}>
                            {mrSt.link
                              ? <a href={mrSt.link} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}
                                  style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--blue)', textDecoration: 'none' }}>
                                  MR #{j.mr_number} <FiExternalLink size={10} />
                                </a>
                              : <span style={{ fontSize: 12, color: 'var(--faint)' }}>—</span>}
                          </td>
                          <td style={{ padding: '11px 14px' }}>
                            <Badge variant={j.status === 'completed' ? 'success' : j.status === 'failed' ? 'destructive' : 'warning'}>
                              {j.status}
                            </Badge>
                          </td>
                          <td style={{ padding: '11px 14px' }}>
                            {verifySt.ok ? (
                              <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--green)' }}><FiCheckCircle size={12} /> Confirmed</span>
                            ) : verifySt.warn ? (
                              <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--red)' }}><FiAlertTriangle size={12} /> Not rotated</span>
                            ) : j.mr_url ? (
                              <Button size="sm" variant="default" onClick={e => { e.stopPropagation(); verify(j) }} disabled={verifying === j.id}>
                                {verifying === j.id
                                  ? <><FiLoader size={11} className="spin" /> Checking...</>
                                  : <><FiRefreshCw size={11} /> Verify</>}
                              </Button>
                            ) : <span style={{ fontSize: 12, color: 'var(--faint)' }}>—</span>}
                          </td>
                          <td style={{ padding: '11px 14px', fontSize: 12, color: 'var(--faint)', whiteSpace: 'nowrap' }}>{timeAgo(j.created_at)}</td>
                          <td style={{ padding: '11px 14px', color: 'var(--faint)' }}>
                            {isSel ? <FiChevronLeft size={14} /> : <FiChevronRight size={14} />}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {/* Detail panel */}
            {selected && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>

                {/* Pipeline stages */}
                <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px' }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12 }}>
                    Pipeline Status
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {STAGES.map(stage => {
                      const st = stageStatus(selected, stage.key)
                      const { Icon } = stage
                      return (
                        <div key={stage.key} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                          <div style={{
                            width: 30, height: 30, borderRadius: 6, flexShrink: 0,
                            background: st.ok ? 'var(--green-bg)' : st.warn ? 'var(--orange-bg)' : 'var(--hover)',
                            border: `1px solid ${st.ok ? 'rgba(63,185,80,0.3)' : st.warn ? 'rgba(210,153,34,0.3)' : 'var(--border)'}`,
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            color: st.ok ? 'var(--green)' : st.warn ? 'var(--orange)' : 'var(--faint)',
                          }}>
                            <Icon size={14} />
                          </div>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 1 }}>
                              <span style={{ fontSize: 12, fontWeight: 600, color: st.ok ? 'var(--text)' : 'var(--muted)' }}>{stage.label}</span>
                              {st.ok && <FiCheck size={11} style={{ color: 'var(--green)' }} />}
                              {st.warn && !st.ok && <FiAlertTriangle size={11} style={{ color: 'var(--orange)' }} />}
                              {st.link && (
                                <a href={st.link} target="_blank" rel="noreferrer" style={{ color: 'var(--blue)' }}>
                                  <FiExternalLink size={10} />
                                </a>
                              )}
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--faint)' }}>{stage.desc}</div>
                            {st.info && st.info !== '—' && (
                              <div style={{ fontSize: 11, fontFamily: 'monospace', marginTop: 2, color: st.ok ? 'var(--green)' : st.warn ? 'var(--orange)' : 'var(--faint)' }}>
                                {st.info}
                              </div>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* AI-generated patch */}
                {selected.patch_content && (
                  <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px' }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 10 }}>
                      AI Patch
                    </div>
                    <pre style={{
                      background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
                      padding: 10, fontSize: 11, fontFamily: 'JetBrains Mono, monospace',
                      color: 'var(--green)', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0,
                    }}>
                      {selected.patch_content}
                    </pre>
                  </div>
                )}

                {/* Revocation details */}
                {selected.revocation_msg && (
                  <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px' }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
                      Revocation
                    </div>
                    <div style={{ fontSize: 12, color: selected.revocation_status === 'revoked' ? 'var(--green)' : 'var(--orange)', lineHeight: 1.6 }}>
                      {selected.revocation_msg}
                    </div>
                  </div>
                )}

                {/* Post-merge banners */}
                {selected.post_merge_status === 'not_rotated' && (
                  <div style={{
                    padding: '10px 14px', background: 'var(--red-bg)',
                    border: '1px solid rgba(248,81,73,0.3)', borderRadius: 8,
                    fontSize: 12, color: 'var(--red)', display: 'flex', alignItems: 'flex-start', gap: 8,
                  }}>
                    <FiAlertTriangle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
                    <span><strong>MR merged but credential not rotated.</strong> Vault poison still active. Update Vault and re-verify.</span>
                  </div>
                )}
                {selected.post_merge_status === 'rotation_confirmed' && (
                  <div style={{
                    padding: '10px 14px', background: 'var(--green-bg)',
                    border: '1px solid rgba(63,185,80,0.3)', borderRadius: 8,
                    fontSize: 12, color: 'var(--green)', display: 'flex', alignItems: 'center', gap: 8,
                  }}>
                    <FiCheckCircle size={13} style={{ flexShrink: 0 }} />
                    <span><strong>Rotation confirmed.</strong> Vault value updated. Finding automatically closed.</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </TabsContent>

        {/* History alerts tab */}
        <TabsContent value="history">
          <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            {alerts.length === 0 ? (
              <div style={{ padding: 60, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
                No history alerts — no long-lived credentials detected yet
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Repository', 'Days Exposed', 'Alert Level', 'First Author', 'Commits', 'Date'].map(h => (
                      <th key={h} style={{ padding: '9px 16px', textAlign: 'left', color: 'var(--faint)', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {alerts.map(a => {
                    const levelColor = ({ CRITICAL: 'var(--red)', WARNING: 'var(--orange)', INFO: 'var(--muted)' } as any)[a.alert_level] || 'var(--faint)'
                    const badgeVariant: 'critical' | 'warning' | 'secondary' =
                      a.alert_level === 'CRITICAL' ? 'critical' : a.alert_level === 'WARNING' ? 'warning' : 'secondary'
                    return (
                      <tr key={a.id} style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.1s' }}
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--hover)'}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                      >
                        <td style={{ padding: '11px 16px', fontWeight: 500 }}>{a.repo_name}</td>
                        <td style={{ padding: '11px 16px', fontWeight: 700, color: levelColor, fontFamily: 'monospace' }}>{a.days_exposed}d</td>
                        <td style={{ padding: '11px 16px' }}><Badge variant={badgeVariant}>{a.alert_level}</Badge></td>
                        <td style={{ padding: '11px 16px', fontSize: 12, color: 'var(--muted)' }}>{a.first_seen_author}</td>
                        <td style={{ padding: '11px 16px', fontSize: 12, color: 'var(--muted)', fontFamily: 'monospace' }}>{a.commit_count}</td>
                        <td style={{ padding: '11px 16px', fontSize: 12, color: 'var(--faint)' }}>{a.first_seen_date}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
