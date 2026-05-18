'use client'
import { useEffect, useState, useCallback, useRef } from 'react'
import {
  ChevronDown, ChevronRight, GitCommit, Calendar, User, Shield,
  FolderOpen, RefreshCw, Loader2, ExternalLink, FileCode,
  CheckCircle, Clock, GitMerge, AlertTriangle, Zap, XCircle
} from 'lucide-react'
import { api } from '@/lib/api'
import type { Finding } from '@/types'

const STATUS_LABEL: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  open:           { label: 'Open',          color: 'text-blue-400 border-blue-500/30 bg-blue-500/10',     icon: <AlertTriangle className="w-3 h-3" /> },
  confirmed:      { label: 'Confirmed',     color: 'text-orange-400 border-orange-500/30 bg-orange-500/10', icon: <CheckCircle className="w-3 h-3" /> },
  remediating:    { label: 'Remediating…',  color: 'text-purple-400 border-purple-500/30 bg-purple-500/10', icon: <Loader2 className="w-3 h-3 animate-spin" /> },
  remediated:     { label: 'MR Created',    color: 'text-teal-400 border-teal-500/30 bg-teal-500/10',     icon: <GitMerge className="w-3 h-3" /> },
  mr_created:     { label: 'MR Created',    color: 'text-teal-400 border-teal-500/30 bg-teal-500/10',     icon: <GitMerge className="w-3 h-3" /> },
  closed:         { label: 'Closed',        color: 'text-green-400 border-green-500/30 bg-green-500/10',  icon: <CheckCircle className="w-3 h-3" /> },
  false_positive: { label: 'False Positive',color: 'text-gray-400 border-gray-500/30 bg-gray-500/10',    icon: <XCircle className="w-3 h-3" /> },
  ignored:        { label: 'Ignored',       color: 'text-gray-500 border-gray-500/20 bg-gray-500/5',     icon: <XCircle className="w-3 h-3" /> },
}

// Remediation pipeline stages shown while status = remediating
const PIPELINE_STAGES = [
  { key: 'patch',  label: 'AI Patch Generation',   desc: 'Generating code fix via LLM' },
  { key: 'vault',  label: 'Vault Poison Injection', desc: 'Writing placeholder to Vault KV' },
  { key: 'branch', label: 'Branch & Commit',        desc: 'Creating branch, committing patch' },
  { key: 'mr',     label: 'Merge Request',          desc: 'Opening MR with rotation checklist' },
  { key: 'notify', label: 'Notifications',          desc: 'Slack + email alerts sent' },
]

function RemediationPipeline({ startedAt }: { startedAt: number }) {
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setElapsed(Date.now() - startedAt), 500)
    return () => clearInterval(t)
  }, [startedAt])

  // Estimate current stage based on elapsed time
  const stageIdx = Math.min(Math.floor(elapsed / 4000), PIPELINE_STAGES.length - 1)

  return (
    <div className="bg-purple-500/5 border border-purple-500/20 rounded-xl p-4 mt-3">
      <div className="flex items-center gap-2 mb-3">
        <Loader2 className="w-4 h-4 animate-spin text-purple-400" />
        <span className="text-sm font-semibold text-purple-400">Remediation in progress…</span>
        <span className="text-xs text-muted ml-auto">{Math.round(elapsed / 1000)}s</span>
      </div>
      <div className="space-y-2">
        {PIPELINE_STAGES.map((stage, i) => {
          const done = i < stageIdx
          const active = i === stageIdx
          return (
            <div key={stage.key} className={`flex items-center gap-3 text-xs transition-all ${done ? 'opacity-60' : active ? 'opacity-100' : 'opacity-30'}`}>
              <div className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 border ${
                done   ? 'bg-green-500/20 border-green-500/40 text-green-400' :
                active ? 'bg-purple-500/20 border-purple-500/40 text-purple-400' :
                         'bg-elevated border-border text-muted'
              }`}>
                {done ? <CheckCircle className="w-3 h-3" /> :
                 active ? <Loader2 className="w-3 h-3 animate-spin" /> :
                 <span className="text-[10px]">{i + 1}</span>}
              </div>
              <div className="flex-1">
                <span className={`font-medium ${active ? 'text-white' : 'text-muted'}`}>{stage.label}</span>
                {active && <span className="text-muted ml-2">{stage.desc}</span>}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const s = STATUS_LABEL[status] || { label: status, color: 'text-muted border-border bg-elevated', icon: null }
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${s.color}`}>
      {s.icon}{s.label}
    </span>
  )
}

function FindingRow({
  finding, onRefresh, remediatingSet, setRemediating
}: {
  finding: Finding
  onRefresh: () => void
  remediatingSet: Map<number, number>
  setRemediating: (id: number, ts: number | null) => void
}) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  const isDone = finding.status === 'remediated' || finding.remediation_status === 'mr_created' || finding.remediation_status === 'completed'
  const isRemediating = !isDone && (finding.status === 'remediating' || remediatingSet.has(finding.id))
  const remediationStart = remediatingSet.get(finding.id) || 0

  const doRemediate = async () => {
    setBusy(true)
    try {
      await api.triggerRemediation(finding.id)
      // Optimistically mark as remediating immediately
      setRemediating(finding.id, Date.now())
      onRefresh()
    } catch (e) { console.error(e) }
    finally { setBusy(false) }
  }

  const doStatus = async (status: string) => {
    setBusy(true)
    try {
      await api.updateFindingStatus(finding.id, status)
      onRefresh()
    } catch (e) { console.error(e) }
    finally { setBusy(false) }
  }

  return (
    <div className={`border rounded-xl overflow-hidden transition-all ${
      isRemediating ? 'border-purple-500/30 bg-purple-500/5' : 'border-border bg-surface'
    }`}>
      {/* Header row */}
      <button onClick={() => setOpen(o => !o)}
        className="w-full flex items-start gap-3 p-3.5 hover:bg-white/5 transition-colors text-left">
        <div className="mt-0.5 shrink-0">
          {open ? <ChevronDown className="w-4 h-4 text-muted" /> : <ChevronRight className="w-4 h-4 text-muted" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-white font-mono">
              {finding.secret_type?.replace(/_/g, ' ')}
            </span>
            <StatusBadge status={finding.remediation_status === 'mr_created' ? 'mr_created' : finding.status} />
          </div>
          <div className="flex items-center gap-3 mt-1 flex-wrap">
            {finding.source_url ? (
              <a href={finding.source_url} target="_blank" rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 font-mono">
                <FileCode className="w-3 h-3 shrink-0" />
                {finding.file_path}:{finding.line_number}
                <ExternalLink className="w-3 h-3 shrink-0" />
              </a>
            ) : (
              <span className="text-xs text-muted font-mono">{finding.file_path}:{finding.line_number}</span>
            )}
            {(finding.days_exposed ?? 0) > 0 && (
              <span className="text-xs text-orange-400 font-mono">{finding.days_exposed}d exposed</span>
            )}
            {finding.masked_value && (
              <span className="text-xs text-muted font-mono">{finding.masked_value}</span>
            )}
          </div>
        </div>
        {busy && <Loader2 className="w-4 h-4 animate-spin text-muted shrink-0 mt-0.5" />}
        {finding.mr_url && (
          <a href={finding.mr_url} target="_blank" rel="noopener noreferrer"
            onClick={e => e.stopPropagation()}
            className="flex items-center gap-1 text-xs text-teal-400 hover:text-teal-300 border border-teal-500/30 px-2 py-1 rounded-lg shrink-0">
            <GitMerge className="w-3 h-3" /> View MR
          </a>
        )}
      </button>

      {/* Remediation pipeline (shown while in progress) */}
      {isRemediating && (
        <div className="px-4 pb-4">
          <RemediationPipeline startedAt={remediationStart || Date.now()} />
        </div>
      )}

      {/* MR created success banner */}
      {(finding.remediation_status === 'mr_created' || finding.status === 'remediated') && finding.mr_url && (
        <div className="mx-4 mb-4 flex items-center gap-3 bg-teal-500/10 border border-teal-500/30 rounded-xl px-4 py-3">
          <GitMerge className="w-5 h-5 text-teal-400 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-semibold text-teal-400">Merge Request Created</div>
            <div className="text-xs text-muted mt-0.5 truncate">Review the patch and merge to complete rotation</div>
          </div>
          <a href={finding.mr_url} target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1 text-xs text-teal-400 hover:text-teal-300 border border-teal-500/40 px-3 py-1.5 rounded-lg shrink-0">
            Open MR <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      )}

      {/* Expanded details */}
      {open && (
        <div className="border-t border-border p-4 space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { icon: User,      label: 'Author',     value: finding.first_commit_author || '—' },
              { icon: Calendar,  label: 'First Seen', value: finding.first_commit_date ? new Date(finding.first_commit_date).toLocaleDateString() : '—' },
              { icon: GitCommit, label: 'Commits',    value: String(finding.total_commits || 0) },
              { icon: Shield,    label: 'Confidence', value: `${Math.round((finding.ai_confidence || 0) * 100)}%` },
            ].map(({ icon: Icon, label, value }) => (
              <div key={label} className="bg-canvas rounded-lg p-2.5">
                <div className="flex items-center gap-1.5 text-xs text-muted mb-1"><Icon className="w-3 h-3" />{label}</div>
                <div className="text-sm text-white font-mono truncate">{value}</div>
              </div>
            ))}
          </div>

          {finding.ai_reasoning && (
            <div className="bg-canvas rounded-lg p-3">
              <div className="text-xs text-muted mb-1">AI Analysis</div>
              <div className="text-xs text-white/80 leading-relaxed">{finding.ai_reasoning}</div>
            </div>
          )}

          {finding.vault_path && (
            <div className="bg-canvas rounded-lg p-3">
              <div className="text-xs text-muted mb-1">Vault Path</div>
              <code className="text-xs text-yellow-400 font-mono">{finding.vault_path}</code>
            </div>
          )}

          {/* Action buttons */}
          {!isRemediating && (
            <div className="flex flex-wrap gap-2 pt-1">
              {(finding.status === 'open' || finding.status === 'confirmed') && (
                <button onClick={doRemediate} disabled={busy}
                  className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors">
                  {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                  {finding.status === 'open' ? 'Confirm & Remediate' : 'Start Remediation'}
                </button>
              )}
              {finding.status === 'open' && (
                <>
                  <button onClick={() => doStatus('false_positive')} disabled={busy}
                    className="px-3 py-2 bg-elevated text-muted border border-border rounded-lg text-sm hover:text-white transition-colors">
                    False Positive
                  </button>
                  <button onClick={() => doStatus('ignored')} disabled={busy}
                    className="px-3 py-2 bg-elevated text-muted border border-border rounded-lg text-sm hover:text-white transition-colors">
                    Ignore
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

type Group = { repoId: number; scanId: number; findings: Finding[] }

export default function FindingsView() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [filterStatus, setFilterStatus] = useState('')
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  // Track locally which findings we just triggered remediation on + when
  const [remediatingMap, setRemediatingMap] = useState<Map<number, number>>(new Map())
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (filterStatus) params.status = filterStatus
      const data = await api.getFindings(params)
      setFindings(data)

      // Clear local remediating state for findings that now have a real status
      setRemediatingMap(prev => {
        const next = new Map(prev)
        data.forEach((f: Finding) => {
          if (f.status !== 'open' && f.status !== 'confirmed') {
            next.delete(f.id)
          }
        })
        return next
      })

      // Auto-expand all groups on first load
      setExpandedGroups(prev => {
        if (prev.size > 0) return prev
        const keys = new Set<string>()
        data.forEach((f: Finding) => keys.add(`${f.repository_id}-${f.scan_id}`))
        return keys
      })
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [filterStatus])

  useEffect(() => {
    load()
    // Poll every 4s while any finding is remediating
    pollRef.current = setInterval(() => load(true), 4000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [load])

  const setRemediating = (id: number, ts: number | null) => {
    setRemediatingMap(prev => {
      const next = new Map(prev)
      if (ts === null) next.delete(id)
      else next.set(id, ts)
      return next
    })
  }

  // Group findings by repo+scan
  const groups: Group[] = []
  const seen = new Map<string, Group>()
  for (const f of findings) {
    const key = `${f.repository_id}-${f.scan_id}`
    if (!seen.has(key)) {
      const g: Group = { repoId: f.repository_id, scanId: f.scan_id, findings: [] }
      seen.set(key, g)
      groups.push(g)
    }
    seen.get(key)!.findings.push(f)
  }

  const toggleGroup = (key: string) =>
    setExpandedGroups(prev => {
      const s = new Set(prev); s.has(key) ? s.delete(key) : s.add(key); return s
    })

  const severityOrder = ['critical', 'high', 'medium', 'low']
  const activeRemediations = findings.filter(f =>
    f.status === 'remediating' || remediatingMap.has(f.id)
  ).length

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-6 space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white">Findings</h1>
            <div className="flex items-center gap-3 mt-0.5">
              <p className="text-sm text-muted">{findings.length} total across {groups.length} scans</p>
              {activeRemediations > 0 && (
                <span className="flex items-center gap-1.5 text-xs text-purple-400 bg-purple-500/10 border border-purple-500/30 px-2 py-0.5 rounded-full">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  {activeRemediations} remediating
                </span>
              )}
            </div>
          </div>
          <button onClick={() => load()} disabled={loading}
            className="flex items-center gap-2 px-3 py-2 bg-elevated border border-border hover:border-blue-500/50 text-sm text-white rounded-lg transition-colors">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* Filters */}
        <div className="flex gap-2 flex-wrap">
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
            className="bg-surface border border-border text-sm text-white rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500/50">
            <option value="">All Statuses</option>
            {['open','confirmed','remediating','remediated','closed','false_positive','ignored'].map(s => (
              <option key={s} value={s}>{s.replace(/_/g,' ')}</option>
            ))}
          </select>

        </div>

        {loading && findings.length === 0 ? (
          <div className="flex items-center justify-center gap-3 text-muted py-20">
            <Loader2 className="w-5 h-5 animate-spin" /> Loading findings…
          </div>
        ) : findings.length === 0 ? (
          <div className="text-center py-20 text-muted">
            <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No findings — run a scan first</p>
          </div>
        ) : (
          <div className="space-y-4">
            {groups.map(group => {
              const key = `${group.repoId}-${group.scanId}`
              const isOpen = expandedGroups.has(key)
              const sorted = [...group.findings].sort((a, b) =>
                severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
              const openCount = group.findings.filter(f => f.status === 'open').length
              const remCount  = group.findings.filter(f => f.status === 'remediating' || remediatingMap.has(f.id)).length

              return (
                <div key={key} className="bg-elevated/30 border border-border rounded-2xl overflow-hidden">
                  <button onClick={() => toggleGroup(key)}
                    className="w-full flex items-center gap-3 p-4 hover:bg-elevated/60 transition-colors text-left">
                    <FolderOpen className="w-5 h-5 text-blue-400 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold text-white">Scan #{group.scanId}</span>
                        {openCount > 0 && <span className="text-xs text-muted">{openCount} open</span>}
                        {remCount > 0  && <span className="flex items-center gap-1 text-xs text-purple-400"><Loader2 className="w-3 h-3 animate-spin" />{remCount} remediating</span>}
                      </div>
                      <div className="text-xs text-muted mt-0.5">{group.findings.length} finding{group.findings.length !== 1 ? 's' : ''}</div>
                    </div>
                    {isOpen ? <ChevronDown className="w-4 h-4 text-muted shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted shrink-0" />}
                  </button>

                  {isOpen && (
                    <div className="px-4 pb-4 space-y-2">
                      {sorted.map(f => (
                        <FindingRow
                          key={f.id}
                          finding={f}
                          onRefresh={() => load(true)}
                          remediatingSet={remediatingMap}
                          setRemediating={setRemediating}
                        />
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
