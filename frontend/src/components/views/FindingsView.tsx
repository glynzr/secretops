'use client'
import { useEffect, useState, useCallback } from 'react'
import { AlertTriangle, CheckCircle, XCircle, Clock, ChevronDown, ChevronUp, Zap, Eye, EyeOff, GitCommit, Calendar, User, Shield } from 'lucide-react'
import { api } from '@/lib/api'
import type { Finding } from '@/types'

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/30',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/10 text-green-400 border-green-500/30',
}

const STATUS_STYLES: Record<string, string> = {
  open: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  confirmed: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  false_positive: 'bg-gray-500/10 text-gray-400 border-gray-500/30',
  ignored: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
  closed: 'bg-green-500/10 text-green-400 border-green-500/30',
}

export default function FindingsView() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [filterStatus, setFilterStatus] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [remediating, setRemediating] = useState<Set<number>>(new Set())
  const [updating, setUpdating] = useState<Set<number>>(new Set())

  const load = useCallback(async () => {
    try {
      const params: Record<string, string> = {}
      if (filterStatus) params.status = filterStatus
      if (filterSeverity) params.severity = filterSeverity
      const data = await api.getFindings(params)
      setFindings(data)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [filterStatus, filterSeverity])

  useEffect(() => { load() }, [load])

  const handleStatusUpdate = async (id: number, status: string) => {
    setUpdating(prev => new Set(prev).add(id))
    try {
      await api.updateFindingStatus(id, status)
      await load()
    } catch (e) {
      console.error(e)
    } finally {
      setUpdating(prev => { const s = new Set(prev); s.delete(id); return s })
    }
  }

  const handleRemediate = async (id: number) => {
    setRemediating(prev => new Set(prev).add(id))
    try {
      await api.triggerRemediation(id)
      await load()
    } catch (e) {
      console.error(e)
    } finally {
      setRemediating(prev => { const s = new Set(prev); s.delete(id); return s })
    }
  }

  return (
    <div className="p-6 space-y-5 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-fg">Findings</h1>
          <p className="text-sm text-fg-muted mt-0.5">{findings.length} findings detected</p>
        </div>
        <button onClick={load} className="text-sm text-accent-blue hover:text-blue-400 font-mono">↻ Refresh</button>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <select
          value={filterStatus}
          onChange={e => setFilterStatus(e.target.value)}
          className="bg-elevated border border-border rounded-md px-3 py-1.5 text-sm text-fg-muted font-mono focus:outline-none focus:border-border-active"
        >
          <option value="">All Status</option>
          <option value="open">Open</option>
          <option value="confirmed">Confirmed</option>
          <option value="false_positive">False Positive</option>
          <option value="ignored">Ignored</option>
          <option value="closed">Closed</option>
        </select>
        <select
          value={filterSeverity}
          onChange={e => setFilterSeverity(e.target.value)}
          className="bg-elevated border border-border rounded-md px-3 py-1.5 text-sm text-fg-muted font-mono focus:outline-none focus:border-border-active"
        >
          <option value="">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Findings List */}
      {loading ? (
        <div className="flex items-center justify-center py-20 text-fg-muted font-mono text-sm">
          <div className="w-4 h-4 border-2 border-accent-blue border-t-transparent rounded-full animate-spin mr-3" />
          Loading findings...
        </div>
      ) : findings.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-fg-muted">
          <Shield className="w-12 h-12 mb-4 text-fg-subtle" />
          <p className="font-mono text-sm">No findings match the current filter</p>
        </div>
      ) : (
        <div className="space-y-2">
          {findings.map(finding => (
            <FindingRow
              key={finding.id}
              finding={finding}
              expanded={expandedId === finding.id}
              onToggle={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
              onStatusUpdate={handleStatusUpdate}
              onRemediate={handleRemediate}
              isUpdating={updating.has(finding.id)}
              isRemediating={remediating.has(finding.id)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function FindingRow({ finding, expanded, onToggle, onStatusUpdate, onRemediate, isUpdating, isRemediating }: {
  finding: Finding
  expanded: boolean
  onToggle: () => void
  onStatusUpdate: (id: number, status: string) => void
  onRemediate: (id: number) => void
  isUpdating: boolean
  isRemediating: boolean
}) {
  const confidence = Math.round(finding.ai_confidence * 100)

  return (
    <div className={`bg-surface border rounded-lg overflow-hidden transition-all duration-200 ${expanded ? 'border-border-active/40' : 'border-border hover:border-border/80'}`}>
      {/* Row Header */}
      <div
        className="flex items-center gap-3 px-4 py-3.5 cursor-pointer"
        onClick={onToggle}
      >
        <div className={`severity-badge px-2 py-0.5 rounded border ${SEVERITY_STYLES[finding.severity] || SEVERITY_STYLES.medium}`}>
          {finding.severity}
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm text-fg font-mono truncate">{finding.file_path}</span>
            <span className="text-xs text-fg-muted font-mono shrink-0">:{finding.line_number}</span>
          </div>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-xs text-fg-muted font-mono">{finding.secret_type.replace(/_/g, ' ')}</span>
            {(finding.days_exposed ?? 0) > 0 && (
              <span className="text-xs text-accent-orange font-mono">{finding.days_exposed}d exposed</span>
            )}
            {finding.first_commit_author && (
              <span className="text-xs text-fg-subtle font-mono truncate">{finding.first_commit_author}</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="hidden md:flex items-center gap-1.5">
            <div className="h-1.5 w-16 bg-border rounded-full overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${confidence}%`,
                  background: confidence > 80 ? '#f85149' : confidence > 60 ? '#f0883e' : '#e3b341'
                }}
              />
            </div>
            <span className="text-xs text-fg-muted font-mono">{confidence}%</span>
          </div>

          <div className={`severity-badge px-2 py-0.5 rounded border text-xs ${STATUS_STYLES[finding.status] || STATUS_STYLES.open}`}>
            {finding.status.replace('_', ' ')}
          </div>

          {expanded ? <ChevronUp className="w-4 h-4 text-fg-subtle" /> : <ChevronDown className="w-4 h-4 text-fg-subtle" />}
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="border-t border-border px-4 py-4 space-y-4 animate-slide-up">
          {/* Meta Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <MetaItem icon={<Shield className="w-3.5 h-3.5" />} label="Type" value={finding.secret_type.replace(/_/g, ' ')} />
            <MetaItem icon={<User className="w-3.5 h-3.5" />} label="First Author" value={finding.first_commit_author || '—'} />
            <MetaItem icon={<Calendar className="w-3.5 h-3.5" />} label="First Seen" value={finding.first_commit_date ? new Date(finding.first_commit_date).toLocaleDateString() : '—'} />
            <MetaItem icon={<GitCommit className="w-3.5 h-3.5" />} label="Commits" value={String(finding.total_commits || 0)} />
          </div>

          {/* Masked value */}
          <div className="bg-elevated rounded-md p-3 font-mono text-sm">
            <span className="text-fg-muted text-xs block mb-1">Detected value (masked)</span>
            <span className="text-accent-red">{finding.masked_value || '****'}</span>
          </div>

          {/* AI Reasoning */}
          {finding.ai_reasoning && (
            <div className="bg-elevated rounded-md p-3">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs font-mono text-fg-muted">AI Analysis</span>
                {finding.ai_model && <span className="text-xs bg-border px-2 py-0.5 rounded font-mono text-fg-subtle">{finding.ai_model}</span>}
              </div>
              <p className="text-sm text-fg-muted leading-relaxed">{finding.ai_reasoning}</p>
            </div>
          )}

          {/* Vault & MR */}
          {(finding.vault_path || finding.mr_url) && (
            <div className="flex gap-3 flex-wrap">
              {finding.vault_path && (
                <div className="flex items-center gap-2 bg-elevated px-3 py-2 rounded-md text-xs font-mono">
                  <div className={`w-2 h-2 rounded-full ${finding.vault_poisoned ? 'bg-accent-green' : 'bg-fg-subtle'}`} />
                  <span className="text-fg-muted">Vault:</span>
                  <span className="text-accent-blue">{finding.vault_path}</span>
                </div>
              )}
              {finding.mr_url && (
                <a href={finding.mr_url} target="_blank" rel="noreferrer"
                  className="flex items-center gap-2 bg-elevated px-3 py-2 rounded-md text-xs font-mono text-accent-blue hover:text-blue-400 transition-colors">
                  View Merge Request →
                </a>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2 flex-wrap pt-2">
            {finding.status !== 'confirmed' && finding.status !== 'closed' && (
              <button
                onClick={() => onStatusUpdate(finding.id, 'confirmed')}
                disabled={isUpdating}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-accent-orange/10 text-accent-orange border border-accent-orange/30 rounded-md text-xs font-mono hover:bg-accent-orange/20 transition-colors disabled:opacity-50"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                Mark Confirmed
              </button>
            )}
            {finding.status === 'confirmed' && finding.remediation_status === 'none' && (
              <button
                onClick={() => onRemediate(finding.id)}
                disabled={isRemediating}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-accent-blue/10 text-accent-blue border border-accent-blue/30 rounded-md text-xs font-mono hover:bg-accent-blue/20 transition-colors disabled:opacity-50"
              >
                <Zap className="w-3.5 h-3.5" />
                {isRemediating ? 'Starting...' : 'Start Remediation'}
              </button>
            )}
            {finding.status !== 'false_positive' && finding.status !== 'closed' && (
              <button
                onClick={() => onStatusUpdate(finding.id, 'false_positive')}
                disabled={isUpdating}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-border text-fg-muted rounded-md text-xs font-mono hover:text-fg transition-colors disabled:opacity-50"
              >
                <XCircle className="w-3.5 h-3.5" />
                False Positive
              </button>
            )}
            {finding.status !== 'ignored' && finding.status !== 'closed' && (
              <button
                onClick={() => onStatusUpdate(finding.id, 'ignored')}
                disabled={isUpdating}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-border text-fg-subtle rounded-md text-xs font-mono hover:text-fg-muted transition-colors disabled:opacity-50"
              >
                <EyeOff className="w-3.5 h-3.5" />
                Ignore
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function MetaItem({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="bg-elevated rounded-md p-2.5">
      <div className="flex items-center gap-1.5 mb-1 text-fg-subtle">
        {icon}
        <span className="text-xs">{label}</span>
      </div>
      <p className="text-xs text-fg font-mono truncate">{value}</p>
    </div>
  )
}
