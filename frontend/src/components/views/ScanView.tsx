'use client'
import { useEffect, useState, useRef } from 'react'
import { CheckCircle, AlertCircle, Loader, FileSearch, GitBranch, Brain, Shield, ArrowRight } from 'lucide-react'
import { api } from '@/lib/api'
import type { Scan } from '@/types'
import type { View } from '@/app/page'

const STAGES = [
  { key: 'cloning',   label: 'Cloning Repository',  icon: GitBranch,  desc: 'Fetching repository via authenticated Git clone' },
  { key: 'indexing',  label: 'Indexing Files',       icon: FileSearch, desc: 'Building file list, filtering binary/vendor files' },
  { key: 'scanning',  label: 'Regex Pre-filter',     icon: Shield,     desc: 'Stage 1: Pattern matching with high-specificity provider patterns' },
  { key: 'completed', label: 'Scan Complete',        icon: CheckCircle,desc: 'All findings saved to database' },
]

export default function ScanView({ scanId, onNavigate }: {
  scanId: number | null
  onNavigate: (v: View) => void
}) {
  const [scan, setScan]   = useState<Scan | null>(null)
  const [logs, setLogs]   = useState<string[]>([])
  const logsEndRef        = useRef<HTMLDivElement>(null)
  const pollRef           = useRef<ReturnType<typeof setInterval> | null>(null)
  const esRef             = useRef<EventSource | null>(null)

  const addLog = (msg: string) =>
    setLogs(prev => [...prev.slice(-200), `[${new Date().toLocaleTimeString()}] ${msg}`])

  const stopAll = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
    if (esRef.current)   { esRef.current.close();          esRef.current   = null }
  }

  useEffect(() => {
    if (!scanId) return
    stopAll()

    // 1. Immediate fetch so UI shows something right away
    api.getScan(scanId).then(s => {
      setScan(s)
      if (s.status === 'completed' || s.status === 'failed') {
        addLog(`Scan already ${s.status}: ${s.findings_count} findings in ${s.total_files} files`)
        return
      }
      startStreaming(scanId)
    }).catch(() => startStreaming(scanId))

    return () => stopAll()
  }, [scanId])

  const startStreaming = (id: number) => {
    // SSE for live updates
    const es = new EventSource(`/api/v1/scans/${id}/stream`)
    esRef.current = es
    es.onmessage = (e) => {
      try {
        const data: Scan = JSON.parse(e.data)
        setScan(data)
        addLog(`Stage: ${data.stage} | ${data.scanned_files}/${data.total_files} files | ${data.findings_count} findings`)
        if (data.status === 'completed' || data.status === 'failed') {
          stopAll()
        }
      } catch {}
    }
    // SSE error = stream closed (scan done too fast) → fall back to polling
    es.onerror = () => {
      es.close()
      esRef.current = null
      startPolling(id)
    }

    // Also poll every 2s as a safety net in case SSE misses the final event
    startPolling(id)
  }

  const startPolling = (id: number) => {
    if (pollRef.current) return // already polling
    pollRef.current = setInterval(async () => {
      try {
        const s = await api.getScan(id)
        setScan(s)
        if (s.status === 'completed' || s.status === 'failed') {
          addLog(`✓ Scan ${s.status}: ${s.findings_count} findings in ${s.total_files} files`)
          stopAll()
        }
      } catch {}
    }, 2000)
  }

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const currentStageIdx = scan
    ? scan.status === 'completed' || scan.status === 'failed'
      ? STAGES.length - 1
      : STAGES.findIndex(s => scan.stage?.startsWith(s.key))
    : -1

  const progress = scan && scan.total_files > 0
    ? Math.round((scan.scanned_files / scan.total_files) * 100)
    : scan?.status === 'completed' ? 100 : 0

  if (!scanId) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-muted p-8 gap-4">
        <Shield className="w-16 h-16 opacity-20" />
        <p className="font-mono text-sm">No active scan</p>
        <button onClick={() => onNavigate('repositories')}
          className="text-blue-400 hover:text-blue-300 text-sm font-mono">
          → Start a scan from Repositories
        </button>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-5 overflow-y-auto h-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Live Scanner</h1>
          <p className="text-sm text-muted font-mono mt-0.5">Scan #{scanId}</p>
        </div>
        {(scan?.status === 'completed' || scan?.status === 'failed') && (
          <button onClick={() => onNavigate('findings')}
            className="flex items-center gap-2 px-4 py-2 bg-green-500/10 text-green-400 border border-green-500/30 rounded-lg text-sm font-mono hover:bg-green-500/20 transition-colors">
            View {scan.findings_count} Findings <ArrowRight className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Status bar */}
      {scan && (
        <div className="bg-surface border border-border rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {scan.status === 'running'   && <div className="w-2.5 h-2.5 rounded-full bg-blue-400 animate-pulse" />}
              {scan.status === 'completed' && <div className="w-2.5 h-2.5 rounded-full bg-green-400" />}
              {scan.status === 'failed'    && <div className="w-2.5 h-2.5 rounded-full bg-red-400" />}
              <span className="text-sm font-mono text-white capitalize">{scan.status}</span>
              <span className="text-xs text-muted font-mono">— {scan.stage}</span>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono text-muted">
              <span>{scan.scanned_files}/{scan.total_files} files</span>
              <span className="text-orange-400">{scan.findings_count} findings</span>
              <span>{progress}%</span>
            </div>
          </div>
          <div className="h-1.5 bg-elevated rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${progress}%`,
                background: scan.status === 'failed'
                  ? '#f85149'
                  : scan.status === 'completed'
                  ? '#3fb950'
                  : 'linear-gradient(90deg,#388bfd,#a371f7)'
              }} />
          </div>
          {scan.error_message && (
            <p className="text-xs text-red-400 font-mono">{scan.error_message}</p>
          )}
        </div>
      )}

      {/* Stage pipeline */}
      <div className="bg-surface border border-border rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-4 font-mono">Detection Pipeline</h3>
        <div className="space-y-2">
          {STAGES.map((stage, i) => {
            const isDone    = scan?.status === 'completed' || i < currentStageIdx
            const isCurrent = i === currentStageIdx && scan?.status === 'running'
            const Icon      = stage.icon
            return (
              <div key={stage.key}
                className={`flex items-center gap-4 p-3 rounded-lg transition-all ${isCurrent ? 'bg-blue-500/10 border border-blue-500/30' : 'bg-elevated/40'}`}>
                <div className={`w-7 h-7 rounded-full flex items-center justify-center shrink-0 ${
                  isDone ? 'bg-green-500/20' : isCurrent ? 'bg-blue-500/20' : 'bg-border'}`}>
                  {isDone
                    ? <CheckCircle className="w-4 h-4 text-green-400" />
                    : isCurrent
                    ? <Loader className="w-4 h-4 text-blue-400 animate-spin" />
                    : <Icon className="w-4 h-4 text-muted" />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-mono ${isDone ? 'text-green-400' : isCurrent ? 'text-white' : 'text-muted'}`}>
                    {stage.label}
                  </p>
                  <p className="text-xs text-muted truncate">{stage.desc}</p>
                </div>
                {isCurrent && <span className="text-xs font-mono text-blue-400 animate-pulse shrink-0">running</span>}
                {isDone     && <span className="text-xs font-mono text-green-400 shrink-0">✓</span>}
              </div>
            )
          })}
        </div>
      </div>

      {/* Log output */}
      <div className="bg-surface border border-border rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-3 font-mono">Output</h3>
        <div className="bg-canvas rounded-lg p-3 h-48 overflow-y-auto font-mono text-xs space-y-0.5">
          {logs.length === 0
            ? <span className="text-muted">{scan?.status === 'completed' ? '✓ Scan completed' : 'Connecting…'}</span>
            : logs.map((log, i) => <div key={i} className="text-green-400/80">{log}</div>)}
          <div ref={logsEndRef} />
        </div>
      </div>
    </div>
  )
}
