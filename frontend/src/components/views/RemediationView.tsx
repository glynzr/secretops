'use client';

import { useState, useEffect } from 'react';
import {
  GitMerge, AlertTriangle, CheckCircle, Clock, ExternalLink,
  Loader2, RefreshCw, ChevronDown, ChevronRight, Shield,
  GitBranch, Bell, Mail, Key, RotateCcw, XCircle, Activity
} from 'lucide-react';
import { api } from '@/lib/api';
import { Finding } from '@/types';

const STAGE_META: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  git_history:     { label: 'Git History',      icon: <GitBranch className="w-4 h-4" />,   color: 'text-blue-400' },
  ai_patch:        { label: 'AI Patch Gen',     icon: <Activity className="w-4 h-4" />,    color: 'text-purple-400' },
  vault_inject:    { label: 'Vault Injection',  icon: <Shield className="w-4 h-4" />,      color: 'text-yellow-400' },
  branch_create:   { label: 'Branch & Commit',  icon: <GitBranch className="w-4 h-4" />,   color: 'text-cyan-400' },
  merge_request:   { label: 'Merge Request',    icon: <GitMerge className="w-4 h-4" />,    color: 'text-green-400' },
  notifications:   { label: 'Notifications',    icon: <Bell className="w-4 h-4" />,         color: 'text-orange-400' },
  revocation:      { label: 'Revocation',       icon: <Key className="w-4 h-4" />,          color: 'text-red-400' },
  verification:    { label: 'Verification',     icon: <RotateCcw className="w-4 h-4" />,   color: 'text-teal-400' },
};

function StageTimeline({ stages }: { stages: Record<string, string> }) {
  const keys = Object.keys(STAGE_META);
  return (
    <div className="space-y-2">
      {keys.map((key, idx) => {
        const meta = STAGE_META[key];
        const status = stages?.[key] || 'pending';
        return (
          <div key={key} className="flex items-center gap-3">
            <div className={`flex-shrink-0 w-8 h-8 rounded-full border flex items-center justify-center ${
              status === 'complete' ? 'border-green-500/50 bg-green-500/10 text-green-400' :
              status === 'running'  ? 'border-blue-500/50 bg-blue-500/10 text-blue-400' :
              status === 'failed'   ? 'border-red-500/50 bg-red-500/10 text-red-400' :
              'border-border bg-elevated text-muted'
            }`}>
              {status === 'running' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> :
               status === 'complete' ? <CheckCircle className="w-3.5 h-3.5" /> :
               status === 'failed'   ? <XCircle className="w-3.5 h-3.5" /> :
               <span className="text-xs font-mono">{idx + 1}</span>}
            </div>
            <div className="flex-1">
              <div className={`text-sm font-medium ${meta.color}`}>{meta.label}</div>
            </div>
            <div className={`text-xs px-2 py-0.5 rounded-full border ${
              status === 'complete' ? 'border-green-500/30 bg-green-500/10 text-green-400' :
              status === 'running'  ? 'border-blue-500/30 bg-blue-500/10 text-blue-400' :
              status === 'failed'   ? 'border-red-500/30 bg-red-500/10 text-red-400' :
              'border-border text-muted'
            }`}>
              {status}
            </div>
          </div>
        );
      })}
    </div>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 border-red-500/30 bg-red-500/10',
  high:     'text-orange-400 border-orange-500/30 bg-orange-500/10',
  medium:   'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
  low:      'text-blue-400 border-blue-500/30 bg-blue-500/10',
};

const STATUS_COLORS: Record<string, string> = {
  remediating:  'text-purple-400 border-purple-500/30 bg-purple-500/10',
  remediated:   'text-green-400 border-green-500/30 bg-green-500/10',
  verified:     'text-teal-400 border-teal-500/30 bg-teal-500/10',
  failed:       'text-red-400 border-red-500/30 bg-red-500/10',
};

function RemediationCard({ finding, jobs }: { finding: Finding; jobs: any[] }) {
  const [expanded, setExpanded] = useState(false);
  const job = jobs.find(j => j.finding_id === finding.id && j.job_type === 'remediation');
  const verifyJob = jobs.find(j => j.finding_id === finding.id && j.job_type === 'verification');

  const stages: Record<string, string> = {};
  if (job?.result) {
    try {
      const parsed = typeof job.result === 'string' ? JSON.parse(job.result) : job.result;
      Object.assign(stages, parsed.stages || {});
    } catch { }
  }

  const mr_url = job?.result ? (() => {
    try {
      const p = typeof job.result === 'string' ? JSON.parse(job.result) : job.result;
      return p.merge_request_url;
    } catch { return null; }
  })() : null;

  const vault_path = job?.result ? (() => {
    try {
      const p = typeof job.result === 'string' ? JSON.parse(job.result) : job.result;
      return p.vault_path;
    } catch { return null; }
  })() : null;

  return (
    <div className="bg-surface border border-border rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-4 p-4 hover:bg-elevated/30 transition-colors text-left"
      >
        <div className={`flex-shrink-0 p-2 rounded-lg border ${SEVERITY_COLORS[finding.severity] || 'text-muted border-border bg-elevated'}`}>
          <AlertTriangle className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-white">{finding.secret_type?.replace(/_/g, ' ')}</span>
            <span className={`text-xs px-2 py-0.5 rounded-full border ${SEVERITY_COLORS[finding.severity] || 'text-muted border-border'}`}>
              {finding.severity}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full border ${STATUS_COLORS[finding.status] || 'text-muted border-border'}`}>
              {finding.status?.replace(/_/g, ' ')}
            </span>
          </div>
          <div className="text-xs text-muted mt-0.5 font-mono truncate">{finding.file_path}:{finding.line_number}</div>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          {mr_url && (
            <a
              href={mr_url}
              target="_blank"
              rel="noopener noreferrer"
              onClick={e => e.stopPropagation()}
              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 border border-blue-500/30 px-2 py-1 rounded-lg"
            >
              <GitMerge className="w-3 h-3" /> MR
            </a>
          )}
          {expanded ? <ChevronDown className="w-4 h-4 text-muted" /> : <ChevronRight className="w-4 h-4 text-muted" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-border p-4 space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Pipeline stages */}
            <div>
              <div className="text-xs font-semibold text-muted uppercase tracking-wider mb-3">Remediation Pipeline</div>
              {Object.keys(stages).length > 0 ? (
                <StageTimeline stages={stages} />
              ) : (
                <div className="text-sm text-muted">No stage data available</div>
              )}
            </div>

            {/* Details */}
            <div className="space-y-3">
              <div className="text-xs font-semibold text-muted uppercase tracking-wider">Details</div>
              {vault_path && (
                <div>
                  <div className="text-xs text-muted mb-1">Vault Path</div>
                  <code className="text-xs text-yellow-400 bg-canvas border border-border rounded px-2 py-1 block font-mono">{vault_path}</code>
                </div>
              )}
              {mr_url && (
                <div>
                  <div className="text-xs text-muted mb-1">Merge Request</div>
                  <a href={mr_url} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 font-mono truncate">
                    <ExternalLink className="w-3 h-3 flex-shrink-0" />
                    {mr_url}
                  </a>
                </div>
              )}
              {finding.days_exposed !== undefined && (
                <div>
                  <div className="text-xs text-muted mb-1">Exposure Duration</div>
                  <div className={`text-sm font-medium ${(finding.days_exposed ?? 0) > 30 ? 'text-red-400' : (finding.days_exposed ?? 0) > 7 ? 'text-yellow-400' : 'text-green-400'}`}>
                    {finding.days_exposed} days
                  </div>
                </div>
              )}
              {finding.commit_author && (
                <div>
                  <div className="text-xs text-muted mb-1">First Author</div>
                  <div className="text-sm text-white">{finding.commit_author}</div>
                </div>
              )}
              {finding.commit_count !== undefined && (
                <div>
                  <div className="text-xs text-muted mb-1">Commit Appearances</div>
                  <div className="text-sm text-white">{finding.commit_count} commit{finding.commit_count !== 1 ? 's' : ''}</div>
                </div>
              )}
            </div>
          </div>

          {/* Verification job */}
          {verifyJob && (
            <div className="border-t border-border pt-4">
              <div className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Verification Status</div>
              <div className={`flex items-center gap-2 text-sm ${
                verifyJob.status === 'completed' ? 'text-green-400' :
                verifyJob.status === 'running' ? 'text-blue-400' :
                verifyJob.status === 'failed' ? 'text-red-400' : 'text-muted'
              }`}>
                {verifyJob.status === 'running' ? <Loader2 className="w-4 h-4 animate-spin" /> :
                 verifyJob.status === 'completed' ? <CheckCircle className="w-4 h-4" /> :
                 <Clock className="w-4 h-4" />}
                Rotation verification: {verifyJob.status}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function RemediationView() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [jobs, setJobs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'remediating' | 'remediated' | 'verified'>('all');

  const fetchData = async () => {
    setLoading(true);
    try {
      const [f, j] = await Promise.all([api.getFindings(), api.getJobs()]);
      const remediationFindings = f.filter((x: Finding) =>
        ['remediating', 'remediated', 'verified', 'closed'].includes(x.status || '')
      );
      setFindings(remediationFindings);
      setJobs(j);
    } catch { }
    setLoading(false);
  };

  useEffect(() => { fetchData(); }, []);

  const filtered = filter === 'all' ? findings : findings.filter(f => f.status === filter);

  const stats = {
    total: findings.length,
    remediating: findings.filter(f => f.status === 'remediating').length,
    remediated: findings.filter(f => f.status === 'remediated').length,
    verified: findings.filter(f => ['verified', 'closed'].includes(f.status || '')).length,
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white">Remediation</h1>
            <p className="text-sm text-muted mt-1">Track pipeline progress and rotation verification</p>
          </div>
          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 bg-elevated border border-border hover:border-blue-500/50 text-sm text-white rounded-lg transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total', value: stats.total, color: 'text-white' },
            { label: 'In Progress', value: stats.remediating, color: 'text-purple-400' },
            { label: 'Pending Verification', value: stats.remediated, color: 'text-yellow-400' },
            { label: 'Verified Closed', value: stats.verified, color: 'text-green-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-surface border border-border rounded-xl p-4 text-center">
              <div className={`text-2xl font-bold font-mono ${color}`}>{value}</div>
              <div className="text-xs text-muted mt-1">{label}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex gap-2">
          {(['all', 'remediating', 'remediated', 'verified'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 text-sm rounded-lg border transition-colors capitalize ${
                filter === f
                  ? 'border-blue-500/50 bg-blue-500/10 text-blue-400'
                  : 'border-border bg-elevated text-muted hover:text-white'
              }`}
            >
              {f}
            </button>
          ))}
        </div>

        {/* List */}
        {loading ? (
          <div className="flex items-center justify-center gap-3 text-muted py-20">
            <Loader2 className="w-5 h-5 animate-spin" /> Loading remediation data…
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-20 text-muted">
            <GitMerge className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <div className="text-sm">No remediation pipelines found</div>
            <div className="text-xs mt-1">Confirm findings from the Findings view to start remediation</div>
          </div>
        ) : (
          <div className="space-y-3">
            {filtered.map(f => (
              <RemediationCard key={f.id} finding={f} jobs={jobs} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
