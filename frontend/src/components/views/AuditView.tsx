'use client';

import { useState, useEffect } from 'react';
import { ScrollText, RefreshCw, Loader2, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { api } from '@/lib/api';

const ACTION_COLORS: Record<string, string> = {
  scan_started:        'text-blue-400 border-blue-500/30 bg-blue-500/10',
  scan_completed:      'text-green-400 border-green-500/30 bg-green-500/10',
  finding_confirmed:   'text-orange-400 border-orange-500/30 bg-orange-500/10',
  finding_false_pos:   'text-muted border-border bg-elevated',
  finding_ignored:     'text-muted border-border bg-elevated',
  remediation_started: 'text-purple-400 border-purple-500/30 bg-purple-500/10',
  remediation_done:    'text-teal-400 border-teal-500/30 bg-teal-500/10',
  rotation_verified:   'text-green-400 border-green-500/30 bg-green-500/10',
  rotation_pending:    'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
  integration_saved:   'text-cyan-400 border-cyan-500/30 bg-cyan-500/10',
};

function timeAgo(ts: string): string {
  const ms = Date.now() - new Date(ts).getTime();
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function AuditView() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await api.getAuditLogs();
      setLogs(data);
    } catch { }
    setLoading(false);
  };

  useEffect(() => { fetchLogs(); }, []);

  const filtered = logs.filter(l =>
    !search ||
    l.action?.toLowerCase().includes(search.toLowerCase()) ||
    l.entity_type?.toLowerCase().includes(search.toLowerCase()) ||
    l.details?.toLowerCase().includes(search.toLowerCase()) ||
    l.user_id?.toLowerCase().includes(search.toLowerCase())
  );

  const paginated = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-6 space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white">Audit Log</h1>
            <p className="text-sm text-muted mt-1">Complete activity history for compliance and forensics</p>
          </div>
          <button
            onClick={fetchLogs}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 bg-elevated border border-border hover:border-blue-500/50 text-sm text-white rounded-lg transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0); }}
            placeholder="Search actions, entities, details…"
            className="w-full bg-surface border border-border rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-muted/50 focus:outline-none focus:border-blue-500/60"
          />
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-4 text-xs text-muted">
          <span>{filtered.length} entries</span>
          {search && <span className="text-blue-400">filtered from {logs.length} total</span>}
        </div>

        {/* Table */}
        {loading ? (
          <div className="flex items-center justify-center gap-3 text-muted py-20">
            <Loader2 className="w-5 h-5 animate-spin" /> Loading audit logs…
          </div>
        ) : paginated.length === 0 ? (
          <div className="text-center py-20 text-muted">
            <ScrollText className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <div className="text-sm">No audit entries found</div>
          </div>
        ) : (
          <div className="bg-surface border border-border rounded-xl overflow-hidden">
            <div className="grid grid-cols-[auto_1fr_auto_auto] text-xs text-muted font-medium uppercase tracking-wider px-4 py-2.5 border-b border-border bg-elevated/50">
              <div className="w-32">Action</div>
              <div className="px-4">Details</div>
              <div className="w-28 text-right">Entity</div>
              <div className="w-24 text-right pl-4">Time</div>
            </div>
            <div className="divide-y divide-border">
              {paginated.map((log, idx) => {
                const colorCls = ACTION_COLORS[log.action] || 'text-muted border-border bg-elevated';
                let details = log.details;
                try { details = JSON.stringify(JSON.parse(log.details), null, 0); } catch { }

                return (
                  <div key={idx} className="grid grid-cols-[auto_1fr_auto_auto] items-start px-4 py-3 hover:bg-elevated/30 transition-colors group">
                    <div className="w-32">
                      <span className={`text-xs px-2 py-0.5 rounded-full border inline-block ${colorCls}`}>
                        {log.action?.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <div className="px-4 min-w-0">
                      <div className="text-xs text-white/80 font-mono truncate max-w-md" title={details}>
                        {details || '—'}
                      </div>
                      {log.user_id && (
                        <div className="text-xs text-muted mt-0.5">by {log.user_id}</div>
                      )}
                    </div>
                    <div className="w-28 text-right">
                      {log.entity_type && (
                        <span className="text-xs text-muted bg-elevated border border-border rounded px-1.5 py-0.5">
                          {log.entity_type} {log.entity_id ? `#${log.entity_id}` : ''}
                        </span>
                      )}
                    </div>
                    <div className="w-24 text-right pl-4 text-xs text-muted whitespace-nowrap" title={log.created_at}>
                      {timeAgo(log.created_at)}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-muted hover:text-white disabled:opacity-30 border border-border rounded-lg"
            >
              <ChevronLeft className="w-4 h-4" /> Prev
            </button>
            <span className="text-xs text-muted">Page {page + 1} of {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page === totalPages - 1}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-muted hover:text-white disabled:opacity-30 border border-border rounded-lg"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
