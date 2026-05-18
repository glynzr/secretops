'use client'
import { useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle, XCircle, Clock, Shield, TrendingUp, Search, Zap } from 'lucide-react'
import { api } from '@/lib/api'
import type { Stats } from '@/types'
import type { View } from '@/app/page'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

const SEV_COLORS = { critical: '#f85149', high: '#f0883e', medium: '#e3b341', low: '#3fb950' }

export default function Dashboard({ onStartScan, onNavigate }: {
  onStartScan: (id: number) => void
  onNavigate: (v: View) => void
}) {
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const data = await api.getStats()
        setStats(data)
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    load()
    const interval = setInterval(load, 15000)
    return () => clearInterval(interval)
  }, [])

  const sevData = stats ? Object.entries(stats.type_breakdown).map(([k, v]) => ({
    name: k.charAt(0).toUpperCase() + k.slice(1),
    value: v,
    color: SEV_COLORS[k as keyof typeof SEV_COLORS] || '#8b949e'
  })) : []

  const typeData = stats ? Object.entries(stats.type_breakdown)
    .slice(0, 8)
    .map(([k, v]) => ({ name: k.replace(/_/g, ' '), count: v })) : []

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex items-center gap-3 text-fg-muted">
          <div className="w-4 h-4 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
          <span className="font-mono text-sm">Loading dashboard...</span>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-fg">Security Dashboard</h1>
          <p className="text-sm text-fg-muted mt-0.5">Real-time secrets detection overview</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => onNavigate('repositories')}
            className="flex items-center gap-2 px-4 py-2 bg-accent-blue hover:bg-blue-500 text-white rounded-md text-sm font-medium transition-colors"
          >
            <Search className="w-4 h-4" />
            New Scan
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Findings"
          value={stats?.total_findings ?? 0}
          icon={<AlertTriangle className="w-5 h-5 text-accent-orange" />}
          trend={stats?.open_findings ? `${stats.open_findings} open` : undefined}
          trendColor="text-accent-orange"
        />
        <StatCard
          label="Critical/High"
          value={(stats?.type_breakdown?.critical ?? 0) + (stats?.type_breakdown?.high ?? 0)}
          icon={<Shield className="w-5 h-5 text-accent-red" />}
          trend="Requires attention"
          trendColor="text-accent-red"
        />
        <StatCard
          label="Remediated"
          value={stats?.closed_findings ?? 0}
          icon={<CheckCircle className="w-5 h-5 text-accent-green" />}
          trend={`${stats?.false_positive_findings ?? 0} false positives`}
          trendColor="text-fg-muted"
        />
        <StatCard
          label="Avg. Days Exposed"
          value={Math.round(stats?.avg_days_exposed ?? 0)}
          icon={<Clock className="w-5 h-5 text-accent-yellow" />}
          trend={`${stats?.total_repositories ?? 0} repos scanned`}
          trendColor="text-fg-muted"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Severity Pie */}
        <div className="bg-surface border border-border rounded-lg p-5">
          <h3 className="text-sm font-semibold text-fg mb-4 font-mono">Severity Distribution</h3>
          {sevData.length > 0 ? (
            <div className="flex items-center gap-6">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie data={sevData} cx="50%" cy="50%" innerRadius={40} outerRadius={65}
                    dataKey="value" stroke="none">
                    {sevData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2">
                {sevData.map((item) => (
                  <div key={item.name} className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full shrink-0" style={{ background: item.color }} />
                    <span className="text-xs text-fg-muted font-mono">{item.name}</span>
                    <span className="text-xs text-fg font-semibold ml-auto pl-4">{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <EmptyChart label="No findings yet" />
          )}
        </div>

        {/* Type Breakdown */}
        <div className="bg-surface border border-border rounded-lg p-5">
          <h3 className="text-sm font-semibold text-fg mb-4 font-mono">Secret Types Detected</h3>
          {typeData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={typeData} layout="vertical" margin={{ left: 0, right: 20 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" width={120} tick={{ fill: '#8b949e', fontSize: 11, fontFamily: 'JetBrains Mono' }} />
                <Tooltip
                  contentStyle={{ background: '#181c22', border: '1px solid #21262d', borderRadius: '6px', color: '#e6edf3', fontSize: '12px' }}
                  cursor={{ fill: 'rgba(56,139,253,0.1)' }}
                />
                <Bar dataKey="count" fill="#388bfd" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyChart label="No data yet" />
          )}
        </div>
      </div>

      {/* Status Overview */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-semibold text-fg mb-4 font-mono">Finding Status Pipeline</h3>
        <div className="flex gap-2 flex-wrap">
          {[
            { label: 'Open', count: stats?.open_findings ?? 0, color: 'bg-accent-blue/20 text-accent-blue border-accent-blue/30' },
            { label: 'Confirmed', count: stats?.confirmed_findings ?? 0, color: 'bg-accent-orange/20 text-accent-orange border-accent-orange/30' },
            { label: 'Closed', count: stats?.closed_findings ?? 0, color: 'bg-accent-green/20 text-accent-green border-accent-green/30' },
            { label: 'False Positive', count: stats?.false_positive_findings ?? 0, color: 'bg-fg-subtle/20 text-fg-muted border-fg-subtle/30' },
          ].map(({ label, count, color }) => (
            <div key={label} className={`flex items-center gap-3 px-4 py-2.5 rounded-md border ${color}`}>
              <span className="text-xs font-mono">{label}</span>
              <span className="text-lg font-bold font-mono">{count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <QuickAction
          icon={<Search className="w-5 h-5 text-accent-blue" />}
          title="Start Scan"
          description="Scan a GitLab repository for secrets"
          onClick={() => onNavigate('repositories')}
        />
        <QuickAction
          icon={<Zap className="w-5 h-5 text-accent-orange" />}
          title="Review Findings"
          description="Triage and confirm detected secrets"
          onClick={() => onNavigate('findings')}
        />
        <QuickAction
          icon={<TrendingUp className="w-5 h-5 text-accent-purple" />}
          title="Configure Integrations"
          description="Connect AI providers, GitLab, Vault, Slack"
          onClick={() => onNavigate('integrations')}
        />
      </div>
    </div>
  )
}

function StatCard({ label, value, icon, trend, trendColor }: {
  label: string; value: number; icon: React.ReactNode; trend?: string; trendColor?: string
}) {
  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs text-fg-muted font-medium">{label}</span>
        {icon}
      </div>
      <p className="text-3xl font-bold text-fg font-mono">{value.toLocaleString()}</p>
      {trend && <p className={`text-xs mt-1 ${trendColor}`}>{trend}</p>}
    </div>
  )
}

function QuickAction({ icon, title, description, onClick }: {
  icon: React.ReactNode; title: string; description: string; onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="bg-surface border border-border rounded-lg p-5 text-left hover:border-border-active/50 hover:bg-elevated transition-all duration-150 group"
    >
      <div className="w-9 h-9 rounded-md bg-elevated flex items-center justify-center mb-3 group-hover:bg-border transition-colors">
        {icon}
      </div>
      <p className="text-sm font-semibold text-fg mb-1">{title}</p>
      <p className="text-xs text-fg-muted">{description}</p>
    </button>
  )
}

function EmptyChart({ label }: { label: string }) {
  return (
    <div className="h-32 flex items-center justify-center text-fg-subtle text-sm font-mono">
      {label}
    </div>
  )
}

export { Dashboard }
