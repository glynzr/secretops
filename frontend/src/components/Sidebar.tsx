'use client'
import { Shield, Search, AlertTriangle, Settings, GitBranch, Zap, FileText, Activity } from 'lucide-react'
import type { View } from '@/app/page'

const navItems = [
  { id: 'dashboard',    icon: Activity,      label: 'Dashboard' },
  { id: 'repositories', icon: GitBranch,     label: 'Repositories' },
  { id: 'scan',         icon: Search,        label: 'Scanner' },
  { id: 'findings',     icon: AlertTriangle, label: 'Findings' },
  { id: 'remediation',  icon: Zap,           label: 'Remediation' },
  { id: 'integrations', icon: Settings,      label: 'Integrations' },
  { id: 'audit',        icon: FileText,      label: 'Audit Log' },
] as const

export default function Sidebar({ activeView, onNavigate }: {
  activeView: View
  onNavigate: (v: View) => void
}) {
  return (
    <aside className="w-16 lg:w-56 flex flex-col h-full border-r border-border bg-surface shrink-0">
      <div className="flex items-center gap-3 px-4 py-5 border-b border-border">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-accent-blue to-accent-purple flex items-center justify-center shrink-0">
          <Shield className="w-4 h-4 text-white" />
        </div>
        <div className="hidden lg:block">
          <p className="text-sm font-semibold text-fg font-mono">SecretOps</p>
          <p className="text-xs text-fg-muted">v1.0.0</p>
        </div>
      </div>

      <nav className="flex-1 py-4 space-y-1 px-2">
        {navItems.map(({ id, icon: Icon, label }) => {
          const active = activeView === id
          return (
            <button
              key={id}
              onClick={() => onNavigate(id as View)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-150 group
                ${active
                  ? 'bg-elevated text-fg border border-border-active/30 shadow-sm'
                  : 'text-fg-muted hover:bg-elevated hover:text-fg border border-transparent'
                }`}
            >
              <Icon className={`w-4 h-4 shrink-0 ${active ? 'text-accent-blue' : 'text-fg-subtle group-hover:text-fg-muted'}`} />
              <span className="hidden lg:block">{label}</span>
              {active && <div className="hidden lg:block ml-auto w-1.5 h-1.5 rounded-full bg-accent-blue" />}
            </button>
          )
        })}
      </nav>

      <div className="border-t border-border px-4 py-3 hidden lg:block">
        <p className="text-xs text-fg-subtle font-mono">Fallback-first design</p>
        <p className="text-xs text-fg-subtle">Provider-agnostic AI</p>
      </div>
    </aside>
  )
}
