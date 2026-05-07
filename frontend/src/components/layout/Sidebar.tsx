'use client'
import { useState, useRef, useEffect } from 'react'
import {
  FiLink, FiFolder, FiSearch, FiTool, FiShield,
  FiGrid, FiRepeat, FiPlus, FiCheck, FiAlertCircle,
  FiUsers, FiSettings,
} from 'react-icons/fi'
import type { Page } from '@/app/page'
import type { Organization } from '@/lib/api'

const NAV: { id: Page; label: string; Icon: React.ComponentType<{ size?: number }> }[] = [
  { id: 'dashboard',    label: 'Dashboard',    Icon: FiGrid },
  { id: 'projects',     label: 'Projects',     Icon: FiFolder },
  { id: 'findings',     label: 'Findings',     Icon: FiAlertCircle },
  { id: 'remediation',  label: 'Remediation',  Icon: FiTool },
  { id: 'integrations', label: 'Integrations', Icon: FiLink },
]

// Generate a consistent color from org name
function orgColor(name: string) {
  const palette = ['#5B8FF9', '#E8637B', '#F4A34A', '#5AD8A6', '#9B6FDA', '#F7665E', '#6DC8EC', '#C2A4F0']
  let hash = 0
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash)
  return palette[Math.abs(hash) % palette.length]
}

function orgInitials(name: string) {
  return name.split(/\s+/).slice(0, 2).map(w => w[0]).join('').toUpperCase() || '?'
}

function OrgAvatar({ name, size = 32 }: { name: string; size?: number }) {
  return (
    <div style={{
      width: size, height: size, borderRadius: '50%', flexShrink: 0,
      background: orgColor(name),
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: size * 0.38, fontWeight: 700, color: '#fff', letterSpacing: '-0.01em',
    }}>
      {orgInitials(name)}
    </div>
  )
}

interface Props {
  active: Page
  onSelect: (p: Page) => void
  orgs: Organization[]
  currentOrgId: string
  onOrgSelect: (id: string) => void
  onCreateOrg: () => void
}

export default function Sidebar({ active, onSelect, orgs, currentOrgId, onOrgSelect, onCreateOrg }: Props) {
  const [dropOpen, setDropOpen]   = useState(false)
  const [searchQ, setSearchQ]     = useState('')
  const searchRef                 = useRef<HTMLInputElement>(null)
  const currentOrg                = orgs.find(o => o.id === currentOrgId)
  const filtered                  = orgs.filter(o => o.name.toLowerCase().includes(searchQ.toLowerCase()))

  useEffect(() => {
    if (dropOpen) setTimeout(() => searchRef.current?.focus(), 50)
    else setSearchQ('')
  }, [dropOpen])

  return (
    <aside style={{
      width: 220, minWidth: 220, height: '100vh',
      background: '#1a1d27',
      borderRight: '1px solid rgba(255,255,255,0.06)',
      display: 'flex', flexDirection: 'column',
      color: '#c9d1d9',
    }}>

      {/* Logo */}
      <div style={{ padding: '18px 16px 14px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: 'var(--blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <FiShield size={14} color="white" />
          </div>
          <span style={{ fontWeight: 700, fontSize: 15, color: '#fff', letterSpacing: '-0.02em' }}>SecretOps</span>
        </div>
      </div>

      {/* Org row */}
      <div style={{ padding: '12px 12px 6px', position: 'relative' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {currentOrg && <OrgAvatar name={currentOrg.name} size={34} />}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 10, color: '#636e7b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 1 }}>Organization</div>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#e6edf3', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {currentOrg?.name || '—'}
            </div>
          </div>
          <button
            title="Switch organization"
            onClick={() => setDropOpen(v => !v)}
            style={{
              width: 28, height: 28, borderRadius: 6, flexShrink: 0,
              background: dropOpen ? 'rgba(255,255,255,0.1)' : 'rgba(255,255,255,0.05)',
              border: '1px solid rgba(255,255,255,0.08)',
              cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: '#8b949e', transition: 'background 0.15s',
            }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.12)'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = dropOpen ? 'rgba(255,255,255,0.1)' : 'rgba(255,255,255,0.05)'}
          >
            <FiRepeat size={12} />
          </button>
        </div>

        {/* Org dropdown */}
        {dropOpen && (
          <>
            <div onClick={() => setDropOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 40 }} />
            <div style={{
              position: 'absolute', top: 'calc(100% + 6px)', left: 12, right: 12, zIndex: 50,
              background: '#fff', borderRadius: 10, overflow: 'hidden',
              boxShadow: '0 8px 32px rgba(0,0,0,0.45)', border: '1px solid #e1e4e8',
            }}>
              {/* Header */}
              <div style={{ padding: '10px 14px 6px', background: '#f6f8fa', borderBottom: '1px solid #e1e4e8' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#57606a', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 8 }}>
                  Choose an org
                </div>
                {/* Search */}
                <div style={{ position: 'relative' }}>
                  <FiSearch size={12} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: '#57606a' }} />
                  <input
                    ref={searchRef}
                    value={searchQ}
                    onChange={e => setSearchQ(e.target.value)}
                    placeholder="Search for an org"
                    style={{
                      width: '100%', boxSizing: 'border-box',
                      padding: '6px 8px 6px 28px', fontSize: 12,
                      border: '1.5px solid #0969da', borderRadius: 6,
                      background: '#fff', color: '#1f2328', outline: 'none',
                    }}
                  />
                </div>
              </div>

              {/* Org list */}
              <div style={{ maxHeight: 220, overflowY: 'auto' }}>
                {filtered.length === 0 && (
                  <div style={{ padding: '14px', fontSize: 12, color: '#57606a', textAlign: 'center' }}>No results</div>
                )}
                {filtered.map(org => (
                  <button
                    key={org.id}
                    onClick={() => { onOrgSelect(org.id); setDropOpen(false) }}
                    style={{
                      width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                      padding: '9px 14px', background: 'transparent', border: 'none',
                      cursor: 'pointer', textAlign: 'left',
                    }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#f6f8fa'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                  >
                    <OrgAvatar name={org.name} size={28} />
                    <span style={{ flex: 1, fontSize: 13, color: '#1f2328', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: org.id === currentOrgId ? 600 : 400 }}>
                      {org.name}
                    </span>
                    {org.id === currentOrgId && <FiCheck size={13} style={{ color: '#0969da', flexShrink: 0 }} />}
                  </button>
                ))}
              </div>

              {/* Create org */}
              <div style={{ borderTop: '1px solid #e1e4e8' }}>
                <button
                  onClick={() => { onCreateOrg(); setDropOpen(false) }}
                  style={{
                    width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                    padding: '10px 14px', background: 'transparent', border: 'none',
                    cursor: 'pointer', textAlign: 'left', fontSize: 13, color: '#0969da', fontWeight: 500,
                  }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#f6f8fa'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                >
                  <FiPlus size={14} /> Create new Organization
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 2 }}>
        {NAV.map(({ id, label, Icon }) => {
          const isActive = active === id
          return (
            <button
              key={id}
              onClick={() => onSelect(id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 9,
                padding: '8px 10px', borderRadius: 7, width: '100%',
                background: isActive ? 'rgba(88,130,255,0.18)' : 'transparent',
                color: isActive ? '#7c9ef8' : '#8b949e',
                border: 'none', cursor: 'pointer', textAlign: 'left',
                fontSize: 13, fontWeight: isActive ? 600 : 400,
                transition: 'background 0.1s, color 0.1s',
              }}
              onMouseEnter={e => { if (!isActive) { (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.05)'; (e.currentTarget as HTMLElement).style.color = '#c9d1d9' } }}
              onMouseLeave={e => { if (!isActive) { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = '#8b949e' } }}
            >
              <Icon size={15} />
              {label}
            </button>
          )
        })}

        {/* Placeholder nav items */}
        {[{ label: 'Members', Icon: FiUsers }, { label: 'Settings', Icon: FiSettings }].map(({ label, Icon }) => (
          <button
            key={label}
            style={{
              display: 'flex', alignItems: 'center', gap: 9,
              padding: '8px 10px', borderRadius: 7, width: '100%',
              background: 'transparent', color: '#636e7b',
              border: 'none', cursor: 'not-allowed', textAlign: 'left',
              fontSize: 13, fontWeight: 400, opacity: 0.6,
            }}
          >
            <Icon size={15} />
            {label}
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div style={{ padding: '10px 14px', borderTop: '1px solid rgba(255,255,255,0.06)', fontSize: 11, color: '#636e7b' }}>
        BHOS · InfoSec · 2026
      </div>
    </aside>
  )
}
