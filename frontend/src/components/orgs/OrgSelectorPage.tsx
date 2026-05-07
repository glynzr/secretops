'use client'
import { useState } from 'react'
import { FiShield, FiPlus, FiArrowRight, FiLoader, FiX } from 'react-icons/fi'
import { api, Organization } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

function orgColor(name: string) {
  const palette = ['#5B8FF9', '#E8637B', '#F4A34A', '#5AD8A6', '#9B6FDA', '#F7665E', '#6DC8EC', '#C2A4F0']
  let hash = 0
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash)
  return palette[Math.abs(hash) % palette.length]
}

function orgInitials(name: string) {
  return name.split(/\s+/).slice(0, 2).map(w => w[0]).join('').toUpperCase() || '?'
}

function OrgAvatar({ name, size = 40 }: { name: string; size?: number }) {
  return (
    <div style={{
      width: size, height: size, borderRadius: '50%', flexShrink: 0,
      background: orgColor(name),
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: size * 0.38, fontWeight: 700, color: '#fff',
    }}>
      {orgInitials(name)}
    </div>
  )
}

interface Props {
  orgs: Organization[]
  onSelect: (id: string) => void
  onCreate: (org: Organization) => void
  onCancel?: () => void
}

export default function OrgSelectorPage({ orgs, onSelect, onCreate, onCancel }: Props) {
  const [name, setName]         = useState('')
  const [creating, setCreating] = useState(false)
  const [showCreate, setShowCreate] = useState(orgs.length === 0)
  const [error, setError]       = useState('')

  const create = async () => {
    const n = name.trim()
    if (!n) return
    setCreating(true); setError('')
    try {
      const org = await api.createOrg(n)
      onCreate(org)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setCreating(false)
    }
  }

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      minHeight: '100vh', background: 'var(--bg)', padding: 24,
    }}>
      {/* Cancel button */}
      {onCancel && (
        <button
          onClick={onCancel}
          style={{
            position: 'fixed', top: 20, right: 20,
            background: 'var(--card)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '6px 12px', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 6,
            fontSize: 13, color: 'var(--muted)',
          }}
        >
          <FiX size={13} /> Cancel
        </button>
      )}

      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 40 }}>
        <div style={{ width: 36, height: 36, borderRadius: 8, background: 'var(--blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <FiShield size={18} color="white" />
        </div>
        <span style={{ fontSize: 20, fontWeight: 700, letterSpacing: '-0.02em' }}>SecretOps</span>
      </div>

      <div style={{ width: '100%', maxWidth: 440 }}>
        {orgs.length === 0 || showCreate ? (
          /* Create org form */
          <>
            <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 8, textAlign: 'center' }}>
              {orgs.length === 0 ? 'Create your organization' : 'Create new organization'}
            </h1>
            <p style={{ fontSize: 14, color: 'var(--muted)', textAlign: 'center', marginBottom: 32, lineHeight: 1.6 }}>
              Organizations hold your integrations, projects, findings, and team settings.
            </p>

            <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 10, padding: 24 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--muted)', marginBottom: 6 }}>
                Organization name
              </label>
              <Input
                value={name}
                onChange={e => setName(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && create()}
                placeholder="e.g. Acme Corp Security"
                autoFocus
                style={{ marginBottom: 16 }}
              />
              {error && <div style={{ fontSize: 12, color: 'var(--red)', marginBottom: 12 }}>{error}</div>}
              <Button onClick={create} disabled={!name.trim() || creating} style={{ width: '100%' }}>
                {creating ? <><FiLoader size={13} className="spin" /> Creating...</> : <>Create organization <FiArrowRight size={13} /></>}
              </Button>
              {orgs.length > 0 && (
                <button
                  onClick={() => setShowCreate(false)}
                  style={{ width: '100%', marginTop: 10, background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, color: 'var(--muted)' }}
                >
                  ← Back to organizations
                </button>
              )}
            </div>
          </>
        ) : (
          /* Org list */
          <>
            <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 6, textAlign: 'center' }}>Switch organization</h1>
            <p style={{ fontSize: 13, color: 'var(--muted)', textAlign: 'center', marginBottom: 24 }}>
              Select an organization to continue
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
              {orgs.map(org => (
                <button
                  key={org.id}
                  onClick={() => onSelect(org.id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 14,
                    padding: '14px 18px', background: 'var(--card)',
                    border: '1px solid var(--border)', borderRadius: 10,
                    cursor: 'pointer', textAlign: 'left', width: '100%',
                    transition: 'border-color 0.15s, box-shadow 0.15s',
                  }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = 'var(--blue)'; (e.currentTarget as HTMLElement).style.boxShadow = '0 0 0 3px rgba(47,129,247,0.12)' }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'; (e.currentTarget as HTMLElement).style.boxShadow = 'none' }}
                >
                  <OrgAvatar name={org.name} size={40} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 2 }}>{org.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--faint)', fontFamily: 'monospace' }}>{org.slug}</div>
                  </div>
                  <FiArrowRight size={16} style={{ color: 'var(--faint)', flexShrink: 0 }} />
                </button>
              ))}
            </div>

            <button
              onClick={() => setShowCreate(true)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7,
                padding: '11px', background: 'transparent',
                border: '1px dashed var(--border)', borderRadius: 10,
                cursor: 'pointer', fontSize: 13, color: 'var(--blue)', fontWeight: 500,
              }}
              onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--hover)'}
              onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
            >
              <FiPlus size={14} /> Create new Organization
            </button>
          </>
        )}
      </div>
    </div>
  )
}
