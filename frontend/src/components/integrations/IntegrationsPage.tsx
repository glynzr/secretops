'use client'
import { useEffect, useRef, useState } from 'react'
import {
  FiGitlab, FiShield, FiBell, FiMail, FiCpu,
  FiEye, FiEyeOff, FiChevronDown, FiChevronUp,
  FiExternalLink, FiCheck, FiX, FiArrowRight, FiLoader,
  FiPlus, FiTrash2, FiZap,
} from 'react-icons/fi'
import { orgApi, Connection } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'

// ── AI provider definitions ───────────────────────────────────────────────────

const AI_PROVIDERS = [
  {
    type: 'claude', label: 'Claude AI', vendor: 'Anthropic',
    logo: '🤖',
    fields: [
      { key: 'api_key',   label: 'API Key',                   placeholder: 'sk-ant-api03-...', secret: true },
      { key: 'api_key_2', label: 'Backup Key (optional)',      placeholder: 'sk-ant-api03-...', secret: true, hint: 'Used when primary hits rate limits' },
    ],
    docsUrl: 'https://console.anthropic.com',
  },
  {
    type: 'openai', label: 'OpenAI', vendor: 'OpenAI',
    logo: '⚡',
    fields: [
      { key: 'api_key', label: 'API Key', placeholder: 'sk-...', secret: true },
    ],
    docsUrl: 'https://platform.openai.com/api-keys',
  },
  {
    type: 'deepseek', label: 'DeepSeek', vendor: 'DeepSeek AI',
    logo: '🔍',
    fields: [
      { key: 'api_key', label: 'API Key', placeholder: 'sk-...', secret: true },
    ],
    docsUrl: 'https://platform.deepseek.com',
  },
  {
    type: 'gemini', label: 'Gemini', vendor: 'Google',
    logo: '✨',
    fields: [
      { key: 'api_key', label: 'API Key', placeholder: 'AIza...', secret: true },
    ],
    docsUrl: 'https://aistudio.google.com/app/apikey',
  },
  {
    type: 'ollama', label: 'Ollama', vendor: 'Local',
    logo: '🦙',
    fields: [
      { key: 'base_url', label: 'Base URL', placeholder: 'http://localhost:11434' },
      { key: 'model',    label: 'Model',    placeholder: 'llama3.1:8b' },
    ],
    docsUrl: 'https://ollama.ai',
  },
]

// ── Other integrations ────────────────────────────────────────────────────────

const OTHER_INTEGRATIONS = [
  {
    type: 'gitlab', name: 'GitLab', Icon: FiGitlab, required: true,
    desc: 'Import repositories, create MRs and issues',
    docsUrl: 'https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html',
    fields: [
      { key: 'url',   label: 'Instance URL',          placeholder: 'https://gitlab.com' },
      { key: 'token', label: 'Personal Access Token', placeholder: 'glpat-...', secret: true, hint: 'read_api, read_repository, write_repository' },
    ],
  },
  {
    type: 'vault', name: 'HashiCorp Vault', Icon: FiShield, required: false,
    desc: 'Inject poison placeholders to force runtime failures',
    docsUrl: 'https://developer.hashicorp.com/vault',
    fields: [
      { key: 'addr',  label: 'Address', placeholder: 'http://localhost:8200' },
      { key: 'token', label: 'Token',   placeholder: 'hvs...', secret: true, hint: 'KV-v2 write access on secretops/ path' },
    ],
  },
  {
    type: 'slack', name: 'Slack', Icon: FiBell, required: false,
    desc: 'Send security alerts to a channel',
    docsUrl: 'https://api.slack.com/messaging/webhooks',
    fields: [
      { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/...', secret: true },
    ],
  },
  {
    type: 'email', name: 'Email (SMTP)', Icon: FiMail, required: false,
    desc: 'Email notifications to your security team',
    fields: [
      { key: 'smtp_host',     label: 'Host',       placeholder: 'smtp.gmail.com' },
      { key: 'smtp_port',     label: 'Port',       placeholder: '587' },
      { key: 'smtp_user',     label: 'Username',   placeholder: 'security@company.com' },
      { key: 'smtp_password', label: 'Password',   placeholder: '···', secret: true },
      { key: 'recipients',    label: 'Recipients', placeholder: 'security@company.com', hint: 'Comma-separated' },
    ],
  },
]

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusDot({ connected }: { connected: boolean }) {
  return <span style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', flexShrink: 0, background: connected ? 'var(--green)' : 'var(--faint)' }} />
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 10, marginTop: 4 }}>
      {children}
    </div>
  )
}

// ── Add AI Connector Modal ────────────────────────────────────────────────────

function AddAIConnectorModal({ onDone, orgId }: { onDone: () => void; orgId: string }) {
  const oApi = orgApi(orgId)
  const [selectedType, setSelectedType] = useState<string | null>(null)
  const [form, setForm]   = useState<Record<string, string>>({})
  const [reveal, setReveal] = useState<Record<string, boolean>>({})
  const [saving, setSaving] = useState(false)
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null)

  const provider = AI_PROVIDERS.find(p => p.type === selectedType)

  const save = async () => {
    if (!selectedType) return
    setSaving(true); setResult(null)
    try {
      await oApi.saveConnection(selectedType, form)
      const r = await oApi.testConnection(selectedType)
      setResult({ ok: r.connected, msg: r.error || (r.connected ? 'Connected successfully' : 'Connection failed') })
      if (r.connected) setTimeout(onDone, 800)
    } catch (e: any) {
      setResult({ ok: false, msg: e.message })
    } finally { setSaving(false) }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 100,
      background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 24,
    }}>
      <div style={{
        background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 12,
        width: '100%', maxWidth: 520, boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 20px', borderBottom: '1px solid var(--border)' }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>Add AI connector</div>
            <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>At least one AI provider is required for scanning</div>
          </div>
          <button onClick={onDone} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--faint)', padding: 4 }}>
            <FiX size={18} />
          </button>
        </div>

        <div style={{ padding: '20px' }}>
          {/* Provider grid */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--muted)', marginBottom: 10 }}>Select AI provider</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8 }}>
              {AI_PROVIDERS.map(p => (
                <button
                  key={p.type}
                  onClick={() => { setSelectedType(p.type); setForm({}); setResult(null) }}
                  style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
                    padding: '12px 6px', borderRadius: 8, border: '2px solid',
                    borderColor: selectedType === p.type ? 'var(--blue)' : 'var(--border)',
                    background: selectedType === p.type ? 'var(--blue-bg)' : 'var(--hover)',
                    cursor: 'pointer', transition: 'border-color 0.15s',
                  }}
                >
                  <span style={{ fontSize: 20, lineHeight: 1 }}>{p.logo}</span>
                  <span style={{ fontSize: 11, fontWeight: 500, color: selectedType === p.type ? 'var(--blue)' : 'var(--muted)' }}>{p.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Fields */}
          {provider && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
              {provider.docsUrl && (
                <a href={provider.docsUrl} target="_blank" rel="noreferrer"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--blue)', textDecoration: 'none' }}>
                  <FiExternalLink size={11} /> {provider.vendor} docs
                </a>
              )}
              {provider.fields.map((field: any) => (
                <div key={field.key}>
                  <label style={{ display: 'block', fontSize: 12, fontWeight: 500, color: 'var(--muted)', marginBottom: 5 }}>
                    {field.label}
                    {field.hint && <span style={{ color: 'var(--faint)', fontWeight: 400 }}> — {field.hint}</span>}
                  </label>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <Input
                      style={{ flex: 1 }}
                      type={field.secret && !reveal[field.key] ? 'password' : 'text'}
                      placeholder={field.placeholder}
                      value={form[field.key] || ''}
                      onChange={e => setForm(f => ({ ...f, [field.key]: e.target.value }))}
                    />
                    {field.secret && (
                      <Button variant="outline" size="icon" type="button"
                        onClick={() => setReveal(r => ({ ...r, [field.key]: !r[field.key] }))}>
                        {reveal[field.key] ? <FiEyeOff size={13} /> : <FiEye size={13} />}
                      </Button>
                    )}
                  </div>
                </div>
              ))}

              {result && (
                <div style={{
                  padding: '9px 12px', borderRadius: 6, fontSize: 12,
                  display: 'flex', alignItems: 'center', gap: 7,
                  background: result.ok ? 'var(--green-bg)' : 'var(--red-bg)',
                  border: `1px solid ${result.ok ? 'rgba(63,185,80,0.3)' : 'rgba(248,81,73,0.3)'}`,
                  color: result.ok ? 'var(--green)' : 'var(--red)',
                }}>
                  {result.ok ? <FiCheck size={13} /> : <FiX size={13} />} {result.msg}
                </div>
              )}

              <div style={{ display: 'flex', gap: 8 }}>
                <Button onClick={save} disabled={saving} style={{ flex: 1 }}>
                  {saving ? <><FiLoader size={12} className="spin" /> Testing...</> : <><FiZap size={12} /> Connect & test</>}
                </Button>
                <Button variant="outline" onClick={onDone}>Cancel</Button>
              </div>
            </div>
          )}

          {!provider && (
            <div style={{ textAlign: 'center', padding: '20px 0', fontSize: 13, color: 'var(--faint)' }}>
              Select a provider above to configure your API key
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Collapsible integration row ───────────────────────────────────────────────

function IntegrationRow({ integ, oApi, expanded, onToggle, conn, onSaved }: any) {
  const [form, setForm]       = useState<Record<string, string>>({})
  const [reveal, setReveal]   = useState<Record<string, boolean>>({})
  const [testing, setTesting] = useState(false)
  const [result, setResult]   = useState<{ ok: boolean; msg: string } | null>(null)
  const initialized           = useRef(false)
  const connected = conn?.status === 'connected'
  const { Icon } = integ

  // Pre-fill saved values once when the connection data first arrives.
  // The ref guard ensures user edits are never overwritten by subsequent
  // parent re-renders or status refreshes.
  useEffect(() => {
    if (!initialized.current && conn?.config) {
      const clean: Record<string, string> = {}
      Object.entries(conn.config).forEach(([k, v]) => {
        const val = String(v ?? '')
        if (!val.includes('•')) clean[k] = val
      })
      setForm(clean)
      initialized.current = true
    }
  }, [conn])

  const setField = (key: string, val: string) =>
    setForm(f => ({ ...f, [key]: val }))

  const test = async () => {
    setTesting(true); setResult(null)
    try {
      await oApi.saveConnection(integ.type, form)
      const r = await oApi.testConnection(integ.type)
      setResult({ ok: r.connected, msg: r.error || (r.connected ? 'Connected successfully' : 'Connection failed') })
      onSaved?.()
    } catch (e: any) { setResult({ ok: false, msg: e.message }) }
    finally { setTesting(false) }
  }

  return (
    <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
      <button onClick={onToggle} style={{
        width: '100%', display: 'flex', alignItems: 'center', gap: 12,
        padding: '12px 16px', background: 'transparent', border: 'none', cursor: 'pointer', textAlign: 'left',
      }}>
        <div style={{ width: 34, height: 34, borderRadius: 7, background: 'var(--hover)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--muted)', flexShrink: 0 }}>
          <Icon size={16} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 1 }}>
            <span style={{ fontSize: 13, fontWeight: 500 }}>{integ.name}</span>
            {integ.required && <span style={{ fontSize: 10, color: 'var(--blue)', fontWeight: 700, letterSpacing: '0.04em' }}>REQUIRED</span>}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--faint)' }}>
            <StatusDot connected={connected} />
            {connected ? <span style={{ color: 'var(--green)' }}>Connected</span> : 'Not configured'}
            <span>·</span>
            <span>{integ.desc}</span>
          </div>
        </div>
        <span style={{ color: 'var(--faint)', flexShrink: 0 }}>
          {expanded ? <FiChevronUp size={15} /> : <FiChevronDown size={15} />}
        </span>
      </button>

      {expanded && (
        <div style={{ borderTop: '1px solid var(--border)', padding: '16px' }}>
          {integ.docsUrl && (
            <a href={integ.docsUrl} target="_blank" rel="noreferrer"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--blue)', textDecoration: 'none', marginBottom: 14 }}>
              <FiExternalLink size={11} /> View docs
            </a>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {integ.fields.map((field: any) => (
              <div key={field.key}>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 500, color: 'var(--muted)', marginBottom: 5 }}>
                  {field.label}
                  {field.hint && <span style={{ color: 'var(--faint)', fontWeight: 400 }}> — {field.hint}</span>}
                </label>
                <div style={{ display: 'flex', gap: 6 }}>
                  <Input
                    style={{ flex: 1 }}
                    type={field.secret && !reveal[field.key] ? 'password' : 'text'}
                    placeholder={field.secret && connected && !form[field.key] ? 'Already saved — re-enter to change' : field.placeholder}
                    value={form[field.key] || ''}
                    onChange={e => setField(field.key, e.target.value)}
                  />
                  {field.secret && (
                    <Button variant="outline" size="icon" onClick={() => setReveal(r => ({ ...r, [field.key]: !r[field.key] }))}>
                      {reveal[field.key] ? <FiEyeOff size={13} /> : <FiEye size={13} />}
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
          {result && (
            <div style={{
              marginTop: 12, padding: '9px 12px', borderRadius: 6, fontSize: 12,
              display: 'flex', alignItems: 'center', gap: 7,
              background: result.ok ? 'var(--green-bg)' : 'var(--red-bg)',
              border: `1px solid ${result.ok ? 'rgba(63,185,80,0.3)' : 'rgba(248,81,73,0.3)'}`,
              color: result.ok ? 'var(--green)' : 'var(--red)',
            }}>
              {result.ok ? <FiCheck size={13} /> : <FiX size={13} />} {result.msg}
            </div>
          )}
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
            <Button onClick={test} disabled={testing} size="sm">
              {testing ? <><FiLoader size={12} className="spin" /> Testing...</> : 'Save & Test'}
            </Button>
            {connected && (
              <Button variant="outline" size="sm" onClick={() => oApi.deleteConnection(integ.type).then(onSaved)}
                style={{ color: 'var(--red)', borderColor: 'rgba(248,81,73,0.3)' }}>
                Disconnect
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function IntegrationsPage({ orgId, onReady }: { orgId: string; onReady: () => void }) {
  const oApi = orgApi(orgId)
  const [conns, setConns]       = useState<Record<string, Connection>>({})
  const [expanded, setExpanded] = useState<string | null>('gitlab')
  const [showAIModal, setShowAIModal] = useState(false)

  const refreshConns = () => oApi.listConnections().then(list => {
    const m: Record<string, Connection> = {}
    list.forEach(c => { m[c.type] = c })
    setConns(m)
  }).catch(() => {})

  useEffect(() => { refreshConns() }, [orgId])

  const connectedAIs = AI_PROVIDERS.filter(p => conns[p.type]?.status === 'connected')
  const gitlabOk = conns['gitlab']?.status === 'connected'
  const anyAIOk  = connectedAIs.length > 0
  const ready    = anyAIOk && gitlabOk

  return (
    <div style={{ padding: '32px 40px', maxWidth: 680, margin: '0 auto' }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, marginBottom: 4 }}>Integrations</h1>
        <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }}>
          Connect at least one AI provider and GitLab to start scanning.
        </p>
      </div>

      {/* ── AI Providers ── */}
      <SectionLabel>AI Providers</SectionLabel>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 24 }}>
        {/* Connected AI connectors */}
        {connectedAIs.map(p => (
          <div key={p.type} style={{
            background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8,
            padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12,
          }}>
            <div style={{ width: 34, height: 34, borderRadius: 7, background: 'var(--hover)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, flexShrink: 0 }}>
              {p.logo}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 13, fontWeight: 500 }}>{p.label}</span>
                <Badge variant="success">Connected</Badge>
              </div>
              <div style={{ fontSize: 12, color: 'var(--faint)', marginTop: 2 }}>{p.vendor}</div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <Button variant="outline" size="sm" onClick={() => oApi.deleteConnection(p.type).then(refreshConns)} style={{ color: 'var(--red)', borderColor: 'rgba(248,81,73,0.3)' }}>
                <FiTrash2 size={11} /> Remove
              </Button>
            </div>
          </div>
        ))}

        {/* Add AI connector button */}
        <button
          onClick={() => setShowAIModal(true)}
          style={{
            display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center',
            padding: '12px 16px', background: 'var(--card)',
            border: '1px dashed var(--border)', borderRadius: 8,
            cursor: 'pointer', fontSize: 13, color: 'var(--blue)', fontWeight: 500,
            transition: 'background 0.1s',
          }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--hover)'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'var(--card)'}
        >
          <FiPlus size={14} />
          <FiCpu size={14} />
          Add AI connector
          {connectedAIs.length === 0 && (
            <span style={{ fontSize: 10, color: 'var(--blue)', fontWeight: 700, letterSpacing: '0.04em', marginLeft: 4 }}>REQUIRED</span>
          )}
        </button>

        {connectedAIs.length > 0 && (
          <p style={{ fontSize: 12, color: 'var(--faint)', padding: '0 4px' }}>
            {connectedAIs.length} provider{connectedAIs.length > 1 ? 's' : ''} connected.
            Add more for automatic rate-limit switching.
          </p>
        )}
      </div>

      {/* ── Other integrations ── */}
      <SectionLabel>Source control &amp; notifications</SectionLabel>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 24 }}>
        {OTHER_INTEGRATIONS.map(integ => (
          <IntegrationRow
            key={integ.type}
            integ={integ}
            oApi={oApi}
            expanded={expanded === integ.type}
            onToggle={() => setExpanded(expanded === integ.type ? null : integ.type)}
            conn={conns[integ.type]}
            onSaved={refreshConns}
          />
        ))}
      </div>

      {/* Ready banner */}
      <div style={{
        padding: '14px 18px', borderRadius: 8,
        background: ready ? 'var(--green-bg)' : 'var(--card)',
        border: `1px solid ${ready ? 'rgba(63,185,80,0.3)' : 'var(--border)'}`,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16,
      }}>
        <div>
          <div style={{ fontWeight: 500, fontSize: 13, color: ready ? 'var(--green)' : 'var(--text)', marginBottom: 2, display: 'flex', alignItems: 'center', gap: 6 }}>
            {ready && <FiCheck size={14} />}
            {ready ? 'AI and GitLab are connected' : 'Connect an AI provider + GitLab to continue'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--faint)' }}>
            {ready ? 'You can now import repositories and run scans.' : 'Both are required to start scanning.'}
          </div>
        </div>
        <Button onClick={onReady} disabled={!ready} variant={ready ? 'default' : 'secondary'} size="sm" style={{ whiteSpace: 'nowrap' }}>
          Start scanning <FiArrowRight size={13} />
        </Button>
      </div>

      {/* Add AI connector modal */}
      {showAIModal && (
        <AddAIConnectorModal orgId={orgId} onDone={() => { setShowAIModal(false); refreshConns() }} />
      )}
    </div>
  )
}
