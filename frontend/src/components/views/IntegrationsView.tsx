'use client';

import { useState, useEffect } from 'react';
import {
  GitlabIcon, Shield, Bell, Mail, Brain, Plus, Trash2,
  CheckCircle, XCircle, Loader2, Eye, EyeOff, Save, Zap, ChevronDown, ChevronUp, Server
} from 'lucide-react';
import { api } from '@/lib/api';
import { Integration } from '@/types';

interface IntegrationCardProps {
  title: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}

function IntegrationCard({ title, description, icon, color, children, defaultOpen = false }: IntegrationCardProps) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-surface border border-border rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-4 p-5 hover:bg-elevated/50 transition-colors"
      >
        <div className={`p-2.5 rounded-lg ${color}`}>{icon}</div>
        <div className="text-left flex-1">
          <div className="font-semibold text-white">{title}</div>
          <div className="text-xs text-muted mt-0.5">{description}</div>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-muted" /> : <ChevronDown className="w-4 h-4 text-muted" />}
      </button>
      {open && <div className="border-t border-border p-5">{children}</div>}
    </div>
  );
}

interface FieldProps {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  secret?: boolean;
  type?: string;
}

function Field({ label, value, onChange, placeholder, secret }: FieldProps) {
  const [show, setShow] = useState(false);
  return (
    <div>
      <label className="block text-xs font-medium text-muted mb-1.5">{label}</label>
      <div className="relative">
        <input
          type={secret && !show ? 'password' : 'text'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          className="w-full bg-canvas border border-border rounded-lg px-3 py-2 text-sm text-white placeholder-muted/50 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/20 font-mono"
        />
        {secret && (
          <button
            type="button"
            onClick={() => setShow(!show)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-white transition-colors"
          >
            {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        )}
      </div>
    </div>
  );
}

interface TestBadgeProps {
  status: 'idle' | 'testing' | 'ok' | 'fail';
  message?: string;
}

function TestBadge({ status, message }: TestBadgeProps) {
  if (status === 'idle') return null;
  if (status === 'testing') return (
    <div className="flex items-center gap-2 text-sm text-blue-400">
      <Loader2 className="w-4 h-4 animate-spin" /> Testing connection…
    </div>
  );
  if (status === 'ok') return (
    <div className="flex items-center gap-2 text-sm text-green-400">
      <CheckCircle className="w-4 h-4" /> {message || 'Connected successfully'}
    </div>
  );
  return (
    <div className="flex items-center gap-2 text-sm text-red-400">
      <XCircle className="w-4 h-4" /> {message || 'Connection failed'}
    </div>
  );
}

interface SaveButtonProps {
  onClick: () => void;
  loading: boolean;
  label?: string;
}

function SaveButton({ onClick, loading, label = 'Save & Test' }: SaveButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
    >
      {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
      {label}
    </button>
  );
}

// ─── GitLab ────────────────────────────────────────────────────────────────
function GitLabSection({ integrations, onSaved }: { integrations: Integration[]; onSaved: () => void }) {
  const existing = integrations.find(i => i.provider === 'gitlab');
  const [url, setUrl] = useState(existing?.config?.url || 'https://gitlab.com');
  const [token, setToken] = useState('');
  const [status, setStatus] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle');
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const save = async () => {
    setLoading(true);
    setStatus('testing');
    try {
      const res = await api.saveIntegration({ provider: 'gitlab', config: { url, token } });
      setStatus(res.status === 'connected' ? 'ok' : 'fail');
      setMsg(res.message || '');
      if (res.status === 'connected') onSaved();
    } catch (e: any) {
      setStatus('fail');
      setMsg(e.message);
    }
    setLoading(false);
  };

  return (
    <div className="space-y-4">
      <Field label="GitLab URL" value={url} onChange={setUrl} placeholder="https://gitlab.com" />
      <Field label="Personal Access Token" value={token} onChange={setToken} placeholder="glpat-xxxxxxxxxxxxxxxxxxxx" secret />
      <div className="flex items-center gap-4">
        <SaveButton onClick={save} loading={loading} />
        <TestBadge status={status} message={msg} />
      </div>
      {existing?.status === 'connected' && (
        <div className="text-xs text-muted flex items-center gap-1.5">
          <CheckCircle className="w-3.5 h-3.5 text-green-400" /> Connected to {existing.config?.url}
        </div>
      )}
    </div>
  );
}

// ─── Vault ─────────────────────────────────────────────────────────────────
function VaultSection({ integrations, onSaved }: { integrations: Integration[]; onSaved: () => void }) {
  const existing = integrations.find(i => i.provider === 'vault');
  const [url, setUrl] = useState(existing?.config?.url || 'http://vault:8200');
  const [token, setToken] = useState('');
  const [status, setStatus] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle');
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const save = async () => {
    setLoading(true);
    setStatus('testing');
    try {
      const res = await api.saveIntegration({ provider: 'vault', config: { url, token } });
      setStatus(res.status === 'connected' ? 'ok' : 'fail');
      setMsg(res.message || '');
      if (res.status === 'connected') onSaved();
    } catch (e: any) {
      setStatus('fail');
      setMsg(e.message);
    }
    setLoading(false);
  };

  return (
    <div className="space-y-4">
      <Field label="Vault URL" value={url} onChange={setUrl} placeholder="http://vault:8200" />
      <Field label="Root Token" value={token} onChange={setToken} placeholder="hvs.xxxxxxxx" secret />
      <div className="flex items-center gap-4">
        <SaveButton onClick={save} loading={loading} />
        <TestBadge status={status} message={msg} />
      </div>
      {existing?.status === 'connected' && (
        <div className="text-xs text-muted flex items-center gap-1.5">
          <CheckCircle className="w-3.5 h-3.5 text-green-400" /> Connected to {existing.config?.url}
        </div>
      )}
    </div>
  );
}

// ─── Slack ─────────────────────────────────────────────────────────────────
function SlackSection({ integrations, onSaved }: { integrations: Integration[]; onSaved: () => void }) {
  const existing = integrations.find(i => i.provider === 'slack');
  const [webhook, setWebhook] = useState(existing?.config?.webhook_url || '');
  const [status, setStatus] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle');
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const save = async () => {
    setLoading(true);
    setStatus('testing');
    try {
      const res = await api.saveIntegration({ provider: 'slack', config: { webhook_url: webhook } });
      setStatus(res.status === 'connected' ? 'ok' : 'fail');
      setMsg(res.message || '');
      if (res.status === 'connected') onSaved();
    } catch (e: any) {
      setStatus('fail');
      setMsg(e.message);
    }
    setLoading(false);
  };

  return (
    <div className="space-y-4">
      <Field label="Webhook URL" value={webhook} onChange={setWebhook} placeholder="https://hooks.slack.com/services/xxx/yyy/zzz" secret />
      <div className="flex items-center gap-4">
        <SaveButton onClick={save} loading={loading} />
        <TestBadge status={status} message={msg} />
      </div>
    </div>
  );
}

// ─── SMTP ──────────────────────────────────────────────────────────────────
function SMTPSection({ integrations, onSaved }: { integrations: Integration[]; onSaved: () => void }) {
  const existing = integrations.find(i => i.provider === 'smtp');
  const [host, setHost] = useState(existing?.config?.host || '');
  const [port, setPort] = useState(existing?.config?.port || '587');
  const [user, setUser] = useState(existing?.config?.username || '');
  const [pass, setPass] = useState('');
  const [from, setFrom] = useState(existing?.config?.from_email || '');
  const [status, setStatus] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle');
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const save = async () => {
    setLoading(true);
    setStatus('testing');
    try {
      const res = await api.saveIntegration({
        provider: 'smtp',
        config: { host, port, username: user, password: pass, from_email: from }
      });
      setStatus(res.status === 'connected' ? 'ok' : 'fail');
      setMsg(res.message || '');
      if (res.status === 'connected') onSaved();
    } catch (e: any) {
      setStatus('fail');
      setMsg(e.message);
    }
    setLoading(false);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <Field label="SMTP Host" value={host} onChange={setHost} placeholder="smtp.gmail.com" />
        <Field label="Port" value={port} onChange={setPort} placeholder="587" />
      </div>
      <Field label="Username" value={user} onChange={setUser} placeholder="user@example.com" />
      <Field label="Password / App Password" value={pass} onChange={setPass} secret placeholder="••••••••••••" />
      <Field label="From Email" value={from} onChange={setFrom} placeholder="secretops@example.com" />
      <div className="flex items-center gap-4">
        <SaveButton onClick={save} loading={loading} />
        <TestBadge status={status} message={msg} />
      </div>
    </div>
  );
}

// ─── AI Providers ──────────────────────────────────────────────────────────
interface AIKey {
  id?: number;
  provider: string;
  label: string;
  api_key: string;
  model: string;
  status?: string;
}

const AI_PROVIDERS = [
  { value: 'openai', label: 'OpenAI', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo'] },
  { value: 'anthropic', label: 'Anthropic', models: ['claude-opus-4-5', 'claude-sonnet-4-5', 'claude-haiku-4-5'] },
  { value: 'groq', label: 'Groq', models: ['llama-3.3-70b-versatile', 'mixtral-8x7b-32768', 'llama-3.1-8b-instant'] },
  { value: 'ollama', label: 'Ollama (Local)', models: ['llama3', 'mistral', 'codellama'] },
];

function AISection({ integrations, onSaved }: { integrations: Integration[]; onSaved: () => void }) {
  const aiIntegrations = integrations.filter(i => ['openai', 'anthropic', 'groq', 'ollama'].includes(i.provider));
  const [keys, setKeys] = useState<AIKey[]>(
    aiIntegrations.length > 0
      ? aiIntegrations.map(i => ({
          id: i.id,
          provider: i.provider,
          label: i.config?.label || i.provider,
          api_key: '',
          model: i.config?.model || '',
          status: i.status,
        }))
      : [{ provider: 'openai', label: 'OpenAI Primary', api_key: '', model: 'gpt-4o-mini' }]
  );
  const [testStatuses, setTestStatuses] = useState<Record<number, { status: 'idle' | 'testing' | 'ok' | 'fail'; msg: string }>>({});
  const [loadingIdx, setLoadingIdx] = useState<number | null>(null);

  const addKey = () => {
    setKeys(prev => [...prev, { provider: 'openai', label: '', api_key: '', model: 'gpt-4o-mini' }]);
  };

  const removeKey = (idx: number) => {
    setKeys(prev => prev.filter((_, i) => i !== idx));
  };

  const updateKey = (idx: number, field: keyof AIKey, value: string) => {
    setKeys(prev => prev.map((k, i) => i === idx ? { ...k, [field]: value } : k));
  };

  const saveKey = async (idx: number) => {
    const k = keys[idx];
    setLoadingIdx(idx);
    setTestStatuses(prev => ({ ...prev, [idx]: { status: 'testing', msg: '' } }));
    try {
      const res = await api.saveIntegration({
        provider: k.provider,
        config: { label: k.label, api_key: k.api_key, model: k.model }
      });
      setTestStatuses(prev => ({
        ...prev,
        [idx]: { status: res.status === 'connected' ? 'ok' : 'fail', msg: res.message || '' }
      }));
      if (res.status === 'connected') onSaved();
    } catch (e: any) {
      setTestStatuses(prev => ({ ...prev, [idx]: { status: 'fail', msg: e.message } }));
    }
    setLoadingIdx(null);
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted">Add multiple AI providers for automatic failover when rate limits are hit.</p>
        <button
          onClick={addKey}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-elevated border border-border hover:border-blue-500/50 text-white text-xs rounded-lg transition-colors"
        >
          <Plus className="w-3.5 h-3.5" /> Add Provider
        </button>
      </div>

      {keys.map((k, idx) => {
        const providerMeta = AI_PROVIDERS.find(p => p.value === k.provider);
        const ts = testStatuses[idx] || { status: 'idle', msg: '' };
        const isOllama = k.provider === 'ollama';

        return (
          <div key={idx} className="bg-canvas border border-border rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-yellow-400" />
                <span className="text-sm font-medium text-white">Provider {idx + 1}</span>
                {k.status === 'connected' && (
                  <span className="text-xs px-2 py-0.5 bg-green-500/10 text-green-400 border border-green-500/20 rounded-full">active</span>
                )}
              </div>
              {keys.length > 1 && (
                <button onClick={() => removeKey(idx)} className="text-muted hover:text-red-400 transition-colors">
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-muted mb-1.5">Provider</label>
                <select
                  value={k.provider}
                  onChange={e => updateKey(idx, 'provider', e.target.value)}
                  className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/60"
                >
                  {AI_PROVIDERS.map(p => (
                    <option key={p.value} value={p.value}>{p.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-muted mb-1.5">Model</label>
                <select
                  value={k.model}
                  onChange={e => updateKey(idx, 'model', e.target.value)}
                  className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/60"
                >
                  {(providerMeta?.models || []).map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
            </div>

            <Field label="Label / Nickname" value={k.label} onChange={v => updateKey(idx, 'label', v)} placeholder={`${providerMeta?.label} Primary`} />

            {!isOllama && (
              <Field label="API Key" value={k.api_key} onChange={v => updateKey(idx, 'api_key', v)} placeholder="sk-..." secret />
            )}
            {isOllama && (
              <Field label="Ollama Base URL" value={k.api_key} onChange={v => updateKey(idx, 'api_key', v)} placeholder="http://localhost:11434" />
            )}

            <div className="flex items-center gap-4">
              <SaveButton onClick={() => saveKey(idx)} loading={loadingIdx === idx} />
              <TestBadge status={ts.status} message={ts.msg} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Alert Recipients ───────────────────────────────────────────────────────
function RecipientsSection() {
  const [recipients, setRecipients] = useState<any[]>([]);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState('developer');
  const [loading, setLoading] = useState(false);
  const [fetching, setFetching] = useState(true);

  const fetchRecipients = async () => {
    try {
      const data = await api.getRecipients();
      setRecipients(data);
    } catch { }
    setFetching(false);
  };

  useEffect(() => { fetchRecipients(); }, []);

  const add = async () => {
    if (!email || !name) return;
    setLoading(true);
    try {
      await api.addRecipient({ email, name, role });
      setEmail(''); setName('');
      fetchRecipients();
    } catch { }
    setLoading(false);
  };

  const remove = async (id: number) => {
    try {
      await api.deleteRecipient(id);
      fetchRecipients();
    } catch { }
  };

  const ROLES = ['developer', 'team_lead', 'devsecops', 'manager'];

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted">These recipients receive Slack and email alerts for all findings and rotation reminders.</p>

      <div className="grid grid-cols-3 gap-3">
        <Field label="Name" value={name} onChange={setName} placeholder="Alice Smith" />
        <Field label="Email" value={email} onChange={setEmail} placeholder="alice@company.com" />
        <div>
          <label className="block text-xs font-medium text-muted mb-1.5">Role</label>
          <select
            value={role}
            onChange={e => setRole(e.target.value)}
            className="w-full bg-canvas border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/60"
          >
            {ROLES.map(r => <option key={r} value={r}>{r.replace('_', ' ')}</option>)}
          </select>
        </div>
      </div>

      <button
        onClick={add}
        disabled={loading || !email || !name}
        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-sm font-medium rounded-lg transition-colors"
      >
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
        Add Recipient
      </button>

      {fetching ? (
        <div className="flex items-center gap-2 text-muted text-sm py-4">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading…
        </div>
      ) : recipients.length === 0 ? (
        <div className="text-center py-8 text-muted text-sm border border-dashed border-border rounded-xl">
          No recipients configured yet
        </div>
      ) : (
        <div className="space-y-2">
          {recipients.map((r: any) => (
            <div key={r.id} className="flex items-center justify-between bg-canvas border border-border rounded-lg px-4 py-2.5">
              <div>
                <span className="text-sm text-white font-medium">{r.name}</span>
                <span className="text-xs text-muted ml-3">{r.email}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs px-2 py-0.5 bg-elevated border border-border rounded-full text-muted capitalize">{r.role?.replace('_', ' ')}</span>
                <button onClick={() => remove(r.id)} className="text-muted hover:text-red-400 transition-colors">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main view ─────────────────────────────────────────────────────────────
export function IntegrationsView() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchIntegrations = async () => {
    try {
      const data = await api.getIntegrations();
      setIntegrations(data);
    } catch { }
    setLoading(false);
  };

  useEffect(() => { fetchIntegrations(); }, []);

  const connected = (provider: string) => integrations.find(i => i.provider === provider)?.status === 'connected';
  const aiConnected = integrations.filter(i => ['openai', 'anthropic', 'groq', 'ollama'].includes(i.provider) && i.status === 'connected').length;

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-6 max-w-3xl mx-auto space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-xl font-bold text-white">Integrations</h1>
          <p className="text-sm text-muted mt-1">Configure external services. All credentials are AES-GCM encrypted at rest.</p>
        </div>

        {/* Status pills */}
        <div className="flex flex-wrap gap-2">
          {[
            { label: 'GitLab', ok: connected('gitlab') },
            { label: 'Vault', ok: connected('vault') },
            { label: 'Slack', ok: connected('slack') },
            { label: 'SMTP', ok: connected('smtp') },
            { label: `AI (${aiConnected})`, ok: aiConnected > 0 },
          ].map(({ label, ok }) => (
            <div key={label} className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs border ${ok ? 'border-green-500/30 bg-green-500/10 text-green-400' : 'border-border bg-elevated text-muted'}`}>
              {ok ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
              {label}
            </div>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center gap-3 text-muted py-12 justify-center">
            <Loader2 className="w-5 h-5 animate-spin" /> Loading integrations…
          </div>
        ) : (
          <div className="space-y-3">
            <IntegrationCard
              title="GitLab"
              description="Source repository scanning and merge request creation"
              icon={<GitlabIcon className="w-5 h-5 text-orange-400" />}
              color="bg-orange-500/10"
              defaultOpen={!connected('gitlab')}
            >
              <GitLabSection integrations={integrations} onSaved={fetchIntegrations} />
            </IntegrationCard>

            <IntegrationCard
              title="HashiCorp Vault"
              description="Poison placeholder injection and secret rotation tracking"
              icon={<Shield className="w-5 h-5 text-purple-400" />}
              color="bg-purple-500/10"
              defaultOpen={!connected('vault')}
            >
              <VaultSection integrations={integrations} onSaved={fetchIntegrations} />
            </IntegrationCard>

            <IntegrationCard
              title="AI Providers"
              description="LLM classification engine — add multiple for automatic failover"
              icon={<Brain className="w-5 h-5 text-blue-400" />}
              color="bg-blue-500/10"
              defaultOpen={aiConnected === 0}
            >
              <AISection integrations={integrations} onSaved={fetchIntegrations} />
            </IntegrationCard>

            <IntegrationCard
              title="Slack"
              description="Block Kit alerts for findings, rotation reminders, and resolutions"
              icon={<Bell className="w-5 h-5 text-green-400" />}
              color="bg-green-500/10"
              defaultOpen={!connected('slack')}
            >
              <SlackSection integrations={integrations} onSaved={fetchIntegrations} />
            </IntegrationCard>

            <IntegrationCard
              title="SMTP Email"
              description="HTML email alerts with finding details and rotation checklists"
              icon={<Mail className="w-5 h-5 text-cyan-400" />}
              color="bg-cyan-500/10"
              defaultOpen={!connected('smtp')}
            >
              <SMTPSection integrations={integrations} onSaved={fetchIntegrations} />
            </IntegrationCard>

            <IntegrationCard
              title="Alert Recipients"
              description="People who receive Slack and email notifications"
              icon={<Server className="w-5 h-5 text-yellow-400" />}
              color="bg-yellow-500/10"
            >
              <RecipientsSection />
            </IntegrationCard>
          </div>
        )}
      </div>
    </div>
  );
}
