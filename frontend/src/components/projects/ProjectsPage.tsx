'use client'
import { useEffect, useState, useCallback } from 'react'
import {
  FiRefreshCw, FiSearch, FiPlay, FiLoader, FiAlertCircle,
  FiGitBranch, FiLock, FiGlobe, FiChevronLeft, FiChevronRight,
  FiPlus, FiCheck, FiTrash2, FiX, FiFolder,
} from 'react-icons/fi'
import { orgApi, GitLabRepo, ImportedProject, ScanJob } from '@/lib/api'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select'

const MODELS = [
  { value: 'claude-3-5-sonnet-20241022', label: 'Claude 3.5 Sonnet' },
  { value: 'claude-3-haiku-20240307',    label: 'Claude 3 Haiku' },
  { value: 'gpt-4o',                     label: 'GPT-4o' },
  { value: 'gpt-4o-mini',               label: 'GPT-4o Mini' },
  { value: 'deepseek-chat',             label: 'DeepSeek V3' },
  { value: 'llama3.1:8b',              label: 'LLaMA 3.1 (local)' },
]

function timeAgo(s: string) {
  if (!s) return '—'
  const d = Math.floor((Date.now() - new Date(s).getTime()) / 1000)
  if (d < 60) return 'just now'
  if (d < 3600) return `${Math.floor(d / 60)}m ago`
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`
  return `${Math.floor(d / 86400)}d ago`
}

function scanBadgeVariant(s: string): 'success' | 'destructive' | 'warning' {
  return s === 'completed' ? 'success' : s === 'failed' ? 'destructive' : 'warning'
}

// ─── Add Projects Modal ────────────────────────────────────────────────────────
interface AddProjectsModalProps {
  orgId: string
  importedGitlabIds: Set<number>
  onClose: () => void
  onImported: () => void
}

function AddProjectsModal({ orgId, importedGitlabIds, onClose, onImported }: AddProjectsModalProps) {
  const oApi = orgApi(orgId)
  const [repos, setRepos]           = useState<GitLabRepo[]>([])
  const [groups, setGroups]         = useState<{ id: number; name: string }[]>([])
  const [loading, setLoading]       = useState(false)
  const [search, setSearch]         = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [page, setPage]             = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [groupId, setGroupId]       = useState('')
  const [importing, setImporting]   = useState<number | null>(null)
  const [justAdded, setJustAdded]   = useState<Set<number>>(new Set())
  const [error, setError]           = useState('')

  const loadRepos = useCallback(() => {
    setLoading(true); setError('')
    oApi.gitlabRepos({ search: search || undefined, page: String(page), group_id: groupId || undefined })
      .then(r => { setRepos(r.repos || []); setTotalPages(parseInt(r.total_pages || '1') || 1) })
      .catch(e => { setError(e.message); setRepos([]) })
      .finally(() => setLoading(false))
  }, [orgId, search, page, groupId])

  useEffect(() => {
    oApi.gitlabGroups().then(r => setGroups(r.groups || [])).catch(() => {})
    loadRepos()
  }, [orgId])

  useEffect(() => { loadRepos() }, [search, page, groupId])

  const importRepo = async (repo: GitLabRepo) => {
    setImporting(repo.id)
    try {
      await oApi.importProject(repo)
      setJustAdded(prev => new Set(prev).add(repo.id))
      onImported()
    } catch (e: any) { setError(e.message) }
    finally { setImporting(null) }
  }

  const isAdded = (id: number) => importedGitlabIds.has(id) || justAdded.has(id)

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.55)', backdropFilter: 'blur(3px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 24,
    }}>
      <div style={{
        width: '100%', maxWidth: 860, maxHeight: '90vh',
        background: 'var(--bg)', border: '1px solid var(--border)',
        borderRadius: 12, display: 'flex', flexDirection: 'column',
        boxShadow: '0 24px 64px rgba(0,0,0,0.4)',
        overflow: 'hidden',
      }}>
        {/* Modal header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '18px 24px', borderBottom: '1px solid var(--border)',
          flexShrink: 0,
        }}>
          <div>
            <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 2 }}>Add projects</h2>
            <p style={{ fontSize: 12, color: 'var(--muted)' }}>Browse your GitLab repositories and import them into this organization</p>
          </div>
          <button
            onClick={onClose}
            style={{
              width: 32, height: 32, borderRadius: 6, border: '1px solid var(--border)',
              background: 'transparent', cursor: 'pointer', display: 'flex',
              alignItems: 'center', justifyContent: 'center', color: 'var(--muted)',
            }}
          >
            <FiX size={15} />
          </button>
        </div>

        {/* Toolbar */}
        <div style={{ padding: '14px 24px', borderBottom: '1px solid var(--border)', flexShrink: 0, display: 'flex', gap: 8 }}>
          <div style={{ display: 'flex', flex: 1, maxWidth: 380 }}>
            <Input
              value={searchInput}
              onChange={e => setSearchInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { setSearch(searchInput); setPage(1) } }}
              placeholder="Search repositories..."
              style={{ borderRadius: '6px 0 0 6px', borderRight: 'none', height: 34 }}
            />
            <Button
              onClick={() => { setSearch(searchInput); setPage(1) }}
              style={{ borderRadius: '0 6px 6px 0', height: 34, paddingLeft: 10, paddingRight: 10 }}
              size="sm"
            >
              <FiSearch size={13} />
            </Button>
          </div>
          {groups.length > 0 && (
            <Select value={groupId || '__all__'} onValueChange={v => { setGroupId(v === '__all__' ? '' : v); setPage(1) }}>
              <SelectTrigger className="w-40 text-xs h-[34px]">
                <SelectValue placeholder="All groups" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__all__">All groups</SelectItem>
                {groups.map(g => <SelectItem key={g.id} value={String(g.id)}>{g.name}</SelectItem>)}
              </SelectContent>
            </Select>
          )}
          <Button variant="outline" size="sm" onClick={loadRepos} style={{ height: 34 }}>
            <FiRefreshCw size={13} />
          </Button>
        </div>

        {error && (
          <div style={{
            margin: '0 24px', marginTop: 12,
            padding: '8px 12px', background: 'var(--red-bg)',
            border: '1px solid rgba(248,81,73,0.3)',
            borderRadius: 6, fontSize: 12, color: 'var(--red)',
            display: 'flex', alignItems: 'center', gap: 7, flexShrink: 0,
          }}>
            <FiAlertCircle size={13} /> {error}
          </div>
        )}

        {/* Repo list */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading ? (
            <div style={{ padding: 60, textAlign: 'center', color: 'var(--muted)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
              <FiLoader size={22} className="spin" />
              <span style={{ fontSize: 13 }}>Loading repositories...</span>
            </div>
          ) : repos.length === 0 ? (
            <div style={{ padding: 60, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
              No repositories found
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead style={{ position: 'sticky', top: 0, background: 'var(--bg)', zIndex: 1 }}>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Repository', 'Group', 'Branch', 'Visibility', 'Last activity', ''].map(h => (
                    <th key={h} style={{ padding: '8px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {repos.map(repo => {
                  const added = isAdded(repo.id)
                  return (
                    <tr
                      key={repo.id}
                      style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.1s' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--hover)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                    >
                      <td style={{ padding: '10px 16px' }}>
                        <div style={{ fontWeight: 500 }}>{repo.name}</div>
                        <div style={{ fontSize: 11, color: 'var(--faint)', fontFamily: 'monospace', marginTop: 1 }}>{repo.path_with_namespace}</div>
                      </td>
                      <td style={{ padding: '10px 16px', fontSize: 12, color: 'var(--muted)' }}>{repo.namespace?.name || '—'}</td>
                      <td style={{ padding: '10px 16px', fontSize: 12, color: 'var(--muted)' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <FiGitBranch size={11} /> {repo.default_branch || 'main'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        {repo.visibility === 'private'
                          ? <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--orange)' }}><FiLock size={11} /> Private</span>
                          : <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--faint)' }}><FiGlobe size={11} /> Public</span>}
                      </td>
                      <td style={{ padding: '10px 16px', fontSize: 12, color: 'var(--faint)' }}>{timeAgo(repo.last_activity_at)}</td>
                      <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                        {added ? (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--green)', justifyContent: 'flex-end', fontWeight: 500 }}>
                            <FiCheck size={13} /> Added
                          </span>
                        ) : (
                          <Button
                            size="sm"
                            disabled={importing === repo.id}
                            onClick={() => importRepo(repo)}
                          >
                            {importing === repo.id
                              ? <><FiLoader size={11} className="spin" /> Adding</>
                              : <><FiPlus size={11} /> Add</>}
                          </Button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination + close */}
        <div style={{
          padding: '12px 24px', borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {totalPages > 1 && (
              <>
                <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
                  <FiChevronLeft size={13} />
                </Button>
                <span style={{ fontSize: 12, color: 'var(--muted)' }}>Page {page} of {totalPages}</span>
                <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>
                  <FiChevronRight size={13} />
                </Button>
              </>
            )}
          </div>
          <Button variant="outline" onClick={onClose}>Done</Button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────
export default function ProjectsPage({ orgId, onScanComplete }: { orgId: string; onScanComplete: (id: string) => void }) {
  const oApi = orgApi(orgId)

  const [imported, setImported]     = useState<ImportedProject[]>([])
  const [scans, setScans]           = useState<ScanJob[]>([])
  const [scanning, setScanning]     = useState<number | null>(null)
  const [removing, setRemoving]     = useState<string | null>(null)
  const [model, setModel]           = useState('claude-3-5-sonnet-20241022')
  const [tab, setTab]               = useState<'imported' | 'history'>('imported')
  const [showModal, setShowModal]   = useState(false)
  const [error, setError]           = useState('')

  const importedGitlabIds = new Set(imported.map(p => p.gitlab_id))

  const loadImported = useCallback(() => {
    oApi.listProjects().then(setImported).catch(() => {})
  }, [orgId])

  const loadScans = useCallback(() => {
    oApi.listScans().then(setScans).catch(() => {})
  }, [orgId])

  useEffect(() => {
    loadImported()
    loadScans()
  }, [orgId])

  const removeProject = async (project: ImportedProject) => {
    setRemoving(project.id)
    try {
      await oApi.removeProject(project.id)
      loadImported(); loadScans()
    } catch (e: any) { setError(e.message) }
    finally { setRemoving(null) }
  }

  const startScan = async (project: ImportedProject) => {
    setScanning(project.gitlab_id)
    try {
      const res = await oApi.createScan({
        repo_url: project.http_url_to_repo,
        branch: project.default_branch || 'main',
        source: 'gitlab',
        ai_model: model,
      })
      const poll = setInterval(async () => {
        try {
          const s = await api.getScan(res.id)
          if (s.status === 'completed' || s.status === 'failed') {
            clearInterval(poll); setScanning(null)
            loadScans(); loadImported()
            onScanComplete(res.id)
          }
        } catch { clearInterval(poll); setScanning(null) }
      }, 3000)
    } catch (e: any) { setError(e.message); setScanning(null) }
  }

  return (
    <div style={{ padding: '32px 40px', maxWidth: 1100, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 600, marginBottom: 4 }}>Projects</h1>
          <p style={{ fontSize: 13, color: 'var(--muted)' }}>Import repositories and run AI secret scans</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 12, color: 'var(--muted)' }}>Model</span>
          <Select value={model} onValueChange={setModel}>
            <SelectTrigger className="w-48 text-xs h-8">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {MODELS.map(m => <SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>)}
            </SelectContent>
          </Select>
          <Button size="sm" onClick={() => setShowModal(true)}>
            <FiPlus size={13} /> Add projects
          </Button>
        </div>
      </div>

      {/* Scanning banner */}
      {scanning !== null && (
        <div style={{
          marginBottom: 20, padding: '12px 16px',
          background: 'var(--blue-bg)', border: '1px solid rgba(47,129,247,0.3)',
          borderRadius: 8, display: 'flex', alignItems: 'center', gap: 10, fontSize: 13,
        }}>
          <FiLoader size={16} className="spin" style={{ color: 'var(--blue)', flexShrink: 0 }} />
          <span style={{ fontWeight: 500, color: 'var(--blue)' }}>Scan in progress</span>
          <span style={{ color: 'var(--muted)', marginLeft: 4 }}>— you&apos;ll be taken to findings when complete.</span>
        </div>
      )}

      {error && (
        <div style={{
          marginBottom: 16, padding: '10px 14px',
          background: 'var(--red-bg)', border: '1px solid rgba(248,81,73,0.3)',
          borderRadius: 6, fontSize: 13, color: 'var(--red)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <FiAlertCircle size={14} /> {error}
          <button onClick={() => setError('')} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--red)' }}>
            <FiX size={13} />
          </button>
        </div>
      )}

      <Tabs value={tab} onValueChange={v => setTab(v as 'imported' | 'history')}>
        <TabsList>
          <TabsTrigger value="imported">
            <FiFolder size={13} style={{ marginRight: 5 }} />
            Imported ({imported.length})
          </TabsTrigger>
          <TabsTrigger value="history">Scan history ({scans.length})</TabsTrigger>
        </TabsList>

        {/* ── Imported projects ── */}
        <TabsContent value="imported">
          <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            {imported.length === 0 ? (
              <div style={{ padding: 72, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
                <div style={{ width: 48, height: 48, borderRadius: 12, background: 'var(--hover)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
                  <FiFolder size={22} style={{ color: 'var(--faint)' }} />
                </div>
                <div style={{ fontWeight: 500, fontSize: 14, marginBottom: 6 }}>No projects yet</div>
                <div style={{ marginBottom: 20 }}>Import GitLab repositories to start scanning for secrets</div>
                <Button size="sm" onClick={() => setShowModal(true)}>
                  <FiPlus size={13} /> Add your first project
                </Button>
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Project', 'Branch', 'Last scan', 'Secrets', ''].map(h => (
                      <th key={h} style={{ padding: '9px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {imported.map(p => (
                    <tr
                      key={p.id}
                      style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.1s' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--hover)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                    >
                      <td style={{ padding: '11px 16px' }}>
                        <div style={{ fontWeight: 500 }}>{p.name}</div>
                        <div style={{ fontSize: 11, color: 'var(--faint)', fontFamily: 'monospace', marginTop: 1 }}>{p.path_with_namespace}</div>
                      </td>
                      <td style={{ padding: '11px 16px', fontSize: 12, color: 'var(--muted)' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <FiGitBranch size={11} /> {p.default_branch || 'main'}
                        </span>
                      </td>
                      <td style={{ padding: '11px 16px' }}>
                        {p.last_scan_status
                          ? <Badge variant={scanBadgeVariant(p.last_scan_status)}>{p.last_scan_status}</Badge>
                          : <span style={{ fontSize: 12, color: 'var(--faint)' }}>Never</span>}
                      </td>
                      <td style={{ padding: '11px 16px', fontWeight: 600, fontFamily: 'monospace', color: p.last_finding_count > 0 ? 'var(--red)' : 'var(--muted)' }}>
                        {p.last_scan_status ? p.last_finding_count : '—'}
                      </td>
                      <td style={{ padding: '11px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                          <Button size="sm" disabled={scanning !== null} onClick={() => startScan(p)}>
                            {scanning === p.gitlab_id
                              ? <><FiLoader size={11} className="spin" /> Scanning</>
                              : <><FiPlay size={11} /> Scan</>}
                          </Button>
                          <Button
                            size="sm" variant="ghost"
                            style={{ color: 'var(--faint)' }}
                            disabled={removing === p.id}
                            onClick={() => removeProject(p)}
                          >
                            {removing === p.id ? <FiLoader size={11} className="spin" /> : <FiTrash2 size={11} />}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </TabsContent>

        {/* ── Scan history ── */}
        <TabsContent value="history">
          <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            {scans.length === 0 ? (
              <div style={{ padding: 60, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
                No scans yet — import a project and run a scan to get started
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Repository', 'Model', 'Status', 'Secrets', 'Date', ''].map(h => (
                      <th key={h} style={{ padding: '9px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--faint)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scans.map(s => (
                    <tr
                      key={s.id}
                      style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer', transition: 'background 0.1s' }}
                      onClick={() => onScanComplete(s.id)}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--hover)'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                    >
                      <td style={{ padding: '11px 16px' }}>
                        <div style={{ fontWeight: 500 }}>{s.repo_name}</div>
                        <div style={{ fontSize: 11, color: 'var(--faint)', fontFamily: 'monospace', marginTop: 1 }}>{s.repo_url}</div>
                      </td>
                      <td style={{ padding: '11px 16px', fontSize: 12, color: 'var(--muted)', fontFamily: 'monospace' }}>{s.ai_model.split('-').slice(0, 3).join('-')}</td>
                      <td style={{ padding: '11px 16px' }}><Badge variant={scanBadgeVariant(s.status)}>{s.status}</Badge></td>
                      <td style={{ padding: '11px 16px', fontWeight: 600, color: s.finding_count > 0 ? 'var(--red)' : 'var(--muted)', fontFamily: 'monospace' }}>{s.finding_count}</td>
                      <td style={{ padding: '11px 16px', fontSize: 12, color: 'var(--faint)' }}>{timeAgo(s.created_at)}</td>
                      <td style={{ padding: '11px 16px', textAlign: 'right' }}>
                        {s.status === 'completed' && (
                          <Button variant="ghost" size="sm" style={{ color: 'var(--blue)' }}>View</Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </TabsContent>
      </Tabs>

      {/* Add Projects Modal */}
      {showModal && (
        <AddProjectsModal
          orgId={orgId}
          importedGitlabIds={importedGitlabIds}
          onClose={() => setShowModal(false)}
          onImported={loadImported}
        />
      )}
    </div>
  )
}
