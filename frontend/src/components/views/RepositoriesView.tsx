'use client'
import { useEffect, useState } from 'react'
import { GitBranch, Plus, Search, RefreshCw, ExternalLink } from 'lucide-react'
import { api } from '@/lib/api'
import type { Repository } from '@/types'

export default function RepositoriesView({ onStartScan }: { onStartScan: (id: number) => void }) {
  const [repos, setRepos] = useState<Repository[]>([])
  const [gitlabRepos, setGitlabRepos] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingGitlab, setLoadingGitlab] = useState(false)
  const [scanning, setScanning] = useState<number | null>(null)
  const [tab, setTab] = useState<'added' | 'browse'>('added')
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    api.getRepositories().then(setRepos).finally(() => setLoading(false))
  }, [])

  const loadGitLabRepos = async () => {
    setLoadingGitlab(true)
    try {
      const data = await api.getGitLabRepositories()
      setGitlabRepos(data)
      setTab('browse')
    } catch (e: any) {
      alert(`Failed to list GitLab repositories: ${e.message}`)
    } finally {
      setLoadingGitlab(false)
    }
  }

  const addRepo = async (glRepo: any) => {
    try {
      await api.addRepository({
        gitlab_id: glRepo.id,
        name: glRepo.name,
        full_path: glRepo.path_with_namespace,
        url: glRepo.http_url_to_repo,
        default_branch: glRepo.default_branch || 'main',
      })
      const updated = await api.getRepositories()
      setRepos(updated)
      setTab('added')
    } catch (e: any) {
      alert(`Failed to add repository: ${e.message}`)
    }
  }

  const startScan = async (repo: Repository) => {
    setScanning(repo.id)
    try {
      const result = await api.startScan({ repository_id: repo.id, branch: repo.default_branch })
      onStartScan(result.scan_id)
    } catch (e: any) {
      alert(`Failed to start scan: ${e.message}`)
    } finally {
      setScanning(null)
    }
  }

  const filtered = gitlabRepos.filter(r =>
    r.name_with_namespace?.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="p-6 space-y-5 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-fg">Repositories</h1>
          <p className="text-sm text-fg-muted mt-0.5">Browse and scan GitLab repositories</p>
        </div>
        <button
          onClick={loadGitLabRepos}
          disabled={loadingGitlab}
          className="flex items-center gap-2 px-4 py-2 bg-accent-blue hover:bg-blue-500 text-white rounded-md text-sm font-medium transition-colors disabled:opacity-60"
        >
          {loadingGitlab ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
          Browse GitLab
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border">
        {(['added', 'browse'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-mono border-b-2 transition-colors ${
              tab === t ? 'border-accent-blue text-fg' : 'border-transparent text-fg-muted hover:text-fg'
            }`}
          >
            {t === 'added' ? `Added Repositories (${repos.length})` : `Browse GitLab (${gitlabRepos.length})`}
          </button>
        ))}
      </div>

      {tab === 'added' && (
        <div className="space-y-2">
          {loading ? (
            <div className="text-fg-muted font-mono text-sm py-8 text-center">Loading...</div>
          ) : repos.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-fg-muted">
              <GitBranch className="w-12 h-12 mb-4 text-fg-subtle" />
              <p className="font-mono text-sm mb-2">No repositories added yet</p>
              <p className="text-xs text-fg-subtle">Click "Browse GitLab" to add repositories</p>
            </div>
          ) : (
            repos.map(repo => (
              <div key={repo.id} className="bg-surface border border-border rounded-lg p-4 flex items-center gap-4">
                <GitBranch className="w-5 h-5 text-accent-blue shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-fg font-mono">{repo.name}</p>
                  <p className="text-xs text-fg-muted font-mono">{repo.full_path}</p>
                  {repo.last_scanned_at && (
                    <p className="text-xs text-fg-subtle mt-0.5">
                      Last scanned: {new Date(repo.last_scanned_at).toLocaleString()}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs font-mono text-fg-muted bg-elevated px-2 py-1 rounded">
                    {repo.default_branch}
                  </span>
                  <button
                    onClick={() => startScan(repo)}
                    disabled={scanning === repo.id}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-accent-blue/10 text-accent-blue border border-accent-blue/30 rounded-md text-xs font-mono hover:bg-accent-blue/20 transition-colors disabled:opacity-50"
                  >
                    {scanning === repo.id ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Search className="w-3.5 h-3.5" />
                    )}
                    {scanning === repo.id ? 'Starting...' : 'Scan'}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {tab === 'browse' && (
        <div className="space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-fg-subtle" />
            <input
              type="text"
              placeholder="Search repositories..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full bg-elevated border border-border rounded-md pl-9 pr-4 py-2 text-sm text-fg placeholder:text-fg-subtle font-mono focus:outline-none focus:border-border-active"
            />
          </div>

          <div className="space-y-2">
            {filtered.slice(0, 50).map((repo: any) => {
              const alreadyAdded = repos.some(r => r.gitlab_id === repo.id)
              return (
                <div key={repo.id} className="bg-surface border border-border rounded-lg p-4 flex items-center gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-fg font-mono">{repo.name}</p>
                      {repo.visibility && (
                        <span className="text-xs bg-elevated px-1.5 py-0.5 rounded text-fg-subtle font-mono">{repo.visibility}</span>
                      )}
                    </div>
                    <p className="text-xs text-fg-muted font-mono">{repo.path_with_namespace}</p>
                    {repo.description && <p className="text-xs text-fg-subtle mt-0.5 truncate">{repo.description}</p>}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <a href={repo.web_url} target="_blank" rel="noreferrer"
                      className="text-fg-subtle hover:text-fg transition-colors">
                      <ExternalLink className="w-4 h-4" />
                    </a>
                    {alreadyAdded ? (
                      <span className="text-xs font-mono text-accent-green px-2 py-1 bg-accent-green/10 rounded">Added</span>
                    ) : (
                      <button
                        onClick={() => addRepo(repo)}
                        className="flex items-center gap-1 px-3 py-1.5 bg-elevated border border-border text-fg-muted rounded-md text-xs font-mono hover:text-fg hover:border-border-active/50 transition-colors"
                      >
                        <Plus className="w-3 h-3" />
                        Add
                      </button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
