const BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080/api/v1'

async function f<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts?.headers }, ...opts,
  })
  if (!res.ok) {
    const e = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(e.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export interface Organization { id: string; name: string; slug: string; created_at: string }
export interface ImportedProject {
  id: string; org_id: string; gitlab_id: number
  name: string; path_with_namespace: string; http_url_to_repo: string
  default_branch: string; visibility: string; namespace_name: string
  last_activity_at: string; imported_at: string
  scan_count: number; last_finding_count: number
  last_scan_status?: string; last_scan_id?: string
}
export interface OrgStats {
  total_findings: number; open_findings: number
  critical: number; high: number
  project_count: number; scan_count: number
}
export interface Connection { id: string; type: string; status: string; config: Record<string,string>; connected_at?: string; created_at: string; error_msg?: string }
export interface ScanJob { id: string; repo_url: string; repo_name: string; branch: string; status: string; ai_model: string; total_files: number; scanned_files: number; finding_count: number; error_msg: string; created_at: string; updated_at: string }
export interface Finding { id: string; scan_id: string; file_path: string; line_number: number; candidate_value: string; context_code: string; is_secret: boolean; confidence: number; secret_type: string; severity: string; reasoning: string; status: string; ai_model: string; env_var_suggestion: string; vault_path_suggestion: string; commit_author: string; commit_email: string; days_in_history: number; history_alert_level: string; first_seen_date: string; remediation_id: string; created_at: string }
export interface Remediation { id: string; finding_id: string; scan_id: string; repo_url: string; status: string; vault_path: string; vault_status: string; mr_url: string; mr_number: number; mr_branch: string; patch_content: string; env_var_name: string; issue_url: string; issue_number: number; slack_status: string; email_status: string; revocation_status: string; revocation_msg: string; post_merge_status: string; error_msg: string; created_at: string; updated_at: string }
export interface HistoryAlert { id: string; finding_id: string; days_exposed: number; alert_level: string; first_seen_author: string; first_seen_date: string; commit_count: number; repo_name: string; created_at: string }
export interface GitLabRepo { id: number; name: string; path_with_namespace: string; http_url_to_repo: string; default_branch: string; visibility: string; description: string; last_activity_at: string; namespace: { name: string } }

// Org-scoped API — all calls under /orgs/:orgId/...
export function orgApi(orgId: string) {
  const base = `/orgs/${orgId}`
  return {
    // Connections
    listConnections: () => f<Connection[]>(`${base}/connections`),
    saveConnection: (type: string, config: Record<string,string>) =>
      f<{id:string;status:string}>(`${base}/connections/${type}`, {method:'PUT', body: JSON.stringify(config)}),
    testConnection: (type: string) =>
      f<{connected:boolean;status:string;error?:string}>(`${base}/connections/${type}/test`, {method:'POST'}),
    deleteConnection: (type: string) =>
      f<{deleted:boolean}>(`${base}/connections/${type}`, {method:'DELETE'}),

    // GitLab proxy
    gitlabRepos: (p?: {search?:string;page?:string;group_id?:string}) => {
      const q = new URLSearchParams(Object.fromEntries(Object.entries(p||{}).filter(([,v])=>v))).toString()
      return f<{repos:GitLabRepo[];page:number;total_pages:string;total:string}>(`${base}/gitlab/repos${q?'?'+q:''}`)
    },
    gitlabGroups: () => f<{groups:{id:number;name:string;full_path:string}[]}>(`${base}/gitlab/groups`),

    // Imported projects
    listProjects: () => f<ImportedProject[]>(`${base}/projects`),
    importProject: (repo: GitLabRepo) => f<{id:string;org_id:string}>(`${base}/projects`, {
      method: 'POST',
      body: JSON.stringify({
        gitlab_id: repo.id, name: repo.name,
        path_with_namespace: repo.path_with_namespace,
        http_url_to_repo: repo.http_url_to_repo,
        default_branch: repo.default_branch || 'main',
        visibility: repo.visibility,
        namespace_name: repo.namespace?.name || '',
        last_activity_at: repo.last_activity_at,
      }),
    }),
    removeProject: (id: string) => f<{deleted:boolean}>(`${base}/projects/${id}`, {method:'DELETE'}),

    // Scans
    listScans: () => f<ScanJob[]>(`${base}/scans`),
    createScan: (d: Record<string,string>) =>
      f<{id:string;status:string}>(`${base}/scans`, {method:'POST', body: JSON.stringify(d)}),

    // Findings
    listFindings: (p?: {status?:string;severity?:string}) => {
      const q = new URLSearchParams(Object.fromEntries(Object.entries(p||{}).filter(([,v])=>v))).toString()
      return f<Finding[]>(`${base}/findings${q?'?'+q:''}`)
    },

    // Remediations
    listRemediations: () => f<Remediation[]>(`${base}/remediations`),

    // History alerts
    listHistoryAlerts: () => f<HistoryAlert[]>(`${base}/history-alerts`),

    // Stats
    getStats: () => f<OrgStats>(`${base}/stats`),
  }
}

// Global / non-org-scoped calls (legacy, used by old routes + CLI callbacks)
export const api = {
  // Orgs
  listOrgs: () => f<Organization[]>('/orgs'),
  createOrg: (name: string) => f<Organization>('/orgs', {method:'POST', body: JSON.stringify({name})}),
  deleteOrg: (id: string) => f<{deleted:boolean}>(`/orgs/${id}`, {method:'DELETE'}),
  updateOrg: (id: string, name: string) => f<{updated:boolean}>(`/orgs/${id}`, {method:'PUT', body: JSON.stringify({name})}),

  // Scan-level operations (still non-org-scoped for CLI service compatibility)
  getScan: (id: string) => f<ScanJob>(`/scans/${id}`),
  getScanFindings: (id: string) => f<Finding[]>(`/scans/${id}/findings`),
  updateFindingStatus: (id: string, status: string) =>
    f<{updated:boolean}>(`/findings/${id}/status`, {method:'PATCH', body: JSON.stringify({status})}),
  remediate: (id: string) => f<{remediation_id:string}>(`/findings/${id}/remediate`, {method:'POST'}),
  postMergeVerify: (id: string) =>
    f<{status:string}>(`/remediations/${id}/verify`, {method:'POST'}),
}
