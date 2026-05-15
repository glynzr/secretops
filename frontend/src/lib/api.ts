const API_BASE = '/api/v1'

async function request(path: string, options?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  })
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(error.error || `Request failed: ${res.status}`)
  }
  return res.json()
}

export const api = {
  // Stats
  getStats: () => request('/stats'),

  // Integrations
  getIntegrations: () => request('/integrations'),
  saveIntegration: (data: any) => request('/integrations', { method: 'POST', body: JSON.stringify(data) }),
  testIntegration: (type: string) => request(`/integrations/${type}/test`, { method: 'POST' }),
  deleteIntegration: (type: string) => request(`/integrations/${type}`, { method: 'DELETE' }),

  // Repositories
  getRepositories: () => request('/repositories'),
  getGitLabRepositories: () => request('/repositories/gitlab'),
  addRepository: (data: any) => request('/repositories', { method: 'POST', body: JSON.stringify(data) }),

  // Scans
  startScan: (data: any) => request('/scans', { method: 'POST', body: JSON.stringify(data) }),
  getScan: (id: number) => request(`/scans/${id}`),

  // Findings
  getFindings: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request(`/findings${qs}`)
  },
  getFinding: (id: number) => request(`/findings/${id}`),
  updateFindingStatus: (id: number, status: string) =>
    request(`/findings/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  triggerRemediation: (id: number) =>
    request(`/findings/${id}/remediate`, { method: 'POST' }),
  getFindingHistory: (id: number) => request(`/findings/${id}/history`),

  // Jobs
  getJobs: () => request('/jobs'),

  // Recipients
  getRecipients: () => request('/recipients'),
  addRecipient: (data: any) => request('/recipients', { method: 'POST', body: JSON.stringify(data) }),
  deleteRecipient: (id: number) => request(`/recipients/${id}`, { method: 'DELETE' }),

  // Audit
  getAuditLogs: () => request('/audit'),
}
