export interface Integration {
  id: number
  provider: string
  config: Record<string, any>
  status: 'untested' | 'connected' | 'error'
  message?: string
  last_tested_at: string | null
  created_at: string
  updated_at: string
}

export interface Repository {
  id: number
  gitlab_id: number
  name: string
  full_path: string
  url: string
  default_branch: string
  last_scanned_at: string | null
  created_at: string
}

export interface Scan {
  id: number
  repository_id: number
  status: 'pending' | 'running' | 'completed' | 'failed'
  stage: string
  total_files: number
  scanned_files: number
  findings_count: number
  started_at: string
  completed_at: string | null
  error_message?: string
}

export interface Finding {
  id: number
  scan_id: number
  repository_id: number
  file_path: string
  line_number: number
  secret_type: string
  raw_value_hash: string
  masked_value: string
  ai_confidence: number
  ai_reasoning: string
  ai_model: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: string
  detection_stage: string
  first_commit_hash?: string
  commit_author?: string
  first_commit_author?: string
  first_commit_date?: string | null
  commit_count?: number
  total_commits?: number
  days_exposed?: number
  vault_path?: string
  vault_poisoned?: boolean
  mr_url?: string
  mr_id?: string
  issue_url?: string
  branch_name?: string
  remediation_status?: string
  revoked?: boolean
  rotation_confirmed?: boolean
  created_at: string
  updated_at: string
}

export interface Stats {
  total_findings: number
  open_findings: number
  confirmed_findings: number
  closed_findings: number
  false_positive_findings: number
  total_scans: number
  active_scans: number
  total_repositories: number
  avg_days_exposed: number
  severity_breakdown: Record<string, number>
  type_breakdown: Record<string, number>
}

export interface Job {
  id: number
  finding_id?: number
  scan_id?: number
  job_type: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  result?: string
  error?: string
  created_at: string
  updated_at: string
}
