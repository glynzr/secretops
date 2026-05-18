package models

import "time"

type Integration struct {
	ID               int64      `json:"id"`
	Type             string     `json:"type"`
	Provider         string     `json:"provider"`
	Config           string     `json:"config"`
	EncryptedSecrets string     `json:"-"`
	Status           string     `json:"status"`
	LastTestedAt     *time.Time `json:"last_tested_at"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type Repository struct {
	ID            int64      `json:"id"`
	Provider      string     `json:"provider"`
	RemoteID      string     `json:"remote_id"`
	GitlabID      int64      `json:"gitlab_id"`
	Name          string     `json:"name"`
	FullPath      string     `json:"full_path"`
	URL           string     `json:"url"`
	DefaultBranch string     `json:"default_branch"`
	LastScannedAt *time.Time `json:"last_scanned_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

type Scan struct {
	ID            int64      `json:"id"`
	RepositoryID  int64      `json:"repository_id"`
	Status        string     `json:"status"`
	Stage         string     `json:"stage"`
	TotalFiles    int        `json:"total_files"`
	ScannedFiles  int        `json:"scanned_files"`
	FindingsCount int        `json:"findings_count"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at"`
	ErrorMessage  string     `json:"error_message,omitempty"`
}

type Finding struct {
	ID                int64      `json:"id"`
	ScanID            int64      `json:"scan_id"`
	RepositoryID      int64      `json:"repository_id"`
	FilePath          string     `json:"file_path"`
	LineNumber        int        `json:"line_number"`
	SecretType        string     `json:"secret_type"`
	RawValueHash      string     `json:"raw_value_hash"`
	MaskedValue       string     `json:"masked_value"`
	AIConfidence      float64    `json:"ai_confidence"`
	AIReasoning       string     `json:"ai_reasoning"`
	AIModel           string     `json:"ai_model"`
	Severity          string     `json:"severity"`
	Status            string     `json:"status"`
	DetectionStage    string     `json:"detection_stage"`
	FirstCommitHash   string     `json:"first_commit_hash"`
	FirstCommitAuthor string     `json:"first_commit_author"`
	FirstCommitDate   *time.Time `json:"first_commit_date"`
	TotalCommits      int        `json:"total_commits"`
	DaysExposed       int        `json:"days_exposed"`
	VaultPath         string     `json:"vault_path"`
	VaultPoisoned     bool       `json:"vault_poisoned"`
	MrURL             string     `json:"mr_url"`
	MrID              string     `json:"mr_id"`
	IssueURL          string     `json:"issue_url"`
	BranchName        string     `json:"branch_name"`
	RemediationStatus string     `json:"remediation_status"`
	Revoked           bool       `json:"revoked"`
	RotationConfirmed bool       `json:"rotation_confirmed"`
	SourceURL         string     `json:"source_url"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type Job struct {
	ID          int64      `json:"id"`
	Type        string     `json:"type"`
	Status      string     `json:"status"`
	Payload     string     `json:"payload"`
	Result      string     `json:"result"`
	Error       string     `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

type NotificationRecipient struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditLog struct {
	ID         int64     `json:"id"`
	Action     string    `json:"action"`
	EntityType string    `json:"entity_type"`
	EntityID   int64     `json:"entity_id"`
	Details    string    `json:"details"`
	CreatedAt  time.Time `json:"created_at"`
}
