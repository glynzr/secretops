package db

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

func Initialize(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", fmt.Sprintf("%s?_journal_mode=WAL&_foreign_keys=on", path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func RunMigrations(db *sql.DB) error {
	schema := `
	-- Organisations (Snyk-style multi-tenant)
	CREATE TABLE IF NOT EXISTS organisations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		slug TEXT NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT OR IGNORE INTO organisations (id, name, slug) VALUES (1, 'Default', 'default');

	CREATE TABLE IF NOT EXISTS integrations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id INTEGER NOT NULL DEFAULT 1,
		type TEXT NOT NULL,
		config TEXT NOT NULL DEFAULT '{}',
		encrypted_secrets TEXT,
		status TEXT DEFAULT 'untested',
		last_tested_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(org_id, type),
		FOREIGN KEY (org_id) REFERENCES organisations(id)
	);

	CREATE TABLE IF NOT EXISTS repositories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id INTEGER NOT NULL DEFAULT 1,
		provider TEXT NOT NULL DEFAULT 'gitlab',
		remote_id TEXT,
		name TEXT NOT NULL,
		full_path TEXT NOT NULL,
		url TEXT NOT NULL,
		default_branch TEXT DEFAULT 'main',
		last_scanned_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (org_id) REFERENCES organisations(id)
	);

	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id INTEGER NOT NULL DEFAULT 1,
		repository_id INTEGER NOT NULL,
		status TEXT DEFAULT 'pending',
		stage TEXT DEFAULT 'initializing',
		total_files INTEGER DEFAULT 0,
		scanned_files INTEGER DEFAULT 0,
		findings_count INTEGER DEFAULT 0,
		started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME,
		error_message TEXT,
		FOREIGN KEY (repository_id) REFERENCES repositories(id),
		FOREIGN KEY (org_id) REFERENCES organisations(id)
	);

	CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id INTEGER NOT NULL DEFAULT 1,
		scan_id INTEGER NOT NULL,
		repository_id INTEGER NOT NULL,
		file_path TEXT NOT NULL,
		line_number INTEGER,
		secret_type TEXT NOT NULL,
		raw_value_hash TEXT NOT NULL,
		masked_value TEXT,
		ai_confidence REAL DEFAULT 0,
		ai_reasoning TEXT,
		ai_model TEXT,
		severity TEXT DEFAULT 'high',
		status TEXT DEFAULT 'open',
		detection_stage TEXT,
		first_commit_hash TEXT,
		first_commit_author TEXT,
		first_commit_date DATETIME,
		total_commits INTEGER DEFAULT 0,
		days_exposed INTEGER DEFAULT 0,
		vault_path TEXT,
		vault_poisoned INTEGER DEFAULT 0,
		mr_url TEXT,
		mr_id TEXT,
		issue_url TEXT,
		branch_name TEXT,
		remediation_status TEXT DEFAULT 'none',
		revoked INTEGER DEFAULT 0,
		rotation_confirmed INTEGER DEFAULT 0,
		source_url TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id),
		FOREIGN KEY (repository_id) REFERENCES repositories(id)
	);

	CREATE TABLE IF NOT EXISTS jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id INTEGER NOT NULL DEFAULT 1,
		finding_id INTEGER,
		scan_id INTEGER,
		type TEXT NOT NULL,
		status TEXT DEFAULT 'pending',
		payload TEXT,
		result TEXT,
		error TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		started_at DATETIME,
		completed_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id INTEGER NOT NULL DEFAULT 1,
		action TEXT NOT NULL,
		entity_type TEXT,
		entity_id INTEGER,
		details TEXT,
		user_id TEXT DEFAULT 'system',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS notification_recipients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id INTEGER NOT NULL DEFAULT 1,
		email TEXT NOT NULL,
		name TEXT,
		role TEXT DEFAULT 'engineer',
		active INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(org_id, email)
	);

	CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
	CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id);
	CREATE INDEX IF NOT EXISTS idx_findings_repository ON findings(repository_id);
	CREATE INDEX IF NOT EXISTS idx_repos_org ON repositories(org_id);
	CREATE INDEX IF NOT EXISTS idx_integrations_org ON integrations(org_id);
	`
	_, err := db.Exec(schema)
	if err != nil {
		return err
	}
	// Idempotent migrations for columns added after initial release
	migrations := []string{
		`ALTER TABLE findings ADD COLUMN source_url TEXT DEFAULT ''`,
		`ALTER TABLE repositories ADD COLUMN provider TEXT DEFAULT 'gitlab'`,
		`ALTER TABLE repositories ADD COLUMN remote_id TEXT DEFAULT ''`,
		`ALTER TABLE integrations ADD COLUMN org_id INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE scans ADD COLUMN org_id INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE findings ADD COLUMN org_id INTEGER NOT NULL DEFAULT 1`,
	}
	for _, m := range migrations {
		db.Exec(m) // ignore errors — column may already exist
	}
	return nil
}
