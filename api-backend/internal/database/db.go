package database

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func Initialize(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return db, nil
}

func migrate(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS integrations (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL CHECK(type IN ('ai_provider','gitlab','vault','slack','smtp')),
		config_encrypted TEXT NOT NULL,
		is_active INTEGER DEFAULT 1,
		last_tested_at DATETIME,
		test_status TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS repositories (
		id TEXT PRIMARY KEY,
		gitlab_integration_id TEXT REFERENCES integrations(id),
		project_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		full_path TEXT NOT NULL,
		default_branch TEXT DEFAULT 'main',
		clone_url TEXT NOT NULL,
		added_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		repository_id TEXT REFERENCES repositories(id),
		status TEXT DEFAULT 'pending' CHECK(status IN ('pending','cloning','git_history','scanning','complete','failed')),
		total_files INTEGER DEFAULT 0,
		scanned_files INTEGER DEFAULT 0,
		findings_count INTEGER DEFAULT 0,
		started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME,
		error_message TEXT
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		scan_id TEXT REFERENCES scans(id),
		repository_id TEXT REFERENCES repositories(id),
		file_path TEXT NOT NULL,
		line_number INTEGER NOT NULL,
		secret_type TEXT NOT NULL,
		raw_value_hash TEXT NOT NULL,
		masked_value TEXT,
		ai_confidence REAL,
		ai_reasoning TEXT,
		ai_model TEXT,
		severity TEXT DEFAULT 'high',
		status TEXT DEFAULT 'open' CHECK(status IN ('open','confirmed','false_positive','ignored','closed')),
		first_commit_hash TEXT,
		first_commit_author TEXT,
		first_commit_date DATETIME,
		total_commit_count INTEGER DEFAULT 0,
		days_exposed INTEGER DEFAULT 0,
		vault_path TEXT,
		vault_placeholder TEXT,
		mr_url TEXT,
		issue_url TEXT,
		remediation_id TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS remediations (
		id TEXT PRIMARY KEY,
		finding_id TEXT REFERENCES findings(id),
		status TEXT DEFAULT 'pending' CHECK(status IN ('pending','patching','branch_created','mr_open','verifying','complete','failed')),
		branch_name TEXT,
		mr_url TEXT,
		mr_iid INTEGER,
		issue_url TEXT,
		patch_diff TEXT,
		vault_path TEXT,
		vault_placeholder TEXT,
		rotation_checklist TEXT,
		provider_revoked INTEGER DEFAULT 0,
		started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME,
		error_message TEXT
	);

	CREATE TABLE IF NOT EXISTS verification_checks (
		id TEXT PRIMARY KEY,
		finding_id TEXT REFERENCES findings(id),
		remediation_id TEXT REFERENCES remediations(id),
		vault_value_hash TEXT,
		original_hash TEXT,
		result TEXT CHECK(result IN ('rotated','placeholder','same','error')),
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		alert_sent INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS notification_log (
		id TEXT PRIMARY KEY,
		finding_id TEXT,
		channel TEXT,
		subject TEXT,
		status TEXT,
		sent_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
	CREATE INDEX IF NOT EXISTS idx_remediations_finding ON remediations(finding_id);
	CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repository_id);
	`

	_, err := db.Exec(schema)
	return err
}
