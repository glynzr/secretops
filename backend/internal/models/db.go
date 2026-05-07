package models

import (
	"database/sql"
	"os"
	"path/filepath"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct{ *sql.DB }

func NewDB(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	if err := createTables(db); err != nil {
		return nil, err
	}
	if err := runMigrations(db); err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

func createTables(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS organizations (
		id         TEXT PRIMARY KEY,
		name       TEXT NOT NULL,
		slug       TEXT UNIQUE NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	INSERT OR IGNORE INTO organizations(id, name, slug) VALUES('default', 'My Organization', 'default');

	CREATE TABLE IF NOT EXISTS connections (
		id           TEXT PRIMARY KEY,
		org_id       TEXT NOT NULL DEFAULT 'default',
		type         TEXT NOT NULL,
		config       TEXT NOT NULL DEFAULT '{}',
		status       TEXT NOT NULL DEFAULT 'disconnected',
		error_msg    TEXT NOT NULL DEFAULT '',
		connected_at TEXT,
		created_at   TEXT NOT NULL DEFAULT (datetime('now')),
		UNIQUE(org_id, type)
	);
	CREATE TABLE IF NOT EXISTS scan_jobs (
		id             TEXT PRIMARY KEY,
		org_id         TEXT NOT NULL DEFAULT 'default',
		repo_url       TEXT NOT NULL,
		repo_name      TEXT NOT NULL DEFAULT '',
		branch         TEXT NOT NULL DEFAULT 'main',
		source         TEXT NOT NULL DEFAULT 'gitlab',
		status         TEXT NOT NULL DEFAULT 'pending',
		ai_model       TEXT NOT NULL DEFAULT 'claude-3-5-sonnet-20241022',
		total_files    INTEGER NOT NULL DEFAULT 0,
		scanned_files  INTEGER NOT NULL DEFAULT 0,
		finding_count  INTEGER NOT NULL DEFAULT 0,
		error_msg      TEXT NOT NULL DEFAULT '',
		created_at     TEXT NOT NULL DEFAULT (datetime('now')),
		updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS findings (
		id                   TEXT PRIMARY KEY,
		scan_id              TEXT NOT NULL,
		file_path            TEXT NOT NULL,
		line_number          INTEGER NOT NULL DEFAULT 0,
		candidate_value      TEXT NOT NULL DEFAULT '',
		context_code         TEXT NOT NULL DEFAULT '',
		is_secret            INTEGER NOT NULL DEFAULT 0,
		confidence           REAL NOT NULL DEFAULT 0,
		secret_type          TEXT NOT NULL DEFAULT 'unknown',
		severity             TEXT NOT NULL DEFAULT 'medium',
		reasoning            TEXT NOT NULL DEFAULT '',
		status               TEXT NOT NULL DEFAULT 'open',
		ai_model             TEXT NOT NULL DEFAULT '',
		env_var_suggestion   TEXT NOT NULL DEFAULT '',
		vault_path_suggestion TEXT NOT NULL DEFAULT '',
		commit_author        TEXT NOT NULL DEFAULT '',
		commit_email         TEXT NOT NULL DEFAULT '',
		days_in_history      INTEGER NOT NULL DEFAULT 0,
		history_alert_level  TEXT NOT NULL DEFAULT 'none',
		first_seen_date      TEXT NOT NULL DEFAULT '',
		remediation_id       TEXT NOT NULL DEFAULT '',
		created_at           TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS remediation_jobs (
		id                 TEXT PRIMARY KEY,
		finding_id         TEXT NOT NULL,
		scan_id            TEXT NOT NULL,
		repo_url           TEXT NOT NULL DEFAULT '',
		status             TEXT NOT NULL DEFAULT 'pending',
		vault_path         TEXT NOT NULL DEFAULT '',
		vault_status       TEXT NOT NULL DEFAULT '',
		mr_url             TEXT NOT NULL DEFAULT '',
		mr_number          INTEGER NOT NULL DEFAULT 0,
		mr_branch          TEXT NOT NULL DEFAULT '',
		patch_content      TEXT NOT NULL DEFAULT '',
		env_var_name       TEXT NOT NULL DEFAULT '',
		issue_url          TEXT NOT NULL DEFAULT '',
		issue_number       INTEGER NOT NULL DEFAULT 0,
		slack_status       TEXT NOT NULL DEFAULT '',
		email_status       TEXT NOT NULL DEFAULT '',
		revocation_status  TEXT NOT NULL DEFAULT '',
		revocation_msg     TEXT NOT NULL DEFAULT '',
		history_alert_sent INTEGER NOT NULL DEFAULT 0,
		post_merge_status  TEXT NOT NULL DEFAULT 'pending',
		error_msg          TEXT NOT NULL DEFAULT '',
		created_at         TEXT NOT NULL DEFAULT (datetime('now')),
		updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS history_alerts (
		id                TEXT PRIMARY KEY,
		finding_id        TEXT NOT NULL,
		scan_id           TEXT NOT NULL,
		repo_name         TEXT NOT NULL DEFAULT '',
		days_exposed      INTEGER NOT NULL DEFAULT 0,
		alert_level       TEXT NOT NULL DEFAULT 'INFO',
		first_seen_commit TEXT NOT NULL DEFAULT '',
		first_seen_author TEXT NOT NULL DEFAULT '',
		first_seen_date   TEXT NOT NULL DEFAULT '',
		commit_count      INTEGER NOT NULL DEFAULT 0,
		slack_sent        INTEGER NOT NULL DEFAULT 0,
		email_sent        INTEGER NOT NULL DEFAULT 0,
		created_at        TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS imported_projects (
		id                   TEXT PRIMARY KEY,
		org_id               TEXT NOT NULL DEFAULT 'default',
		gitlab_id            INTEGER NOT NULL,
		name                 TEXT NOT NULL,
		path_with_namespace  TEXT NOT NULL,
		http_url_to_repo     TEXT NOT NULL,
		default_branch       TEXT NOT NULL DEFAULT 'main',
		visibility           TEXT NOT NULL DEFAULT 'private',
		namespace_name       TEXT NOT NULL DEFAULT '',
		last_activity_at     TEXT NOT NULL DEFAULT '',
		imported_at          TEXT NOT NULL DEFAULT (datetime('now')),
		UNIQUE(org_id, gitlab_id)
	);`)
	return err
}

func tableHasColumn(db *sql.DB, table, column string) bool {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var dflt interface{}
		rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk)
		if name == column {
			return true
		}
	}
	return false
}

func runMigrations(db *sql.DB) error {
	// Migrate connections: change unique constraint from (type) to (org_id, type)
	if !tableHasColumn(db, "connections", "org_id") {
		db.Exec(`CREATE TABLE connections_v2 (
			id           TEXT PRIMARY KEY,
			org_id       TEXT NOT NULL DEFAULT 'default',
			type         TEXT NOT NULL,
			config       TEXT NOT NULL DEFAULT '{}',
			status       TEXT NOT NULL DEFAULT 'disconnected',
			error_msg    TEXT NOT NULL DEFAULT '',
			connected_at TEXT,
			created_at   TEXT NOT NULL DEFAULT (datetime('now')),
			UNIQUE(org_id, type)
		)`)
		db.Exec(`INSERT OR IGNORE INTO connections_v2(id,org_id,type,config,status,error_msg,connected_at,created_at)
			SELECT id,'default',type,config,status,error_msg,connected_at,created_at FROM connections`)
		db.Exec(`DROP TABLE connections`)
		db.Exec(`ALTER TABLE connections_v2 RENAME TO connections`)
	}

	// Add org_id to scan_jobs
	if !tableHasColumn(db, "scan_jobs", "org_id") {
		db.Exec(`ALTER TABLE scan_jobs ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'`)
	}

	return nil
}
