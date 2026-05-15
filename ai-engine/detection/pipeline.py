"""
3-Stage Detection Pipeline:
Stage 1: Regex pre-filter (patterns.py)
Stage 2: LLM classification (llm_classifier.py) 
Stage 3: Git history correlation (git_ops/history.py)
"""
import json
import logging
import os
import sqlite3
import tempfile
from datetime import datetime

from detection.patterns import scan_file_content, is_false_positive
from detection.llm_classifier import LLMClassifier
from detection.utils import hash_sha256, mask_secret
from git_ops.history import clone_repository, get_file_list, analyze_secret_history

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/secretops.db")
CLONE_DIR = os.environ.get("CLONE_DIR", "/tmp/secretops-repos")


SCHEMA = """
CREATE TABLE IF NOT EXISTS integrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL UNIQUE,
    config TEXT NOT NULL DEFAULT '{}',
    encrypted_secrets TEXT,
    status TEXT DEFAULT 'untested',
    last_tested_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS repositories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gitlab_id INTEGER,
    name TEXT NOT NULL,
    full_path TEXT NOT NULL,
    url TEXT NOT NULL,
    default_branch TEXT DEFAULT 'main',
    last_scanned_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER,
    status TEXT DEFAULT 'pending',
    stage TEXT DEFAULT '',
    total_files INTEGER DEFAULT 0,
    scanned_files INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    error_message TEXT DEFAULT '',
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    repository_id INTEGER,
    file_path TEXT NOT NULL,
    line_number INTEGER DEFAULT 0,
    secret_type TEXT NOT NULL,
    raw_value_hash TEXT NOT NULL,
    masked_value TEXT,
    ai_confidence REAL DEFAULT 0,
    ai_reasoning TEXT DEFAULT '',
    ai_model TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'open',
    detection_stage TEXT DEFAULT '',
    first_commit_hash TEXT DEFAULT '',
    first_commit_author TEXT DEFAULT '',
    first_commit_date DATETIME,
    total_commits INTEGER DEFAULT 0,
    days_exposed INTEGER DEFAULT 0,
    vault_path TEXT DEFAULT '',
    vault_poisoned INTEGER DEFAULT 0,
    mr_url TEXT DEFAULT '',
    mr_id TEXT DEFAULT '',
    issue_url TEXT DEFAULT '',
    branch_name TEXT DEFAULT '',
    remediation_status TEXT DEFAULT '',
    revoked INTEGER DEFAULT 0,
    rotation_confirmed INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, file_path, line_number, raw_value_hash)
);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    scan_id INTEGER,
    job_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    payload TEXT DEFAULT '',
    result TEXT DEFAULT '',
    error TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    started_at DATETIME,
    completed_at DATETIME
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    details TEXT,
    user_id TEXT DEFAULT 'system',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notification_recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'developer',
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    # Ensure schema exists (idempotent)
    for stmt in SCHEMA.strip().split(";"):
        stmt = stmt.strip()
        if stmt:
            conn.execute(stmt)
    conn.commit()
    return conn


class DetectionPipeline:
    def __init__(self):
        self.classifier = LLMClassifier(get_db)
    
    def test_provider(self, provider: str, api_key: str) -> dict:
        return self.classifier.test_provider(provider, api_key)
    
    def update_scan(self, db, scan_id: int, **kwargs):
        sets = ", ".join(f"{k}=?" for k in kwargs)
        values = list(kwargs.values()) + [scan_id]
        db.execute(f"UPDATE scans SET {sets} WHERE id=?", values)
        db.commit()
    
    def run_scan(self, payload: dict):
        scan_id = payload["scan_id"]
        repo_id = payload["repo_id"]
        repo_path = payload["repo_path"]
        repo_url = payload["repo_url"]
        branch = payload.get("branch", "main")
        gitlab_url = payload["gitlab_url"]
        gitlab_token = payload["gitlab_token"]
        
        db = get_db()
        
        try:
            logger.info(f"[scan:{scan_id}] Starting for {repo_path}")
            self.update_scan(db, scan_id, stage="cloning", status="running")
            
            # Clone repository
            try:
                logger.info(f"[scan:{scan_id}] Cloning {repo_url}")
                local_path = clone_repository(gitlab_url, repo_path, gitlab_token, CLONE_DIR)
                logger.info(f"[scan:{scan_id}] Clone complete: {local_path}")
            except Exception as e:
                logger.error(f"[scan:{scan_id}] Clone failed: {e}")
                self.update_scan(db, scan_id, status="failed", stage="failed",
                               error_message=f"Clone failed: {e}", completed_at=datetime.utcnow().isoformat())
                return
            
            # Get file list
            self.update_scan(db, scan_id, stage="indexing")
            files = get_file_list(local_path)
            total_files = len(files)
            logger.info(f"[scan:{scan_id}] Found {total_files} files to scan")
            self.update_scan(db, scan_id, total_files=total_files, stage="scanning")
            
            logger.info(f"Scan {scan_id}: scanning {total_files} files")
            
            findings_count = 0
            
            for idx, file_path in enumerate(files):
                try:
                    full_path = os.path.join(local_path, file_path)
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    
                    # Stage 1: Regex pattern matching
                    candidates = scan_file_content(content)
                    
                    lines = content.split("\n")
                    
                    for candidate in candidates:
                        # Build context window (5 lines before/after)
                        start = max(0, candidate.line_number - 6)
                        end = min(len(lines), candidate.line_number + 5)
                        context = "\n".join(f"{i+start+1}: {l}" for i, l in enumerate(lines[start:end]))
                        
                        masked = mask_secret(candidate.value)
                        value_hash = hash_sha256(candidate.value)
                        
                        ai_result = None
                        ai_model = "regex_only"
                        final_confidence = candidate.confidence
                        final_severity = candidate.severity
                        ai_reasoning = "Detected via high-specificity regex pattern with high entropy."
                        is_secret = True
                        
                        # Stage 2: LLM classification (only if not high-confidence regex match)
                        if not candidate.skip_llm:
                            try:
                                ai_result = self.classifier.classify(
                                    secret_type=candidate.secret_type,
                                    file_path=file_path,
                                    line_number=candidate.line_number,
                                    context=context,
                                    masked_value=masked
                                )
                                if ai_result:
                                    is_secret = ai_result.get("is_secret", True)
                                    final_confidence = ai_result.get("confidence", candidate.confidence)
                                    final_severity = ai_result.get("severity", candidate.severity)
                                    ai_reasoning = ai_result.get("reasoning", "")
                                    ai_model = ai_result.get("_model", "unknown")
                                    
                                    if not is_secret:
                                        continue  # Skip false positive
                            except Exception as e:
                                logger.warning(f"LLM classification failed for {file_path}:{candidate.line_number}: {e}")
                        
                        if not is_secret:
                            continue
                        
                        # Stage 3: Git history correlation
                        history = analyze_secret_history(local_path, candidate.value)
                        
                        first_commit_hash = ""
                        first_commit_author = ""
                        first_commit_date = None
                        total_commits = history.total_commits
                        days_exposed = history.days_exposed
                        
                        if history.first_commit:
                            first_commit_hash = history.first_commit.hash
                            first_commit_author = history.first_commit.author_email
                            first_commit_date = history.first_commit.date.isoformat()
                        
                        detection_stage = "regex_highconf" if candidate.skip_llm else "llm_classified"
                        
                        # Save finding
                        db.execute("""
                            INSERT OR IGNORE INTO findings 
                            (scan_id, repository_id, file_path, line_number, secret_type,
                             raw_value_hash, masked_value, ai_confidence, ai_reasoning, ai_model,
                             severity, status, detection_stage, first_commit_hash, first_commit_author,
                             first_commit_date, total_commits, days_exposed)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """, (
                            scan_id, repo_id, file_path, candidate.line_number,
                            candidate.secret_type, value_hash, masked,
                            final_confidence, ai_reasoning, ai_model,
                            final_severity, "open", detection_stage,
                            first_commit_hash, first_commit_author, first_commit_date,
                            total_commits, days_exposed
                        ))
                        db.commit()
                        findings_count += 1
                
                except Exception as e:
                    logger.error(f"Error scanning file {file_path}: {e}")
                
                # Update progress
                self.update_scan(db, scan_id, 
                               scanned_files=idx + 1, 
                               findings_count=findings_count,
                               stage=f"scanning ({idx+1}/{total_files})")
            
            # Complete scan
            self.update_scan(db, scan_id,
                           status="completed",
                           stage="completed", 
                           findings_count=findings_count,
                           scanned_files=total_files,
                           completed_at=datetime.utcnow().isoformat())
            
            # Update repo last scanned
            db.execute("UPDATE repositories SET last_scanned_at=? WHERE id=?",
                      (datetime.utcnow().isoformat(), repo_id))
            db.commit()
            
            logger.info(f"Scan {scan_id} completed: {findings_count} findings in {total_files} files")
        
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            self.update_scan(db, scan_id, 
                           status="failed", stage="failed",
                           error_message=str(e),
                           completed_at=datetime.utcnow().isoformat())
        finally:
            db.close()
