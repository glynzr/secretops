"""Git history analysis using git log -S for commit tracking."""
import subprocess
import os
import re
import logging
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CommitInfo:
    hash: str
    author_email: str
    author_name: str
    date: datetime
    message: str


@dataclass 
class SecretHistory:
    first_commit: Optional[CommitInfo]
    total_commits: int
    days_exposed: int
    all_commit_hashes: list


def analyze_secret_history(repo_path: str, secret_value: str) -> SecretHistory:
    """Use git log -S to find all commits containing the secret value."""
    try:
        result = subprocess.run(
            ["git", "log", "-S", secret_value, "--format=%H|%ae|%an|%aI|%s", "--all"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        commits = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("|", 4)
            if len(parts) < 5:
                continue
            try:
                date = datetime.fromisoformat(parts[3].replace("Z", "+00:00"))
                commits.append(CommitInfo(
                    hash=parts[0],
                    author_email=parts[1],
                    author_name=parts[2],
                    date=date,
                    message=parts[4]
                ))
            except Exception:
                continue
        
        if not commits:
            return SecretHistory(None, 0, 0, [])
        
        # Sort by date, oldest first
        commits.sort(key=lambda c: c.date)
        first_commit = commits[0]
        
        # Calculate days exposed
        now = datetime.now(timezone.utc)
        days_exposed = (now - first_commit.date).days
        
        return SecretHistory(
            first_commit=first_commit,
            total_commits=len(commits),
            days_exposed=days_exposed,
            all_commit_hashes=[c.hash for c in commits]
        )
    
    except subprocess.TimeoutExpired:
        logger.warning(f"git log -S timed out for repo {repo_path}")
        return SecretHistory(None, 0, 0, [])
    except Exception as e:
        logger.error(f"Failed to analyze git history: {e}")
        return SecretHistory(None, 0, 0, [])


def clone_repository(gitlab_url: str, repo_path: str, token: str, clone_dir: str) -> str:
    """Clone a GitLab repository using token authentication."""
    # Build authenticated URL
    clean_url = gitlab_url.rstrip("/")
    # Format: https://oauth2:TOKEN@gitlab.example.com/group/repo.git
    from urllib.parse import urlparse
    parsed = urlparse(clean_url)
    auth_url = f"{parsed.scheme}://oauth2:{token}@{parsed.netloc}/{repo_path}.git"
    
    dest = os.path.join(clone_dir, repo_path.replace("/", "_"))
    
    if os.path.exists(dest):
        # Pull latest
        try:
            subprocess.run(["git", "pull"], cwd=dest, capture_output=True, timeout=120)
            return dest
        except Exception:
            import shutil
            shutil.rmtree(dest, ignore_errors=True)
    
    os.makedirs(clone_dir, exist_ok=True)
    
    # Full clone needed for git log -S history analysis
    result = subprocess.run(
        ["git", "clone", auth_url, dest],
        capture_output=True,
        text=True,
        timeout=300
    )
    
    if result.returncode != 0:
        raise RuntimeError(f"Clone failed: {result.stderr[:500]}")
    
    return dest


def get_file_list(repo_path: str) -> list[str]:
    """Get list of all tracked files in repository."""
    SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
        ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip",
        ".tar", ".gz", ".lock", ".sum", ".mod"
    }
    SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".next", "__pycache__"}
    
    files = []
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    
    for f in result.stdout.strip().split("\n"):
        if not f:
            continue
        parts = f.split("/")
        if any(d in SKIP_DIRS for d in parts[:-1]):
            continue
        ext = os.path.splitext(f)[1].lower()
        if ext in SKIP_EXTENSIONS:
            continue
        files.append(f)
    
    return files
