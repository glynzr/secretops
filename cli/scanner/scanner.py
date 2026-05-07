"""Scanner — file collection + git history correlation."""
import os, re, subprocess
from datetime import datetime
from typing import List, Tuple, Dict

SKIP_DIRS = {
    "node_modules", ".git", ".next", "__pycache__", ".pytest_cache",
    "dist", "build", "vendor", "target", ".terraform", ".venv", "venv",
    "env", ".env.bak", "coverage", ".nyc_output",
}
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".rs", ".scala", ".env",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".xml", ".tf", ".tfvars", ".sh", ".bash", ".zsh", ".ps1", ".dockerfile",
    ".gradle", ".pom", ".gemfile",
}
SCAN_FILENAMES = {
    ".env", "Dockerfile", ".envrc", "Makefile", "Procfile",
    "docker-compose.yml", "docker-compose.yaml", "Vagrantfile",
}


class SecretScanner:
    def collect_files(self, directory: str) -> List[str]:
        files = []
        for root, dirs, filenames in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext in SCAN_EXTENSIONS or fname in SCAN_FILENAMES:
                    full = os.path.join(root, fname)
                    if os.path.getsize(full) < 5_000_000:  # skip huge files
                        files.append(full)
        return files

    def check_git_history(self, repo_path: str, candidate_value: str) -> Dict:
        """Search git history for credential appearances."""
        # Use the raw value (not abstracted) for git log search
        # Strip the "..." suffix we add for display
        search_val = candidate_value.rstrip(".")
        if search_val.endswith("..."):
            search_val = search_val[:-3]
        if len(search_val) < 8:
            return {"found_in_history": False, "days_exposed": 0, "alert_level": "none"}

        try:
            result = subprocess.run(
                ["git", "log", "-S", search_val,
                 "--pretty=format:%H|%ae|%ai|%s", "--all"],
                cwd=repo_path, capture_output=True, text=True, timeout=30
            )
            commits = [c for c in result.stdout.strip().split("\n") if "|" in c]
            if not commits:
                return {"found_in_history": False, "days_exposed": 0, "alert_level": "none"}

            first = commits[-1].split("|")
            try:
                first_date = datetime.fromisoformat(first[2][:19])
                days = (datetime.now() - first_date).days
            except Exception:
                days = 0

            level = "none"
            if days > 0:
                level = "INFO" if days < 7 else ("WARNING" if days < 90 else "CRITICAL")

            return {
                "found_in_history": True,
                "commit_count": len(commits),
                "first_seen_commit": first[0][:8] if first else "",
                "first_seen_author": first[1] if len(first) > 1 else "",
                "first_seen_date": first[2][:10] if len(first) > 2 else "",
                "days_exposed": days,
                "alert_level": level,
                "history_sanitisation_required": days > 30,
            }
        except Exception:
            return {"found_in_history": False, "days_exposed": 0, "alert_level": "none"}

    def git_blame(self, file_path: str, line_number: int, repo_path: str) -> Tuple[str, str]:
        try:
            result = subprocess.run(
                ["git", "blame", "-L", f"{line_number},{line_number}",
                 "--porcelain", file_path],
                cwd=repo_path, capture_output=True, text=True, timeout=10
            )
            author, email = "", ""
            for line in result.stdout.split("\n"):
                if line.startswith("author ") and not line.startswith("author-"):
                    author = line[7:].strip()
                elif line.startswith("author-mail "):
                    email = line[12:].strip().strip("<>")
            return author, email
        except Exception:
            return "", ""
