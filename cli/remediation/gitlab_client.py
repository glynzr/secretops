"""GitLab Client — MR + Issue creation with vault path and history warnings."""
import base64, logging, os, urllib.parse
import requests

logger = logging.getLogger("secretops.gitlab")


class GitLabClient:
    def __init__(self, config: dict = None):
        cfg = config or {}
        self.url   = cfg.get("url", os.environ.get("GITLAB_URL", "")).rstrip("/")
        self.token = cfg.get("token", os.environ.get("GITLAB_TOKEN", ""))
        self._h = {"PRIVATE-TOKEN": self.token, "Content-Type": "application/json"}

    def _api(self, method, path, **kwargs):
        if not self.url or not self.token:
            return None
        try:
            return getattr(requests, method)(
                f"{self.url}/api/v4{path}", headers=self._h, timeout=20, **kwargs
            )
        except Exception as ex:
            logger.error(f"GitLab {method.upper()} {path}: {ex}")
            return None

    def resolve_project_id(self, repo_url: str) -> str:
        if not repo_url or not self.url:
            return ""
        try:
            path = repo_url.replace(self.url, "").strip("/").removesuffix(".git")
            encoded = urllib.parse.quote(path, safe="")
            r = self._api("get", f"/projects/{encoded}")
            if r and r.status_code == 200:
                return str(r.json()["id"])
        except Exception:
            pass
        return ""

    def get_default_branch(self, project_id: str) -> str:
        r = self._api("get", f"/projects/{project_id}")
        if r and r.status_code == 200:
            return r.json().get("default_branch", "main")
        return "main"

    def create_mr(self, project_id, file_path, line_number, patched_line,
                  import_statement, env_var_name, vault_path, mr_title, mr_description,
                  finding_id, rotation_steps, days_in_history=0, hist_level="none") -> dict:
        branch_name = f"secretops/fix-{finding_id[:8]}"
        default_branch = self.get_default_branch(project_id)

        # Create branch
        r = self._api("post", f"/projects/{project_id}/repository/branches",
                      json={"branch": branch_name, "ref": default_branch})
        if not r or r.status_code not in (200, 201):
            logger.warning("Branch creation failed")
            return {"mr_url": "", "mr_number": 0, "mr_branch": ""}

        # Get current file content
        encoded_path = urllib.parse.quote(file_path, safe="")
        r_file = self._api("get", f"/projects/{project_id}/repository/files/{encoded_path}",
                           params={"ref": default_branch})
        new_content = patched_line
        if r_file and r_file.status_code == 200:
            try:
                current = base64.b64decode(r_file.json()["content"]).decode("utf-8", errors="ignore")
                lines = current.split("\n")
                if 0 < line_number <= len(lines):
                    # Add inline comment above the patched line
                    comment_lines = [
                        f"# SecretOps auto-patch: hardcoded {env_var_name} removed",
                        f"# ACTION REQUIRED before merging:",
                        f"#   1. Rotate the old credential at the provider dashboard",
                        f"#   2. Update Vault at {vault_path} with the NEW credential",
                        f"#   3. Verify staging environment recovers",
                        f"# After merge: SecretOps will verify Vault != old value and close this finding.",
                    ]
                    if days_in_history > 7:
                        comment_lines.insert(1, f"# WARNING: credential was in git history for {days_in_history} days — may be compromised!")
                    lines[line_number - 1] = "\n".join(comment_lines) + "\n" + patched_line
                if import_statement and import_statement not in current:
                    lines.insert(0, import_statement)
                new_content = "\n".join(lines)
            except Exception:
                pass

        # Commit patched file
        commit_msg = f"security: remove hardcoded secret from {file_path}\n\n[SecretOps] Finding: {finding_id[:8]}"
        self._api("put", f"/projects/{project_id}/repository/files/{encoded_path}",
                  json={"branch": branch_name, "content": new_content,
                        "commit_message": commit_msg, "encoding": "text"})

        # Build full MR description
        steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(rotation_steps))
        hist_warning = ""
        if days_in_history > 7:
            hist_warning = f"\n> ⚠️ **HISTORY WARNING**: This credential has been in Git history for **{days_in_history} days** ({hist_level}). Assume it may already be in attacker possession. Review access logs.\n"

        full_desc = f"""{mr_description}

---
## 🔐 SecretOps Remediation Details
{hist_warning}
**Finding ID:** `{finding_id[:8]}`
**File:** `{file_path}` (line {line_number})
**Environment variable:** `{env_var_name}`

## Vault Poison Injection Status

✅ Vault has been updated at `{vault_path}` with a poison placeholder:
```
SECRETOPS_POISONED_..._FINDING_{finding_id[:8]}_ROTATE_IMMEDIATELY
```
⚠️ Your application **WILL FAIL** at runtime until you update Vault with the real credential.

## Steps YOU MUST complete before merging

{steps_md}

{len(rotation_steps)+1}. Update Vault at `{vault_path}` with the **NEW** credential value
{len(rotation_steps)+2}. Verify your application recovers in staging
{len(rotation_steps)+3}. Merge this MR

**DO NOT MERGE** until Vault is updated — SecretOps will auto-verify after merge.

---
*Auto-generated by SecretOps v3.0 | Review required before merge*"""

        r_mr = self._api("post", f"/projects/{project_id}/merge_requests", json={
            "source_branch": branch_name,
            "target_branch": default_branch,
            "title": mr_title,
            "description": full_desc,
            "labels": "security,secretops",
            "remove_source_branch": True,
        })
        if r_mr and r_mr.status_code in (200, 201):
            d = r_mr.json()
            return {"mr_url": d.get("web_url", ""), "mr_number": d.get("iid", 0), "mr_branch": branch_name}
        return {"mr_url": "", "mr_number": 0, "mr_branch": branch_name}

    def create_issue(self, project_id, finding_id, file_path, line_number,
                     secret_type, severity, commit_author, commit_email,
                     env_var_name, mr_url, vault_path, days_in_history=0) -> dict:
        assignee_id = self._resolve_user(commit_email)
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
        hist_note = f"\n**⏱️ Days in history:** {days_in_history}" if days_in_history > 0 else ""

        desc = f"""## {sev_emoji} SecretOps: Hardcoded Secret Detected

**Finding ID:** `{finding_id[:8]}`
**File:** `{file_path}` (line {line_number})
**Type:** {secret_type} | **Severity:** {severity.upper()}{hist_note}

## Remediation Checklist

- [ ] Rotate the exposed credential at the provider dashboard
- [ ] Update Vault at `{vault_path}` with the new credential
- [ ] Verify staging environment recovers (poison placeholder removed)
- [ ] Review and merge the SecretOps MR: {mr_url or '_creating..._'}
- [ ] Close this issue

---
*Auto-created by SecretOps. Contact security team if assistance needed.*"""

        payload = {
            "title": f"[SecretOps] {sev_emoji} Hardcoded {secret_type} in {file_path}",
            "description": desc,
            "labels": f"security,secretops,{severity}",
        }
        if assignee_id:
            payload["assignee_id"] = assignee_id

        r = self._api("post", f"/projects/{project_id}/issues", json=payload)
        if r and r.status_code in (200, 201):
            d = r.json()
            return {"issue_url": d.get("web_url", ""), "issue_number": d.get("iid", 0)}
        return {"issue_url": "", "issue_number": 0}

    def _resolve_user(self, email: str) -> int | None:
        if not email:
            return None
        r = self._api("get", "/users", params={"search": email})
        if r and r.status_code == 200:
            users = r.json()
            if users:
                return users[0].get("id")
        return None

    def revoke_pat(self, token_value: str) -> tuple:
        try:
            r = requests.get(f"{self.url}/api/v4/personal_access_tokens/self",
                             headers={"PRIVATE-TOKEN": token_value}, timeout=10)
            if r.status_code != 200:
                return False, f"Could not look up token: HTTP {r.status_code}"
            token_id = r.json().get("id")
            if not token_id:
                return False, "Could not get token ID"
            r_del = self._api("delete", f"/personal_access_tokens/{token_id}")
            if r_del and r_del.status_code in (200, 204):
                return True, f"GitLab PAT (ID: {token_id}) revoked"
            return False, f"Revocation HTTP {getattr(r_del, 'status_code', 'error')}"
        except Exception as ex:
            return False, str(ex)
