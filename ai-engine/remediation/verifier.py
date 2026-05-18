"""
Post-merge rotation verification.

How SecretOps knows an MR was merged:
  1. GitLab webhook: GitLab POSTs to /api/webhook/gitlab on every MR event.
     SecretOps auto-registers this webhook when creating the MR.
  2. Background polling: every 10 min, polls GitLab API for MR state AND
     checks Vault value against the original exposed hash.

Verification logic (three scenarios):
  - Vault value == original hash   → NOT rotated, send escalation alert
  - Vault value starts with SECRETOPS_POISONED_ → placeholder still there, send reminder
  - Vault value changed + not placeholder → ROTATION CONFIRMED, close finding
"""
import hashlib
import json
import logging
import os
import sqlite3
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
DB_PATH = os.environ.get("DB_PATH", "/data/secretops.db")
POISON_PREFIX = "SECRETOPS_POISONED_"


class RotationVerifier:

    def get_db(self):
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def get_integration(self, db, itype: str) -> tuple:
        try:
            row = db.execute(
                "SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type=? ORDER BY id LIMIT 1",
                (itype,)
            ).fetchone()
            if not row:
                return {}, {}
            config = json.loads(row[0]) if row[0] else {}
            secrets = {}
            if row[1]:
                from detection.utils import decrypt
                try:
                    secrets = json.loads(decrypt(row[1]))
                except Exception:
                    pass
            # config wins — frontend stores credentials there
            merged = {**secrets, **config}
            return merged, secrets
        except Exception:
            return {}, {}

    def _check_mr_merged(self, db, finding: dict) -> bool:
        """
        Ask GitLab if the MR for this finding has been merged.
        Returns True if merged, False if still open/not found.
        """
        mr_url = finding.get("mr_url", "")
        mr_id = finding.get("mr_id", "")
        repo_path = finding.get("repo_full_path", "")

        if not mr_url and not mr_id:
            # No MR created yet — not merged
            return False

        config, _ = self.get_integration(db, "gitlab")
        gitlab_url = config.get("url", "").rstrip("/")
        token = config.get("token", "")

        if not gitlab_url or not token:
            # Can't check — assume not merged, Vault check will determine state
            logger.warning("GitLab not configured — cannot check MR state, relying on Vault value")
            return True  # proceed to Vault check anyway

        try:
            # Get project info
            encoded_path = requests.utils.quote(repo_path, safe="")
            resp = requests.get(
                f"{gitlab_url}/api/v4/projects/{encoded_path}",
                headers={"PRIVATE-TOKEN": token},
                timeout=10
            )
            if resp.status_code != 200:
                logger.warning(f"Could not get project {repo_path}: {resp.status_code}")
                return True  # proceed to Vault check

            project_id = resp.json()["id"]

            # Check MR state
            mr_iid = mr_id.strip("#") if mr_id else ""
            if not mr_iid and mr_url:
                # Extract IID from URL e.g. .../merge_requests/5
                parts = mr_url.rstrip("/").split("/")
                mr_iid = parts[-1] if parts else ""

            if not mr_iid:
                return True

            mr_resp = requests.get(
                f"{gitlab_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}",
                headers={"PRIVATE-TOKEN": token},
                timeout=10
            )
            if mr_resp.status_code == 200:
                state = mr_resp.json().get("state", "")
                logger.info(f"MR {mr_iid} state: {state}")
                return state == "merged"

        except Exception as e:
            logger.warning(f"MR state check failed: {e} — proceeding to Vault check")
            return True

        return False

    def verify(self, finding_id: int) -> dict:
        db = self.get_db()
        try:
            row = db.execute("""
                SELECT f.id, f.vault_path, f.raw_value_hash, f.secret_type, f.status,
                       f.repository_id, f.file_path, f.line_number,
                       f.days_exposed, f.first_commit_author,
                       f.mr_url, f.mr_id,
                       COALESCE(r.full_path, '') as repo_full_path
                FROM findings f
                LEFT JOIN repositories r ON r.id = f.repository_id
                WHERE f.id=?
            """, (finding_id,)).fetchone()

            if not row:
                return {"error": "Finding not found"}

            (finding_id, vault_path, raw_hash, secret_type, status,
             repo_id, file_path, line_number, days_exposed, author,
             mr_url, mr_id, repo_full_path) = row

            finding = {
                "id": finding_id, "vault_path": vault_path,
                "raw_value_hash": raw_hash, "secret_type": secret_type,
                "status": status, "days_exposed": days_exposed,
                "first_commit_author": author, "mr_url": mr_url or "",
                "mr_id": mr_id or "", "repo_full_path": repo_full_path
            }

            if not vault_path:
                return {"status": "no_vault_path", "message": "No Vault path for this finding"}

            # Step 1: Check if MR has been merged
            mr_merged = self._check_mr_merged(db, finding)
            logger.info(f"[verify:{finding_id}] MR merged={mr_merged}, vault_path={vault_path}")

            if not mr_merged:
                return {
                    "status": "mr_not_merged",
                    "message": "MR has not been merged yet. Waiting for developer to merge the patch.",
                    "mr_url": mr_url
                }

            # Step 2: MR is merged — check Vault value
            config, secrets = self.get_integration(db, "vault")
            vault_addr = config.get("url", config.get("address", "")).strip()
            vault_token = config.get("token", secrets.get("token", ""))
            if not vault_addr:
                vault_addr = os.environ.get("VAULT_ADDR", "http://vault:8200")
            if not vault_token:
                vault_token = os.environ.get("VAULT_TOKEN", "secretops-root-token")

            # Build KV-v2 path
            if vault_path.startswith("secret/data/"):
                kv_path = vault_path
            elif vault_path.startswith("secret/"):
                kv_path = vault_path.replace("secret/", "secret/data/", 1)
            else:
                kv_path = f"secret/data/{vault_path}"

            try:
                resp = requests.get(
                    f"{vault_addr}/v1/{kv_path}",
                    headers={"X-Vault-Token": vault_token},
                    timeout=10
                )
                if resp.status_code == 404:
                    # Vault path doesn't exist — credential not stored yet
                    self._send_escalation_alert(
                        db, finding_id, secret_type, vault_path,
                        days_exposed, author, "vault_path_missing"
                    )
                    return {
                        "status": "vault_path_missing",
                        "message": "MR merged but no credential stored in Vault yet. Store the new credential.",
                        "action": "reminder_sent"
                    }
                resp.raise_for_status()
                current_value = resp.json().get("data", {}).get("data", {}).get("value", "")
            except requests.exceptions.RequestException as e:
                return {"status": "vault_unreachable", "message": str(e)}

            current_hash = hashlib.sha256(current_value.encode()).hexdigest()

            # Scenario A: Vault still has the original exposed value
            if current_hash == raw_hash:
                logger.warning(f"[verify:{finding_id}] Original secret still in Vault — escalating")
                self._send_escalation_alert(
                    db, finding_id, secret_type, vault_path,
                    days_exposed, author, "same_value"
                )
                return {
                    "status": "not_rotated",
                    "message": "MR merged but Vault still contains the original exposed credential. Rotate immediately.",
                    "action": "escalation_sent"
                }

            # Scenario B: Vault has the poison placeholder — not rotated yet
            if current_value.startswith(POISON_PREFIX):
                logger.warning(f"[verify:{finding_id}] Poison placeholder still in Vault — sending reminder")
                self._send_escalation_alert(
                    db, finding_id, secret_type, vault_path,
                    days_exposed, author, "still_placeholder"
                )
                return {
                    "status": "placeholder_only",
                    "message": "MR merged but Vault still has placeholder. Store the rotated credential in Vault.",
                    "action": "reminder_sent"
                }

            # Scenario C: Value changed and is not a placeholder — ROTATION CONFIRMED
            logger.info(f"[verify:{finding_id}] Rotation confirmed! Closing finding.")
            db.execute("""
                UPDATE findings SET
                    status='closed', rotation_confirmed=1,
                    remediation_status='completed',
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=?
            """, (finding_id,))
            db.execute("""
                INSERT INTO audit_logs (action, entity_type, entity_id, details)
                VALUES ('rotation.confirmed', 'finding', ?, ?)
            """, (finding_id, json.dumps({
                "vault_path": vault_path,
                "confirmed_at": datetime.utcnow().isoformat()
            })))
            db.commit()

            self._send_resolution_alert(db, finding_id, secret_type, vault_path)

            return {
                "status": "rotation_confirmed",
                "message": "Credential rotated successfully. Finding closed.",
                "action": "finding_closed"
            }

        finally:
            db.close()

    def _send_escalation_alert(self, db, finding_id, secret_type, vault_path,
                               days_exposed, author, reason):
        from notifications.slack_notifier import SlackNotifier
        from notifications.email_notifier import EmailNotifier

        msg = {
            "finding_id": finding_id, "secret_type": secret_type,
            "vault_path": vault_path, "days_exposed": days_exposed,
            "author": author, "reason": reason
        }
        try:
            SlackNotifier(db).send_rotation_reminder(msg)
        except Exception as e:
            logger.warning(f"Slack escalation failed: {e}")
        try:
            EmailNotifier(db).send_rotation_reminder(msg)
        except Exception as e:
            logger.warning(f"Email escalation failed: {e}")

    def _send_resolution_alert(self, db, finding_id, secret_type, vault_path):
        from notifications.slack_notifier import SlackNotifier
        from notifications.email_notifier import EmailNotifier

        msg = {"finding_id": finding_id, "secret_type": secret_type, "vault_path": vault_path}
        try:
            SlackNotifier(db).send_resolution(msg)
        except Exception as e:
            logger.warning(f"Slack resolution failed: {e}")
        try:
            EmailNotifier(db).send_resolution(msg)
        except Exception as e:
            logger.warning(f"Email resolution failed: {e}")
