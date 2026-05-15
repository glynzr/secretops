"""
Post-merge rotation verification loop.
Compares Vault value SHA-256 against stored finding hash.
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
        return sqlite3.connect(DB_PATH)
    
    def get_integration(self, db, itype: str) -> tuple[dict, dict]:
        try:
            row = db.execute(
                "SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type=?", (itype,)
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
            return config, secrets
        except Exception:
            return {}, {}
    
    def verify(self, finding_id: int) -> dict:
        db = self.get_db()
        try:
            row = db.execute("""
                SELECT id, vault_path, raw_value_hash, secret_type, status, repository_id,
                       file_path, line_number, days_exposed, first_commit_author
                FROM findings WHERE id=?
            """, (finding_id,)).fetchone()
            
            if not row:
                return {"error": "Finding not found"}
            
            finding_id, vault_path, raw_hash, secret_type, status, repo_id,                 file_path, line_number, days_exposed, author = row
            
            if not vault_path:
                return {"status": "no_vault_path", "message": "No Vault path configured for this finding"}
            
            # Read current Vault value
            config, secrets = self.get_integration(db, "vault")
            if not config:
                return {"status": "vault_not_configured"}
            
            vault_addr = config.get("address", "http://vault:8200")
            token = secrets.get("token", "")
            
            kv_path = vault_path.replace("secret/", "secret/data/", 1)
            
            try:
                resp = requests.get(
                    f"{vault_addr}/v1/{kv_path}",
                    headers={"X-Vault-Token": token},
                    timeout=10
                )
                
                if resp.status_code == 404:
                    return {"status": "vault_path_missing", "message": "Vault path does not exist"}
                
                resp.raise_for_status()
                vault_data = resp.json()
                current_value = vault_data.get("data", {}).get("data", {}).get("value", "")
            
            except requests.exceptions.RequestException as e:
                return {"status": "vault_unreachable", "message": str(e)}
            
            current_hash = hashlib.sha256(current_value.encode()).hexdigest()
            
            # Scenario 1: Hash matches original - NOT rotated
            if current_hash == raw_hash:
                self._send_escalation_alert(db, finding_id, secret_type, vault_path, days_exposed, author, "same_value")
                return {
                    "status": "not_rotated",
                    "message": "Vault still contains the original exposed credential. Rotation incomplete.",
                    "action": "escalated_alert_sent"
                }
            
            # Scenario 2: Still contains poison placeholder
            if current_value.startswith(POISON_PREFIX):
                self._send_escalation_alert(db, finding_id, secret_type, vault_path, days_exposed, author, "still_placeholder")
                return {
                    "status": "placeholder_only",
                    "message": "Vault contains poison placeholder. Developer has not yet stored the rotated credential.",
                    "action": "reminder_sent"
                }
            
            # Scenario 3: Value changed and not placeholder - ROTATION CONFIRMED
            db.execute("""
                UPDATE findings SET 
                status='closed', rotation_confirmed=1, remediation_status='completed',
                updated_at=CURRENT_TIMESTAMP
                WHERE id=?
            """, (finding_id,))
            db.commit()
            
            self._send_resolution_alert(db, finding_id, secret_type, vault_path)
            
            db.execute("""
                INSERT INTO audit_logs (action, entity_type, entity_id, details)
                VALUES ('rotation.confirmed', 'finding', ?, ?)
            """, (finding_id, json.dumps({"vault_path": vault_path, "confirmed_at": datetime.utcnow().isoformat()})))
            db.commit()
            
            return {
                "status": "rotation_confirmed",
                "message": "Credential successfully rotated. Finding closed.",
                "action": "finding_closed"
            }
        
        finally:
            db.close()
    
    def _send_escalation_alert(self, db, finding_id, secret_type, vault_path, days_exposed, author, reason):
        """Send daily reminder alert via Slack and email."""
        from notifications.slack_notifier import SlackNotifier
        from notifications.email_notifier import EmailNotifier
        
        message = {
            "finding_id": finding_id,
            "secret_type": secret_type,
            "vault_path": vault_path,
            "days_exposed": days_exposed,
            "author": author,
            "reason": reason
        }
        
        try:
            SlackNotifier(db).send_rotation_reminder(message)
        except Exception as e:
            logger.warning(f"Slack escalation failed: {e}")
        
        try:
            EmailNotifier(db).send_rotation_reminder(message)
        except Exception as e:
            logger.warning(f"Email escalation failed: {e}")
    
    def _send_resolution_alert(self, db, finding_id, secret_type, vault_path):
        """Send resolution confirmation alert."""
        from notifications.slack_notifier import SlackNotifier
        from notifications.email_notifier import EmailNotifier
        
        message = {"finding_id": finding_id, "secret_type": secret_type, "vault_path": vault_path}
        
        try:
            SlackNotifier(db).send_resolution(message)
        except Exception as e:
            logger.warning(f"Slack resolution notification failed: {e}")
        
        try:
            EmailNotifier(db).send_resolution(message)
        except Exception as e:
            logger.warning(f"Email resolution notification failed: {e}")
