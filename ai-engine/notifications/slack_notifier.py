"""Slack Block Kit notifications for SecretOps."""
import json
import logging
import requests
import sqlite3

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {"critical": "🚨", "high": "⚠️", "medium": "🔶", "low": "ℹ️"}


class SlackNotifier:
    def __init__(self, db):
        self.db = db
        self._webhook = None
        self._load_config()
    
    def _load_config(self):
        try:
            row = self.db.execute(
                "SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type='slack'"
            ).fetchone()
            if not row:
                return
            config = json.loads(row[0]) if row[0] else {}
            secrets = {}
            if row[1]:
                from detection.utils import decrypt
                try:
                    secrets = json.loads(decrypt(row[1]))
                except Exception:
                    pass
            self._webhook = config.get("webhook_url") or secrets.get("webhook_url")
            self._channel = config.get("channel", "#security-alerts")
        except Exception as e:
            logger.warning(f"Slack config load failed: {e}")
    
    def _post(self, blocks: list, text: str = "SecretOps Alert"):
        if not self._webhook:
            logger.warning("Slack webhook not configured")
            return
        try:
            resp = requests.post(
                self._webhook,
                json={"text": text, "blocks": blocks},
                timeout=10
            )
            if resp.status_code != 200:
                logger.warning(f"Slack returned {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"Slack post failed: {e}")
    
    def send_finding_alert(self, data: dict):
        finding = data["finding"]
        vault_path = data.get("vault_path", "")
        mr_url = data.get("mr_url", "")
        issue_url = data.get("issue_url", "")
        
        sev = finding.get("severity", "high")
        emoji = SEVERITY_EMOJI.get(sev, "⚠️")
        days = finding.get("days_exposed", 0)
        
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} SecretOps: Secret Detected & Remediation Started"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Secret Type:*\n`{finding['secret_type']}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{sev.upper()}"},
                {"type": "mrkdwn", "text": f"*File:*\n`{finding['file_path']}:{finding['line_number']}`"},
                {"type": "mrkdwn", "text": f"*Days Exposed:*\n{days} days"},
                {"type": "mrkdwn", "text": f"*First Author:*\n{finding.get('first_commit_author', 'unknown')}"},
                {"type": "mrkdwn", "text": f"*AI Confidence:*\n{finding.get('ai_confidence', 0):.0%}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Vault Path:* `{vault_path}`\n*Status:* Poison placeholder injected ✓"}},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*AI Analysis:* {finding.get('ai_reasoning', 'No analysis available')[:500]}"}},
            {"type": "actions", "elements": [
                *([ {"type": "button", "text": {"type": "plain_text", "text": "View MR"}, "url": mr_url, "style": "primary"} ] if mr_url else []),
                *([ {"type": "button", "text": {"type": "plain_text", "text": "View Issue"}, "url": issue_url} ] if issue_url else []),
            ]},
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"Finding #{finding['id']} | SecretOps Automated Security Platform"}
            ]}
        ]
        
        self._post(blocks, f"{emoji} SecretOps: {sev.upper()} credential exposed - {finding['secret_type']}")
    
    def send_rotation_reminder(self, data: dict):
        finding_id = data["finding_id"]
        secret_type = data["secret_type"]
        days = data.get("days_exposed", 0)
        reason = data.get("reason", "")
        
        reason_text = {
            "same_value": "⛔ Vault still contains the ORIGINAL exposed credential!",
            "still_placeholder": "⏳ Vault only contains the poison placeholder. Rotation not complete."
        }.get(reason, "Rotation not confirmed")
        
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🔔 SecretOps: Rotation Reminder"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Finding #{finding_id}* — `{secret_type}`\n\n{reason_text}\n\nThe credential has been exposed for *{days} days* and rotation is not confirmed."}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Vault Path:* `{data['vault_path']}`\n\nPlease complete the rotation and update the Vault path with the new credential."}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": "SecretOps will send daily reminders until rotation is confirmed."}]}
        ]
        self._post(blocks, f"🔔 Rotation reminder: Finding #{finding_id}")
    
    def send_resolution(self, data: dict):
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "✅ SecretOps: Rotation Confirmed"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"Finding #{data['finding_id']} — `{data['secret_type']}` has been successfully rotated.\n\nVault path `{data['vault_path']}` now contains the new credential. Finding closed."}},
        ]
        self._post(blocks, f"✅ Rotation confirmed: Finding #{data['finding_id']}")
