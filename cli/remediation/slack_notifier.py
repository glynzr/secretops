"""Slack Notifier."""
import logging, os
import requests

logger = logging.getLogger("secretops.slack")


class SlackNotifier:
    def __init__(self, config: dict = None):
        cfg = config or {}
        self.webhook = cfg.get("webhook_url", os.environ.get("SLACK_WEBHOOK_URL", ""))

    def is_configured(self): return bool(self.webhook)

    def notify(self, finding_id, file_path, line_number, secret_type, severity,
               repo_name, ai_model, mr_url="", issue_url="",
               vault_path="", days_in_history=0, hist_level="none") -> tuple:
        if not self.is_configured():
            return False, "not_configured"

        sev_color = {"critical": "#FF0000", "high": "#FF6600", "medium": "#FFCC00", "low": "#36A64F"}.get(severity, "#999")
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")

        hist_block = {}
        if days_in_history > 7:
            hist_block = {
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": f"⏱️ *History Alert ({hist_level}):* Credential has been in Git history for *{days_in_history} days*. May already be compromised."}
            }

        blocks = [
            {"type": "header", "text": {"type": "plain_text",
             "text": f"{sev_emoji} SecretOps: Secret Detected — {severity.upper()}"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Repository:*\n{repo_name}"},
                {"type": "mrkdwn", "text": f"*File:*\n`{file_path}:{line_number}`"},
                {"type": "mrkdwn", "text": f"*Type:*\n{secret_type}"},
                {"type": "mrkdwn", "text": f"*AI Model:*\n{ai_model}"},
            ]},
        ]
        if hist_block:
            blocks.append(hist_block)

        blocks += [
            {"type": "section", "text": {"type": "mrkdwn",
             "text": f"*Vault Poisoned:* `{vault_path}`\n*MR:* {mr_url or '_pending_'}\n*Issue:* {issue_url or '_pending_'}"}},
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"Finding ID: `{finding_id[:8]}`"}
            ]},
        ]
        actions = []
        if mr_url:
            actions.append({"type": "button", "text": {"type": "plain_text", "text": "View MR"}, "url": mr_url, "style": "primary"})
        if issue_url:
            actions.append({"type": "button", "text": {"type": "plain_text", "text": "View Issue"}, "url": issue_url})
        if actions:
            blocks.append({"type": "actions", "elements": actions})

        try:
            r = requests.post(self.webhook, json={
                "username": "SecretOps", "icon_emoji": ":lock:",
                "attachments": [{"color": sev_color, "blocks": blocks}]
            }, timeout=10)
            return r.status_code == 200, "sent" if r.status_code == 200 else f"http_{r.status_code}"
        except Exception as ex:
            return False, str(ex)

    def notify_post_merge_fail(self, finding_id, vault_path, rem_id):
        if not self.is_configured():
            return
        try:
            requests.post(self.webhook, json={
                "text": f"🚨 *SecretOps Post-Merge Alert*\nMR merged but credential NOT rotated!\nFinding: `{finding_id[:8]}` | Vault still poisoned at `{vault_path}`\nRemediation: `{rem_id[:8]}`\nPlease rotate the credential immediately and update Vault."
            }, timeout=10)
        except Exception:
            pass
