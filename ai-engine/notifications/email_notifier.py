"""Email notifications via SMTP for SecretOps."""
import json
import logging
import smtplib
import sqlite3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


class EmailNotifier:
    def __init__(self, db):
        self.db = db
        self._config = {}
        self._secrets = {}
        self._load_config()
    
    def _load_config(self):
        try:
            row = self.db.execute(
                "SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type='smtp'"
            ).fetchone()
            if not row:
                return
            self._config = json.loads(row[0]) if row[0] else {}
            if row[1]:
                from detection.utils import decrypt
                try:
                    self._secrets = json.loads(decrypt(row[1]))
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"SMTP config load failed: {e}")
    
    def _get_recipients(self) -> list[str]:
        rows = self.db.execute(
            "SELECT email FROM notification_recipients WHERE active=1"
        ).fetchall()
        return [r[0] for r in rows]
    
    def _send(self, subject: str, html_body: str, recipients: list[str] = None):
        if not self._config:
            logger.warning("SMTP not configured")
            return
        
        if not recipients:
            recipients = self._get_recipients()
        if not recipients:
            logger.warning("No email recipients configured")
            return
        
        host = self._config.get("host", "localhost")
        port = int(self._config.get("port", 587))
        username = self._config.get("username", "")
        password = self._secrets.get("password", "")
        from_addr = self._config.get("from", username)
        use_tls = self._config.get("use_tls", True)
        
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"SecretOps <{from_addr}>"
            msg["To"] = ", ".join(recipients)
            msg.attach(MIMEText(html_body, "html"))
            
            with smtplib.SMTP(host, port, timeout=10) as server:
                if use_tls:
                    server.starttls()
                if username and password:
                    server.login(username, password)
                server.sendmail(from_addr, recipients, msg.as_string())
            
            logger.info(f"Email sent to {len(recipients)} recipients: {subject}")
        except Exception as e:
            logger.error(f"Email send failed: {e}")
    
    def send_finding_alert(self, data: dict):
        finding = data["finding"]
        vault_path = data.get("vault_path", "")
        mr_url = data.get("mr_url", "")
        issue_url = data.get("issue_url", "")
        sev = finding.get("severity", "high")
        patch = data.get("patch", {})
        
        rotation_steps_html = "".join(
            f"<li>{step}</li>" for step in patch.get("rotation_steps", [])
        )
        
        body = f"""
        <html><body style="font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px;">
            <h2 style="color: #f85149; margin-top: 0;">⚠️ SecretOps Security Alert</h2>
            <p style="color: #8b949e;">Finding #{finding['id']} — Automated remediation started</p>
            
            <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
                <tr><td style="padding: 8px; color: #8b949e;">Secret Type</td><td style="padding: 8px; color: #e6edf3;"><code>{finding['secret_type']}</code></td></tr>
                <tr><td style="padding: 8px; color: #8b949e;">Severity</td><td style="padding: 8px; color: #f85149; font-weight: bold;">{sev.upper()}</td></tr>
                <tr><td style="padding: 8px; color: #8b949e;">File</td><td style="padding: 8px; color: #e6edf3;"><code>{finding['file_path']}:{finding['line_number']}</code></td></tr>
                <tr><td style="padding: 8px; color: #8b949e;">Days Exposed</td><td style="padding: 8px; color: #f0883e;">{finding.get('days_exposed', 0)} days</td></tr>
                <tr><td style="padding: 8px; color: #8b949e;">First Author</td><td style="padding: 8px; color: #e6edf3;">{finding.get('first_commit_author', 'unknown')}</td></tr>
                <tr><td style="padding: 8px; color: #8b949e;">AI Confidence</td><td style="padding: 8px; color: #e6edf3;">{finding.get('ai_confidence', 0):.0%}</td></tr>
                <tr><td style="padding: 8px; color: #8b949e;">Vault Path</td><td style="padding: 8px; color: #58a6ff;"><code>{vault_path}</code></td></tr>
            </table>
            
            <h3 style="color: #58a6ff;">Rotation Steps</h3>
            <ol style="color: #c9d1d9;">{rotation_steps_html}</ol>
            
            <div style="margin-top: 20px;">
                {f'<a href="{mr_url}" style="background: #238636; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; margin-right: 10px;">View Merge Request</a>' if mr_url else ""}
                {f'<a href="{issue_url}" style="background: #1f6feb; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none;">View Issue</a>' if issue_url else ""}
            </div>
            
            <p style="color: #8b949e; font-size: 12px; margin-top: 24px;">SecretOps Automated Security Platform</p>
        </div></body></html>
        """
        
        self._send(f"[SecretOps] {sev.upper()} — Exposed {finding['secret_type']} in {finding.get('repo_name', 'repository')} (Finding #{finding['id']})", body)
    
    def send_rotation_reminder(self, data: dict):
        body = f"""
        <html><body style="font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px;">
            <h2 style="color: #f0883e; margin-top: 0;">🔔 SecretOps: Rotation Reminder</h2>
            <p>Finding #{data['finding_id']} — <code>{data['secret_type']}</code> is still not rotated.</p>
            <p>Days exposed: <strong style="color: #f85149;">{data.get('days_exposed', 0)} days</strong></p>
            <p>Vault Path: <code>{data['vault_path']}</code></p>
            <p style="color: #8b949e;">Please complete the rotation process. SecretOps will send daily reminders until confirmed.</p>
        </div></body></html>
        """
        self._send(f"[SecretOps] Rotation Reminder — Finding #{data['finding_id']}", body)
    
    def send_resolution(self, data: dict):
        body = f"""
        <html><body style="font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #161b22; border: 1px solid #238636; border-radius: 8px; padding: 24px;">
            <h2 style="color: #3fb950; margin-top: 0;">✅ SecretOps: Rotation Confirmed</h2>
            <p>Finding #{data['finding_id']} — <code>{data['secret_type']}</code> has been successfully rotated.</p>
            <p>Vault path <code>{data['vault_path']}</code> has been updated. Finding closed.</p>
        </div></body></html>
        """
        self._send(f"[SecretOps] ✅ Rotation Confirmed — Finding #{data['finding_id']}", body)
