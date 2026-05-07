"""Email Notifier — SMTP dual-channel notifications."""
import logging, os, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("secretops.email")


class EmailNotifier:
    def __init__(self, config: dict = None):
        cfg = config or {}
        self.host     = cfg.get("smtp_host", os.environ.get("SMTP_HOST", ""))
        self.port     = int(cfg.get("smtp_port", os.environ.get("SMTP_PORT", "587")))
        self.user     = cfg.get("smtp_user", os.environ.get("SMTP_USER", ""))
        self.password = cfg.get("smtp_password", os.environ.get("SMTP_PASSWORD", ""))
        self.sender   = cfg.get("sender", self.user)
        self.recipients = cfg.get("recipients", os.environ.get("EMAIL_RECIPIENTS", ""))

    def is_configured(self):
        return bool(self.host and self.user and self.recipients)

    def _send(self, subject: str, body_html: str) -> tuple:
        if not self.is_configured():
            return False, "not_configured"
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.sender
            to_list = [r.strip() for r in self.recipients.split(",") if r.strip()]
            msg["To"] = ", ".join(to_list)
            msg.attach(MIMEText(body_html, "html"))
            with smtplib.SMTP(self.host, self.port, timeout=15) as s:
                s.ehlo()
                s.starttls()
                s.login(self.user, self.password)
                s.sendmail(self.sender, to_list, msg.as_string())
            return True, "sent"
        except Exception as ex:
            logger.error(f"Email send failed: {ex}")
            return False, str(ex)

    def notify(self, finding_id, file_path, line_number, secret_type, severity,
               repo_name, mr_url="", issue_url="", vault_path="",
               days_in_history=0, hist_level="none") -> tuple:
        sev_color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#16a34a"}.get(severity, "#6b7280")
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")

        hist_warning = ""
        if days_in_history > 7:
            hist_warning = f"""
            <div style="background:#fef3c7;border-left:4px solid #d97706;padding:12px;margin:12px 0;border-radius:4px;">
                ⏱️ <strong>History Alert ({hist_level}):</strong> This credential has been in Git history for
                <strong>{days_in_history} days</strong>. It may already be in attacker possession.
                Review access logs from the first exposure date.
            </div>"""

        body = f"""
        <html><body style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;color:#1f2937;">
        <div style="background:{sev_color};color:white;padding:20px;border-radius:8px 8px 0 0;">
            <h2 style="margin:0;">{sev_emoji} SecretOps: Hardcoded Secret Detected</h2>
            <p style="margin:4px 0 0;opacity:0.9;">{severity.upper()} | {repo_name}</p>
        </div>
        <div style="padding:20px;background:#f9fafb;border:1px solid #e5e7eb;">
            {hist_warning}
            <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
                <tr><td style="padding:8px;border-bottom:1px solid #e5e7eb;font-weight:600;width:40%;">Finding ID</td>
                    <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-family:monospace;">{finding_id[:8]}</td></tr>
                <tr><td style="padding:8px;border-bottom:1px solid #e5e7eb;font-weight:600;">File</td>
                    <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-family:monospace;">{file_path}:{line_number}</td></tr>
                <tr><td style="padding:8px;border-bottom:1px solid #e5e7eb;font-weight:600;">Type</td>
                    <td style="padding:8px;border-bottom:1px solid #e5e7eb;">{secret_type}</td></tr>
                <tr><td style="padding:8px;border-bottom:1px solid #e5e7eb;font-weight:600;">Vault Path Poisoned</td>
                    <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-family:monospace;">{vault_path}</td></tr>
            </table>
            <div style="display:flex;gap:12px;flex-wrap:wrap;">
                {f'<a href="{mr_url}" style="background:#2563eb;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600;">View Merge Request</a>' if mr_url else ''}
                {f'<a href="{issue_url}" style="background:#7c3aed;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600;">View Issue</a>' if issue_url else ''}
            </div>
            <p style="color:#6b7280;font-size:13px;margin-top:16px;">
                Rotate the credential immediately and update Vault before merging the MR.
                SecretOps will verify rotation automatically after merge.
            </p>
        </div>
        <div style="background:#e5e7eb;padding:12px;text-align:center;font-size:12px;color:#6b7280;border-radius:0 0 8px 8px;">
            SecretOps v3.0 | Auto-generated security alert
        </div>
        </body></html>"""

        subject = f"[SecretOps] {sev_emoji} {severity.upper()}: Hardcoded {secret_type} in {repo_name}"
        return self._send(subject, body)

    def notify_post_merge_fail(self, finding_id, vault_path, rem_id):
        body = f"""
        <html><body style="font-family:Arial,sans-serif;color:#1f2937;">
        <div style="background:#dc2626;color:white;padding:20px;border-radius:8px;">
            <h2>🚨 SecretOps: Post-Merge Verification Failed</h2>
        </div>
        <div style="padding:20px;border:1px solid #e5e7eb;">
            <p>A merge request was merged but the credential was <strong>NOT rotated</strong>.</p>
            <p><strong>Finding:</strong> {finding_id[:8]}</p>
            <p><strong>Vault path still poisoned:</strong> <code>{vault_path}</code></p>
            <p><strong>Remediation ID:</strong> {rem_id[:8]}</p>
            <p style="color:#dc2626;font-weight:600;">Please rotate the credential immediately and update Vault.</p>
        </div>
        </body></html>"""
        self._send(f"[SecretOps] 🚨 CRITICAL: Credential Not Rotated After MR Merge — {finding_id[:8]}", body)
