"""
TruffleHog v3 integration — primary secret detection engine.
Falls back to regex patterns if TruffleHog is not installed.
"""
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TruffleHogFinding:
    secret_type: str        # e.g. "AWS", "Stripe", "GitHubToken"
    detector_name: str      # Raw TruffleHog detector name
    file_path: str
    line_number: int
    raw_value: str
    masked_value: str
    commit_hash: str
    commit_author: str
    commit_date: str
    verified: bool          # TruffleHog verified this is a live credential
    severity: str
    confidence: float


SEVERITY_MAP = {
    # Critical — active credentials to production systems
    "AWS": "critical", "AWSSessionToken": "critical",
    "Stripe": "critical", "StripeWebhook": "high",
    "Twilio": "high", "TwilioAccountSid": "medium",
    "Slack": "high", "SlackWebhook": "high",
    "GitHub": "high", "GitLab": "high",
    "OpenAI": "high", "Anthropic": "high", "Groq": "high",
    "SendGrid": "high", "Mailgun": "high",
    "GCP": "critical", "GoogleCloud": "critical",
    "Azure": "critical",
    "PrivateKey": "critical", "RSAPrivateKey": "critical",
    "JWT": "high", "JSONWebToken": "high",
    "Postgres": "critical", "MySQL": "critical", "MongoDB": "critical",
    "Redis": "high",
}

SECRET_TYPE_MAP = {
    "AWS": "aws_access_key",
    "AWSSessionToken": "aws_session_token",
    "Stripe": "stripe_secret_key",
    "StripeWebhook": "stripe_webhook_secret",
    "Slack": "slack_token",
    "SlackWebhook": "slack_webhook",
    "GitHub": "github_pat",
    "GitLab": "gitlab_pat",
    "OpenAI": "openai_api_key",
    "Anthropic": "anthropic_api_key",
    "Groq": "groq_api_key",
    "SendGrid": "sendgrid_api_key",
    "Mailgun": "mailgun_api_key",
    "Twilio": "twilio_auth_token",
    "GCP": "gcp_service_account_key",
    "PrivateKey": "private_key_block",
    "JWT": "jwt_secret",
    "Postgres": "connection_string",
    "MySQL": "connection_string",
    "MongoDB": "connection_string",
}


def is_trufflehog_available() -> bool:
    try:
        result = subprocess.run(
            ["trufflehog", "--version"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def mask_value(value: str) -> str:
    if not value or len(value) < 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def scan_with_trufflehog(repo_path: str) -> list[TruffleHogFinding]:
    """
    Run TruffleHog v3 on a local repo directory.
    Returns a list of TruffleHogFinding objects.
    """
    if not is_trufflehog_available():
        logger.warning("TruffleHog not available, skipping")
        return []

    try:
        cmd = [
            "trufflehog", "filesystem",
            "--json",
            "--no-update",
            "--concurrency=4",
            repo_path
        ]
        logger.info(f"Running TruffleHog on {repo_path}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        findings = []
        seen_hashes = set()

        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                raw = item.get("Raw", "") or item.get("RawV2", "")
                if not raw:
                    continue

                value_hash = raw[:8] + str(len(raw))
                if value_hash in seen_hashes:
                    continue
                seen_hashes.add(value_hash)

                detector = item.get("DetectorName", "Unknown")
                secret_type = SECRET_TYPE_MAP.get(detector, detector.lower().replace(" ", "_"))
                severity = "high"
                for key, sev in SEVERITY_MAP.items():
                    if key.lower() in detector.lower():
                        severity = sev
                        break

                # Extract file path and line number from SourceMetadata
                file_path = ""
                line_number = 0
                commit_hash = ""
                commit_author = ""
                commit_date = ""

                meta = item.get("SourceMetadata", {})
                if meta:
                    data = meta.get("Data", {})
                    fs = data.get("Filesystem", {})
                    git = data.get("Git", {})
                    if fs:
                        file_path = fs.get("file", "")
                        line_number = int(fs.get("line", 0))
                    elif git:
                        file_path = git.get("file", "")
                        line_number = int(git.get("line", 0))
                        commit_hash = git.get("commit", "")
                        commit_author = git.get("email", "")
                        commit_date = git.get("timestamp", "")

                # Strip repo_path prefix from file_path
                if file_path.startswith(repo_path):
                    file_path = file_path[len(repo_path):].lstrip("/")

                verified = item.get("Verified", False)
                confidence = 0.99 if verified else 0.85

                findings.append(TruffleHogFinding(
                    secret_type=secret_type,
                    detector_name=detector,
                    file_path=file_path or "unknown",
                    line_number=line_number or 1,
                    raw_value=raw,
                    masked_value=mask_value(raw),
                    commit_hash=commit_hash,
                    commit_author=commit_author,
                    commit_date=commit_date,
                    verified=verified,
                    severity=severity,
                    confidence=confidence,
                ))

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.debug(f"TruffleHog parse error: {e} on line: {line[:100]}")
                continue

        logger.info(f"TruffleHog found {len(findings)} findings in {repo_path}")
        return findings

    except subprocess.TimeoutExpired:
        logger.error("TruffleHog timed out")
        return []
    except Exception as e:
        logger.error(f"TruffleHog error: {e}")
        return []
