"""Revocation Engine — AWS, GitLab PAT, GitHub PAT."""
import logging, os
from typing import Tuple

logger = logging.getLogger("secretops.revocation")


class RevocationEngine:
    REVOCABLE = {"aws_access_key", "aws_secret_key", "gitlab_pat", "github_pat"}

    def __init__(self, aws_config=None, gitlab_config=None, github_config=None):
        self._aws = aws_config or {}
        self._gl  = gitlab_config or {}
        self._gh  = github_config or {}

    def attempt_revocation(self, secret_type: str, candidate_value: str) -> Tuple[bool, str]:
        st = secret_type.lower()
        try:
            if "aws" in st and "access" in st:
                return self._revoke_aws(candidate_value)
            if "gitlab" in st:
                return self._revoke_gitlab(candidate_value)
            if "github" in st:
                return self._revoke_github(candidate_value)
            return False, f"Auto-revocation not supported for {secret_type} — rotate manually at provider dashboard. Vault poison injection is active."
        except Exception as ex:
            return False, f"Revocation error: {ex}"

    def _revoke_aws(self, key_id: str) -> Tuple[bool, str]:
        try:
            import boto3
            key_id = key_id.split(".")[0].strip()
            if not key_id.startswith(("AKIA", "ASIA")):
                return False, "Not a valid AWS key format"
            iam = boto3.client("iam",
                aws_access_key_id=self._aws.get("access_key_id") or os.environ.get("ADMIN_AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=self._aws.get("secret_access_key") or os.environ.get("ADMIN_AWS_SECRET_ACCESS_KEY"),
                region_name=self._aws.get("region", "us-east-1"),
            )
            # Find key owner
            target_user = None
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                    for k in keys:
                        if k["AccessKeyId"] == key_id:
                            target_user = user["UserName"]
                            break
                if target_user:
                    break

            kwargs = {"AccessKeyId": key_id, "Status": "Inactive"}
            if target_user:
                kwargs["UserName"] = target_user
            iam.update_access_key(**kwargs)
            user_info = f" for user '{target_user}'" if target_user else ""
            return True, f"AWS IAM key {key_id[:8]}...{user_info} deactivated"
        except ImportError:
            return False, "boto3 not installed — install it or configure AWS credentials"
        except Exception as ex:
            return False, f"AWS revocation failed: {ex}"

    def _revoke_gitlab(self, token_value: str) -> Tuple[bool, str]:
        try:
            import requests
            gitlab_url = self._gl.get("url", "").rstrip("/")
            if not gitlab_url:
                return False, "GitLab URL not configured"
            r = requests.get(f"{gitlab_url}/api/v4/personal_access_tokens/self",
                headers={"PRIVATE-TOKEN": token_value}, timeout=10)
            if r.status_code != 200:
                return False, f"Could not look up token: HTTP {r.status_code}"
            token_id = r.json().get("id")
            admin_token = self._gl.get("token", "")
            r_del = requests.delete(f"{gitlab_url}/api/v4/personal_access_tokens/{token_id}",
                headers={"PRIVATE-TOKEN": admin_token}, timeout=10)
            if r_del.status_code in (200, 204):
                return True, f"GitLab PAT (ID: {token_id}) revoked"
            return False, f"Revocation returned HTTP {r_del.status_code}"
        except Exception as ex:
            return False, f"GitLab revocation failed: {ex}"

    def _revoke_github(self, token_value: str) -> Tuple[bool, str]:
        try:
            import requests
            r = requests.get("https://api.github.com/user",
                headers={"Authorization": f"token {token_value}", "Accept": "application/vnd.github.v3+json"}, timeout=10)
            if r.status_code == 401:
                return False, "GitHub token already invalid"
            username = r.json().get("login", "unknown")
            client_id = self._gh.get("client_id", "") or os.environ.get("GITHUB_OAUTH_CLIENT_ID", "")
            client_secret = self._gh.get("client_secret", "") or os.environ.get("GITHUB_OAUTH_CLIENT_SECRET", "")
            if client_id and client_secret:
                r_del = requests.delete(
                    f"https://api.github.com/applications/{client_id}/token",
                    auth=(client_id, client_secret),
                    json={"access_token": token_value},
                    headers={"Accept": "application/vnd.github.v3+json"}, timeout=10
                )
                if r_del.status_code == 204:
                    return True, f"GitHub PAT for '{username}' revoked"
            return False, f"GitHub PAT for '{username}' — manual revocation: github.com/settings/tokens"
        except Exception as ex:
            return False, f"GitHub revocation failed: {ex}"
