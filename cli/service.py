"""
SecretOps CLI Service v3
Full workflow: Git history → Triage Detection → 7-Stage Remediation
"""
import hashlib, json, logging, os, re, shutil, smtplib, subprocess
import tempfile, threading, time, uuid as _uuid
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests as http_req
from flask import Flask, request, jsonify

try:
    import psutil; HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("secretops")

app = Flask(__name__)
BACKEND = os.environ.get("BACKEND_URL", "http://backend:8080")
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.70"))


# ── Config helpers ──────────────────────────────────────────────────────────

def get_conn(t):
    try:
        r = http_req.get(f"{BACKEND}/api/v1/connections/{t}/config/raw", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


# ── Health ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify({"status": "ok", "version": "3.0.0"})


# ── Scan endpoint ───────────────────────────────────────────────────────────

@app.post("/scan")
def scan():
    data = request.get_json()
    if not data or "scan_id" not in data:
        return jsonify({"error": "missing scan_id"}), 400
    threading.Thread(target=_run_scan, args=(data,), daemon=True).start()
    return jsonify({"status": "queued"}), 200


def _run_scan(data):
    scan_id  = data["scan_id"]
    repo_url = data.get("repo_url", "")
    branch   = data.get("branch", "main")
    ai_model = data.get("ai_model", "claude-3-5-sonnet-20241022")

    from ai.detector import AIDetector
    from scanner.scanner import SecretScanner

    target_dir = None
    cleanup = False
    try:
        target_dir = tempfile.mkdtemp(prefix="secretops_")
        cleanup = True

        # Inject GitLab token
        clone_url = repo_url
        gl = get_conn("gitlab")
        token = gl.get("token", "")
        if token and "gitlab" in repo_url and "@" not in repo_url:
            clone_url = repo_url.replace("https://", f"https://oauth2:{token}@")

        logger.info(f"[{scan_id[:8]}] Cloning {repo_url}")
        _patch_scan(scan_id, "running")
        try:
            subprocess.run(["git","clone","--depth=50",f"--branch={branch}",clone_url,target_dir],
                check=True, capture_output=True, text=True, timeout=300)
        except subprocess.CalledProcessError:
            subprocess.run(["git","clone","--depth=50",clone_url,target_dir],
                check=True, capture_output=True, text=True, timeout=300)

        scanner = SecretScanner()
        all_files = scanner.collect_files(target_dir)
        logger.info(f"[{scan_id[:8]}] {len(all_files)} files to scan")
        _patch_scan(scan_id, "running", total_files=len(all_files))

        ai_cfg = _get_ai_keys()
        detector = AIDetector(model=ai_model, api_keys=ai_cfg)

        findings = []
        tp = fp = 0
        scan_start = time.time()

        for i, fpath in enumerate(all_files):
            rel = fpath.replace(target_dir, "").lstrip("/")
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                if not code.strip() or len(code) > 150_000:
                    continue

                results = detector.detect_in_chunk(code, rel)
                for cf in results:
                    if cf.confidence < CONFIDENCE_THRESHOLD:
                        fp += 1
                        continue
                    tp += 1
                    lines = code.split("\n")
                    s = max(0, cf.line_number - 4)
                    e = min(len(lines), cf.line_number + 4)
                    context = "\n".join(lines[s:e])

                    # Git history correlation
                    hist = scanner.check_git_history(target_dir, cf.candidate_value)
                    author, email = scanner.git_blame(fpath, cf.line_number, target_dir)

                    finding = {
                        "id": str(_uuid.uuid4()),
                        "scan_id": scan_id,
                        "file_path": rel,
                        "line_number": cf.line_number,
                        "candidate_value": cf.candidate_value[:8] + "...",
                        "context_code": context[:600],
                        "is_secret": True,
                        "confidence": cf.confidence,
                        "secret_type": cf.secret_type,
                        "severity": cf.severity,
                        "reasoning": cf.reasoning,
                        "status": "open",
                        "ai_model": ai_model,
                        "env_var_suggestion": cf.env_var_suggestion,
                        "vault_path_suggestion": cf.vault_path_suggestion,
                        "commit_author": author,
                        "commit_email": email,
                        "days_in_history": hist.get("days_exposed", 0),
                        "history_alert_level": hist.get("alert_level", "none"),
                        "first_seen_date": hist.get("first_seen_date", ""),
                        "remediation_id": "",
                    }
                    findings.append(finding)
                    _post_finding(finding)

                    # Post history alert if significant
                    if hist.get("found_in_history") and hist.get("days_exposed", 0) > 0:
                        _post_history_alert(finding, hist, scan_id, repo_url)

            except Exception as ex:
                logger.debug(f"File {rel}: {ex}")

            if (i + 1) % 5 == 0:
                _patch_scan(scan_id, "running", scanned_files=i+1,
                            total_files=len(all_files), finding_count=tp)

        scan_duration = time.time() - scan_start
        _patch_scan(scan_id, "completed", total_files=len(all_files),
                    scanned_files=len(all_files), finding_count=tp)
        logger.info(f"[{scan_id[:8]}] Done: {tp} secrets in {scan_duration:.1f}s")

    except Exception as ex:
        logger.error(f"[{scan_id[:8]}] Scan failed: {ex}")
        _patch_scan(scan_id, "failed", error=str(ex))
    finally:
        if cleanup and target_dir:
            shutil.rmtree(target_dir, ignore_errors=True)


# ── Remediate endpoint ──────────────────────────────────────────────────────

@app.post("/remediate")
def remediate():
    data = request.get_json()
    if not data or "remediation_id" not in data:
        return jsonify({"error": "missing remediation_id"}), 400
    threading.Thread(target=_run_remediation, args=(data,), daemon=True).start()
    return jsonify({"status": "queued"}), 200


def _run_remediation(data):
    from ai.detector import AIDetector
    from remediation.vault_client import VaultClient
    from remediation.gitlab_client import GitLabClient
    from remediation.slack_notifier import SlackNotifier
    from remediation.email_notifier import EmailNotifier
    from remediation.revocation import RevocationEngine

    rem_id      = data["remediation_id"]
    finding_id  = data.get("finding_id", "")
    scan_id     = data.get("scan_id", "")
    file_path   = data.get("file_path", "")
    line_number = int(data.get("line_number", 0))
    candidate   = data.get("candidate_value", "")
    context     = data.get("context_code", "")
    secret_type = data.get("secret_type", "unknown")
    severity    = data.get("severity", "medium")
    ai_model    = data.get("ai_model", "claude-3-5-sonnet-20241022")
    author      = data.get("commit_author", "")
    email_addr  = data.get("commit_email", "")
    repo_url    = data.get("repo_url", "")
    env_var     = data.get("env_var_suggestion", "")
    vault_path  = data.get("vault_path_suggestion", "")
    days_hist   = int(data.get("days_in_history", 0))
    hist_level  = data.get("history_alert_level", "none")

    result = {
        "status": "completed", "vault_path": vault_path, "vault_status": "",
        "mr_url": "", "mr_number": 0, "mr_branch": "",
        "patch_content": "", "env_var_name": env_var,
        "issue_url": "", "issue_number": 0,
        "slack_status": "", "email_status": "",
        "revocation_status": "", "revocation_msg": "", "error_msg": "",
    }

    try:
        ai_cfg  = _get_ai_keys()
        gl_cfg  = get_conn("gitlab")
        vt_cfg  = get_conn("vault")
        sl_cfg  = get_conn("slack")
        em_cfg  = get_conn("email")
        aws_cfg = get_conn("aws")
        gh_cfg  = get_conn("github")

        repo_name = repo_url.split("/")[-1].removesuffix(".git") if repo_url else file_path

        # Stage 1: AI Patch Generation
        logger.info(f"[Rem {rem_id[:8]}] Stage 1: AI patch")
        detector = AIDetector(model=ai_model, api_keys=ai_cfg)
        rem = detector.generate_remediation(
            candidate=candidate, context=context,
            file_path=file_path, secret_type=secret_type,
            env_var=env_var, vault_path=vault_path,
            days_in_history=days_hist, hist_level=hist_level,
        )
        result["env_var_name"] = rem.env_var_name
        result["patch_content"] = rem.patched_line

        # Stage 2: Vault Poison Injection
        logger.info(f"[Rem {rem_id[:8]}] Stage 2: Vault poison injection")
        vault = VaultClient(config=vt_cfg)
        vpath = vault_path or f"secret/secretops/{repo_name}/{env_var.lower()}"
        ok, vstatus = vault.inject_poison(vpath, secret_type, finding_id, days_hist, candidate)
        result["vault_path"] = vpath
        result["vault_status"] = vstatus

        # Stage 3 + 4: GitLab MR + Issue
        logger.info(f"[Rem {rem_id[:8]}] Stage 3+4: GitLab MR + Issue")
        gitlab = GitLabClient(config=gl_cfg)
        project_id = gitlab.resolve_project_id(repo_url)
        if project_id:
            mr_res = gitlab.create_mr(
                project_id=project_id, file_path=file_path, line_number=line_number,
                patched_line=rem.patched_line, import_statement=rem.import_statement,
                env_var_name=rem.env_var_name, vault_path=vpath,
                mr_title=rem.mr_title, mr_description=rem.mr_description,
                finding_id=finding_id, rotation_steps=rem.rotation_steps,
                days_in_history=days_hist, hist_level=hist_level,
            )
            result["mr_url"]    = mr_res.get("mr_url", "")
            result["mr_number"] = mr_res.get("mr_number", 0)
            result["mr_branch"] = mr_res.get("mr_branch", "")

            issue_res = gitlab.create_issue(
                project_id=project_id, finding_id=finding_id,
                file_path=file_path, line_number=line_number,
                secret_type=secret_type, severity=severity,
                commit_author=author, commit_email=email_addr,
                env_var_name=rem.env_var_name, mr_url=result["mr_url"],
                vault_path=vpath, days_in_history=days_hist,
            )
            result["issue_url"]    = issue_res.get("issue_url", "")
            result["issue_number"] = issue_res.get("issue_number", 0)

        # Stage 5: Slack + Email
        logger.info(f"[Rem {rem_id[:8]}] Stage 5: Notifications")
        slack = SlackNotifier(config=sl_cfg)
        _, sl_status = slack.notify(
            finding_id=finding_id, file_path=file_path, line_number=line_number,
            secret_type=secret_type, severity=severity, repo_name=repo_name,
            ai_model=ai_model, mr_url=result["mr_url"],
            issue_url=result["issue_url"], vault_path=vpath,
            days_in_history=days_hist, hist_level=hist_level,
        )
        result["slack_status"] = sl_status

        emailer = EmailNotifier(config=em_cfg)
        _, em_status = emailer.notify(
            finding_id=finding_id, file_path=file_path, line_number=line_number,
            secret_type=secret_type, severity=severity, repo_name=repo_name,
            mr_url=result["mr_url"], issue_url=result["issue_url"],
            vault_path=vpath, days_in_history=days_hist, hist_level=hist_level,
        )
        result["email_status"] = em_status

        # Stage 6: Direct Revocation
        logger.info(f"[Rem {rem_id[:8]}] Stage 6: Revocation")
        engine = RevocationEngine(aws_config=aws_cfg, gitlab_config=gl_cfg, github_config=gh_cfg)
        rev_ok, rev_msg = engine.attempt_revocation(secret_type, candidate)
        result["revocation_status"] = "revoked" if rev_ok else "not_applicable"
        result["revocation_msg"] = rev_msg

    except Exception as ex:
        logger.error(f"[Rem {rem_id[:8]}] Error: {ex}")
        result["status"] = "failed"
        result["error_msg"] = str(ex)

    try:
        http_req.patch(f"{BACKEND}/api/v1/remediations/{rem_id}", json=result, timeout=10)
        if result["mr_url"] or result["vault_status"] in ("poisoned", "unavailable_fallback"):
            http_req.patch(f"{BACKEND}/api/v1/findings/{finding_id}/status",
                           json={"status": "remediated"}, timeout=5)
    except Exception as ex:
        logger.error(f"Backend update failed: {ex}")


# ── Post-merge Verify endpoint ──────────────────────────────────────────────

@app.post("/verify")
def verify():
    data = request.get_json()
    threading.Thread(target=_run_verify, args=(data,), daemon=True).start()
    return jsonify({"status": "queued"}), 200


def _run_verify(data):
    from remediation.vault_client import VaultClient
    from remediation.slack_notifier import SlackNotifier
    from remediation.email_notifier import EmailNotifier

    rem_id     = data.get("remediation_id", "")
    finding_id = data.get("finding_id", "")
    vault_path = data.get("vault_path", "")

    vt_cfg = get_conn("vault")
    sl_cfg = get_conn("slack")
    em_cfg = get_conn("email")

    vault = VaultClient(config=vt_cfg)
    current_val = vault.read_value(vault_path)

    if current_val is None:
        # Path not updated — prompt engineer
        status = "pending_choice"
        msg = "Vault path not updated after MR merge. Manual confirmation required."
    elif current_val.startswith("SECRETOPS_POISONED_"):
        # Still poisoned — not rotated
        status = "not_rotated"
        msg = "MR merged but credential NOT rotated. Vault still contains poison placeholder."
        # Send escalated alert
        slack = SlackNotifier(config=sl_cfg)
        slack.notify_post_merge_fail(finding_id, vault_path, rem_id)
        emailer = EmailNotifier(config=em_cfg)
        emailer.notify_post_merge_fail(finding_id, vault_path, rem_id)
    else:
        # New value present — rotation confirmed
        status = "rotation_confirmed"
        msg = "Post-merge verification passed. Credential successfully rotated."
        # Close finding
        http_req.patch(f"{BACKEND}/api/v1/findings/{finding_id}/status",
                       json={"status": "closed"}, timeout=5)

    http_req.patch(f"{BACKEND}/api/v1/remediations/{rem_id}",
                   json={"post_merge_status": status, "error_msg": msg}, timeout=10)
    logger.info(f"[Verify {rem_id[:8]}] {status}: {msg}")


# ── Helpers ─────────────────────────────────────────────────────────────────

def _get_ai_keys():
    """Collect AI keys — DB config first, env var fallback. Supports multiple keys per provider."""
    keys = {}
    for provider in ["claude", "openai", "deepseek", "gemini", "ollama"]:
        cfg = get_conn(provider)
        k1 = cfg.get("api_key", "") or os.environ.get(f"{provider.upper()}_API_KEY", "")
        k2 = cfg.get("api_key_2", "")
        if k1:
            keys[provider] = [k1] + ([k2] if k2 else [])
        base_url = cfg.get("base_url", "")
        if base_url:
            keys[f"{provider}_base_url"] = base_url
        model_name = cfg.get("model", "")
        if model_name:
            keys[f"{provider}_model"] = model_name
    return keys

def _patch_scan(scan_id, status, total_files=0, scanned_files=0, finding_count=0, error=""):
    try:
        http_req.patch(f"{BACKEND}/api/v1/scans/{scan_id}", json={
            "status": status, "total_files": total_files,
            "scanned_files": scanned_files, "finding_count": finding_count, "error_msg": error,
        }, timeout=5)
    except Exception:
        pass

def _post_finding(f):
    try: http_req.post(f"{BACKEND}/api/v1/findings", json=f, timeout=5)
    except Exception: pass

def _post_history_alert(finding, hist, scan_id, repo_url):
    repo_name = repo_url.split("/")[-1].removesuffix(".git") if repo_url else ""
    try:
        http_req.post(f"{BACKEND}/api/v1/history-alerts", json={
            "finding_id": finding["id"], "scan_id": scan_id, "repo_name": repo_name,
            "days_exposed": hist.get("days_exposed", 0),
            "alert_level": hist.get("alert_level", "INFO"),
            "first_seen_commit": hist.get("first_seen_commit", ""),
            "first_seen_author": hist.get("first_seen_author", ""),
            "first_seen_date": hist.get("first_seen_date", ""),
            "commit_count": hist.get("commit_count", 0),
            "slack_sent": 0, "email_sent": 0,
        }, timeout=5)
    except Exception:
        pass


if __name__ == "__main__":
    port = int(os.environ.get("CLI_PORT", "5001"))
    logger.info(f"SecretOps CLI Service v3 starting on :{port}")
    app.run(host="0.0.0.0", port=port, threaded=True)
