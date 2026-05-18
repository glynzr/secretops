#!/usr/bin/env python3
"""SecretOps AI Engine"""

import os
import time
import sqlite3
import threading
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

from flask import Flask, request, jsonify
from detection.pipeline import DetectionPipeline
from remediation.pipeline import RemediationPipeline
from remediation.verifier import RotationVerifier

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "/data/secretops.db")

detection_pipeline = DetectionPipeline()
remediation_pipeline = RemediationPipeline()
verifier = RotationVerifier()


@app.route('/api/health')
def health():
    return jsonify({"status": "ok"})


@app.route('/api/test-provider', methods=['POST'])
def test_provider():
    data = request.get_json()
    result = detection_pipeline.classifier.test_provider(
        data.get("provider_type", ""),
        data.get("api_key", "")
    )
    return jsonify(result)


@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    thread = threading.Thread(
        target=detection_pipeline.run_scan, args=(data,), daemon=True
    )
    thread.start()
    return jsonify({"status": "started"}), 202


@app.route('/api/remediate/<int:finding_id>', methods=['POST'])
def remediate(finding_id):
    thread = threading.Thread(
        target=remediation_pipeline.run, args=(finding_id,), daemon=True
    )
    thread.start()
    return jsonify({"status": "started"}), 202


@app.route('/api/verify/<int:finding_id>', methods=['POST'])
def verify(finding_id):
    result = verifier.verify(finding_id)
    return jsonify(result)


@app.route('/api/webhook/gitlab', methods=['POST'])
def gitlab_webhook():
    """Receive GitLab merge request events and trigger verification."""
    data = request.get_json(silent=True) or {}
    event = request.headers.get('X-Gitlab-Event', '')

    logger.info(f"GitLab webhook received: event={event}")

    if event != 'Merge Request Hook':
        return jsonify({"status": "ignored", "event": event}), 200

    mr = data.get('object_attributes', {})
    state = mr.get('state', '')
    action = mr.get('action', '')

    logger.info(f"MR event: state={state} action={action}")

    if state != 'merged':
        return jsonify({"status": "ignored", "state": state}), 200

    mr_url = mr.get('url', '')
    mr_iid = str(mr.get('iid', ''))

    logger.info(f"MR merged: {mr_url} — triggering verification")

    thread = threading.Thread(
        target=_verify_for_mr,
        args=(mr_url, mr_iid),
        daemon=True
    )
    thread.start()

    return jsonify({"status": "verification_triggered"}), 200


def _verify_for_mr(mr_url: str, mr_iid: str):
    """Find all findings for this MR and verify rotation."""
    try:
        db = sqlite3.connect(DB_PATH, timeout=30)
        rows = db.execute(
            "SELECT id FROM findings WHERE (mr_url=? OR mr_id=?) AND status IN ('remediating','remediated','confirmed')",
            (mr_url, mr_iid)
        ).fetchall()
        db.close()

        logger.info(f"Webhook: {len(rows)} findings to verify for MR {mr_url}")
        for (finding_id,) in rows:
            try:
                result = verifier.verify(finding_id)
                logger.info(f"Verified finding {finding_id}: {result.get('status')}")
            except Exception as e:
                logger.error(f"Verify finding {finding_id} failed: {e}")
    except Exception as e:
        logger.error(f"Webhook handler error: {e}")


def _background_loop():
    """Poll every 2 minutes for remediated findings and verify rotation."""
    logger.info("Background verification loop starting in 15s...")
    time.sleep(15)
    logger.info("Background verification loop active — polling every 2 minutes")

    while True:
        try:
            db = sqlite3.connect(DB_PATH, timeout=30)
            db.execute("PRAGMA journal_mode=WAL")
            rows = db.execute("""
                SELECT id, secret_type, mr_url
                FROM findings
                WHERE status IN ('remediating', 'remediated')
                AND vault_path != ''
                AND vault_path IS NOT NULL
            """).fetchall()
            db.close()

            # 1. Retry failed Vault injections
            try:
                s, f = remediation_pipeline.retry_failed_vault_injections(db)
                if s or f:
                    logger.info(f"Vault injection retry: {s} succeeded, {f} still pending")
            except Exception as e:
                logger.error(f"Vault retry error: {e}")

            # 2. Verify rotation for remediated findings
            if rows:
                logger.info(f"Verification loop: checking {len(rows)} finding(s)")
                for (finding_id, secret_type, mr_url) in rows:
                    try:
                        result = verifier.verify(finding_id)
                        logger.info(f"Finding {finding_id} ({secret_type}): {result.get('status')} — {result.get('message','')}")
                    except Exception as e:
                        logger.error(f"Verify finding {finding_id} failed: {e}")
                    time.sleep(1)
            else:
                logger.debug("Verification loop: no findings pending verification")

            db.close()

        except Exception as e:
            logger.error(f"Background loop error: {e}")
            try:
                db.close()
            except Exception:
                pass

        time.sleep(120)


if __name__ == '__main__':
    bg = threading.Thread(target=_background_loop, daemon=True, name="verification-loop")
    bg.start()
    app.run(host='0.0.0.0', port=5001, threaded=True)

# cache-bust: 1779097175
