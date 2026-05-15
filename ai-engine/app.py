#!/usr/bin/env python3
"""SecretOps AI Engine - Detection & Remediation Orchestrator"""

import threading
import logging
from flask import Flask, request, jsonify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
from detection.pipeline import DetectionPipeline
from remediation.pipeline import RemediationPipeline
from remediation.verifier import RotationVerifier

app = Flask(__name__)
app.config['THREADED'] = True

detection_pipeline = DetectionPipeline()
remediation_pipeline = RemediationPipeline()
verifier = RotationVerifier()


@app.route('/api/health')
def health():
    return jsonify({"status": "ok", "service": "secretops-ai-engine"})


@app.route('/api/test-provider', methods=['POST'])
def test_provider():
    data = request.json
    provider = data.get("provider")
    api_key = data.get("api_key")
    result = detection_pipeline.test_provider(provider, api_key)
    if result["success"]:
        return jsonify(result), 200
    return jsonify(result), 400


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    scan_id = data.get("scan_id")
    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400
    
    # Run scan in background thread
    thread = threading.Thread(target=detection_pipeline.run_scan, args=(data,), daemon=True)
    thread.start()
    
    return jsonify({"message": "Scan started", "scan_id": scan_id}), 202


@app.route('/api/remediate/<int:finding_id>', methods=['POST'])
def remediate(finding_id):
    thread = threading.Thread(target=remediation_pipeline.run, args=(finding_id,), daemon=True)
    thread.start()
    return jsonify({"message": "Remediation started", "finding_id": finding_id}), 202


@app.route('/api/verify/<int:finding_id>', methods=['POST'])
def verify(finding_id):
    result = verifier.verify(finding_id)
    return jsonify(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, threaded=True)
