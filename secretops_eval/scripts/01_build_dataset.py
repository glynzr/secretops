"""
Script 01: Build the 50-sample labeled benchmark dataset.
Produces: data/benchmark_50.json

The dataset is constructed to reflect the realistic distribution of
true positives and false positives in enterprise GitLab repositories,
as documented in Basak et al. (2023).

Each sample contains:
  - id: unique identifier
  - code_snippet: representative code line
  - candidate_value: the value being classified
  - ground_truth: True (is a secret) or False (not a secret)
  - secret_type: category label
  - category: description of why this sample is in the dataset
  - file_context: simulated file type for context
"""

import json, os
#dataset is excluded for confidentiality reasons, but in practice this would be populated with the actual samples used in the evaluation.
DATASET=[]

# Verify counts
tp = sum(1 for d in DATASET if d["ground_truth"])
fp = sum(1 for d in DATASET if not d["ground_truth"])
assert len(DATASET) == 50, f"Expected 50 samples, got {len(DATASET)}"
assert tp == 27, f"Expected 27 TP, got {tp}"
assert fp == 23, f"Expected 23 FP, got {fp}"

os.makedirs("data", exist_ok=True)
with open("data/benchmark_50.json", "w") as f:
    json.dump({"metadata": {
        "total": len(DATASET), "true_secrets": tp, "non_secrets": fp,
        "description": "50-sample labeled benchmark for SecretOps thesis evaluation",
        "source": "Gulay Nazarova, BHOS 2026 — categories based on Basak et al. (2023)",
    }, "samples": DATASET}, f, indent=2)

print(f"Dataset built: {len(DATASET)} samples ({tp} TP, {fp} FP)")
print("Saved to: data/benchmark_50.json")
