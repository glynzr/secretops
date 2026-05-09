# SecretOps — Evaluation Scripts

## Overview

These scripts produce the empirical results reported in Chapter 3 of the thesis.
Each script is self-contained, reproducible, and documents exactly what it measures,
how values are calculated, and where each result table comes from.

## Files

| Script | Purpose | Thesis Section |
|--------|---------|----------------|
| eval_detection.py   | RQ2: Detection performance across AI providers + traditional tools | 3.2 |
| eval_remediation.py | RQ3: Remediation pipeline timing, MTTR, Vault coverage, economics | 3.3 |
| run_evaluation.py   | Master runner — executes both scripts, generates consolidated summary | - |

## How to Run

    python run_evaluation.py     # runs everything
    python eval_detection.py     # RQ2 only
    python eval_remediation.py   # RQ3 only

No external dependencies required — Python 3.8+ standard library only.
Output goes to results/ directory.

## Metric Calculations

### Precision, Recall, F1

    TP = predicted secret AND actually secret
    FP = predicted secret AND NOT secret (false alarm)
    TN = predicted not-secret AND NOT secret
    FN = predicted not-secret AND actually secret

    Precision = TP / (TP + FP)
    Recall    = TP / (TP + FN)
    F1        = 2 * Precision * Recall / (Precision + Recall)

### Shannon Entropy (Stage 1 pre-filter)

    H = -sum( p(c) * log2(p(c)) ) for each unique character c
    Genuine secrets typically have H > 3.5 bits/character.
    Low-entropy values (H < 2.5) are unlikely to be real credentials.

### API Call Reduction Rate

    reduction% = (samples handled by Stage 1) / total_samples * 100
    Stage 1 handles: high-confidence provider patterns + documented false positives
    Only ambiguous candidates proceed to LLM classification (Stage 3)

### MTTR Comparison

    mttr_reduction% = (1 - automated_s / (manual_min_h * 3600)) * 100
    Manual baselines from: Rahman et al. (2021), GitGuardian 2025

### Economic ROI

    ai_cost_per_remediation = 350 tokens * $3.00/1M = $0.00105 ~ $0.007
    dev_saved = 1.0 hours * $100/hr = $100
    roi = (100 remediations * $100) / (100 * $0.007) = 14,286:1

## Thesis Table Mapping

| Table | Source |
|-------|--------|
| Table 3.3 Detection benchmark | detection_results.json -> ai_providers + traditional_tools |
| Table 3.6 Pipeline execution  | remediation_results.json -> stage_statistics |
| Table 3.7 MTTR comparison     | remediation_results.json -> mttr_comparison |
| Table 3.8 Vault coverage      | remediation_results.json -> vault_coverage |
