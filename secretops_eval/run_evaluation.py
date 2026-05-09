"""
SecretOps Evaluation Master Runner
====================================
Runs all evaluation scripts and generates a consolidated report.

Run: python run_evaluation.py
"""

import subprocess, json, sys, os
from datetime import datetime

os.makedirs("results", exist_ok=True)

print("╔══════════════════════════════════════════════════════════════╗")
print("║     SecretOps Evaluation Suite — Complete Run                ║")
print(f"║     {datetime.now().strftime('%Y-%m-%d %H:%M')}                                        ║")
print("╚══════════════════════════════════════════════════════════════╝\n")

scripts = [
    ("eval_detection.py",   "RQ2: Detection Performance"),
    ("eval_remediation.py", "RQ3: Remediation Pipeline Performance"),
]

for script, label in scripts:
    print(f"\n{'─'*60}")
    print(f"Running: {label}")
    print(f"Script:  {script}")
    print('─'*60)
    result = subprocess.run([sys.executable, script], capture_output=False)
    if result.returncode != 0:
        print(f" FAILED: {script}")
        sys.exit(1)
    print(f"✓ Completed: {script}")

# ── Load and consolidate results ──────────────────────────────────────────────
print(f"\n{'═'*60}")
print("CONSOLIDATED EVALUATION SUMMARY")
print('═'*60)

with open("results/detection_results.json") as f:
    det = json.load(f)
with open("results/remediation_results.json") as f:
    rem = json.load(f)

print("\n📊 RQ2 — Detection Performance")
print("-"*40)
for provider, label in [
    ("claude-3-5-sonnet", "Claude 3.5 Sonnet"),
    ("gpt-4o",            "GPT-4o"),
    ("deepseek-v3",       "DeepSeek V3"),
    ("gemini-2.0-flash",  "Gemini 2.0 Flash"),
    ("ollama-llama3.1",   "Ollama LLaMA-3.1-8B"),
]:
    m = det["ai_providers"][provider]
    print(f"  {label:<25} F1={m['f1']:.3f}  P={m['precision']:.3f}  R={m['recall']:.3f}  {m['avg_latency_ms']}ms")

print()
for tool, label in [("gitleaks","Gitleaks"),("trufflehog","TruffleHog"),("detect_secrets","detect-secrets")]:
    m = det["traditional_tools"][tool]
    print(f"  {label:<25} F1={m['f1']:.3f}  P={m['precision']:.3f}  R={m['recall']:.3f}  (baseline)")

stage1 = det["stage1_prefiler"]
print(f"\n  Stage 1 API reduction: {stage1['api_reduction_pct']}%  ({stage1['llm_calls_needed']}/{det['dataset']['total']} files sent to LLM)")

print("\n RQ3 — Remediation Pipeline Performance")
print("-"*40)
for stage, stats in rem["stage_statistics"].items():
    label = stage.replace("stage", "Stage ").replace("_", " ").title()
    print(f"  {label:<30} {stats['success_rate_pct']:>5.0f}%  {stats['avg_duration_s']:.2f}s avg")

mttr = rem["mttr_comparison"]
print(f"\n  MTTR: {mttr['manual_min_hours']:.0f}–{mttr['manual_max_hours']:.0f}h manual → "
      f"{mttr['secretops_total_s']:.1f}s automated ({mttr['mttr_reduction_pct']:.1f}% reduction)")

vault = rem["vault_coverage"]
print(f"  Vault Poison Coverage: {vault['vault_coverage_pct']:.0f}% ({vault['vault_poison_types']}/{vault['secret_types_total']} types)")

econ = rem["economic_analysis"]
print(f"  ROI: {econ['roi_100_remediations_per_month']:,.0f}:1 "
      f"(AI cost ${econ['monthly_ai_cost_usd']:.2f}/mo vs ${econ['monthly_dev_savings_usd']:,.0f}/mo saved)")

# Save consolidated summary
summary = {
    "generated_at": datetime.now().isoformat(),
    "rq2_detection": {
        "dataset_size": det["dataset"]["total"],
        "stage1_api_reduction_pct": stage1["api_reduction_pct"],
        "providers": {p: {"f1": det["ai_providers"][p]["f1"],
                          "precision": det["ai_providers"][p]["precision"],
                          "recall": det["ai_providers"][p]["recall"],
                          "latency_ms": det["ai_providers"][p]["avg_latency_ms"]}
                      for p in det["ai_providers"]},
        "traditional": {t: {"f1": det["traditional_tools"][t]["f1"],
                             "precision": det["traditional_tools"][t]["precision"],
                             "recall": det["traditional_tools"][t]["recall"]}
                        for t in det["traditional_tools"]},
    },
    "rq3_remediation": {
        "n_executions": rem["n_executions"],
        "avg_pipeline_s": rem["pipeline_timing"]["avg_total_s"],
        "mttr_reduction_pct": rem["mttr_comparison"]["mttr_reduction_pct"],
        "vault_coverage_pct": rem["vault_coverage"]["vault_coverage_pct"],
        "roi": rem["economic_analysis"]["roi_100_remediations_per_month"],
    }
}

with open("results/summary.json", "w") as f:
    json.dump(summary, f, indent=2)

print(f"\n{'═'*60}")
print(" All evaluations complete. Results in results/")
print("  ├── detection_results.json   (RQ2 full data)")
print("  ├── remediation_results.json (RQ3 full data)")
print("  ├── detection_report.txt     (human-readable)")
print("  ├── remediation_report.txt   (human-readable)")
print("  └── summary.json             (consolidated)")
