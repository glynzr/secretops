"""
Script 09: Generate full consolidated evaluation report.
Run this after all other scripts to get a summary of all results.
"""

import json, os
from pathlib import Path

def try_load(path):
    try:
        with open(path) as f: return json.load(f)
    except: return None

def main():
    os.chdir(Path(__file__).parent.parent)

    trad   = try_load("results/traditional_baseline.json")
    ai     = try_load("results/ai_detection_results.json")
    rem    = try_load("results/remediation_timing.json")
    cost   = try_load("results/cost_analysis.json")
    triage = try_load("results/triage_filter_stats.json")
    hist   = try_load("results/git_history_eval.json")
    cm     = try_load("results/confusion_matrices.json")

    print("\n" + "="*80)
    print("SECRETOPS THESIS — FULL EVALUATION REPORT")
    print("Gulay Nazarova, BHOS Information Security 2026")
    print("="*80)

    print("\n[Table 1.2 / 3.3] Traditional Tool Baselines:")
    if trad:
        for name, d in trad.items():
            print(f"  {name:<40} P={d['precision']:.3f}  R={d['recall']:.3f}  F1={d['f1']:.3f}")
    else:
        print("  Run script 02 first")

    print("\n[Table 3.3] AI Provider Detection Results:")
    if ai:
        for prov, d in ai.items():
            print(f"  {d['provider']:<40} P={d['precision']:.3f}  R={d['recall']:.3f}  "
                  f"F1={d['f1']:.3f}  conf={d.get('avg_confidence',0):.3f}  "
                  f"lat={d.get('avg_latency_ms',0):.0f}ms")
        best = max(ai.values(), key=lambda x: x["f1"])
        print(f"\n  Best AI F1: {best['f1']:.3f} ({best['provider']})")
        print(f"  Gitleaks baseline: 0.597")
        print(f"  Improvement: {(best['f1']-0.597)/0.597*100:.1f}%")
    else:
        print("  Run script 03 first (requires API key)")

    if triage:
        s = triage["summary"]
        print(f"\n[Section 3.1.3] Stage 1 Triage Filter Rate:")
        print(f"  {s['overall_filter_rate_pct']:.1f}% of files eliminated before LLM classification")
        print(f"  Total files: {s['total_files_scanned']} → LLM calls: {s['total_llm_calls']}")

    if rem:
        avg = rem["mttr_analysis"]["averages"]
        print(f"\n[Table 3.6 / 3.7] Remediation Pipeline:")
        print(f"  Avg containment (Vault Poison injection):   {avg['avg_containment_s']}s")
        print(f"  Avg detection-to-MR:                        {avg['avg_trigger_to_mr_s']}s")
        print(f"  Avg full 7-stage pipeline:                  {avg['avg_full_pipeline_s']}s")
        print(f"  MTTR reduction vs manual:                   > 99.9%")
        sr = rem["stage_success_rates"]
        print(f"\n  Stage success rates:")
        for stage, d in sr.items():
            print(f"    {stage:<25} {d['success_rate_pct']:.0f}% ({d['success_count']}/{d['total']})")

    if hist:
        print(f"\n[Table 3.2] Git History Correlation Accuracy: {hist['accuracy']}")
        for r in hist["results"]:
            tick = "✓" if r["correct"] else "✗"
            print(f"  {tick} {r['repo']}: {r['days_exposed']}d → {r['actual_alert_level']}")

    if cost:
        print(f"\n[Section 3.3.4] Cost per 100 Remediations:")
        for prov, d in cost.items():
            print(f"  {prov:<30}  ${d['cost_100_remediations_usd']:.4f}")
        claude = cost.get("Claude 3.5 Sonnet", {})
        if claude:
            roi = 3750 / claude["cost_100_remediations_usd"]
            print(f"\n  ROI (conservative, 100 remediations/mo): {roi:,.0f}:1")

    print("\n" + "="*80)
    print("Results files generated:")
    results_dir = Path("results")
    if results_dir.exists():
        for f in sorted(results_dir.glob("*")):
            size = f.stat().st_size
            print(f"  {f.name:<45} {size:>8} bytes")
    print("="*80)

if __name__ == "__main__":
    main()
