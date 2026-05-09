"""
Script 07: Cost analysis per provider.
Produces: results/cost_analysis.json (Section 3.3.4)

Calculates detection and remediation costs based on measured token counts
from the evaluation runs.
"""

import json, os
from pathlib import Path

# Measured token counts from evaluation (per-call averages from api_call_log.jsonl)
# Detection prompt: system ~800 tokens + user ~150 tokens + response ~120 tokens
# Remediation prompt: system ~600 tokens + user ~200 tokens + response ~300 tokens

DETECTION_TOKENS = {"input": 950, "output": 120}
REMEDIATION_TOKENS = {"input": 800, "output": 300}

# Pricing per 1M tokens (USD), as of evaluation date
PROVIDERS = {
    "Claude 3.5 Sonnet": {
        "input_per_1m": 3.00, "output_per_1m": 15.00,
        "rpm_limit": 1000, "data_leaves": "YES (ZDR req.)",
        "f1": 0.921,
    },
    "GPT-4o": {
        "input_per_1m": 2.50, "output_per_1m": 10.00,
        "rpm_limit": 500, "data_leaves": "YES (ZDR req.)",
        "f1": 0.926,
    },
    "DeepSeek V3": {
        "input_per_1m": 0.07, "output_per_1m": 1.10,
        "rpm_limit": 999999, "data_leaves": "YES (PIPL risk)",
        "f1": 0.903,
    },
    "Gemini 2.0 Flash": {
        "input_per_1m": 0.10, "output_per_1m": 0.40,
        "rpm_limit": 2000, "data_leaves": "YES",
        "f1": 0.860,
    },
    "Ollama LLaMA-3.1-8B": {
        "input_per_1m": 0.00, "output_per_1m": 0.00,  # local GPU cost only
        "rpm_limit": 999999, "data_leaves": "NO (on-premise)",
        "f1": 0.900,
        "gpu_note": "A10G GPU ~$0.75/hr. At 890ms/call, costs ~$0.0002/call in GPU time.",
    },
}

def cost_per_call(provider: dict, token_type: str) -> float:
    if token_type == "detection":
        t = DETECTION_TOKENS
    else:
        t = REMEDIATION_TOKENS
    input_cost  = provider["input_per_1m"]  / 1_000_000 * t["input"]
    output_cost = provider["output_per_1m"] / 1_000_000 * t["output"]
    return input_cost + output_cost

def main():
    os.chdir(Path(__file__).parent.parent)
    os.makedirs("results", exist_ok=True)

    results = {}
    print("\n" + "="*100)
    print("TABLE: Cost Analysis per Provider (Section 3.3.4)")
    print("="*100)
    print(f"{'Provider':<25} {'F1':>5} {'Cost/Detection':>15} {'Cost/500 files':>15} {'Cost/Remediaton':>17} {'100 rem/mo':>12}")
    print("-"*100)

    for name, p in PROVIDERS.items():
        det_cost = cost_per_call(p, "detection")
        rem_cost = cost_per_call(p, "remediation")
        # 500-file repo: ~40% filtered by Stage 1, so ~300 LLM calls
        cost_500_files = det_cost * 300
        cost_100_rem = rem_cost * 100

        results[name] = {
            "f1": p["f1"],
            "cost_per_detection_call_usd": round(det_cost, 6),
            "cost_per_remediation_call_usd": round(rem_cost, 6),
            "cost_500_file_scan_usd": round(cost_500_files, 4),
            "cost_100_remediations_usd": round(cost_100_rem, 4),
            "rpm_limit": p["rpm_limit"],
            "data_leaves_network": p["data_leaves"],
        }
        if "gpu_note" in p:
            results[name]["gpu_note"] = p["gpu_note"]

        print(f"  {name:<23} {p['f1']:>5.3f} "
              f"${det_cost*1000:>12.4f}m  "
              f"${cost_500_files:>13.4f}  "
              f"${rem_cost:>15.6f}  "
              f"${cost_100_rem:>10.4f}")

    print("="*100)
    print("\nDeveloper time saved (conservative estimate):")
    print("  Patch creation: 30 min - 2 hrs @ $75-150/hr = $37.50 - $300 per finding")
    print("  100 remediations/month = $3,750 - $30,000 in developer time")
    claude_cost = results["Claude 3.5 Sonnet"]["cost_100_remediations_usd"]
    print(f"  Claude 3.5 Sonnet AI cost for 100 remediations: ${claude_cost:.4f}")
    roi = 3750 / claude_cost if claude_cost > 0 else float('inf')
    print(f"  ROI (conservative): {roi:,.0f}:1")

    with open("results/cost_analysis.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nSaved: results/cost_analysis.json")

if __name__ == "__main__":
    main()
