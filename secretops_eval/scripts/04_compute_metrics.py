"""
Script 04: Compute final metrics table combining AI + traditional tool results.
Produces: results/metrics_summary.csv  (Table 3.3 in thesis)
          results/confusion_matrices.json
          results/metrics_summary.png  (bar chart)

Run AFTER scripts 02 and 03.
"""

import json, os
import csv
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("matplotlib not installed — skipping charts")

def load_json(path):
    with open(path) as f:
        return json.load(f)

def main():
    os.chdir(Path(__file__).parent.parent)
    os.makedirs("results", exist_ok=True)

    rows = []

    # Traditional tools
    if os.path.exists("results/traditional_baseline.json"):
        trad = load_json("results/traditional_baseline.json")
        for name, d in trad.items():
            rows.append({
                "tool": name,
                "type": "Traditional",
                "precision": d["precision"],
                "recall": d["recall"],
                "f1": d["f1"],
                "avg_confidence": "N/A",
                "avg_latency_ms": "< 1",
                "data_leaves_network": "No",
                "tp": d["tp"], "fp": d["fp"], "tn": d["tn"], "fn": d["fn"],
            })

    # AI tools
    if os.path.exists("results/ai_detection_results.json"):
        ai = load_json("results/ai_detection_results.json")
        provider_meta = {
            "claude":   {"type": "AI few-shot", "data_leaves": "YES (ZDR req.)"},
            "openai":   {"type": "AI few-shot", "data_leaves": "YES (ZDR req.)"},
            "deepseek": {"type": "AI few-shot", "data_leaves": "YES (PIPL risk)"},
            "gemini":   {"type": "AI few-shot", "data_leaves": "YES"},
            "ollama":   {"type": "AI few-shot (local)", "data_leaves": "NO — on-premise"},
        }
        for prov, d in ai.items():
            meta = provider_meta.get(prov, {"type": "AI few-shot", "data_leaves": "?"})
            rows.append({
                "tool": d["provider"],
                "type": meta["type"],
                "precision": d["precision"],
                "recall": d["recall"],
                "f1": d["f1"],
                "avg_confidence": d.get("avg_confidence", "N/A"),
                "avg_latency_ms": d.get("avg_latency_ms", "N/A"),
                "data_leaves_network": meta["data_leaves"],
                "tp": d["tp"], "fp": d["fp"], "tn": d["tn"], "fn": d["fn"],
            })

    if not rows:
        print("No results found — run scripts 02 and 03 first.")
        return

    # Sort: AI first by F1 descending, then traditional
    ai_rows   = sorted([r for r in rows if r["type"] != "Traditional"], key=lambda x: -x["f1"])
    trad_rows = sorted([r for r in rows if r["type"] == "Traditional"], key=lambda x: -x["f1"])
    rows = ai_rows + trad_rows

    # Print table
    print("\n" + "="*100)
    print("TABLE 3.3: Detection Performance on 50-Sample Labeled Benchmark")
    print("="*100)
    print(f"{'Tool':<40} {'Type':<22} {'Prec':>6} {'Rec':>6} {'F1':>6} {'AvgConf':>8} {'Lat(ms)':>8} {'Privacy'}")
    print("-"*100)
    for r in rows:
        conf = f"{r['avg_confidence']:.3f}" if isinstance(r['avg_confidence'], float) else str(r['avg_confidence'])
        lat  = f"{r['avg_latency_ms']:.0f}" if isinstance(r['avg_latency_ms'], float) else str(r['avg_latency_ms'])
        print(f"{r['tool']:<40} {r['type']:<22} {r['precision']:>6.3f} {r['recall']:>6.3f} {r['f1']:>6.3f} "
              f"{conf:>8} {lat:>8} {r['data_leaves_network']}")
    print("="*100)

    # CSV output
    fieldnames = ["tool","type","precision","recall","f1","avg_confidence","avg_latency_ms",
                  "data_leaves_network","tp","fp","tn","fn"]
    with open("results/metrics_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print("\nSaved: results/metrics_summary.csv")

    # Confusion matrices
    cm_data = {r["tool"]: {"tp":r["tp"],"fp":r["fp"],"tn":r["tn"],"fn":r["fn"],
                            "precision":r["precision"],"recall":r["recall"],"f1":r["f1"]}
               for r in rows}
    with open("results/confusion_matrices.json","w") as f:
        json.dump(cm_data, f, indent=2)
    print("Saved: results/confusion_matrices.json")

    # F1 bar chart
    if HAS_MPL:
        fig, ax = plt.subplots(figsize=(12, 5))
        tools = [r["tool"].split("(")[0].strip() for r in rows]
        f1s   = [r["f1"] for r in rows]
        types = [r["type"] for r in rows]
        colors = ["#2f81f7" if "AI" in t else "#6e7681" for t in types]
        bars = ax.barh(tools, f1s, color=colors, height=0.6, edgecolor='#30363d')
        ax.axvline(x=0.597, color='#f85149', linestyle='--', linewidth=1.5, label='Gitleaks baseline (F1=0.597)')
        ax.set_xlabel('F1-Score', fontsize=12)
        ax.set_title('SecretOps Detection Benchmark — F1-Score Comparison\n(50-sample labeled dataset, thesis Table 3.3)', fontsize=13, pad=12)
        ax.set_xlim(0, 1.05)
        for bar, val in zip(bars, f1s):
            ax.text(val + 0.01, bar.get_y() + bar.get_height()/2, f'{val:.3f}', va='center', fontsize=10)
        ai_patch   = mpatches.Patch(color='#2f81f7', label='AI providers')
        trad_patch = mpatches.Patch(color='#6e7681', label='Traditional tools')
        ax.legend(handles=[ai_patch, trad_patch, ax.lines[0]], loc='lower right', fontsize=10)
        ax.set_facecolor('#161b22')
        fig.patch.set_facecolor('#0d1117')
        ax.tick_params(colors='#e6edf3')
        ax.xaxis.label.set_color('#e6edf3')
        ax.title.set_color('#e6edf3')
        plt.tight_layout()
        plt.savefig("results/metrics_f1_comparison.png", dpi=150, bbox_inches='tight',
                    facecolor='#0d1117')
        print("Saved: results/metrics_f1_comparison.png")
        plt.close()

    # Key stats for thesis text
    if ai_rows:
        best_ai = max(ai_rows, key=lambda x: x["f1"])
        baseline_f1 = 0.597
        improvement = (best_ai["f1"] - baseline_f1) / baseline_f1 * 100
        print(f"\nKey statistics for thesis:")
        print(f"  Best AI F1: {best_ai['f1']:.3f} ({best_ai['tool']})")
        print(f"  Gitleaks baseline F1: {baseline_f1}")
        print(f"  Improvement over Gitleaks: {improvement:.1f}%")
        if any("ollama" in r.get("type","").lower() or "local" in r.get("type","").lower() for r in ai_rows):
            local = next(r for r in ai_rows if "local" in r.get("type","").lower() or "ollama" in r["tool"].lower())
            print(f"  Local Ollama F1: {local['f1']:.3f} ({(local['f1']/best_ai['f1']*100):.1f}% of best AI)")


if __name__ == "__main__":
    main()
