"""
Script 03: Evaluate AI detection performance across providers.
Produces: results/ai_detection_results.json

This is the main evaluation script. It sends each of the 50 benchmark
samples to the configured AI provider using the EXACT prompt from thesis
Section 2.3.2 and measures:
  - Precision, Recall, F1
  - Average confidence score
  - Average latency per call (ms)
  - API call count (for triage filter rate comparison)

Usage:
  export ANTHROPIC_API_KEY=sk-ant-...
  python scripts/03_ai_detection_eval.py --provider claude
  python scripts/03_ai_detection_eval.py --provider openai
  python scripts/03_ai_detection_eval.py --provider ollama --base-url http://localhost:11434

The script logs every API call to results/api_call_log.jsonl for audit.
"""

import argparse, json, math, os, re, sys, time
from pathlib import Path
from datetime import datetime

# ── Detection prompt (final version from thesis Section 2.3.2) ──────────────
DETECTION_SYSTEM_PROMPT = """You are an expert application security engineer detecting hardcoded credentials in enterprise source code.

DEFINITION — REAL SECRET:
A credential value that grants unauthorized access to any system, service, data store, or cloud infrastructure:
- API keys for paid/authenticated services (Stripe, OpenAI, AWS, Anthropic, Google)
- Database connection strings with embedded passwords
- Private cryptographic keys (RSA, EC, PGP private components)
- OAuth tokens, bearer tokens, session tokens with real access
- Cloud provider credentials (AWS IAM, Azure service principal)
- Service account credentials, CI/CD pipeline tokens

FALSE POSITIVES — NEVER flag these:
- Documentation examples: AKIAIOSFODNN7EXAMPLE, sk_test_4eC39HqLyjWD...
- Placeholder strings: your_key_here, REPLACE_THIS, change_me, INSERT_TOKEN, <YOUR_API_KEY>, xxxxxxxxxxxx
- Stripe publishable keys (pk_live_, pk_test_) — these are public by design
- RSA/EC/Certificate PUBLIC key components
- Git commit SHA hashes used as identifiers
- UUID/GUID values used as record identifiers
- Django INSECURE_SECRET_KEY = 'django-insecure-...' defaults
- Any value containing the words: fake, test, example, demo, sample, placeholder, mock

CLASSIFICATION RULES (apply in order):
1. PROVIDER FORMAT: prefix sk_live_, AKIA, glpat-, ghp_, xoxb-, sk-ant-, sk-proj-, hvs- = strong evidence
2. CONTEXT OVERRIDES FORMAT: sk_live_ in test file = likely false positive; generic high-entropy string in .env = likely real
3. ENTROPY: genuine secrets > 3.5 bits/char. Low entropy (< 2.5 bits/char) = almost certainly not real
4. VARIABLE NAME: API_KEY, SECRET, TOKEN, PASSWORD, CREDENTIAL = higher likelihood; EXAMPLE, TEST, MOCK, DEFAULT = lower
5. FILE TYPE: .env, config/, terraform/, k8s/ = higher likelihood; test/, __tests__/, spec/, docs/, README = lower
6. NEVER flag: public keys, commit SHAs, publishable keys (pk_*), UUIDs, documented placeholder patterns

CONFIDENCE CALIBRATION:
- 0.95-1.00: Clear provider format in production context
- 0.80-0.94: Strong contextual evidence with entropy support
- 0.70-0.79: Probable but some context ambiguity
- 0.50-0.69: Uncertain — DO NOT flag (below threshold)
- 0.00-0.49: False positive

SEVERITY:
- critical: Cloud provider keys, database passwords, private cryptographic keys
- high: Third-party API keys with billing/data access (Stripe, AI providers)
- medium: Service tokens, OAuth tokens, internal API keys
- low: Low-privilege read-only tokens

Respond with ONLY valid JSON, no explanation outside JSON:
{
  "is_secret": true | false,
  "confidence": 0.0 to 1.0,
  "secret_type": "api_key" | "private_key" | "password" | "token" | "database_url" | "generic_secret" | "none",
  "severity": "critical" | "high" | "medium" | "low",
  "reasoning": "<one sentence: specific evidence for this decision>",
  "env_var_suggestion": "<UPPERCASE_SNAKE_CASE or empty string>",
  "vault_path_suggestion": "<secret/appname/credential_name or empty string>",
  "false_positive_reason": "<if false positive: which rule triggered>"
}"""

CONFIDENCE_THRESHOLD = 0.70


def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((v/len(s)) * math.log2(v/len(s)) for v in freq.values())


def build_user_message(sample: dict) -> str:
    val = sample["candidate_value"]
    length = len(val)
    entropy = shannon_entropy(val)
    prefix = val[:6] if length > 10 else val[:3]
    has_upper = bool(re.search(r'[A-Z]', val))
    has_digit = bool(re.search(r'[0-9]', val))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', val))
    abstracted = (f"[CANDIDATE: len={length}, entropy={entropy:.2f}b/char, "
                  f"prefix='{prefix}...', upper={has_upper}, digit={has_digit}, special={has_special}]")

    return (f"File: {sample['file_context']}\n"
            f"Code context:\n```\n{sample['code_snippet']}\n```\n"
            f"Candidate value: {abstracted}")


def call_claude(client, sample: dict) -> tuple:
    msg = build_user_message(sample)
    t0 = time.time()
    resp = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=400,
        temperature=0,
        system=DETECTION_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": msg}],
    )
    latency_ms = (time.time() - t0) * 1000
    raw = resp.content[0].text.strip().lstrip("```json").rstrip("```").strip()
    return json.loads(raw), latency_ms


def call_openai_compatible(client, model: str, sample: dict) -> tuple:
    msg = build_user_message(sample)
    t0 = time.time()
    resp = client.chat.completions.create(
        model=model,
        max_tokens=400,
        temperature=0,
        messages=[
            {"role": "system", "content": DETECTION_SYSTEM_PROMPT},
            {"role": "user", "content": msg},
        ],
    )
    latency_ms = (time.time() - t0) * 1000
    raw = resp.choices[0].message.content.strip().lstrip("```json").rstrip("```").strip()
    return json.loads(raw), latency_ms


def evaluate(provider: str, call_fn, samples: list, log_file: str) -> dict:
    tp = fp = tn = fn = 0
    confidences = []
    latencies = []
    predictions = []
    errors = 0

    print(f"\nEvaluating {provider} on {len(samples)} samples...")
    for i, sample in enumerate(samples):
        try:
            result, latency_ms = call_fn(sample)
            predicted = result.get("is_secret", False) and result.get("confidence", 0) >= CONFIDENCE_THRESHOLD
            gt = sample["ground_truth"]
            confidence = result.get("confidence", 0)
            confidences.append(confidence)
            latencies.append(latency_ms)

            if predicted and gt:     tp += 1
            elif predicted and not gt: fp += 1
            elif not predicted and gt: fn += 1
            else:                    tn += 1

            pred_record = {
                "id": sample["id"],
                "ground_truth": gt,
                "predicted": predicted,
                "confidence": confidence,
                "secret_type_pred": result.get("secret_type", ""),
                "reasoning": result.get("reasoning", ""),
                "latency_ms": round(latency_ms, 1),
            }
            predictions.append(pred_record)

            # Audit log
            with open(log_file, "a") as f:
                f.write(json.dumps({
                    "timestamp": datetime.utcnow().isoformat(),
                    "provider": provider,
                    "sample_id": sample["id"],
                    "file_context": sample["file_context"],
                    "result": pred_record,
                }) + "\n")

            status = "✓" if predicted == gt else "✗"
            print(f"  [{i+1:2d}/50] {sample['id']} {status}  conf={confidence:.2f}  {latency_ms:.0f}ms")

        except Exception as ex:
            print(f"  [{i+1:2d}/50] {sample['id']} ERROR: {ex}")
            errors += 1
            predictions.append({"id": sample["id"], "ground_truth": sample["ground_truth"],
                                 "predicted": False, "error": str(ex)})
            if sample["ground_truth"]:
                fn += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    avg_conf = sum(confidences) / len(confidences) if confidences else 0
    avg_lat  = sum(latencies) / len(latencies) if latencies else 0

    result = {
        "provider": provider,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3),
        "recall":    round(recall, 3),
        "f1":        round(f1, 3),
        "avg_confidence": round(avg_conf, 3),
        "avg_latency_ms": round(avg_lat, 1),
        "errors": errors,
        "predictions": predictions,
    }

    print(f"\n  Results for {provider}:")
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}  Errors={errors}")
    print(f"  Precision={precision:.3f}  Recall={recall:.3f}  F1={f1:.3f}")
    print(f"  Avg confidence={avg_conf:.3f}  Avg latency={avg_lat:.0f}ms")

    return result


def main():
    parser = argparse.ArgumentParser(description="Evaluate AI provider on SecretOps benchmark")
    parser.add_argument("--provider", choices=["claude","openai","deepseek","ollama"], default="claude")
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    args = parser.parse_args()

    os.chdir(Path(__file__).parent.parent)
    with open("data/benchmark_50.json") as f:
        samples = json.load(f)["samples"]

    os.makedirs("results", exist_ok=True)
    log_file = f"results/api_call_log_{args.provider}.jsonl"

    # Load existing results if any
    results_file = "results/ai_detection_results.json"
    all_results = {}
    if os.path.exists(results_file):
        with open(results_file) as f:
            all_results = json.load(f)

    if args.provider == "claude":
        import anthropic
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            print("ERROR: set ANTHROPIC_API_KEY"); sys.exit(1)
        client = anthropic.Anthropic(api_key=key)
        result = evaluate("Claude 3.5 Sonnet", lambda s: call_claude(client, s), samples, log_file)

    elif args.provider == "openai":
        import openai
        key = os.environ.get("OPENAI_API_KEY", "")
        model = args.model or "gpt-4o"
        client = openai.OpenAI(api_key=key)
        result = evaluate(f"GPT-4o ({model})", lambda s: call_openai_compatible(client, model, s), samples, log_file)

    elif args.provider == "deepseek":
        import openai
        key = os.environ.get("DEEPSEEK_API_KEY", "")
        model = args.model or "deepseek-chat"
        client = openai.OpenAI(api_key=key, base_url="https://api.deepseek.com")
        result = evaluate("DeepSeek V3", lambda s: call_openai_compatible(client, model, s), samples, log_file)

    elif args.provider == "ollama":
        import openai
        base_url = args.base_url or "http://localhost:11434"
        model = args.model or "llama3.1:8b"
        client = openai.OpenAI(api_key="ollama", base_url=f"{base_url}/v1")
        result = evaluate(f"Ollama ({model})", lambda s: call_openai_compatible(client, model, s), samples, log_file)

    all_results[args.provider] = result
    with open(results_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nResults saved to {results_file}")
    print(f"API call log: {log_file}")


if __name__ == "__main__":
    main()
