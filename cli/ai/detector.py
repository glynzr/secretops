"""AI Detector — multi-provider with round-robin key rotation."""
import json, logging, os, re, time
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("secretops.detector")

@dataclass
class ChunkFinding:
    line_number: int
    candidate_value: str
    secret_type: str
    severity: str
    confidence: float
    reasoning: str
    env_var_suggestion: str
    vault_path_suggestion: str = ""

@dataclass
class RemediationResult:
    patched_line: str
    import_statement: str
    mr_title: str
    mr_description: str
    env_var_name: str
    rotation_steps: List[str]

DETECTION_PROMPT = """You are an expert application security engineer detecting hardcoded credentials in enterprise source code.

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

CANDIDATE VALUE is abstracted for privacy — use structural properties and surrounding context to classify.

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

REMEDIATION_PROMPT = """You are a security engineer generating a code fix and developer guidance for a detected hardcoded secret.

Generate a complete remediation package for the detected credential. The developer will receive this as a GitLab MR.

IMPORTANT:
- NEVER include the actual secret value in any output
- The Vault path has already been POISONED with a placeholder — the app will fail until developer updates Vault
- If days_in_history > 7: add a CRITICAL WARNING that the credential may already be compromised
- Generate rotation steps SPECIFIC to the secret_type

Respond with ONLY valid JSON:
{
  "patched_line": "<the fixed line of code with env var reference>",
  "import_statement": "<import statement needed or empty string>",
  "mr_title": "<conventional commit format: security: remove hardcoded [type]>",
  "mr_description": "<full markdown MR description with warnings, vault path, rotation steps>",
  "env_var_name": "<UPPERCASE_SNAKE_CASE>",
  "rotation_steps": ["<step 1>", "<step 2>", ...]
}"""

# High-confidence regex patterns for Stage 1 pre-filter
PROVIDER_PATTERNS = [
    (re.compile(r'sk_live_[a-zA-Z0-9]{24,}'), 'api_key', 'critical', 'STRIPE_SECRET_KEY'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'api_key', 'critical', 'AWS_ACCESS_KEY_ID'),
    (re.compile(r'glpat-[a-zA-Z0-9\-_]{20,}'), 'token', 'high', 'GITLAB_TOKEN'),
    (re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'), 'token', 'high', 'GITHUB_TOKEN'),
    (re.compile(r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+'), 'token', 'high', 'SLACK_BOT_TOKEN'),
    (re.compile(r'sk-ant-api[0-9]+-[A-Za-z0-9\-_]{40,}'), 'api_key', 'high', 'ANTHROPIC_API_KEY'),
    (re.compile(r'sk-proj-[A-Za-z0-9\-_]{40,}'), 'api_key', 'high', 'OPENAI_API_KEY'),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 'api_key', 'high', 'GOOGLE_API_KEY'),
    (re.compile(r'hvs\.[A-Za-z0-9]+'), 'token', 'high', 'VAULT_TOKEN'),
    (re.compile(r'(?:postgresql|mysql|mongodb)://[^:]+:[^@]+@[^/]+'), 'database_url', 'critical', 'DATABASE_URL'),
]

FALSE_POSITIVE_PATTERNS = [
    re.compile(r'AKIAIOSFODNN7EXAMPLE'),
    re.compile(r'sk_test_4eC39HqLyjWD'),
    re.compile(r'your[_\-]?(api[_\-]?)?key[_\-]?here', re.I),
    re.compile(r'replace[_\-]?this', re.I),
    re.compile(r'change[_\-]?me', re.I),
    re.compile(r'insert[_\-]?token', re.I),
    re.compile(r'x{8,}'),
    re.compile(r'0{8,}'),
    re.compile(r'<your[_\-]', re.I),
    re.compile(r'django-insecure-'),
    re.compile(r'pk_live_|pk_test_'),
]


def shannon_entropy(s: str) -> float:
    import math
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())


def abstract_candidate(value: str) -> str:
    length = len(value)
    entropy = shannon_entropy(value)
    prefix = value[:6] if length > 10 else value[:3]
    has_upper = bool(re.search(r'[A-Z]', value))
    has_digit = bool(re.search(r'[0-9]', value))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', value))
    return (f"[CANDIDATE: len={length}, entropy={entropy:.2f}b/char, "
            f"prefix='{prefix}...', upper={has_upper}, digit={has_digit}, special={has_special}]")


class AIDetector:
    def __init__(self, model: str = "claude-3-5-sonnet-20241022", api_keys: dict = None):
        self.model = model
        self._keys = api_keys or {}
        self._provider = self._detect_provider(model)
        self._key_index = 0
        self._client = self._init_client()

    def _detect_provider(self, model: str) -> str:
        if "claude" in model: return "claude"
        if "gpt" in model or "o1" in model: return "openai"
        if "gemini" in model: return "gemini"
        if "deepseek" in model: return "deepseek"
        if "llama" in model or "mistral" in model: return "ollama"
        return "openai"

    def _get_key(self) -> str:
        keys = self._keys.get(self._provider, [])
        if isinstance(keys, list) and keys:
            key = keys[self._key_index % len(keys)]
            return key
        if isinstance(keys, str):
            return keys
        return os.environ.get(f"{self._provider.upper()}_API_KEY", "")

    def _rotate_key(self):
        keys = self._keys.get(self._provider, [])
        if isinstance(keys, list) and len(keys) > 1:
            self._key_index += 1
            self._client = self._init_client()
            logger.info(f"Rotated to API key {self._key_index % len(keys) + 1}")

    def _init_client(self):
        key = self._get_key()
        if self._provider == "claude":
            import anthropic
            return anthropic.Anthropic(api_key=key)
        if self._provider in ("openai", "deepseek"):
            import openai
            base = "https://api.deepseek.com" if self._provider == "deepseek" else None
            kwargs = {"api_key": key}
            if base: kwargs["base_url"] = base
            return openai.OpenAI(**kwargs)
        if self._provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=key)
            return genai.GenerativeModel(self.model)
        if self._provider == "ollama":
            import openai
            base = self._keys.get("ollama_base_url", "http://localhost:11434")
            model_name = self._keys.get("ollama_model", "llama3.1:8b")
            self.model = model_name
            return openai.OpenAI(api_key="ollama", base_url=f"{base}/v1")
        return None

    def _call_llm(self, system: str, user: str, retries: int = 2) -> str:
        for attempt in range(retries + 1):
            try:
                if self._provider == "claude":
                    resp = self._client.messages.create(
                        model=self.model, max_tokens=800, temperature=0,
                        system=system,
                        messages=[{"role": "user", "content": user}]
                    )
                    return resp.content[0].text
                elif self._provider == "gemini":
                    resp = self._client.generate_content(f"{system}\n\n{user}")
                    return resp.text
                else:
                    resp = self._client.chat.completions.create(
                        model=self.model, max_tokens=800, temperature=0,
                        messages=[{"role": "system", "content": system},
                                  {"role": "user", "content": user}]
                    )
                    return resp.choices[0].message.content
            except Exception as ex:
                if "429" in str(ex) and attempt < retries:
                    logger.warning(f"Rate limited, rotating key (attempt {attempt+1})")
                    self._rotate_key()
                    time.sleep(2 ** attempt)
                    continue
                raise
        return ""

    def detect_in_chunk(self, code: str, file_path: str) -> List[ChunkFinding]:
        findings = []
        lines = code.split("\n")
        candidates_checked = set()

        for i, line in enumerate(lines):
            line_num = i + 1

            # Stage 1A: Check false positive patterns first
            is_fp = any(p.search(line) for p in FALSE_POSITIVE_PATTERNS)
            if is_fp:
                continue

            # Stage 1B: High-confidence provider patterns — direct flag
            for pattern, stype, severity, env_var in PROVIDER_PATTERNS:
                m = pattern.search(line)
                if m:
                    val = m.group(0)
                    if val in candidates_checked:
                        continue
                    candidates_checked.add(val)
                    entropy = shannon_entropy(val)
                    if entropy < 2.5:
                        continue
                    findings.append(ChunkFinding(
                        line_number=line_num,
                        candidate_value=val[:8] + "...",
                        secret_type=stype,
                        severity=severity,
                        confidence=0.95,
                        reasoning=f"Provider-format {stype} detected with high entropy ({entropy:.2f}b/char)",
                        env_var_suggestion=env_var,
                        vault_path_suggestion=f"secret/app/{env_var.lower()}",
                    ))
                    break
            else:
                # Stage 1C: Look for assignment patterns for LLM classification
                # Pattern: variable_name = "value" where value looks interesting
                assign_patterns = [
                    re.compile(r'(?:api[_\-]?key|secret|token|password|credential|auth)["\s]*[=:]["\s]*["\']([A-Za-z0-9+/=_\-\.]{16,})["\']', re.I),
                    re.compile(r'(?:ACCESS_KEY|SECRET_KEY|API_TOKEN|DB_PASS|AUTH_TOKEN)\s*=\s*["\']([A-Za-z0-9+/=_\-\.]{16,})["\']'),
                ]
                for ap in assign_patterns:
                    m = ap.search(line)
                    if m:
                        val = m.group(1) if m.lastindex else m.group(0)
                        if val in candidates_checked or shannon_entropy(val) < 2.8:
                            continue
                        candidates_checked.add(val)

                        # Get context window
                        ctx_start = max(0, i - 4)
                        ctx_end   = min(len(lines), i + 5)
                        context   = "\n".join(lines[ctx_start:ctx_end])
                        abstracted = abstract_candidate(val)

                        user_msg = f"File: {file_path}\nLine {line_num}:\n```\n{context}\n```\nCandidate on line {line_num}: {abstracted}"
                        try:
                            raw = self._call_llm(DETECTION_PROMPT, user_msg)
                            raw = raw.strip().lstrip("```json").rstrip("```").strip()
                            result = json.loads(raw)
                            if result.get("is_secret") and result.get("confidence", 0) >= 0.70:
                                findings.append(ChunkFinding(
                                    line_number=line_num,
                                    candidate_value=val[:8] + "...",
                                    secret_type=result.get("secret_type", "generic_secret"),
                                    severity=result.get("severity", "medium"),
                                    confidence=result.get("confidence", 0.0),
                                    reasoning=result.get("reasoning", ""),
                                    env_var_suggestion=result.get("env_var_suggestion", ""),
                                    vault_path_suggestion=result.get("vault_path_suggestion", ""),
                                ))
                        except Exception as ex:
                            logger.debug(f"LLM classify error: {ex}")
                        break

        return findings

    def generate_remediation(self, candidate: str, context: str, file_path: str,
                              secret_type: str, env_var: str, vault_path: str,
                              days_in_history: int, hist_level: str) -> RemediationResult:
        history_warning = ""
        if days_in_history > 7:
            history_warning = f"\nWARNING: days_in_history={days_in_history}, alert_level={hist_level}. This credential may already be compromised. Access logs should be reviewed from the first exposure date."

        user_msg = (f"secret_type: {secret_type}\nfile_path: {file_path}\n"
                    f"env_var_suggestion: {env_var}\nvault_path_poisoned: {vault_path}\n"
                    f"days_in_history: {days_in_history}\nhist_level: {hist_level}{history_warning}\n\n"
                    f"Code context:\n```\n{context[:800]}\n```")

        try:
            raw = self._call_llm(REMEDIATION_PROMPT, user_msg)
            raw = raw.strip().lstrip("```json").rstrip("```").strip()
            result = json.loads(raw)
            return RemediationResult(
                patched_line=result.get("patched_line", f"# TODO: use os.environ.get('{env_var}')"),
                import_statement=result.get("import_statement", ""),
                mr_title=result.get("mr_title", f"security: remove hardcoded {secret_type}"),
                mr_description=result.get("mr_description", ""),
                env_var_name=result.get("env_var_name", env_var),
                rotation_steps=result.get("rotation_steps", ["Rotate credential at provider dashboard"]),
            )
        except Exception as ex:
            logger.error(f"Remediation generation failed: {ex}")
            return RemediationResult(
                patched_line=f"# TODO: replace with os.environ.get('{env_var}')",
                import_statement="import os",
                mr_title=f"security: remove hardcoded {secret_type}",
                mr_description=f"Hardcoded {secret_type} detected in {file_path}. Vault poisoned at {vault_path}.",
                env_var_name=env_var,
                rotation_steps=["Rotate credential at provider dashboard", f"Update Vault at {vault_path}"],
            )
