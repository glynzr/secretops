"""
Secret detection engine.
Logic inspired by TruffleHog v3 and Gitleaks:
- Keyword pre-filter (fast byte scan before regex)
- Anchored per-provider patterns on the captured value
- Per-rule entropy thresholds on the captured group
- Structured allowlist: path filters + value stopwords + regex exclusions
"""
import re
import math
from dataclasses import dataclass
from typing import Optional


@dataclass
class PatternMatch:
    secret_type: str
    value: str
    line_number: int
    line_content: str
    confidence: float
    severity: str
    skip_llm: bool = False
    rejection_reason: Optional[str] = None


# ── Structured allowlist (Gitleaks-style) ────────────────────────────────────
# Value-level stopwords: if the captured VALUE contains any of these, reject immediately
VALUE_STOPWORDS = [
    "example", "placeholder", "your_", "your-", "changeme", "change_me",
    "dummy", "fake", "mock", "sample", "test", "demo", "insert", "replace",
    "xxxxxxxx", "00000000", "11111111", "12345678", "password123",
    "aaaaaaaaaaaaaaaa",  # all same char repetition
]

# Value-level regex exclusions: reject if captured value matches
VALUE_EXCLUSION_REGEXES = [
    re.compile(r'^\$\{[A-Z_][A-Z0-9_]*\}$'),      # ${ENV_VAR}
    re.compile(r'^\$[A-Z_][A-Z0-9_]*$'),            # $ENV_VAR
    re.compile(r'^<[A-Z_]+>$'),                      # <PLACEHOLDER>
    re.compile(r'^YOUR_[A-Z_]+$'),
    re.compile(r'^INSERT_[A-Z_]+$'),
    # Already reading from environment / framework — not a hardcoded secret
    re.compile(r'^os\.environ'),                     # Python os.environ
    re.compile(r'^process\.env'),                    # JS process.env
    re.compile(r'^ENV\['),                           # Ruby ENV[]
    re.compile(r'^System\.getenv'),                  # Java
    re.compile(r'^os\.Getenv'),                      # Go
    re.compile(r'^request\.(POST|GET|data|form|json|args|params|body)'),  # Django/Flask/Express request
    re.compile(r'^req\.(body|params|query|headers)'),  # Express.js
    re.compile(r'\.get\s*\('),                       # .get('key') accessor pattern
    re.compile(r'^\w+\.(get|find|fetch|load|read)\s*\('),  # any .get() / .fetch()
    re.compile(r'^getenv\s*\('),                     # PHP getenv()
    re.compile(r'^config\['),                        # config["key"] lookups
    re.compile(r'^settings\.'),                      # Django settings.KEY
    re.compile(r'(?i)^none$'),                       # None / null literal
    re.compile(r'^false$|^true$|^null$|^undefined$'),# JS/Python boolean literals
]

# Line-level exclusions: skip the entire line if it matches
LINE_EXCLUSION_REGEXES = [
    re.compile(r'^\s*#'),    # Python/shell comment
    re.compile(r'^\s*//'),   # JS/Go/Java comment
    re.compile(r'^\s*\*'),   # Block comment line
    re.compile(r'^\s*--'),   # SQL comment
]


def is_allowed_value(value: str) -> bool:
    """Return True if the value should be rejected (is a false positive)."""
    v_lower = value.lower()
    for word in VALUE_STOPWORDS:
        if word in v_lower:
            return True
    for pattern in VALUE_EXCLUSION_REGEXES:
        if pattern.search(value):
            return True
    return False


def is_comment_line(line: str) -> bool:
    for pattern in LINE_EXCLUSION_REGEXES:
        if pattern.match(line):
            return True
    return False


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string. TruffleHog/Gitleaks use this to gate generic secrets."""
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    e = 0.0
    n = len(s)
    for count in freq.values():
        p = count / n
        e -= p * math.log2(p)
    return e


# ── Detector definitions ─────────────────────────────────────────────────────
# Each detector mirrors TruffleHog's structure:
#   keywords   — cheap pre-filter strings (any must be present in the line)
#   regex      — anchored pattern; use a capture group for the actual secret value
#   group      — which regex group contains the value (0 = whole match)
#   min_entropy— minimum Shannon entropy of the captured value (Gitleaks uses this)
#   severity, confidence, name — metadata

DETECTORS = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    {
        "name": "aws_access_key",
        "keywords": ["AKIA", "ASIA", "AROA"],
        "regex": r"\b((?:AKIA|ASIA|AROA)[0-9A-Z]{16})\b",
        "group": 1,
        "min_entropy": 3.0,
        "severity": "critical",
        "confidence": 0.97,
    },
    {
        "name": "aws_secret_key",
        "keywords": ["aws_secret", "secret_access_key", "SecretAccessKey"],
        "regex": r"(?i)(?:aws_secret|secret_access_key|SecretAccessKey)[\s=:]+[\s]*[\x27\x22]?([A-Za-z0-9/+=]{40})",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "critical",
        "confidence": 0.92,
    },

    # ── GitHub ────────────────────────────────────────────────────────────────
    {
        "name": "github_pat",
        "keywords": ["ghp_", "gho_", "github_pat_"],
        "regex": r"\b(gh[pousr]_[a-zA-Z0-9]{36,})\b",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "high",
        "confidence": 0.98,
    },
    {
        "name": "github_fine_grained",
        "keywords": ["github_pat_"],
        "regex": r"\b(github_pat_[a-zA-Z0-9_]{82})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "high",
        "confidence": 0.99,
    },

    # ── GitLab ────────────────────────────────────────────────────────────────
    {
        "name": "gitlab_pat",
        "keywords": ["glpat-"],
        "regex": r"\b(glpat-[a-zA-Z0-9\-_]{20})\b",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "high",
        "confidence": 0.98,
    },
    {
        "name": "gitlab_runner_token",
        "keywords": ["GR1348941"],
        "regex": r"\b(GR1348941[a-zA-Z0-9\-_]{20})\b",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "high",
        "confidence": 0.97,
    },

    # ── Stripe ────────────────────────────────────────────────────────────────
    {
        "name": "stripe_secret_key",
        "keywords": ["sk_live_"],
        "regex": r"\b(sk_live_[a-zA-Z0-9]{24,})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "critical",
        "confidence": 0.99,
    },
    {
        "name": "stripe_restricted_key",
        "keywords": ["rk_live_"],
        "regex": r"\b(rk_live_[a-zA-Z0-9]{24,})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "critical",
        "confidence": 0.99,
    },
    {
        "name": "stripe_webhook_secret",
        "keywords": ["whsec_"],
        "regex": r"\b(whsec_[a-zA-Z0-9]{32,})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "high",
        "confidence": 0.98,
    },

    # ── Slack ─────────────────────────────────────────────────────────────────
    # TruffleHog uses: xox[baprs]-[0-9]+-... with no fixed length on last segment
    {
        "name": "slack_token",
        "keywords": ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"],
        "regex": r"\b(xox[baprs]-[0-9]+-[0-9]+-[0-9a-zA-Z]+)\b",
        "group": 1,
        "min_entropy": 3.0,
        "severity": "high",
        "confidence": 0.95,
    },
    {
        "name": "slack_webhook",
        "keywords": ["hooks.slack.com"],
        "regex": r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)",
        "group": 1,
        "min_entropy": 3.0,
        "severity": "high",
        "confidence": 0.98,
    },

    # ── OpenAI / Anthropic / Groq ─────────────────────────────────────────────
    {
        "name": "openai_api_key",
        "keywords": ["sk-proj-", "sk-"],
        "regex": r"\b(sk-(?:proj-)?[a-zA-Z0-9_\-T]{48,})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "high",
        "confidence": 0.95,
    },
    {
        "name": "anthropic_api_key",
        "keywords": ["sk-ant-"],
        "regex": r"\b(sk-ant-[a-zA-Z0-9\-_]{50,})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "high",
        "confidence": 0.97,
    },
    {
        "name": "groq_api_key",
        "keywords": ["gsk_"],
        "regex": r"\b(gsk_[a-zA-Z0-9]{52})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "high",
        "confidence": 0.97,
    },

    # ── Google / GCP ──────────────────────────────────────────────────────────
    {
        "name": "google_api_key",
        "keywords": ["AIza"],
        "regex": r"\b(AIza[0-9A-Za-z\-_]{35})\b",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "high",
        "confidence": 0.97,
    },
    {
        "name": "google_oauth_token",
        "keywords": ["ya29."],
        "regex": r"\b(ya29\.[0-9A-Za-z\-_]{60,})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "high",
        "confidence": 0.90,
    },
    {
        "name": "gcp_inline_key",
        "keywords": ["service_account", "eyJ0eXBlIjoic2VydmljZV9hY2NvdW50"],
        "regex": r"(eyJ0eXBlIjoic2VydmljZV9hY2NvdW50[a-zA-Z0-9+/=]{20,})",
        "group": 1,
        "min_entropy": 4.5,
        "severity": "critical",
        "confidence": 0.97,
    },

    # ── SendGrid / Mailgun ────────────────────────────────────────────────────
    {
        "name": "sendgrid_api_key",
        "keywords": ["SG."],
        "regex": r"\b(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})\b",
        "group": 1,
        "min_entropy": 4.5,
        "severity": "high",
        "confidence": 0.99,
    },
    {
        "name": "mailgun_api_key",
        "keywords": ["key-"],
        "regex": r"\b(key-[a-zA-Z0-9]{32})\b",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "high",
        "confidence": 0.88,
    },

    # ── Twilio ────────────────────────────────────────────────────────────────
    {
        "name": "twilio_account_sid",
        "keywords": ["AC"],
        "regex": r"\b(AC[a-fA-F0-9]{32})\b",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "medium",
        "confidence": 0.85,
    },
    {
        "name": "twilio_auth_token",
        "keywords": ["twilio", "auth_token"],
        "regex": r"(?i)(?:twilio|auth_token)[\s=:\"']+([a-fA-F0-9]{32})\b",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "high",
        "confidence": 0.90,
    },

    # ── Notion / npm / Docker ─────────────────────────────────────────────────
    {
        "name": "notion_api_key",
        "keywords": ["secret_"],
        "regex": r"\b(secret_[a-zA-Z0-9]{43})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "high",
        "confidence": 0.96,
    },
    {
        "name": "npm_token",
        "keywords": ["npm_"],
        "regex": r"\b(npm_[a-zA-Z0-9]{36})\b",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "high",
        "confidence": 0.97,
    },
    {
        "name": "docker_hub_token",
        "keywords": ["dckr_pat_"],
        "regex": r"\b(dckr_pat_[a-zA-Z0-9\-_]{27})\b",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "high",
        "confidence": 0.98,
    },

    # ── New Relic / Sentry ────────────────────────────────────────────────────
    {
        "name": "newrelic_key",
        "keywords": ["NRJS-"],
        "regex": r"\b(NRJS-[a-zA-Z0-9]{40})\b",
        "group": 1,
        "min_entropy": 4.0,
        "severity": "high",
        "confidence": 0.96,
    },
    {
        "name": "sentry_dsn",
        "keywords": ["ingest.sentry.io"],
        "regex": r"(https://[a-fA-F0-9]{32}:[a-fA-F0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+)",
        "group": 1,
        "min_entropy": 3.0,
        "severity": "high",
        "confidence": 0.97,
    },

    # ── Private keys ──────────────────────────────────────────────────────────
    {
        "name": "private_key_block",
        "keywords": ["BEGIN"],
        "regex": r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)",
        "group": 1,
        "min_entropy": 0,
        "severity": "critical",
        "confidence": 0.99,
    },

    # ── Connection strings ────────────────────────────────────────────────────
    {
        "name": "connection_string",
        "keywords": ["://"],
        "regex": r"(?i)((?:mongodb|postgresql|postgres|mysql|redis|mssql)://[^\s\"'<>\n]+:[^\s\"'<>@\n]+@[^\s\"'<>\n]+)",
        "group": 1,
        "min_entropy": 2.5,
        "severity": "critical",
        "confidence": 0.95,
    },

    # ── Django / Flask SECRET_KEY ─────────────────────────────────────────────
    # Gitleaks uses a similar approach: capture the value after the assignment
    {
        "name": "django_secret_key",
        "keywords": ["SECRET_KEY"],
        "regex": r"(?i)SECRET_KEY\s*=\s*['\"]([^'\"]{20,})['\"]",
        "group": 1,
        "min_entropy": 3.5,
        "severity": "high",
        "confidence": 0.88,
    },

    # ── JWT secrets ───────────────────────────────────────────────────────────
    {
        "name": "jwt_secret",
        "keywords": ["jwt_secret", "jwt_key", "signing_key", "jwtSecret"],
        "regex": r"(?i)(?:jwt_secret|jwt_key|signing_key|jwtSecret)\s*[=:\"'\s]+([a-zA-Z0-9!@#$%^&*()\-_+]{16,})",
        "group": 1,
        "min_entropy": 3.2,
        "severity": "high",
        "confidence": 0.85,
    },

    # ── Database passwords ────────────────────────────────────────────────────
    {
        "name": "db_password",
        "keywords": ["db_pass", "database_password", "PGPASSWORD", "db_password"],
        "regex": r"(?i)(?:db_pass(?:word)?|database_password|PGPASSWORD)\s*[=:\"'\s]+([^\s\"',}{>\n]{8,})",
        "group": 1,
        "min_entropy": 2.8,
        "severity": "high",
        "confidence": 0.80,
    },

    # ── Generic high-entropy (Gitleaks-style: entropy gates the noise) ────────
    # Only fires if entropy of the value >= 3.5 AND keyword present
    {
        "name": "generic_secret",
        "keywords": ["password", "passwd", "api_key", "apikey", "auth_token", "access_token"],
        "regex": r"(?i)(?:password|passwd|api_key|apikey|auth_token|access_token)\s*[=:\"'\s]+([^\s\"',}{>\n]{16,})",
        "group": 1,
        "min_entropy": 3.5,   # Gitleaks default for generic
        "severity": "medium",
        "confidence": 0.50,
    },
]

# Pre-compile all regexes at import time (TruffleHog does this too)
for _d in DETECTORS:
    _d["_compiled"] = re.compile(_d["regex"])


# ── Public API (keep original function names for pipeline.py compatibility) ──

def calculate_entropy(s: str) -> float:
    return shannon_entropy(s)


def is_false_positive(value: str) -> bool:
    """Kept for backwards compatibility with pipeline.py import."""
    return is_allowed_value(value)


def scan_line(line: str, line_number: int) -> list:
    """
    TruffleHog-style scan of a single line:
    1. Skip comment lines
    2. Keyword pre-filter (fast)
    3. Regex match on the line
    4. Entropy gate on captured value
    5. Value allowlist check
    """
    if is_comment_line(line):
        return []

    matches = []
    line_lower = line.lower()

    for detector in DETECTORS:
        # Step 1: keyword pre-filter (TruffleHog's biggest performance win)
        if not any(kw.lower() in line_lower for kw in detector["keywords"]):
            continue

        # Step 2: regex match
        for m in detector["_compiled"].finditer(line):
            group = detector.get("group", 0)
            try:
                value = m.group(group) if group else m.group(0)
            except IndexError:
                value = m.group(0)

            if not value or len(value) < 8:
                continue

            # Step 3: entropy gate on captured value (Gitleaks approach)
            entropy = shannon_entropy(value)
            if entropy < detector["min_entropy"]:
                continue

            # Step 4: allowlist check on value only (not the whole line)
            if is_allowed_value(value):
                continue

            base_confidence = detector["confidence"]
            # High-confidence + good entropy = skip LLM (TruffleHog verified finding)
            skip_llm = base_confidence >= 0.90 and entropy >= 3.5

            matches.append(PatternMatch(
                secret_type=detector["name"],
                value=value,
                line_number=line_number,
                line_content=line.strip(),
                confidence=base_confidence,
                severity=detector["severity"],
                skip_llm=skip_llm,
            ))

    return matches


def scan_file_content(content: str) -> list:
    all_matches = []
    seen_values: set = set()

    for i, line in enumerate(content.split("\n"), 1):
        for match in scan_line(line, i):
            if match.value not in seen_values:
                seen_values.add(match.value)
                all_matches.append(match)

    return all_matches
