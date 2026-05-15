"""
High-specificity regex patterns for secret detection.
Stage 1 of the 3-stage detection pipeline.
"""
import re
import math
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class PatternMatch:
    secret_type: str
    value: str
    line_number: int
    line_content: str
    confidence: float
    severity: str
    skip_llm: bool = False  # True if high-specificity + high entropy
    rejection_reason: Optional[str] = None  # Set if rejected as false positive

# High-specificity provider patterns
SECRET_PATTERNS = [
    # AWS
    {"name": "aws_access_key", "regex": r"AKIA[0-9A-Z]{16}", "severity": "critical", "confidence": 0.97},
    {"name": "aws_secret_key", "regex": r"(?i)(aws_secret|aws_secret_access_key|secret_key)[\s=:\"']+([A-Za-z0-9/+=]{40})", "severity": "critical", "confidence": 0.92, "group": 2},

    # GitHub
    {"name": "github_pat", "regex": r"ghp_[a-zA-Z0-9]{36}", "severity": "high", "confidence": 0.98},
    {"name": "github_oauth", "regex": r"gho_[a-zA-Z0-9]{36}", "severity": "high", "confidence": 0.98},
    {"name": "github_fine_grained", "regex": r"github_pat_[a-zA-Z0-9_]{82}", "severity": "high", "confidence": 0.98},

    # GitLab
    {"name": "gitlab_pat", "regex": r"glpat-[a-zA-Z0-9\-_]{20}", "severity": "high", "confidence": 0.98},
    {"name": "gitlab_runner_token", "regex": r"GR1348941[a-zA-Z0-9\-_]{20}", "severity": "high", "confidence": 0.97},

    # Stripe
    {"name": "stripe_secret_key", "regex": r"sk_live_[a-zA-Z0-9]{24,}", "severity": "critical", "confidence": 0.99},
    {"name": "stripe_restricted_key", "regex": r"rk_live_[a-zA-Z0-9]{24,}", "severity": "critical", "confidence": 0.99},

    # Slack
    {"name": "slack_token", "regex": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24,}", "severity": "high", "confidence": 0.98},
    {"name": "slack_webhook", "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "severity": "high", "confidence": 0.98},

    # OpenAI
    {"name": "openai_api_key", "regex": r"sk-[a-zA-Z0-9]{48,}", "severity": "high", "confidence": 0.95},
    {"name": "openai_project_key", "regex": r"sk-proj-[a-zA-Z0-9_\-]{50,}", "severity": "high", "confidence": 0.97},

    # Anthropic
    {"name": "anthropic_api_key", "regex": r"sk-ant-[a-zA-Z0-9\-_]{50,}", "severity": "high", "confidence": 0.97},

    # Google
    {"name": "google_api_key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high", "confidence": 0.97},
    {"name": "google_oauth", "regex": r"ya29\.[0-9A-Za-z\-_]+", "severity": "high", "confidence": 0.90},

    # Notion
    {"name": "notion_api_key", "regex": r"secret_[a-zA-Z0-9]{43}", "severity": "high", "confidence": 0.98},
    {"name": "notion_integration", "regex": r"ntn_[a-zA-Z0-9]{50,}", "severity": "high", "confidence": 0.97},

    # Twilio
    {"name": "twilio_auth_token", "regex": r"(?i)(twilio|auth_token)[\s=:\"']+([a-fA-F0-9]{32})", "severity": "high", "confidence": 0.90, "group": 2},

    # SendGrid
    {"name": "sendgrid_api_key", "regex": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}", "severity": "high", "confidence": 0.99},

    # Mailgun
    {"name": "mailgun_api_key", "regex": r"key-[a-zA-Z0-9]{32}", "severity": "high", "confidence": 0.90},

    # npm
    {"name": "npm_token", "regex": r"npm_[a-zA-Z0-9]{36}", "severity": "high", "confidence": 0.97},

    # Docker Hub
    {"name": "docker_hub_token", "regex": r"dckr_pat_[a-zA-Z0-9\-_]{27}", "severity": "high", "confidence": 0.98},

    # Heroku
    {"name": "heroku_api_key", "regex": r"(?i)heroku[\s\S]{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "severity": "high", "confidence": 0.90},

    # Generic high-entropy secrets (lower confidence, goes to LLM)
    {"name": "generic_secret", "regex": r"(?i)(password|passwd|secret|api_key|apikey|auth_token|access_token|private_key)[\s=:\"']+([A-Za-z0-9+/=_\-]{20,})", "severity": "medium", "confidence": 0.50, "group": 2},
    {"name": "private_key_block", "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": "critical", "confidence": 0.99},
    {"name": "connection_string", "regex": r"(?i)(mongodb|postgresql|postgres|mysql|redis)://[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>]+", "severity": "critical", "confidence": 0.95},
]

# False positive patterns - reject immediately
FALSE_POSITIVE_PATTERNS = [
    r"(?i)example[_\-]?(key|secret|token|password)",
    r"(?i)your[_\-]?(api[_\-]?key|secret|token|password)",
    r"(?i)(test|dummy|fake|mock|sample|placeholder)[_\-]?(key|secret|token|password)",
    r"xxxxxxxx",
    r"00000000",
    r"12345678",
    r"<[A-Z_]+>",
    r"\$\{[A-Z_]+\}",
    r"\$[A-Z_]+",
    r"YOUR_[A-Z_]+",
    r"INSERT_[A-Z_]+",
    r"REPLACE_[A-Z_]+",
]

def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy

def is_false_positive(value: str) -> bool:
    """Check if value matches known false positive patterns."""
    for pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, value):
            return True
    return False

def scan_line(line: str, line_number: int) -> list[PatternMatch]:
    """Scan a single line for secret patterns."""
    matches = []
    
    for pattern_def in SECRET_PATTERNS:
        regex = pattern_def["regex"]
        group = pattern_def.get("group", 0)
        
        for m in re.finditer(regex, line):
            try:
                value = m.group(group) if group else m.group(0)
            except IndexError:
                value = m.group(0)
            
            if not value or len(value) < 8:
                continue
            
            # Check false positives
            if is_false_positive(value):
                continue
            if is_false_positive(line):
                continue
            
            entropy = calculate_entropy(value)
            base_confidence = pattern_def["confidence"]
            
            # High specificity + high entropy = skip LLM
            skip_llm = base_confidence >= 0.90 and entropy >= 3.5
            
            # Low entropy generic secrets go to LLM with low confidence
            if pattern_def["name"] == "generic_secret" and entropy < 3.0:
                continue
            
            matches.append(PatternMatch(
                secret_type=pattern_def["name"],
                value=value,
                line_number=line_number,
                line_content=line.strip(),
                confidence=base_confidence,
                severity=pattern_def["severity"],
                skip_llm=skip_llm,
            ))
    
    return matches

def scan_file_content(content: str) -> list[PatternMatch]:
    """Scan full file content and return all pattern matches."""
    all_matches = []
    lines = content.split("\n")
    seen_values = set()
    
    for i, line in enumerate(lines, 1):
        for match in scan_line(line, i):
            if match.value not in seen_values:
                seen_values.add(match.value)
                all_matches.append(match)
    
    return all_matches
