"""
LLM-based classification for Stage 2 of the detection pipeline.
Sends candidates to configured AI providers with temperature=0 for deterministic results.
"""
import json
import requests
import logging
from typing import Optional

logger = logging.getLogger(__name__)

CLASSIFICATION_PROMPT = """You are a security expert specializing in detecting leaked secrets and credentials in source code.

Analyze the following code snippet and determine if it contains a REAL secret or credential that poses a security risk.

Rules for classification:
1. HIGH ENTROPY: Real secrets typically have high Shannon entropy (>3.5 bits/char for random strings)
2. CONTEXT MATTERS: Variable names like `test_key`, `example_secret`, `dummy_password` suggest false positives
3. FILE TYPE: Config files, .env files, scripts are higher risk than test files or documentation
4. PROVIDER FORMAT: Provider-specific formats (sk-*, ghp-*, AKIA*) are almost always real
5. PLACEHOLDERS: Patterns like ${VAR}, <YOUR_KEY>, XXXXXX, or template strings are false positives
6. COMMIT CONTEXT: If in a test file or example folder, lower confidence
7. ENVIRONMENT VARIABLES: References to env vars (process.env.X, os.environ['X']) are NOT secrets

Secret type: {secret_type}
File path: {file_path}
Line number: {line_number}

Code snippet (surrounding context):
```
{context}
```

Detected value (potentially sensitive): {masked_value}

Respond ONLY with a valid JSON object in exactly this format:
{{
  "is_secret": true,
  "confidence": 0.95,
  "severity": "high",
  "reasoning": "This appears to be a real AWS access key based on the AKIA prefix and high entropy. Found in a production configuration file.",
  "secret_type": "aws_access_key",
  "remediation_hint": "Rotate this AWS key immediately. Replace with: os.environ.get('AWS_ACCESS_KEY_ID') or store in Vault at secret/aws/credentials"
}}

Severity levels: "critical" (immediate revocation needed), "high" (rotate ASAP), "medium" (rotate soon), "low" (low risk)
Confidence: 0.0-1.0 where 1.0 = certain secret, 0.0 = certain false positive
If not a secret, set is_secret=false and confidence close to 0.
"""

class LLMClassifier:
    def __init__(self, db_getter):
        self.db_getter = db_getter
    
    def get_active_providers(self):
        """Get configured AI providers from database, ordered for failover."""
        db = self.db_getter()
        providers = []
        
        try:
            cursor = db.execute("""
                SELECT type, config, encrypted_secrets FROM integrations 
                WHERE type IN ('openai', 'anthropic', 'groq', 'ollama')
                AND status = 'connected'
            """)
            for row in cursor.fetchall():
                providers.append({
                    "type": row[0],
                    "config": json.loads(row[1]) if row[1] else {},
                    "encrypted_secrets": row[2] or ""
                })
        except Exception as e:
            logger.error(f"Failed to get providers: {e}")
        
        return providers
    
    def decrypt_secrets(self, encrypted: str) -> dict:
        """Decrypt provider secrets."""
        if not encrypted:
            return {}
        try:
            from detection.utils import decrypt
            decrypted = decrypt(encrypted)
            return json.loads(decrypted)
        except Exception:
            return {}
    
    def classify(self, secret_type: str, file_path: str, line_number: int,
                 context: str, masked_value: str) -> Optional[dict]:
        """Classify a candidate secret using available LLM providers."""
        providers = self.get_active_providers()
        
        if not providers:
            logger.warning("No AI providers configured, using pattern confidence")
            return None
        
        prompt = CLASSIFICATION_PROMPT.format(
            secret_type=secret_type,
            file_path=file_path,
            line_number=line_number,
            context=context[:2000],  # Limit context window
            masked_value=masked_value
        )
        
        for provider in providers:
            try:
                result = self._call_provider(provider, prompt)
                if result:
                    return result
            except Exception as e:
                logger.warning(f"Provider {provider['type']} failed: {e}, trying next")
                continue
        
        return None
    
    def _call_provider(self, provider: dict, prompt: str) -> Optional[dict]:
        """Make API call to a specific provider."""
        ptype = provider["type"]
        # API key is stored in config (frontend sends it there)
        # Fall back to decrypted secrets for backwards compat
        config = provider.get("config", {})
        api_key = config.get("api_key", "")
        if not api_key:
            secrets = self.decrypt_secrets(provider["encrypted_secrets"])
            api_key = secrets.get("api_key", "")
        
        if ptype == "openai":
            return self._call_openai(api_key, prompt, provider["config"])
        elif ptype == "anthropic":
            return self._call_anthropic(api_key, prompt, provider["config"])
        elif ptype == "groq":
            return self._call_groq(api_key, prompt, provider["config"])
        elif ptype == "ollama":
            return self._call_ollama(provider["config"], prompt)
        
        return None
    
    def _parse_response(self, text: str) -> Optional[dict]:
        """Parse JSON from LLM response."""
        try:
            # Try direct parse
            return json.loads(text)
        except json.JSONDecodeError:
            # Extract JSON from markdown code block
            import re
            match = re.search(r"```(?:json)?\s*({[\s\S]+?})\s*```", text)
            if match:
                try:
                    return json.loads(match.group(1))
                except:
                    pass
            # Try to find JSON object
            match = re.search(r"{[\s\S]+}", text)
            if match:
                try:
                    return json.loads(match.group(0))
                except:
                    pass
        return None
    
    def _call_openai(self, api_key: str, prompt: str, config: dict) -> Optional[dict]:
        model = config.get("model", "gpt-4o-mini")
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": 500
            },
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        result = self._parse_response(text)
        if result:
            result["_model"] = model
        return result
    
    def _call_anthropic(self, api_key: str, prompt: str, config: dict) -> Optional[dict]:
        model = config.get("model", "claude-haiku-4-5-20251001")
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "max_tokens": 500,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0
            },
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        text = data["content"][0]["text"]
        result = self._parse_response(text)
        if result:
            result["_model"] = model
        return result
    
    def _call_groq(self, api_key: str, prompt: str, config: dict) -> Optional[dict]:
        model = config.get("model", "llama-3.3-70b-versatile")
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": 500
            },
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        result = self._parse_response(text)
        if result:
            result["_model"] = model
        return result
    
    def _call_ollama(self, config: dict, prompt: str) -> Optional[dict]:
        base_url = config.get("url", "http://localhost:11434")
        model = config.get("model", "llama3")
        resp = requests.post(
            f"{base_url}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0}},
            timeout=60
        )
        resp.raise_for_status()
        data = resp.json()
        result = self._parse_response(data.get("response", ""))
        if result:
            result["_model"] = model
        return result
    
    def test_provider(self, provider_type: str, api_key: str) -> dict:
        """Test a provider connection."""
        test_prompt = 'Reply with exactly: {"status": "ok"}'
        provider = {"type": provider_type, "config": {}, "encrypted_secrets": ""}
        
        try:
            if provider_type == "openai":
                resp = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": test_prompt}], "max_tokens": 20},
                    timeout=10
                )
                if resp.status_code == 200:
                    return {"success": True, "message": "OpenAI connected"}
                return {"success": False, "message": f"OpenAI error: {resp.status_code}"}
            
            elif provider_type == "anthropic":
                resp = requests.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
                    json={"model": "claude-haiku-4-5-20251001", "max_tokens": 20, "messages": [{"role": "user", "content": test_prompt}]},
                    timeout=10
                )
                if resp.status_code == 200:
                    return {"success": True, "message": "Anthropic connected"}
                return {"success": False, "message": f"Anthropic error: {resp.status_code}"}
            
            elif provider_type == "groq":
                resp = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": test_prompt}], "max_tokens": 20},
                    timeout=15
                )
                if resp.status_code == 200:
                    return {"success": True, "message": "Groq connected successfully"}
                try:
                    err_detail = resp.json().get("error", {}).get("message", resp.text[:200])
                except Exception:
                    err_detail = resp.text[:200]
                return {"success": False, "message": f"Groq error {resp.status_code}: {err_detail}"}
            
            return {"success": True, "message": "Provider saved"}
        except Exception as e:
            return {"success": False, "message": str(e)}
