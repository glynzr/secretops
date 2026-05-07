"""Vault Client — Poison Injection + fallback."""
import json, logging, os
from datetime import datetime, timezone
import requests

logger = logging.getLogger("secretops.vault")
FALLBACK_LOG = "/tmp/secretops_vault_fallback.jsonl"


class VaultClient:
    def __init__(self, config: dict = None):
        cfg = config or {}
        self.addr  = cfg.get("addr", os.environ.get("VAULT_ADDR", "http://vault:8200")).rstrip("/")
        self.token = cfg.get("token", os.environ.get("VAULT_TOKEN", "root"))
        self._ok: bool | None = None

    @property
    def _headers(self):
        return {"X-Vault-Token": self.token, "Content-Type": "application/json"}

    def is_available(self) -> bool:
        if self._ok is not None:
            return self._ok
        try:
            r = requests.get(f"{self.addr}/v1/sys/health", timeout=3)
            self._ok = r.status_code in (200, 429, 472, 501)
        except Exception:
            self._ok = False
        return self._ok

    def inject_poison(self, path: str, secret_type: str, finding_id: str,
                      days_exposed: int, original_value: str) -> tuple:
        """Inject a poison placeholder that forces app runtime failure."""
        import hashlib
        poison_val = (
            f"SECRETOPS_POISONED_{secret_type.upper()}_"
            f"FINDING_{finding_id[:8]}_"
            f"EXPOSED_{days_exposed}d_ROTATE_IMMEDIATELY"
        )
        orig_hash = hashlib.sha256(original_value.encode()).hexdigest()[:16]
        data = {
            "value": poison_val,
            "poisoned_at": datetime.now(timezone.utc).isoformat(),
            "finding_id": finding_id,
            "original_hash": orig_hash,
            "days_exposed": days_exposed,
            "action_required": "1.Rotate at provider 2.Update this Vault path 3.Verify app 4.Merge MR",
            "secretops_version": "3.0",
        }

        if not self.is_available():
            self._write_fallback("poison_inject", path, data)
            return False, "unavailable_fallback"

        # KV-v2 path
        parts = path.lstrip("/").split("/", 1)
        if len(parts) == 2:
            mount, kv_path = parts[0], parts[1]
        else:
            mount, kv_path = "secret", path

        try:
            r = requests.post(
                f"{self.addr}/v1/{mount}/data/{kv_path}",
                headers=self._headers,
                json={"data": data},
                timeout=10,
            )
            if r.status_code in (200, 204):
                return True, "poisoned"
            # Try KV-v1
            r2 = requests.post(
                f"{self.addr}/v1/{path}",
                headers=self._headers,
                json=data,
                timeout=10,
            )
            if r2.status_code in (200, 204):
                return True, "poisoned"
            self._write_fallback("poison_failed", path, data)
            return False, f"vault_error_{r.status_code}"
        except Exception as ex:
            self._write_fallback("poison_error", path, data)
            return False, f"error: {ex}"

    def read_value(self, path: str) -> str | None:
        """Read current value from Vault path for post-merge verification."""
        if not self.is_available():
            return None
        parts = path.lstrip("/").split("/", 1)
        mount = parts[0] if len(parts) == 2 else "secret"
        kv_path = parts[1] if len(parts) == 2 else path
        try:
            r = requests.get(
                f"{self.addr}/v1/{mount}/data/{kv_path}",
                headers=self._headers, timeout=5
            )
            if r.status_code == 200:
                d = r.json()
                data = d.get("data", {}).get("data", {})
                return data.get("value", "")
        except Exception:
            pass
        return None

    def _write_fallback(self, op: str, path: str, data: dict):
        try:
            with open(FALLBACK_LOG, "a") as f:
                f.write(json.dumps({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "operation": op, "vault_addr": self.addr,
                    "vault_path": path, "data_keys": list(data.keys()),
                }) + "\n")
        except Exception:
            pass
