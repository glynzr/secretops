"""
Remediation Pipeline:
1. AI-generated code patch
2. Git branch + MR creation (scripted, not AI)
3. Vault poison injection
4. Multi-channel notifications
5. Credential revocation (AWS IAM, GitLab PAT, GitHub PAT)
"""
import hashlib
import json
import logging
import os
import re
import sqlite3
import subprocess
import tempfile
import shutil
import requests
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/secretops.db")
CLONE_DIR = os.environ.get("CLONE_DIR", "/tmp/secretops-repos")

# ---------------------------------------------------------------------------
# SDK dependency metadata — used by _ensure_sdk_dependency() to patch the
# project's dependency file (requirements.txt, go.mod, package.json, etc.)
# when the Vault SDK is not yet listed.
# ---------------------------------------------------------------------------
VAULT_SDK_DEPS = {
    "python": {
        "package":       "hvac",
        "dep_file":      "requirements.txt",
        "check_pattern": r"^\s*hvac",
        "add_line":      "hvac>=2.3.0",
    },
    "javascript": {
        "package":       "node-vault",
        "dep_file":      "package.json",
        "check_pattern": r'"node-vault"',
        "add_line":      None,   # handled specially — JSON edit
    },
    "typescript": {
        "package":       "node-vault",
        "dep_file":      "package.json",
        "check_pattern": r'"node-vault"',
        "add_line":      None,   # handled specially — JSON edit
    },
    "go": {
        "package":       "github.com/hashicorp/vault/api",
        "dep_file":      "go.mod",
        "check_pattern": r"github\.com/hashicorp/vault/api",
        "add_line":      "\tgithub.com/hashicorp/vault/api v1.13.0",
    },
    "ruby": {
        "package":       "vault",
        "dep_file":      "Gemfile",
        "check_pattern": r"""gem\s+['"]vault['"]""",
        "add_line":      "gem 'vault', '~> 0.18'",
    },
    "java": {
        "package":       "vault-java-driver",
        "dep_file":      "pom.xml",
        "check_pattern": r"vault-java-driver",
        "add_line":      None,   # handled specially — XML snippet
    },
    "php": {
        "package":       "vault-php/vault-php",
        "dep_file":      "composer.json",
        "check_pattern": r'"vault-php/vault-php"',
        "add_line":      None,   # handled specially — JSON edit
    },
}

PATCH_PROMPT = """You are a security engineer. A hardcoded secret was found in source code and must be removed.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VAULT STATUS: {vault_status_instruction}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  READ THE VAULT STATUS ABOVE BEFORE DOING ANYTHING ELSE.
    - If it says CONNECTED     → you MUST use the Vault SDK. Environment variables are FORBIDDEN.
    - If it says NOT CONNECTED → you MUST use environment variables. Vault SDK is FORBIDDEN.
    Do not deviate. Do not mix approaches. One status = one approach, always.

Finding details:
  Secret type : {secret_type}
  File        : {file_path}
  Line        : {line_number}
  Vault path  : {vault_path}

Code context (line {line_number} has the exposed secret):
```
{context}
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TASK: Replace ONLY line {line_number}. Do not change any other line.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STRICT RULES:
1. Keep the EXACT same variable/key name from the original line.
2. Match the existing indentation and code style exactly.
3. Never put import/require statements inside patched_line — use imports_needed field.
4. Never duplicate an import that already exists in the context above.
5. MANDATORY: Follow exactly one of the two branches below based on Vault status. Never blend both.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMPORT PLACEMENT RULES — always obeyed regardless of language or vault status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

imports_needed must contain ONLY the raw import/require statement — no inline comments,
no surrounding code, no blank lines. The consuming tool places it at the correct location.

Placement rules by language:

  Python      → top of file, after any module docstring, before all other code.
                Group with existing imports; stdlib first, then third-party (hvac, etc.).
                Never inside a function, class, or conditional block.

  JS / TS     → top of file, before any other statements.
                ES module files  : use import syntax  → import vault from "node-vault";
                CommonJS files   : use require syntax  → const vault = require("node-vault");
                Never inside a function, callback, or if-block.

  Go          → add only the package path inside the existing import(...) block.
                Never emit a standalone import statement if one already exists in the file.
                Never place inside a func body.

  Ruby        → top of file, after frozen_string_literal comment if present.
                Never inside a method, module body, or conditional.

  Java        → after the package declaration, before the class declaration.
                Never inside a method or static block.

  PHP         → after <?php, before any class or function declaration.
                Never inside a function body.

  .env / YAML / TOML → imports_needed must always be "" — these formats have no import concept.

If the needed import already appears anywhere in the context window, set imports_needed to ""
and do NOT add it again.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BRANCH A — VAULT IS CONNECTED
Use this branch ONLY when Vault status is CONNECTED.
Environment variables (os.environ.get, process.env, os.Getenv, etc.) are FORBIDDEN here
EXCEPT for VAULT_ADDR and VAULT_TOKEN which are used only to authenticate the Vault client.

CRITICAL PATTERN FOR ALL LANGUAGES:
  - Initialize the Vault client ONCE using a module-level or file-level variable.
  - The Vault client credentials (url, token) MUST come from environment variables — NEVER hardcoded.
  - The secret read call uses the already-initialized client — it does NOT re-create it inline.
  - patched_line must be ONLY the secret read — clean, short, readable.
  - The client init code goes in init_code field, NOT in patched_line.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Python (.py):
    init_code     : _vault_client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])
    patched_line  : VARIABLE = _vault_client.secrets.kv.v2.read_secret_version(path="{vault_path_short}")["data"]["data"]["value"]
    imports_needed: "import hvac\\nimport os"  ← omit any already-imported module

  JavaScript / Node.js (.js, .mjs, .cjs):
    init_code     : const _vaultClient = require("node-vault")({{endpoint: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN}});
    patched_line  : const VARIABLE = await _vaultClient.read("{vault_path}").then(r => r.data.data.value);
    imports_needed: ""  ← require is inline in init_code

  TypeScript (.ts, .tsx):
    init_code     : const _vaultClient = vault({{endpoint: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN}});
    patched_line  : const VARIABLE: string = await _vaultClient.read("{vault_path}").then((r: any) => r.data.data.value);
    imports_needed: "import vault from \\"node-vault\\";"

  Go (.go):
    init_code     : var _vaultClient = func() *vaultapi.Client {{ c, _ := vaultapi.NewClient(vaultapi.DefaultConfig()); c.SetAddress(os.Getenv("VAULT_ADDR")); c.SetToken(os.Getenv("VAULT_TOKEN")); return c }}()
    patched_line  : VARIABLE_raw, _ := _vaultClient.Logical().Read("{vault_path}"); VARIABLE := VARIABLE_raw.Data["value"].(string)
    imports_needed: "\\"os\\"\\n\\"github.com/hashicorp/vault/api\\" vaultapi"

  Ruby (.rb):
    init_code     : Vault.configure {{ |config| config.address = ENV["VAULT_ADDR"]; config.token = ENV["VAULT_TOKEN"] }}
    patched_line  : VARIABLE = Vault.logical.read("{vault_path}").data[:value]
    imports_needed: "require \\"vault\\""

  Java (.java):
    init_code     : // Inject VaultTemplate via Spring — configure VAULT_ADDR and VAULT_TOKEN in application.properties
    patched_line  : String VARIABLE = vaultTemplate.read("{vault_path}", Map.class).getData().get("value").toString();
    imports_needed: ""

  PHP (.php):
    init_code     : $vault = new Vault\\Client(getenv("VAULT_ADDR")); $vault->setToken(getenv("VAULT_TOKEN"));
    patched_line  : $VARIABLE = $vault->read("{vault_path}")["data"]["data"]["value"];
    imports_needed: ""

  .env file (NEVER put code in .env):
    init_code     : ""
    patched_line  : VARIABLE=  # SecretOps: hardcoded value removed. Store new credential in Vault: vault kv put {vault_path} value=NEW_VALUE
    imports_needed: ""

  YAML / config (.yml, .yaml, .toml):
    init_code     : ""
    patched_line  : VARIABLE: ${{VARIABLE}}  # SecretOps: inject at deploy from Vault: vault kv get -field=value {vault_path}
    imports_needed: ""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BRANCH B — VAULT IS NOT CONNECTED
Use this branch ONLY when Vault status is NOT CONNECTED.
Vault SDK (hvac, node-vault, etc.) is FORBIDDEN here.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Python (.py):
    init_code     : ""
    patched_line  : VARIABLE = os.environ.get("VARIABLE")  # SecretOps: set this env var
    imports_needed: "import os"  ← omit if already imported

  JavaScript / Node.js:
    init_code     : ""
    patched_line  : const VARIABLE = process.env.VARIABLE; // SecretOps: set this env var
    imports_needed: ""

  TypeScript:
    init_code     : ""
    patched_line  : const VARIABLE: string = process.env.VARIABLE!; // SecretOps: set this env var
    imports_needed: ""

  Go:
    init_code     : ""
    patched_line  : VARIABLE := os.Getenv("VARIABLE") // SecretOps: set this env var
    imports_needed: "\\"os\\""  ← package path only, added inside existing import block

  Ruby:
    init_code     : ""
    patched_line  : VARIABLE = ENV["VARIABLE"] # SecretOps: set this env var
    imports_needed: ""

  Java:
    init_code     : ""
    patched_line  : String VARIABLE = System.getenv("VARIABLE"); // SecretOps: set this env var
    imports_needed: ""

  PHP:
    init_code     : ""
    patched_line  : $VARIABLE = getenv("VARIABLE"); // SecretOps: set this env var
    imports_needed: ""

  .env file:
    init_code     : ""
    patched_line  : VARIABLE=  # SecretOps: hardcoded value removed. Set this before deploy.
    imports_needed: ""

  YAML / config:
    init_code     : ""
    patched_line  : VARIABLE: ${{VARIABLE}}  # SecretOps: set env var before deploy
    imports_needed: ""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Respond ONLY with valid JSON — no markdown, no explanation outside JSON:
{{
  "vault_connected": true or false,
  "patch_strategy": "vault_sdk or env_var",
  "init_code": "module-level Vault client initialization line (Vault branch only), or empty string",
  "init_code_placement": "where init_code must be inserted — e.g. after imports at module level, or empty string",
  "patched_line": "the secret read line — short, uses the already-initialized client, replace VARIABLE with the real variable name",
  "imports_needed": "raw import statement only, using \\n to separate multiple imports, or empty string if none needed",
  "import_placement": "where in the file the import must be inserted — e.g. top of file after line 3 (last existing import)",
  "sdk_dep_needed": true or false,
  "sdk_dep_name": "hvac or node-vault or github.com/hashicorp/vault/api or vault (gem) or vault-java-driver or vault-php/vault-php, or empty string",
  "sdk_dep_version": "recommended minimum version string e.g. 2.3.0, or empty string",
  "env_var_name": "THE_VARIABLE_NAME_IN_UPPER_SNAKE_CASE",
  "language": "python|javascript|typescript|go|ruby|java|php|yaml|dotenv|shell|csharp",
  "vault_path": "{vault_path}",
  "rotation_steps": [
    "1. Immediately revoke the exposed {secret_type} at the provider console — do not wait",
    "2. Generate a fresh replacement credential at the provider",
    "3. Store the new credential in Vault: vault kv put {vault_path} value=<NEW_CREDENTIAL>",
    "4. Ensure VAULT_ADDR and VAULT_TOKEN env vars are set in every deployment environment",
    "5. Install the Vault SDK if needed (pip install hvac / npm install node-vault / go get github.com/hashicorp/vault/api)",
    "6. Merge this MR, deploy, and confirm the app starts successfully"
  ],
  "provider_rotation_url": "",
  "explanation": "One sentence describing what was changed and why."
}}
"""


# ---------------------------------------------------------------------------
# Import insertion — places imports at the structurally correct location
# for each language. Never inserts mid-function or mid-class.
# ---------------------------------------------------------------------------
def _apply_import_to_file(content: str, imports_needed: str, language: str) -> str:
    if not imports_needed or not imports_needed.strip():
        return content

    import_lines = [l.strip() for l in imports_needed.strip().split("\n") if l.strip()]
    lines = content.split("\n")

    if language == "python":
        last_import_idx = -1
        in_docstring = False
        docstring_char = None
        docstring_end_idx = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not in_docstring and docstring_end_idx == -1:
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    char = stripped[:3]
                    if stripped.count(char) >= 2 and len(stripped) > 3:
                        docstring_end_idx = i
                    else:
                        in_docstring = True
                        docstring_char = char
                    continue
            if in_docstring:
                if docstring_char and docstring_char in stripped:
                    in_docstring = False
                    docstring_end_idx = i
                continue
            if (stripped.startswith("import ") or stripped.startswith("from ")) \
                    and not line.startswith(" ") and not line.startswith("\t"):
                last_import_idx = i

        insert_after = last_import_idx if last_import_idx >= 0 else docstring_end_idx
        insert_at = insert_after + 1
        existing = set(lines)
        new_imports = [imp for imp in import_lines if imp not in existing]
        if not new_imports:
            return content
        lines[insert_at:insert_at] = new_imports
        return "\n".join(lines)

    elif language in ("javascript", "typescript"):
        last_import_idx = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("import ") or ("require(" in stripped and stripped.startswith("const ")):
                last_import_idx = i
            elif last_import_idx >= 0 and stripped and not stripped.startswith("//"):
                break
        insert_at = last_import_idx + 1
        existing = set(lines)
        new_imports = [imp for imp in import_lines if imp not in existing]
        if not new_imports:
            return content
        lines[insert_at:insert_at] = new_imports
        return "\n".join(lines)

    elif language == "go":
        import_block_start = -1
        import_block_end = -1
        package_line = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("package ") and package_line < 0:
                package_line = i
            if stripped == "import (" and import_block_start < 0:
                import_block_start = i
            if import_block_start >= 0 and stripped == ")" and import_block_end < 0:
                import_block_end = i
                break
        existing_in_block = set()
        if import_block_start >= 0 and import_block_end >= 0:
            for line in lines[import_block_start + 1:import_block_end]:
                existing_in_block.add(line.strip().strip('"').split()[0].strip('"'))
        new_pkg_paths = []
        for imp in import_lines:
            pkg = imp.strip().strip('"').split()[0].strip('"')
            if pkg not in existing_in_block:
                alias_part = imp.strip()
                new_pkg_paths.append(f'\t{alias_part}' if not alias_part.startswith('"') else f'\t"{pkg}"')
        if not new_pkg_paths:
            return content
        if import_block_start >= 0 and import_block_end >= 0:
            lines[import_block_end:import_block_end] = new_pkg_paths
        else:
            insert_at = (package_line + 1) if package_line >= 0 else 0
            block = ["", "import ("] + new_pkg_paths + [")", ""]
            lines[insert_at:insert_at] = block
        return "\n".join(lines)

    elif language == "ruby":
        insert_after = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("# frozen_string_literal"):
                insert_after = i
            elif stripped.startswith("require "):
                insert_after = i
            elif insert_after >= 0 and stripped and not stripped.startswith("#"):
                break
        insert_at = insert_after + 1
        existing = set(lines)
        new_imports = [imp for imp in import_lines if imp not in existing]
        if not new_imports:
            return content
        lines[insert_at:insert_at] = new_imports
        return "\n".join(lines)

    elif language == "java":
        last_import_idx = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("import "):
                last_import_idx = i
            elif stripped.startswith("public class") or stripped.startswith("class "):
                break
        insert_at = last_import_idx + 1
        existing = set(lines)
        new_imports = [imp for imp in import_lines if imp not in existing]
        if not new_imports:
            return content
        lines[insert_at:insert_at] = new_imports
        return "\n".join(lines)

    elif language == "php":
        insert_after = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("<?php"):
                insert_after = i
            elif stripped.startswith("use ") or stripped.startswith("require"):
                insert_after = i
            elif stripped.startswith("class ") or stripped.startswith("function "):
                break
        insert_at = insert_after + 1
        existing = set(lines)
        new_imports = [imp for imp in import_lines if imp not in existing]
        if not new_imports:
            return content
        lines[insert_at:insert_at] = new_imports
        return "\n".join(lines)

    return content


# ---------------------------------------------------------------------------
# Init code insertion — inserts the Vault client initialization block at
# module level, after imports but before any class or function definitions.
# ---------------------------------------------------------------------------
def _apply_init_code_to_file(content: str, init_code: str, language: str) -> str:
    """
    Insert the Vault client init block at module/file level — after the import
    block but before any class or function definitions. Never inside a function.
    """
    if not init_code or not init_code.strip():
        return content

    lines = content.split("\n")

    if language == "python":
        # Insert after the last top-level import, before the first class/def
        last_import_idx = -1
        first_class_or_def = -1
        in_docstring = False
        docstring_char = None

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not in_docstring:
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    char = stripped[:3]
                    if not (stripped.count(char) >= 2 and len(stripped) > 3):
                        in_docstring = True
                        docstring_char = char
                    continue
            else:
                if docstring_char and docstring_char in stripped:
                    in_docstring = False
                continue

            if (stripped.startswith("import ") or stripped.startswith("from ")) \
                    and not line.startswith(" ") and not line.startswith("\t"):
                last_import_idx = i
            elif (stripped.startswith("class ") or stripped.startswith("def ")) \
                    and not line.startswith(" ") and not line.startswith("\t") \
                    and first_class_or_def < 0:
                first_class_or_def = i

        # Already have a _vault_client init? Skip.
        if any("_vault_client" in l for l in lines):
            return content

        insert_at = last_import_idx + 1 if last_import_idx >= 0 else 0
        # Add a blank line separator
        block = ["", "# SecretOps: Vault client — credentials from environment, never hardcoded"] + \
                [init_code] + [""]
        lines[insert_at:insert_at] = block
        return "\n".join(lines)

    elif language in ("javascript", "typescript"):
        # Insert after the last import/require block
        last_import_idx = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("import ") or ("require(" in stripped and stripped.startswith("const ")):
                last_import_idx = i
            elif last_import_idx >= 0 and stripped and not stripped.startswith("//"):
                break

        if any("_vaultClient" in l for l in lines):
            return content

        insert_at = last_import_idx + 1
        block = ["", "// SecretOps: Vault client — credentials from environment, never hardcoded",
                 init_code, ""]
        lines[insert_at:insert_at] = block
        return "\n".join(lines)

    elif language == "go":
        # Insert as a package-level var after the import block
        import_block_end = -1
        for i, line in enumerate(lines):
            if line.strip() == "import (" :
                for j in range(i + 1, len(lines)):
                    if lines[j].strip() == ")":
                        import_block_end = j
                        break
                break

        if any("_vaultClient" in l for l in lines):
            return content

        insert_at = import_block_end + 1 if import_block_end >= 0 else 0
        block = ["", "// SecretOps: Vault client — credentials from environment, never hardcoded",
                 init_code, ""]
        lines[insert_at:insert_at] = block
        return "\n".join(lines)

    elif language == "ruby":
        # Insert after the last require line
        last_require_idx = -1
        for i, line in enumerate(lines):
            if line.strip().startswith("require "):
                last_require_idx = i

        if any("Vault.configure" in l for l in lines):
            return content

        insert_at = last_require_idx + 1 if last_require_idx >= 0 else 0
        block = ["", "# SecretOps: Vault client — credentials from environment, never hardcoded",
                 init_code, ""]
        lines[insert_at:insert_at] = block
        return "\n".join(lines)

    elif language == "php":
        # Insert after the last use/require statement, before first class/function
        last_use_idx = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("use ") or stripped.startswith("require"):
                last_use_idx = i
            elif stripped.startswith("class ") or stripped.startswith("function "):
                break

        if any("$vault" in l for l in lines):
            return content

        insert_at = last_use_idx + 1 if last_use_idx >= 0 else 1
        block = ["", "// SecretOps: Vault client — credentials from environment, never hardcoded",
                 init_code, ""]
        lines[insert_at:insert_at] = block
        return "\n".join(lines)

    # Go, Java, dotenv, yaml — handled upstream or not applicable
    return content


# ---------------------------------------------------------------------------
# Dependency file patching — adds the Vault SDK to the project's dependency
# manifest (requirements.txt, package.json, go.mod, Gemfile, pom.xml,
# composer.json) when it is not yet listed.
# ---------------------------------------------------------------------------
def _ensure_sdk_dependency(
    repo_dir: str,
    language: str,
    sdk_dep_name: str,
    sdk_dep_version: str,
) -> Optional[str]:
    """
    Check whether the Vault SDK is already declared in the project's dependency
    file. If not, add it and return the relative path of the modified file so
    the caller can include it in the GitLab commit. Returns None if no change
    was needed or the dep file was not found.
    """
    if not sdk_dep_name:
        return None

    meta = VAULT_SDK_DEPS.get(language)
    if not meta:
        return None

    dep_file_name = meta["dep_file"]
    check_pattern = meta["check_pattern"]

    # Search for the dep file starting from repo root, one level deep
    dep_file_path = None
    for root, dirs, files in os.walk(repo_dir):
        # Don't descend into vendor/node_modules
        dirs[:] = [d for d in dirs if d not in ("vendor", "node_modules", ".git")]
        if dep_file_name in files:
            dep_file_path = os.path.join(root, dep_file_name)
            break

    if not dep_file_path:
        logger.info(f"[dep] {dep_file_name} not found in {repo_dir} — skipping dependency patch")
        return None

    try:
        with open(dep_file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.warning(f"[dep] Could not read {dep_file_path}: {e}")
        return None

    if re.search(check_pattern, content, re.MULTILINE):
        logger.info(f"[dep] {sdk_dep_name} already present in {dep_file_path}")
        return None

    logger.info(f"[dep] Adding {sdk_dep_name} to {dep_file_path}")

    try:
        if language == "python":
            # Append to requirements.txt
            new_line = f"hvac>={sdk_dep_version}" if sdk_dep_version else "hvac>=2.3.0"
            updated = content.rstrip("\n") + f"\n{new_line}\n"

        elif language in ("javascript", "typescript"):
            # Edit package.json — add to dependencies
            pkg = json.loads(content)
            version = f"^{sdk_dep_version}" if sdk_dep_version else "^0.7.0"
            pkg.setdefault("dependencies", {})["node-vault"] = version
            updated = json.dumps(pkg, indent=2) + "\n"

        elif language == "go":
            # Append inside the require(...) block
            version = sdk_dep_version or "v1.13.0"
            new_line = f"\tgithub.com/hashicorp/vault/api {version}"
            if "require (" in content:
                updated = content.replace(
                    "require (",
                    f"require (\n{new_line}",
                    1
                )
            else:
                updated = content.rstrip("\n") + f"\nrequire (\n{new_line}\n)\n"

        elif language == "ruby":
            # Append to Gemfile
            version = sdk_dep_version or "0.18"
            new_line = f"gem 'vault', '~> {version}'"
            updated = content.rstrip("\n") + f"\n{new_line}\n"

        elif language == "java":
            # Insert Maven dependency before </dependencies>
            version = sdk_dep_version or "5.1.0"
            snippet = (
                f"        <dependency>\n"
                f"            <groupId>com.bettercloud</groupId>\n"
                f"            <artifactId>vault-java-driver</artifactId>\n"
                f"            <version>{version}</version>\n"
                f"        </dependency>"
            )
            if "</dependencies>" in content:
                updated = content.replace("</dependencies>", f"{snippet}\n    </dependencies>", 1)
            else:
                logger.warning("[dep] pom.xml has no </dependencies> tag — skipping")
                return None

        elif language == "php":
            # Edit composer.json
            pkg = json.loads(content)
            version = f"^{sdk_dep_version}" if sdk_dep_version else "^0.1"
            pkg.setdefault("require", {})["vault-php/vault-php"] = version
            updated = json.dumps(pkg, indent=4) + "\n"

        else:
            return None

        with open(dep_file_path, "w", encoding="utf-8") as f:
            f.write(updated)

        # Return the path relative to repo_dir for the commit action
        return os.path.relpath(dep_file_path, repo_dir)

    except Exception as e:
        logger.warning(f"[dep] Failed to patch {dep_file_path}: {e}")
        return None


class RemediationPipeline:
    def __init__(self):
        pass

    def get_db(self):
        return sqlite3.connect(DB_PATH)

    def get_integration(self, db, itype: str) -> tuple[dict, dict]:
        """Get integration config and decrypted secrets."""
        try:
            row = db.execute(
                "SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type=? ORDER BY id LIMIT 1",
                (itype,)
            ).fetchone()
            if not row:
                logger.warning(f"Integration '{itype}' not found in DB")
                return {}, {}
            config = json.loads(row[0]) if row[0] else {}
            secrets = {}
            if row[1]:
                from detection.utils import decrypt
                try:
                    secrets = json.loads(decrypt(row[1]))
                except Exception:
                    pass
            merged = {**secrets, **config}
            logger.debug(f"Integration '{itype}' config keys: {list(config.keys())}")
            return merged, secrets
        except Exception as e:
            logger.error(f"Failed to get integration {itype}: {e}")
            return {}, {}

    def run(self, finding_id: int):
        db = self.get_db()
        try:
            row = db.execute("""
                SELECT f.*, r.full_path, r.url, r.default_branch, r.name
                FROM findings f
                JOIN repositories r ON f.repository_id = r.id
                WHERE f.id=?
            """, (finding_id,)).fetchone()

            if not row:
                logger.error(f"Finding {finding_id} not found")
                return

            cols = [d[0] for d in db.execute("SELECT * FROM findings LIMIT 0").description]
            finding = dict(zip(cols, row[:len(cols)]))
            finding["repo_full_path"] = row[-4]
            finding["repo_url"] = row[-3]
            finding["default_branch"] = row[-2]
            finding["repo_name"] = row[-1]

            db.execute("UPDATE findings SET status='remediating', remediation_status='in_progress', updated_at=CURRENT_TIMESTAMP WHERE id=?", (finding_id,))
            db.commit()

            vault_path = self._generate_vault_path(finding)
            db.execute("UPDATE findings SET vault_path=? WHERE id=?", (vault_path, finding_id))
            db.commit()

            logger.info(f"[remediation:{finding_id}] Generating AI patch...")
            patch = self._generate_patch(db, finding, vault_path)
            logger.info(f"[remediation:{finding_id}] Patch generated by: {patch.get('_generated_by','unknown')}")

            logger.info(f"[remediation:{finding_id}] Injecting Vault poison at {vault_path}...")
            self._inject_vault_poison(db, finding, vault_path)

            logger.info(f"[remediation:{finding_id}] Creating branch and MR...")
            branch_name, mr_url, mr_id, issue_url = self._create_branch_and_mr(
                db, finding, patch, vault_path
            )

            if branch_name:
                db.execute("""
                    UPDATE findings SET
                    branch_name=?, mr_url=?, mr_id=?, issue_url=?,
                    status='remediated', remediation_status='mr_created', updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                """, (branch_name, mr_url, mr_id, issue_url, finding_id))
            else:
                db.execute("""
                    UPDATE findings SET status='remediated', remediation_status='completed',
                    updated_at=CURRENT_TIMESTAMP WHERE id=?
                """, (finding_id,))
            db.commit()

            self._send_notifications(db, finding, patch, vault_path, mr_url, issue_url)
            self._attempt_revocation(db, finding)

            db.execute("""
                INSERT INTO audit_logs (action, entity_type, entity_id, details)
                VALUES ('remediation.completed', 'finding', ?, ?)
            """, (finding_id, json.dumps({"mr_url": mr_url, "vault_path": vault_path})))
            db.commit()

            logger.info(f"Remediation completed for finding {finding_id}: vault={vault_path}, branch={branch_name}, mr={mr_url}")

        except Exception as e:
            logger.error(f"Remediation failed for finding {finding_id}: {e}")
            db.execute("""
                UPDATE findings SET status='confirmed', remediation_status='failed',
                updated_at=CURRENT_TIMESTAMP WHERE id=?
            """, (finding_id,))
            db.commit()
        finally:
            db.close()

    def _generate_vault_path(self, finding: dict) -> str:
        secret_type = finding["secret_type"].replace("_", "-")
        file_part = finding["file_path"].replace("/", "-").replace(".", "-")[:30]
        return f"secret/{finding['repo_name']}/{secret_type}/{file_part}-{finding['id']}"

    def _generate_patch(self, db, finding: dict, vault_path: str) -> dict:
        """Use AI to generate code patch."""
        config_list = db.execute(
            "SELECT type, config, COALESCE(encrypted_secrets,'') FROM integrations "
            "WHERE type IN ('openai','anthropic','groq') AND status IN ('connected','untested') LIMIT 3"
        ).fetchall()

        logger.info(f"Patch generation: found {len(config_list)} AI providers")

        # Resolve Vault status FIRST — needed by both AI and fallback paths
        vault_cfg, _ = self.get_integration(db, "vault")
        vault_url = vault_cfg.get("url") or vault_cfg.get("address") or ""
        vault_token = vault_cfg.get("token") or ""
        vault_connected = bool(vault_url and vault_token)
        vault_path_short = vault_path.replace("secret/data/", "").replace("secret/", "")

        if not config_list:
            logger.warning("No AI providers found for patch generation, using fallback")
            return self._fallback_patch(finding, vault_path, vault_connected=vault_connected)

        # Read file content for context
        repo_local = os.path.join(CLONE_DIR, finding["repo_full_path"].replace("/", "_"))
        context = ""
        try:
            file_path = os.path.join(repo_local, finding["file_path"])
            with open(file_path, "r", errors="ignore") as f:
                file_lines = f.readlines()
            start = max(0, finding["line_number"] - 6)
            end = min(len(file_lines), finding["line_number"] + 5)
            context = "".join(f"{i+start+1}: {l}" for i, l in enumerate(file_lines[start:end]))
        except Exception:
            context = f"Line {finding['line_number']}: [content unavailable]"

        logger.info(f"[patch] vault_connected={vault_connected} vault_url={vault_url!r} has_token={bool(vault_token)}")

        if vault_connected:
            vault_status_instruction = (
                f"CONNECTED at {vault_url}. "
                f"You MUST fetch the secret from HashiCorp Vault KV-v2 at path: {vault_path_short}. "
                f"The Vault client MUST be initialized once at module level using VAULT_ADDR and VAULT_TOKEN "
                f"environment variables — never hardcode the URL or token. "
                f"patched_line must only contain the secret READ call using the already-initialized client. "
                f"Put the client initialization in the init_code field."
            )
        else:
            vault_status_instruction = (
                "NOT CONNECTED. You MUST use environment variables. "
                "Do NOT reference hvac, node-vault, or any Vault SDK. "
                "Use: os.environ.get() for Python, process.env for JS/TS, os.Getenv() for Go. "
                "Leave init_code as empty string."
            )

        prompt = PATCH_PROMPT.format(
            vault_status_instruction=vault_status_instruction,
            secret_type=finding["secret_type"],
            file_path=finding["file_path"],
            line_number=finding["line_number"],
            vault_path=vault_path,
            vault_path_short=vault_path_short,
            context=context
        )

        from detection.utils import decrypt

        for row in config_list:
            try:
                ptype = row[0]
                config = json.loads(row[1]) if row[1] else {}
                secrets = {}
                if row[2]:
                    try:
                        secrets = json.loads(decrypt(row[2]))
                    except Exception:
                        pass

                api_key = config.get("api_key", secrets.get("api_key", ""))
                result_text = self._call_llm_raw(ptype, api_key, config, prompt)

                if result_text:
                    try:
                        clean = result_text.strip()
                        if "```" in clean:
                            m = re.search(r"```(?:json)?\s*({[\s\S]+?})\s*```", clean)
                            if m:
                                clean = m.group(1)
                        patch = json.loads(clean)
                        patch["_generated_by"] = ptype

                        # Enforce branch consistency — discard if wrong strategy
                        expected_strategy = "vault_sdk" if vault_connected else "env_var"
                        if patch.get("patch_strategy") != expected_strategy:
                            logger.warning(
                                f"[patch] LLM ({ptype}) returned patch_strategy="
                                f"{patch.get('patch_strategy')!r} but expected "
                                f"{expected_strategy!r}. Discarding."
                            )
                            continue

                        # Reject if patched_line still contains a hardcoded vault URL or token
                        patched_line = patch.get("patched_line", "")
                        if vault_connected and (
                            re.search(r'https?://', patched_line) or
                            re.search(r'token\s*=\s*["\'][^"\'${\s]{4,}', patched_line)
                        ):
                            logger.warning(
                                f"[patch] LLM ({ptype}) patched_line contains hardcoded URL or token — discarding."
                            )
                            continue

                        logger.info(f"[patch] LLM ({ptype}) generated: {patched_line[:80]}")
                        return patch
                    except json.JSONDecodeError as je:
                        logger.warning(f"[patch] JSON parse failed for {ptype}: {je} — raw: {result_text[:200]}")
                        continue
            except Exception as e:
                logger.warning(f"Patch generation failed with {row[0]}: {e}")
                continue

        return self._fallback_patch(finding, vault_path, vault_connected=vault_connected)

    def _default_rotation_steps(self, finding: dict, vault_path: str, env_var: str) -> list:
        return [
            f"1. Immediately revoke the exposed {finding['secret_type']} at the provider console — do not wait",
            "2. Generate a fresh replacement credential at the provider",
            f"3. Store the new credential in Vault: vault kv put {vault_path} value=<NEW_CREDENTIAL>",
            "4. Ensure VAULT_ADDR and VAULT_TOKEN env vars are set in every deployment environment",
            "5. Install the Vault SDK if needed (pip install hvac / npm install node-vault / go get github.com/hashicorp/vault/api)",
            "6. Merge this MR, deploy, and confirm the app starts successfully",
        ]

    def _fallback_patch(self, finding: dict, vault_path: str, vault_connected: bool = False) -> dict:
        """Generate a file-type aware patch without LLM."""
        secret_type = finding["secret_type"].upper()
        env_var = secret_type.replace("-", "_").replace(" ", "_")
        file_path = finding.get("file_path", "")
        vault_path_short = vault_path.replace("secret/data/", "").replace("secret/", "")
        strategy = "vault_sdk" if vault_connected else "env_var"

        is_env  = file_path.endswith(".env") or "/.env" in file_path or file_path == ".env"
        is_yaml = file_path.endswith((".yml", ".yaml"))
        is_js   = file_path.endswith((".js", ".mjs", ".jsx"))
        is_ts   = file_path.endswith((".ts", ".tsx"))
        is_go   = file_path.endswith(".go")
        is_ruby = file_path.endswith(".rb")
        is_java = file_path.endswith(".java")
        is_php  = file_path.endswith(".php")

        base = {
            "vault_connected": vault_connected,
            "patch_strategy": strategy,
            "vault_path": vault_path,
            "env_var_name": env_var,
            "provider_rotation_url": "",
            "_generated_by": "fallback",
            "rotation_steps": self._default_rotation_steps(finding, vault_path, env_var),
            "init_code": "",
            "init_code_placement": "",
            "sdk_dep_needed": vault_connected,
            "sdk_dep_version": "",
        }

        if is_env:
            patched = (
                f"{env_var}=  # SecretOps: removed. Store in Vault: vault kv put {vault_path} value=NEW_VALUE"
                if vault_connected else
                f"{env_var}=  # SecretOps: hardcoded value removed. Set this before deploy."
            )
            return {**base, "patched_line": patched, "imports_needed": "", "import_placement": "",
                    "language": "dotenv", "sdk_dep_name": "",
                    "explanation": f"Removed hardcoded {finding['secret_type']} from .env file."}

        if is_yaml:
            patched = (
                f"{env_var.lower()}: ${{{env_var}}}  # SecretOps: inject from Vault {vault_path}"
                if vault_connected else
                f"{env_var.lower()}: ${{{env_var}}}  # SecretOps: set env var before deploy"
            )
            return {**base, "patched_line": patched, "imports_needed": "", "import_placement": "",
                    "language": "yaml", "sdk_dep_name": "",
                    "explanation": f"Replaced hardcoded {finding['secret_type']} with env var reference."}

        if is_js:
            if vault_connected:
                init  = "const _vaultClient = require(\"node-vault\")({endpoint: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN});"
                patch_line = f"const {env_var.lower()} = await _vaultClient.read(\"{vault_path}\").then(r => r.data.data.value);"
                imp, imp_p = "", "require is inline in init_code — no top-level import needed"
                sdk_name = "node-vault"
            else:
                init, patch_line = "", f"const {env_var.lower()} = process.env.{env_var}; // SecretOps: set this env var"
                imp, imp_p, sdk_name = "", "", ""
            return {**base, "init_code": init, "init_code_placement": "after imports at module level",
                    "patched_line": patch_line, "imports_needed": imp, "import_placement": imp_p,
                    "language": "javascript", "sdk_dep_name": sdk_name, "sdk_dep_version": "0.7.0",
                    "explanation": f"Replaced hardcoded {finding['secret_type']} with {'Vault SDK' if vault_connected else 'env var'} lookup."}

        if is_ts:
            if vault_connected:
                init  = "const _vaultClient = vault({endpoint: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN});"
                patch_line = f"const {env_var.lower()}: string = await _vaultClient.read(\"{vault_path}\").then((r: any) => r.data.data.value);"
                imp, imp_p = "import vault from \"node-vault\";", "top of file, before any other statements"
                sdk_name = "node-vault"
            else:
                init, patch_line = "", f"const {env_var.lower()}: string = process.env.{env_var}!; // SecretOps: set this env var"
                imp, imp_p, sdk_name = "", "", ""
            return {**base, "init_code": init, "init_code_placement": "after imports at module level",
                    "patched_line": patch_line, "imports_needed": imp, "import_placement": imp_p,
                    "language": "typescript", "sdk_dep_name": sdk_name, "sdk_dep_version": "0.7.0",
                    "explanation": f"Replaced hardcoded {finding['secret_type']} with {'Vault SDK' if vault_connected else 'env var'} lookup."}

        if is_go:
            if vault_connected:
                init = (
                    'var _vaultClient = func() *vaultapi.Client { '
                    'c, _ := vaultapi.NewClient(vaultapi.DefaultConfig()); '
                    'c.SetAddress(os.Getenv("VAULT_ADDR")); '
                    'c.SetToken(os.Getenv("VAULT_TOKEN")); return c }()'
                )
                patch_line = f'{env_var}_raw, _ := _vaultClient.Logical().Read("{vault_path}"); {env_var} := {env_var}_raw.Data["value"].(string)'
                imp = '"os"\n"github.com/hashicorp/vault/api" vaultapi'
                sdk_name = "github.com/hashicorp/vault/api"
            else:
                init, patch_line = "", f'{env_var} := os.Getenv("{env_var}") // SecretOps: set this env var'
                imp, sdk_name = '"os"', ""
            return {**base, "init_code": init, "init_code_placement": "package-level var after import block",
                    "patched_line": patch_line, "imports_needed": imp,
                    "import_placement": "inside the existing import(...) block",
                    "language": "go", "sdk_dep_name": sdk_name, "sdk_dep_version": "v1.13.0",
                    "explanation": f"Replaced hardcoded {finding['secret_type']} with {'Vault SDK' if vault_connected else 'os.Getenv'} call."}

        if is_ruby:
            if vault_connected:
                init  = "Vault.configure { |config| config.address = ENV[\"VAULT_ADDR\"]; config.token = ENV[\"VAULT_TOKEN\"] }"
                patch_line = f"{env_var.lower()} = Vault.logical.read(\"{vault_path}\").data[:value]"
                imp, imp_p = "require \"vault\"", "top of file, after any frozen_string_literal comment"
                sdk_name = "vault"
            else:
                init, patch_line = "", f'{env_var.lower()} = ENV["{env_var}"] # SecretOps: set this env var'
                imp, imp_p, sdk_name = "", "", ""
            return {**base, "init_code": init, "init_code_placement": "after require block at file level",
                    "patched_line": patch_line, "imports_needed": imp, "import_placement": imp_p,
                    "language": "ruby", "sdk_dep_name": sdk_name, "sdk_dep_version": "0.18",
                    "explanation": f"Replaced hardcoded {finding['secret_type']} with {'Vault SDK' if vault_connected else 'ENV lookup'}."}

        if is_java:
            patched = (
                f'String {env_var.lower()} = vaultTemplate.read("{vault_path}", Map.class).getData().get("value").toString();'
                if vault_connected else
                f'String {env_var.lower()} = System.getenv("{env_var}"); // SecretOps: set this env var'
            )
            return {**base, "patched_line": patched, "imports_needed": "", "import_placement": "",
                    "init_code": "// Inject VaultTemplate via Spring — configure vault.uri and vault.token in application.properties",
                    "init_code_placement": "",
                    "language": "java", "sdk_dep_name": "vault-java-driver" if vault_connected else "", "sdk_dep_version": "5.1.0",
                    "explanation": f"Replaced hardcoded {finding['secret_type']} with {'vaultTemplate' if vault_connected else 'System.getenv'} call."}

        if is_php:
            if vault_connected:
                init  = "$vault = new Vault\\Client(getenv(\"VAULT_ADDR\")); $vault->setToken(getenv(\"VAULT_TOKEN\"));"
                patch_line = f'${env_var.lower()} = $vault->read("{vault_path}")["data"]["data"]["value"];'
                sdk_name = "vault-php/vault-php"
            else:
                init, patch_line = "", f'${env_var.lower()} = getenv("{env_var}"); // SecretOps: set this env var'
                sdk_name = ""
            return {**base, "init_code": init, "init_code_placement": "after use/require block, before first class or function",
                    "patched_line": patch_line, "imports_needed": "", "import_placement": "",
                    "language": "php", "sdk_dep_name": sdk_name, "sdk_dep_version": "0.1",
                    "explanation": f"Replaced hardcoded {finding['secret_type']} with {'Vault SDK' if vault_connected else 'getenv'} call."}

        # Default: Python
        if vault_connected:
            init = (
                "_vault_client = hvac.Client(\n"
                "    url=os.environ[\"VAULT_ADDR\"],\n"
                "    token=os.environ[\"VAULT_TOKEN\"]\n"
                ")"
            )
            patch_line = (
                f"{env_var} = _vault_client.secrets.kv.v2.read_secret_version("
                f"path=\"{vault_path_short}\")[\"data\"][\"data\"][\"value\"]"
            )
            imp = "import hvac\nimport os"
            imp_p = "top of file, after module docstring, stdlib imports first then hvac"
            sdk_name = "hvac"
        else:
            init, patch_line = "", f'{env_var} = os.environ.get("{env_var}")  # SecretOps: Vault path when ready: {vault_path}'
            imp, imp_p, sdk_name = "import os", "top of file, after module docstring", ""

        return {**base, "init_code": init, "init_code_placement": "after imports, before any class or def, at module level",
                "patched_line": patch_line, "imports_needed": imp, "import_placement": imp_p,
                "language": "python", "sdk_dep_name": sdk_name, "sdk_dep_version": "2.3.0",
                "explanation": f"Replaced hardcoded {finding['secret_type']} with {'Vault SDK (hvac) via module-level client' if vault_connected else 'os.environ.get'} call."}

    def _call_llm_raw(self, provider: str, api_key: str, config: dict, prompt: str) -> Optional[str]:
        """Call LLM and return raw text."""
        if provider == "openai":
            model = config.get("model", "gpt-4o-mini")
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={"model": model, "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0.0, "max_tokens": 900},
                timeout=30
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

        elif provider == "anthropic":
            model = config.get("model", "claude-haiku-4-5-20251001")
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
                json={"model": model, "max_tokens": 900, "temperature": 0.0,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=30
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]

        elif provider == "groq":
            models_to_try = [
                config.get("model", ""),
                "llama-3.3-70b-versatile",
                "llama3-70b-8192",
                "llama3-8b-8192",
                "mixtral-8x7b-32768",
            ]
            models_to_try = [m for m in models_to_try if m]
            last_err = None
            for model in models_to_try:
                try:
                    resp = requests.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                        json={"model": model, "messages": [{"role": "user", "content": prompt}],
                              "temperature": 0.0, "max_tokens": 900},
                        timeout=30
                    )
                    if resp.status_code == 200:
                        logger.info(f"Groq success with model: {model}")
                        return resp.json()["choices"][0]["message"]["content"]
                    elif resp.status_code == 404:
                        logger.warning(f"Groq model {model} not found, trying next...")
                        last_err = f"Model {model} not found"
                        continue
                    else:
                        resp.raise_for_status()
                except requests.HTTPError as e:
                    last_err = str(e)
                    continue
            raise Exception(f"All Groq models failed: {last_err}")

        return None

    def _apply_patch_to_file(self, content: str, patch: dict, finding: dict) -> str:
        """
        Apply all changes to the file content in the correct order:
          1. Replace the secret line with patched_line
          2. Insert imports at the structurally correct location (never mid-function)
          3. Insert the Vault client init block at module level (after imports)
        """
        language = patch.get("language", "python")
        lines = content.split("\n")

        # Step 1: Replace the secret line
        line_idx = finding["line_number"] - 1
        if 0 <= line_idx < len(lines):
            lines[line_idx] = patch.get("patched_line", lines[line_idx])
        updated = "\n".join(lines)

        # Step 2: Insert imports (never mid-function)
        imports_needed = patch.get("imports_needed", "")
        if imports_needed:
            updated = _apply_import_to_file(updated, imports_needed, language)

        # Step 3: Insert Vault client init at module level (Vault branch only)
        init_code = patch.get("init_code", "")
        if init_code and patch.get("vault_connected"):
            updated = _apply_init_code_to_file(updated, init_code, language)

        return updated

    def _inject_vault_poison(self, db, finding: dict, vault_path: str):
        """Write poison placeholder to HashiCorp Vault."""
        config, secrets = self.get_integration(db, "vault")
        vault_addr = config.get("url", config.get("address", "http://vault:8200"))
        vault_token = config.get("token", secrets.get("token", ""))
        if not vault_token:
            vault_token = os.environ.get("VAULT_TOKEN", "secretops-root-token")
        if not vault_addr:
            vault_addr = os.environ.get("VAULT_ADDR", "http://vault:8200")
        logger.info(f"Vault config: addr={vault_addr}, token={'set' if vault_token else 'MISSING'}")

        kv_path = vault_path.replace("secret/", "secret/data/", 1)
        poison_value = f"SECRETOPS_POISONED_{finding['raw_value_hash'][:16].upper()}_ROTATE_NOW"

        payload = {
            "data": {
                "value": poison_value,
                "secretops_finding_id": str(finding["id"]),
                "secretops_secret_type": finding["secret_type"],
                "secretops_detected_at": datetime.utcnow().isoformat(),
                "status": "POISONED_PENDING_ROTATION"
            }
        }

        try:
            resp = requests.post(
                f"{vault_addr}/v1/{kv_path}",
                headers={"X-Vault-Token": vault_token, "Content-Type": "application/json"},
                json=payload,
                timeout=10
            )
            if resp.status_code in (200, 204):
                db.execute("UPDATE findings SET vault_poisoned=1 WHERE id=?", (finding["id"],))
                db.commit()
                logger.info(f"Vault poisoned at {vault_path}")
            else:
                raise Exception(f"Vault returned HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"Vault injection failed: {e} — writing JSONL fallback for retry")
            self._write_vault_fallback(finding, vault_path, poison_value, str(e))

    def _write_vault_fallback(self, finding: dict, vault_path: str, poison_value: str, error: str):
        """Write a JSONL fallback record when Vault injection fails."""
        fallback_path = os.environ.get("VAULT_FALLBACK_PATH", "/data/vault_injection_retry.jsonl")
        record = {
            "finding_id": finding["id"],
            "vault_path": vault_path,
            "poison_value": poison_value,
            "secret_type": finding.get("secret_type", ""),
            "raw_value_hash": finding.get("raw_value_hash", ""),
            "failed_at": datetime.utcnow().isoformat(),
            "error": error,
            "retry_count": 0,
            "status": "pending"
        }
        try:
            with open(fallback_path, "a") as f:
                f.write(json.dumps(record) + "\n")
            logger.info(f"JSONL fallback written for finding {finding['id']} at {fallback_path}")
        except Exception as fe:
            logger.error(f"Failed to write JSONL fallback: {fe}")

    def retry_failed_vault_injections(self, db):
        """Retry all pending Vault injection fallback records."""
        fallback_path = os.environ.get("VAULT_FALLBACK_PATH", "/data/vault_injection_retry.jsonl")
        if not os.path.exists(fallback_path):
            return 0, 0

        config, secrets = self.get_integration(db, "vault")
        vault_addr = (config.get("url", config.get("address", "")).strip()
                      or os.environ.get("VAULT_ADDR", "http://vault:8200"))
        vault_token = (config.get("token", secrets.get("token", ""))
                       or os.environ.get("VAULT_TOKEN", "secretops-root-token"))

        succeeded = 0
        failed = 0
        remaining = []

        try:
            with open(fallback_path, "r") as f:
                records = [json.loads(line) for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Failed to read fallback file: {e}")
            return 0, 0

        for record in records:
            if record.get("status") == "succeeded":
                continue

            vault_path = record["vault_path"]
            poison_value = record["poison_value"]
            finding_id = record["finding_id"]
            retry_count = record.get("retry_count", 0) + 1
            kv_path = (vault_path.replace("secret/", "secret/data/", 1)
                       if not vault_path.startswith("secret/data/") else vault_path)

            try:
                resp = requests.post(
                    f"{vault_addr}/v1/{kv_path}",
                    headers={"X-Vault-Token": vault_token, "Content-Type": "application/json"},
                    json={"data": {"value": poison_value, "status": "POISONED_PENDING_ROTATION"}},
                    timeout=10
                )
                if resp.status_code in (200, 204):
                    db.execute("UPDATE findings SET vault_poisoned=1 WHERE id=?", (finding_id,))
                    db.commit()
                    record["status"] = "succeeded"
                    record["retry_count"] = retry_count
                    record["succeeded_at"] = datetime.utcnow().isoformat()
                    logger.info(f"Vault retry succeeded for finding {finding_id} (attempt {retry_count})")
                    succeeded += 1
                else:
                    raise Exception(f"HTTP {resp.status_code}")
            except Exception as e:
                record["retry_count"] = retry_count
                record["last_error"] = str(e)
                record["last_retry_at"] = datetime.utcnow().isoformat()
                logger.warning(f"Vault retry failed for finding {finding_id} (attempt {retry_count}): {e}")
                failed += 1

            remaining.append(record)

        try:
            with open(fallback_path, "w") as f:
                for record in remaining:
                    f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error(f"Failed to rewrite fallback file: {e}")

        return succeeded, failed

    def _create_branch_and_mr(self, db, finding: dict, patch: dict, vault_path: str) -> tuple:
        """Create feature branch and MR using GitLab API."""
        config, secrets = self.get_integration(db, "gitlab")
        gitlab_url = config.get("url", "").rstrip("/")
        token = config.get("token", secrets.get("token", ""))
        logger.info(f"GitLab config: url={gitlab_url}, token={'set' if token else 'MISSING'}")
        if not gitlab_url or not token:
            logger.warning(f"GitLab not configured (url={gitlab_url!r}, token={'set' if token else 'missing'})")
            return None, None, None, None

        ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        secret_slug = finding['secret_type'].replace('_', '-')[:20]
        branch_name = f"secretops/fix-{finding['id']}-{ts}-{secret_slug}"
        repo_path = finding["repo_full_path"]
        target_branch = finding["default_branch"]
        repo_local = os.path.join(CLONE_DIR, finding["repo_full_path"].replace("/", "_"))

        try:
            resp = requests.get(
                f"{gitlab_url}/api/v4/projects/{requests.utils.quote(repo_path, safe='')}",
                headers={"PRIVATE-TOKEN": token},
                timeout=10
            )
            resp.raise_for_status()
            project_id = resp.json()["id"]
        except Exception as e:
            logger.error(f"Failed to get GitLab project: {e}")
            return None, None, None, None

        try:
            requests.post(
                f"{gitlab_url}/api/v4/projects/{project_id}/repository/branches",
                headers={"PRIVATE-TOKEN": token},
                json={"branch": branch_name, "ref": target_branch},
                timeout=10
            )
        except Exception as e:
            logger.warning(f"Branch creation: {e}")

        # Build commit actions — always includes the patched source file,
        # and optionally the dependency manifest if the SDK was added.
        commit_actions = []

        try:
            env_var = patch.get("env_var_name", "SECRET")
            rotation_steps = patch.get("rotation_steps", [])
            explanation = patch.get("explanation", "")

            resp = requests.get(
                f"{gitlab_url}/api/v4/projects/{project_id}/repository/files/{requests.utils.quote(finding['file_path'], safe='')}",
                headers={"PRIVATE-TOKEN": token},
                params={"ref": target_branch},
                timeout=10
            )

            if resp.status_code == 200:
                import base64
                content = base64.b64decode(resp.json()["content"]).decode("utf-8", errors="ignore")
                new_content = self._apply_patch_to_file(content, patch, finding)
                commit_actions.append({
                    "action": "update",
                    "file_path": finding["file_path"],
                    "content": new_content
                })
        except Exception as e:
            logger.warning(f"Source file patch failed: {e}")

        # Patch the dependency file if SDK is needed
        if patch.get("sdk_dep_needed") and patch.get("sdk_dep_name"):
            try:
                dep_rel_path = _ensure_sdk_dependency(
                    repo_dir=repo_local,
                    language=patch.get("language", "python"),
                    sdk_dep_name=patch["sdk_dep_name"],
                    sdk_dep_version=patch.get("sdk_dep_version", ""),
                )
                if dep_rel_path:
                    dep_full_path = os.path.join(repo_local, dep_rel_path)
                    with open(dep_full_path, "r") as f:
                        dep_content = f.read()
                    commit_actions.append({
                        "action": "update",
                        "file_path": dep_rel_path,
                        "content": dep_content
                    })
                    logger.info(f"[dep] Added {patch['sdk_dep_name']} to {dep_rel_path} in commit")
            except Exception as e:
                logger.warning(f"[dep] Dependency file patch failed: {e}")

        if commit_actions:
            try:
                commit_message = f"""fix(security): Remove hardcoded {finding['secret_type']} - SecretOps #{finding['id']}

SecretOps Detection Summary:
- Secret Type: {finding['secret_type']}
- File: {finding['file_path']}:{finding['line_number']}
- First Detected: {finding.get('first_commit_date', 'unknown')}
- Days Exposed: {finding.get('days_exposed', 0)}
- Vault Path: {vault_path}
- AI Confidence: {finding.get('ai_confidence', 0):.0%}

Change: {explanation}

Pre-merge conditions:
1. Rotate the exposed credential BEFORE merging
2. Store new credential in Vault at: {vault_path}
3. Set environment variable: {env_var}
4. Verify old credential is revoked

Rotation Checklist:
{chr(10).join(f'- {step}' for step in rotation_steps)}

Refs: SecretOps Finding #{finding['id']}
"""
                requests.post(
                    f"{gitlab_url}/api/v4/projects/{project_id}/repository/commits",
                    headers={"PRIVATE-TOKEN": token},
                    json={
                        "branch": branch_name,
                        "commit_message": commit_message,
                        "actions": commit_actions
                    },
                    timeout=30
                )
            except Exception as e:
                logger.warning(f"Commit creation failed: {e}")

        issue_url = None
        try:
            issue_resp = requests.post(
                f"{gitlab_url}/api/v4/projects/{project_id}/issues",
                headers={"PRIVATE-TOKEN": token},
                json={
                    "title": f"[SecretOps] Exposed {finding['secret_type']} - {finding['file_path']} (Finding #{finding['id']})",
                    "description": self._build_issue_description(finding, vault_path, patch),
                    "labels": ["security", "secretops", "credentials"],
                    "confidential": True
                },
                timeout=10
            )
            if issue_resp.status_code == 201:
                issue_url = issue_resp.json().get("web_url")
        except Exception as e:
            logger.warning(f"Issue creation failed: {e}")

        mr_url = None
        mr_id = None
        try:
            mr_resp = requests.post(
                f"{gitlab_url}/api/v4/projects/{project_id}/merge_requests",
                headers={"PRIVATE-TOKEN": token},
                json={
                    "source_branch": branch_name,
                    "remove_source_branch": True,
                    "target_branch": target_branch,
                    "title": f"[SecretOps] fix: Remove exposed {finding['secret_type']} (Finding #{finding['id']})",
                    "description": self._build_mr_description(finding, vault_path, patch, issue_url),
                    "labels": ["security", "secretops"],
                },
                timeout=10
            )
            if mr_resp.status_code == 201:
                mr_url = mr_resp.json().get("web_url")
                mr_id = str(mr_resp.json().get("iid"))
        except Exception as e:
            logger.error(f"MR creation failed: {e}")

        return branch_name, mr_url or "", mr_id or "", issue_url or ""

    def _build_mr_description(self, finding: dict, vault_path: str, patch: dict, issue_url: str) -> str:
        rotation_steps = patch.get("rotation_steps", [])
        env_var = patch.get("env_var_name", "SECRET")
        sdk_note = ""
        if patch.get("sdk_dep_needed") and patch.get("sdk_dep_name"):
            sdk_note = f"\n- **SDK Added to deps:** `{patch['sdk_dep_name']}` — install before deploying\n"

        return f"""## 🔐 SecretOps Security Remediation

**Finding ID:** #{finding['id']}  
**Secret Type:** `{finding['secret_type']}`  
**File:** `{finding['file_path']}` (line {finding['line_number']})  
**Severity:** {finding['severity'].upper()}  
**Days Exposed:** {finding.get('days_exposed', 0)} days  
**First Seen Commit:** `{finding.get('first_commit_hash', 'unknown')[:8]}`  
**Commit Author:** {finding.get('first_commit_author', 'unknown')}  

---

## Detection Summary
- **AI Confidence:** {finding.get('ai_confidence', 0):.0%}
- **Detection Method:** {finding.get('detection_stage', 'unknown')}
- **AI Model:** {finding.get('ai_model', 'unknown')}
{sdk_note}
**AI Analysis:** {finding.get('ai_reasoning', 'No reasoning available')}

---

## Vault Containment
A poison placeholder has been written to Vault:
- **Path:** `{vault_path}`
- **Status:**  Pending rotation - current value is a placeholder

---

## Pre-Merge Conditions (DO NOT MERGE BEFORE COMPLETING)

- [ ] Old credential has been revoked at the provider
- [ ] New credential generated and stored in Vault at `{vault_path}`
- [ ] Environment variable `{env_var}` updated in all deployment environments
- [ ] Vault path value updated from placeholder to real rotated credential
- [ ] Verified old credential no longer works

---

## Rotation Checklist

{chr(10).join(f'- [ ] {step}' for step in rotation_steps)}

---

## Related
{f'- Issue: {issue_url}' if issue_url else ''}
- SecretOps Finding: #{finding['id']}

---
*Generated automatically by SecretOps. Developer approval required before merge.*
"""

    def _build_issue_description(self, finding: dict, vault_path: str, patch: dict) -> str:
        rotation_steps = patch.get("rotation_steps", [])
        return f"""## Security Issue: Exposed {finding['secret_type']}

**SecretOps has detected a hardcoded credential in the repository.**

| Field | Value |
|-------|-------|
| Finding ID | #{finding['id']} |
| Secret Type | `{finding['secret_type']}` |
| File | `{finding['file_path']}` |
| Line | {finding['line_number']} |
| Severity | **{finding['severity'].upper()}** |
| Days Exposed | {finding.get('days_exposed', 0)} |
| First Seen | {finding.get('first_commit_date', 'Unknown')} |

## Immediate Actions Required

{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(rotation_steps))}

## Vault Path
Store the rotated credential at: `{vault_path}`

 **This issue is confidential. Do not share the exposed value.**

*Created by SecretOps automated detection*
"""

    def _send_notifications(self, db, finding: dict, patch: dict, vault_path: str, mr_url: str, issue_url: str):
        from notifications.slack_notifier import SlackNotifier
        from notifications.email_notifier import EmailNotifier

        notif_data = {"finding": finding, "patch": patch, "vault_path": vault_path,
                      "mr_url": mr_url, "issue_url": issue_url}
        try:
            SlackNotifier(db).send_finding_alert(notif_data)
        except Exception as e:
            logger.warning(f"Slack notification failed: {e}")
        try:
            EmailNotifier(db).send_finding_alert(notif_data)
        except Exception as e:
            logger.warning(f"Email notification failed: {e}")

    def _attempt_revocation(self, db, finding: dict):
        secret_type = finding["secret_type"]
        revoked = False
        try:
            if secret_type == "aws_access_key":
                revoked = self._revoke_aws_key(db, finding)
            elif secret_type == "gitlab_pat":
                revoked = self._revoke_gitlab_pat(db, finding)
            elif secret_type in ("github_pat", "github_oauth", "github_fine_grained"):
                revoked = self._revoke_github_pat(db, finding)
        except Exception as e:
            logger.error(f"Revocation failed for {secret_type}: {e}")
        if revoked:
            db.execute("UPDATE findings SET revoked=1 WHERE id=?", (finding["id"],))
            db.commit()

    def _revoke_aws_key(self, db, finding: dict) -> bool:
        logger.info("AWS key revocation: requires aws_access_key_id and secret. Logged for manual action.")
        return False

    def _revoke_gitlab_pat(self, db, finding: dict) -> bool:
        config, secrets = self.get_integration(db, "gitlab")
        gitlab_url = config.get("url", "").rstrip("/")
        token = config.get("token", secrets.get("token", ""))
        try:
            resp = requests.get(
                f"{gitlab_url}/api/v4/personal_access_tokens?state=active",
                headers={"PRIVATE-TOKEN": token}, timeout=10
            )
            if resp.status_code == 200:
                logger.info(f"GitLab PAT revocation: {len(resp.json())} active tokens found. Manual revocation required.")
        except Exception as e:
            logger.warning(f"GitLab PAT revocation lookup failed: {e}")
        return False

    def _revoke_github_pat(self, db, finding: dict) -> bool:
        logger.info("GitHub PAT revocation: requires the actual token value. Logged for manual action.")
        return False
