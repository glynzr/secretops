#!/bin/sh
# vault-init.sh — run once to initialize Vault and enable KV-v2

set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
MAX_WAIT=30
i=0

echo "[vault-init] Waiting for Vault to become ready..."
until curl -sf "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; do
  i=$((i+1))
  if [ $i -ge $MAX_WAIT ]; then
    echo "[vault-init] Timed out waiting for Vault"
    exit 1
  fi
  sleep 2
done

echo "[vault-init] Vault is up. Checking init status..."
INIT_STATUS=$(curl -sf "${VAULT_ADDR}/v1/sys/init" | grep -o '"initialized":[a-z]*' | cut -d: -f2)

if [ "$INIT_STATUS" = "false" ]; then
  echo "[vault-init] Initializing Vault with 1 key share..."
  INIT_RESP=$(curl -sf -X PUT "${VAULT_ADDR}/v1/sys/init" \
    -H "Content-Type: application/json" \
    -d '{"secret_shares":1,"secret_threshold":1}')
  
  ROOT_TOKEN=$(echo "$INIT_RESP" | grep -o '"root_token":"[^"]*"' | cut -d'"' -f4)
  UNSEAL_KEY=$(echo "$INIT_RESP" | grep -o '"keys":\["[^"]*"' | cut -d'"' -f3)
  
  echo "[vault-init] Unsealing..."
  curl -sf -X PUT "${VAULT_ADDR}/v1/sys/unseal" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"${UNSEAL_KEY}\"}" > /dev/null

  echo "[vault-init] Enabling KV-v2 secrets engine..."
  curl -sf -X POST "${VAULT_ADDR}/v1/sys/mounts/secret" \
    -H "X-Vault-Token: ${ROOT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"kv","options":{"version":"2"}}' > /dev/null || true

  echo "[vault-init] ============================================"
  echo "[vault-init] ROOT TOKEN : ${ROOT_TOKEN}"
  echo "[vault-init] UNSEAL KEY : ${UNSEAL_KEY}"
  echo "[vault-init] Save these — they will not be shown again."
  echo "[vault-init] ============================================"
else
  echo "[vault-init] Vault already initialized."
fi

echo "[vault-init] Done."
