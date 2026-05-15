"""Utility functions for the AI engine."""
import base64
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_encryption_key() -> bytes:
    key = os.environ.get("SECRETOPS_ENCRYPTION_KEY", "secretops-default-key-change-me!")
    digest = hashlib.sha256(key.encode()).digest()
    return digest


def decrypt(encoded: str) -> str:
    """Decrypt AES-GCM encrypted value."""
    data = base64.b64decode(encoded)
    key = get_encryption_key()
    aesgcm = AESGCM(key)
    # nonce is first 12 bytes
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def hash_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[len(value)-4:]
