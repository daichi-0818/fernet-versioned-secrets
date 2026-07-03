"""
fernet-versioned-secrets
=========================

A tiny utility for encrypting/decrypting secrets with a version-prefixed
Fernet token, so you can migrate encryption keys/algorithms over time
without breaking old data.

Encrypted values look like::

    enc:v1:gAAAAABk...

Values that do NOT start with the ``enc:v<N>:`` prefix are treated as
plaintext and returned as-is by :func:`decrypt`. This lets you roll out
encryption gradually: old plaintext rows keep working, new writes get
encrypted, and a background migration job can re-save rows in place.

Key rotation
------------
The version prefix (``v1``, ``v2``, ...) is reserved for future key/algorithm
rotation. Today only ``v1`` (plain Fernet) is implemented. To add a new
version:

1. Bump ``CURRENT_VERSION`` to ``2`` and implement the new encryption method
   under a ``v2`` branch in :func:`encrypt`.
2. In :func:`decrypt`, branch on the parsed version number and call the
   matching decryption routine (v1 -> old key/algorithm, v2 -> new one).
3. Keep the old branch alive until every stored secret has been
   re-encrypted, then remove it.

This keeps decryption backward-compatible while encryption always writes
the newest version.
"""

from __future__ import annotations

import os
import re

from cryptography.fernet import Fernet, InvalidToken

__all__ = [
    "encrypt",
    "decrypt",
    "generate_key",
    "is_encrypted",
    "CURRENT_VERSION",
    "PREFIX_RE",
    "DecryptionError",
]

# Bump this when a new encryption scheme is introduced.
CURRENT_VERSION = 1

# Environment variable name used when no key is passed explicitly.
DEFAULT_KEY_ENV_VAR = "SECRET_ENC_KEY"

# Matches "enc:v<digits>:<rest>"
PREFIX_RE = re.compile(r"^enc:v(\d+):(.*)$", re.DOTALL)


class DecryptionError(ValueError):
    """Raised when a value carries an ``enc:v<N>:`` prefix but cannot be
    decrypted (bad token, wrong key, or unsupported version)."""


def generate_key() -> str:
    """Generate a new Fernet key, suitable for storing in an env var.

    Returns a URL-safe base64-encoded string (decoded from bytes).
    """
    return Fernet.generate_key().decode("utf-8")


def _resolve_key(key: str | bytes | None) -> bytes:
    """Resolve the encryption key from an explicit argument or environment
    variable, returning bytes suitable for `Fernet(...)`.
    """
    if key is None:
        env_value = os.environ.get(DEFAULT_KEY_ENV_VAR)
        if not env_value:
            raise ValueError(
                f"No encryption key provided and {DEFAULT_KEY_ENV_VAR} is not set"
            )
        key = env_value

    if isinstance(key, str):
        key = key.encode("utf-8")

    return key


def is_encrypted(value: str) -> bool:
    """Return True if `value` carries a recognized `enc:v<N>:` prefix."""
    if not isinstance(value, str):
        return False
    return PREFIX_RE.match(value) is not None


def encrypt(plaintext: str, key: str | bytes | None = None) -> str:
    """Encrypt `plaintext` and return it as `enc:v<CURRENT_VERSION>:<token>`.

    Args:
        plaintext: The value to encrypt.
        key: A Fernet key (str or bytes). If omitted, read from the
            `SECRET_ENC_KEY` environment variable.

    Raises:
        ValueError: If no key is available.
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a str")

    fernet = Fernet(_resolve_key(key))
    token = fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    return f"enc:v{CURRENT_VERSION}:{token}"


def decrypt(value: str, key: str | bytes | None = None) -> str:
    """Decrypt `value` if it carries an `enc:v<N>:` prefix; otherwise return
    it unchanged (treated as legacy plaintext).

    Args:
        value: The stored value, either `enc:v<N>:<token>` or plain text.
        key: A Fernet key (str or bytes). If omitted, read from the
            `SECRET_ENC_KEY` environment variable. Only required when
            `value` is actually encrypted.

    Raises:
        DecryptionError: If the value has a recognized prefix but the token
            is invalid, the key is wrong, or the version is unsupported.
    """
    if not isinstance(value, str):
        raise TypeError("value must be a str")

    match = PREFIX_RE.match(value)
    if not match:
        # No recognized prefix -> treat as plaintext (backward compatibility
        # for data written before encryption was introduced).
        return value

    version = int(match.group(1))
    token = match.group(2)

    if version == 1:
        fernet = Fernet(_resolve_key(key))
        try:
            return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise DecryptionError("Invalid token or wrong key for v1") from exc
    # elif version == 2:
    #     # Placeholder for a future key/algorithm rotation. Implement a
    #     # separate decrypt routine here (e.g. a different key source or
    #     # cipher) and keep this branch until all v1 data is migrated.
    #     ...

    raise DecryptionError(f"Unsupported encryption version: v{version}")
