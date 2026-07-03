# fernet-versioned-secrets

[![CI](https://github.com/daichi-0818/fernet-versioned-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/daichi-0818/fernet-versioned-secrets/actions/workflows/ci.yml)

A tiny, dependency-light utility for encrypting secrets with [Fernet](https://cryptography.io/en/latest/fernet/)
(symmetric AES-based authenticated encryption) and a **version prefix**, so
you can roll out encryption gradually and rotate keys/algorithms later
without breaking existing data.

## Why

Real-world migrations rarely happen atomically: you flip on encryption for
new writes, but old rows in your database are still plaintext until a
backfill job gets around to them. This library makes that transition safe:

- `encrypt()` always writes the current version format: `enc:v1:<token>`.
- `decrypt()` recognizes the `enc:v<N>:` prefix and decrypts accordingly.
  Anything **without** that prefix is treated as legacy plaintext and
  returned unchanged — no crash, no special-casing needed at call sites.
- The version number is baked in so that a future key rotation or algorithm
  change (`v2`, `v3`, ...) can be added without breaking the ability to read
  old `v1` data.

## Install

```bash
pip install cryptography  # only runtime dependency
# then copy src/fernet_versioned into your project, or:
pip install -e .
```

## Usage

```python
import os
from fernet_versioned import encrypt, decrypt, generate_key, is_encrypted

# One-time: generate a key and store it in your secret manager / env var.
key = generate_key()
os.environ["SECRET_ENC_KEY"] = key

# Encrypt
token = encrypt("my-api-token-abc123")
print(token)
# -> enc:v1:gAAAAABk...

print(is_encrypted(token))
# -> True

# Decrypt
print(decrypt(token))
# -> my-api-token-abc123

# Backward compatibility: plaintext without the prefix passes through as-is.
print(decrypt("legacy-unencrypted-value"))
# -> legacy-unencrypted-value
```

You can also pass the key explicitly instead of relying on the environment
variable:

```python
token = encrypt("value", key=key)
plaintext = decrypt(token, key=key)
```

### Key source

By default the key is read from the `SECRET_ENC_KEY` environment variable
if no `key=` argument is given. Change `DEFAULT_KEY_ENV_VAR` in
`fernet_versioned/__init__.py` if you want a different env var name.

### Errors

- `decrypt()` raises `fernet_versioned.DecryptionError` (a `ValueError`
  subclass) when a value has a recognized `enc:v<N>:` prefix but cannot be
  decrypted — wrong key, corrupted token, or unsupported version.
- `encrypt()` / `decrypt()` raise `ValueError` if no key is available
  (neither `key=` nor the env var is set).
- Both raise `TypeError` if given a non-`str` input.

## Key rotation design

The version prefix exists specifically so you can change the encryption
scheme later without breaking old data:

1. Bump `CURRENT_VERSION` to `2` and implement the new logic in `encrypt()`.
2. In `decrypt()`, branch on the parsed version: `v1` uses the old
   key/algorithm, `v2` uses the new one. Both branches can coexist.
3. Once every stored secret has been re-encrypted under `v2` (e.g. via a
   backfill job that reads with `decrypt()` and re-writes with `encrypt()`),
   remove the `v1` branch.

`decrypt()` always dispatches on the version found in the value itself, so
mixed `v1`/`v2` data in the same table is safe to read at any point during
the migration.

## API

| Function | Description |
|---|---|
| `encrypt(plaintext: str, key: str \| bytes \| None = None) -> str` | Encrypts `plaintext`, returns `enc:v<CURRENT_VERSION>:<token>`. |
| `decrypt(value: str, key: str \| bytes \| None = None) -> str` | Decrypts if `enc:v<N>:` prefixed; otherwise returns `value` unchanged. |
| `generate_key() -> str` | Generates a new Fernet key as a string. |
| `is_encrypted(value: str) -> bool` | Returns `True` if `value` carries a recognized `enc:v<N>:` prefix. |

## Development

```bash
pip install -e ".[dev]"
python3.12 -m py_compile src/fernet_versioned/__init__.py
pytest tests/
```

## License

MIT © 2026 daichi-0818
