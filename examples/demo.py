"""Minimal usage example for fernet_versioned.

Run with:
    SECRET_ENC_KEY=$(python -c "from fernet_versioned import generate_key; print(generate_key())") \
        python examples/demo.py
"""

from fernet_versioned import decrypt, encrypt, generate_key, is_encrypted


def main() -> None:
    # 1. Generate a key (in real usage, generate once and store it as an
    #    environment variable / secret manager entry).
    key = generate_key()
    print(f"generated key: {key}")

    # 2. Encrypt a value.
    plaintext = "my-api-token-abc123"
    token = encrypt(plaintext, key=key)
    print(f"encrypted:     {token}")
    print(f"is_encrypted:  {is_encrypted(token)}")

    # 3. Decrypt it back.
    recovered = decrypt(token, key=key)
    print(f"decrypted:     {recovered}")
    assert recovered == plaintext

    # 4. Backward compatibility: plaintext without the prefix passes through
    #    unchanged. This lets you migrate a table of secrets gradually.
    legacy_value = "old-plaintext-value-from-before-encryption"
    print(f"legacy passthrough: {decrypt(legacy_value, key=key)}")
    assert decrypt(legacy_value, key=key) == legacy_value


if __name__ == "__main__":
    main()
