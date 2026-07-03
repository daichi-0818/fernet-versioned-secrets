
import pytest
from cryptography.fernet import Fernet

from fernet_versioned import (
    CURRENT_VERSION,
    DecryptionError,
    decrypt,
    encrypt,
    generate_key,
    is_encrypted,
)


@pytest.fixture()
def key() -> str:
    return generate_key()


def test_generate_key_is_valid_fernet_key():
    key = generate_key()
    # Should not raise
    Fernet(key.encode("utf-8"))


def test_encrypt_returns_versioned_prefix(key):
    token = encrypt("hello world", key=key)
    assert token.startswith(f"enc:v{CURRENT_VERSION}:")


def test_roundtrip_encrypt_decrypt(key):
    plaintext = "super secret value 123 !@#"
    token = encrypt(plaintext, key=key)
    assert decrypt(token, key=key) == plaintext


def test_roundtrip_with_unicode(key):
    plaintext = "パスワードは秘密です"
    token = encrypt(plaintext, key=key)
    assert decrypt(token, key=key) == plaintext


def test_plaintext_passthrough_on_decrypt(key):
    # Values without the enc:v<N>: prefix are returned unchanged.
    plain = "this-was-never-encrypted"
    assert decrypt(plain, key=key) == plain


def test_empty_string_passthrough(key):
    assert decrypt("", key=key) == ""


def test_is_encrypted_true_for_versioned_token(key):
    token = encrypt("value", key=key)
    assert is_encrypted(token) is True


def test_is_encrypted_false_for_plaintext():
    assert is_encrypted("plain-value") is False
    assert is_encrypted("enc:not-a-version:xyz") is False


def test_decrypt_with_wrong_key_raises(key):
    other_key = generate_key()
    token = encrypt("secret", key=key)
    with pytest.raises(DecryptionError):
        decrypt(token, key=other_key)


def test_decrypt_with_corrupted_token_raises(key):
    token = encrypt("secret", key=key)
    corrupted = token[:-4] + "abcd"
    with pytest.raises(DecryptionError):
        decrypt(corrupted, key=key)


def test_decrypt_unsupported_version_raises(key):
    fake = "enc:v99:someopaquetoken"
    with pytest.raises(DecryptionError):
        decrypt(fake, key=key)


def test_key_from_env_var(key, monkeypatch):
    monkeypatch.setenv("SECRET_ENC_KEY", key)
    token = encrypt("value from env")
    assert decrypt(token) == "value from env"


def test_missing_key_raises_when_no_env_and_no_arg(monkeypatch):
    monkeypatch.delenv("SECRET_ENC_KEY", raising=False)
    with pytest.raises(ValueError):
        encrypt("value")


def test_encrypt_rejects_non_string(key):
    with pytest.raises(TypeError):
        encrypt(12345, key=key)  # type: ignore[arg-type]


def test_decrypt_rejects_non_string(key):
    with pytest.raises(TypeError):
        decrypt(12345, key=key)  # type: ignore[arg-type]
