"""
Tests for passwordCracker.hasher.

Coverage targets:
  - Known-answer digests for weak MD5/SHA-256 (proves we call hashlib right)
  - Salt randomness (two calls with same password differ)
  - Encoded format shape for all three modes
  - verify_password: correct/wrong password, all three formats
  - verify_password: malformed input returns False, not crash
  - Error types: ValueError for bad algorithm, TypeError for non-str
"""

from __future__ import annotations

import pytest

from passwordCracker.hasher import (
    ALGORITHM_MD5,
    ALGORITHM_SHA256,
    ALGORITHM_PBKDF2,
    hash_password,
    verify_password,
)


# ---------------------------------------------------------------------------
# Known-answer tests
# ---------------------------------------------------------------------------

def test_weak_md5_known_answer():
    """md5('password') is a fixed, well-known value. If this fails, our
    call into hashlib is wrong, not our test."""
    result = hash_password("password", algorithm=ALGORITHM_MD5, use_salt=False)
    assert result == "5f4dcc3b5aa765d61d8327deb882cf99"


def test_weak_sha256_known_answer():
    """sha256('password') is likewise a fixed value."""
    result = hash_password("password", algorithm=ALGORITHM_SHA256, use_salt=False)
    assert result == (
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    )


def test_weak_md5_is_hex_32_chars():
    result = hash_password("anything", algorithm=ALGORITHM_MD5)
    assert len(result) == 32
    assert all(c in "0123456789abcdef" for c in result)


# ---------------------------------------------------------------------------
# Salt randomness
# ---------------------------------------------------------------------------

def test_weak_salted_differs_per_call():
    """
    Two calls with the same password must produce different encoded
    strings, because a fresh salt is generated each time. This is the
    entire point of salting.
    """
    a = hash_password("password", algorithm=ALGORITHM_MD5, use_salt=True)
    b = hash_password("password", algorithm=ALGORITHM_MD5, use_salt=True)
    assert a != b
    assert ":" in a and ":" in b


def test_weak_salted_format_is_salt_colon_hash():
    encoded = hash_password("password", algorithm=ALGORITHM_MD5, use_salt=True)
    salt_hex, digest_hex = encoded.split(":", 1)
    assert len(salt_hex) == 32          # 16 bytes -> 32 hex chars
    assert len(digest_hex) == 32        # MD5 -> 32 hex chars
    assert all(c in "0123456789abcdef" for c in salt_hex + digest_hex)


# ---------------------------------------------------------------------------
# Strong format
# ---------------------------------------------------------------------------

def test_strong_encoded_format():
    """
    The strong format is: pbkdf2_sha256$<iterations>$<salt>$<hash>.

    We assert against TEST_PBKDF2_ITERATIONS (1000), NOT the production
    value, because the autouse fixture lowered it. This only works
    because hash_password reads PBKDF2_ITERATIONS lazily at call time.
    """
    from conftest import TEST_PBKDF2_ITERATIONS

    encoded = hash_password("password", algorithm=ALGORITHM_PBKDF2)
    parts = encoded.split("$")
    assert len(parts) == 4
    assert parts[0] == "pbkdf2_sha256"
    assert parts[1] == str(TEST_PBKDF2_ITERATIONS)
    assert len(parts[2]) == 32          # 16-byte salt -> 32 hex
    assert len(parts[3]) == 64          # 32-byte derived key -> 64 hex


def test_strong_differs_per_call():
    """Same password, fresh salt each time -> different encoded strings."""
    a = hash_password("password", algorithm=ALGORITHM_PBKDF2)
    b = hash_password("password", algorithm=ALGORITHM_PBKDF2)
    assert a != b


# ---------------------------------------------------------------------------
# verify_password: correctness
# ---------------------------------------------------------------------------

def test_verify_weak_unsalted_correct():
    encoded = hash_password("password", algorithm=ALGORITHM_MD5)
    assert verify_password("password", encoded) is True


def test_verify_weak_unsalted_wrong():
    encoded = hash_password("password", algorithm=ALGORITHM_MD5)
    assert verify_password("Password", encoded) is False


def test_verify_weak_salted_correct():
    encoded = hash_password("password", algorithm=ALGORITHM_MD5, use_salt=True)
    assert verify_password("password", encoded) is True


def test_verify_weak_salted_wrong():
    encoded = hash_password("password", algorithm=ALGORITHM_MD5, use_salt=True)
    assert verify_password("wrong", encoded) is False


def test_verify_strong_correct():
    encoded = hash_password("Summer2024!", algorithm=ALGORITHM_PBKDF2)
    assert verify_password("Summer2024!", encoded) is True


def test_verify_strong_wrong():
    encoded = hash_password("Summer2024!", algorithm=ALGORITHM_PBKDF2)
    assert verify_password("Summer2024", encoded) is False


def test_verify_sha256_unsalted_detected_by_length():
    """
    verify_password must infer SHA-256 from the 64-char digest length.
    This is the one place we rely on digest length to disambiguate the
    algorithm — worth an explicit test.
    """
    encoded = hash_password("password", algorithm=ALGORITHM_SHA256)
    assert len(encoded) == 64
    assert verify_password("password", encoded) is True


# ---------------------------------------------------------------------------
# verify_password: malformed input must return False, not raise
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_input",
    [
        "",
        "not-hex",
        "abc",                          # odd length, not valid hex
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",  # wrong chars for hex
        "pbkdf2_sha256$notint$aa$bb",   # non-integer iterations
        "pbkdf2_sha256$1000$zz$bb",     # bad salt hex
        "unknown_algo$1000$aa$bb",      # unknown algorithm tag
        "$1000$aa$bb",                  # empty algorithm
    ],
)
def test_verify_malformed_returns_false(bad_input):
    assert verify_password("password", bad_input) is False


def test_verify_none_encoded_returns_false():
    assert verify_password("password", None) is False


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------

def test_unknown_algorithm_raises_value_error():
    with pytest.raises(ValueError, match="unknown algorithm"):
        hash_password("password", algorithm="rot13")


def test_non_string_password_raises_type_error():
    with pytest.raises(TypeError):
        hash_password(12345)  # type: ignore[arg-type]


def test_strong_zero_iterations_raises_value_error():
    with pytest.raises(ValueError, match="iterations"):
        hash_password("password", algorithm=ALGORITHM_PBKDF2, iterations=0)