"""
Hashing utilities: the "defense" layer of the project.

Two modes are supported:

    weak   -> fast, unsalted hashes (MD5, SHA-256).
              This is how passwords were *wrongly* stored for decades.

    strong -> PBKDF2-HMAC with a per-password random salt and a high
              iteration count. This is a simplified version of how
              modern systems (Django, passlib, etc.) store passwords.

The output format is deliberately simple and self-describing:

    weak:   "<hex digest>"
    strong: "<algorithm>$<iterations>$<salt_hex>$<hash_hex>"

The strong format is essentially a tiny subset of the PHC string format.
It carries everything needed to verify a password later: algorithm,
iteration count, salt, and the digest itself.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Algorithm identifiers
# ---------------------------------------------------------------------------

ALGORITHM_MD5 = "md5"
ALGORITHM_SHA256 = "sha256"
ALGORITHM_PBKDF2 = "pbkdf2_sha256"

WEAK_ALGORITHMS = {ALGORITHM_MD5, ALGORITHM_SHA256}
STRONG_ALGORITHMS = {ALGORITHM_PBKDF2}

# PBKDF2 parameters. 100_000 iterations is a reasonable teaching value:
# fast enough that tests don't hang, slow enough that brute force is
# obviously impractical.
PBKDF2_ITERATIONS = 100_000
PBKDF2_SALT_BYTES = 16
PBKDF2_DKLEN = 32


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HashResult:
    """
    A single hash, plus the parameters needed to reproduce/verify it.

    `encoded` is the string you would store in a database. It is what the
    CLI prints and what the attacks consume.
    """
    algorithm: str
    encoded: str
    salt_hex: str | None
    iterations: int | None

    def __str__(self) -> str:
        return self.encoded


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def hash_password(
    password: str,
    algorithm: str = ALGORITHM_MD5,
    use_salt: bool = False,
    iterations: int | None = None,
) -> str:
    """
    Hash a password and return the encoded string.

    Parameters
    ----------
    password:
        Plaintext password. Encoded as UTF-8.
    algorithm:
        One of ALGORITHM_MD5, ALGORITHM_SHA256, ALGORITHM_PBKDF2.
    use_salt:
        Only meaningful for weak algorithms. If True, a random salt is
        prepended to the password before hashing (demonstrates that salts
        alone don't save a fast hash, but they do defeat rainbow tables).
        Strong algorithms always use a salt.
    iterations:
        PBKDF2 iteration count. Ignored for weak algorithms.
        If None (the default), falls back to the module-level
        PBKDF2_ITERATIONS *at call time*. This lazy lookup is deliberate:
        it lets tests and future config lower the count without having to
        re-bind a default argument (which Python binds at def-time).

    Returns
    -------
    str
        The encoded hash string. For weak + unsalted, this is the raw hex
        digest. For salted/strong, it is a self-describing string.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    algorithm = algorithm.lower()

    if algorithm in WEAK_ALGORITHMS:
        return _hash_weak(password, algorithm, use_salt)

    if algorithm in STRONG_ALGORITHMS:
        # Lazy default: read the module constant now, not at def-time.
        effective_iterations = (
            PBKDF2_ITERATIONS if iterations is None else iterations
        )
        return _hash_strong(password, effective_iterations)

    raise ValueError(
        f"unknown algorithm {algorithm!r}; "
        f"choose from {sorted(WEAK_ALGORITHMS | STRONG_ALGORITHMS)}"
    )


def verify_password(password: str, encoded: str) -> bool:
    """
    Constant-time verification of a password against an encoded hash.

    This is the function a *login system* would call. It is provided so
    the project can demonstrate the defender's side too, and so tests can
    assert correctness without re-implementing the format.

    Malformed input returns False rather than raising. This matters
    because the attack modules call verify_password in a tight loop
    thousands of times — one uncaught exception would abort the whole
    attack on a single corrupt hash string.
    """
    if not isinstance(encoded, str) or not encoded:
        return False

    # Strong format: algo$iterations$salt_hex$hash_hex
    if "$" in encoded:
        try:
            algo, iter_s, salt_hex, hash_hex = encoded.split("$", 3)
            iterations = int(iter_s)
            if algo != ALGORITHM_PBKDF2:
                return False
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
        except ValueError:
            # Covers: wrong part count, non-integer iterations, non-hex
            # salt, non-hex hash. All of these mean "not a valid encoded
            # hash", so False is the correct answer.
            return False

        candidate = _pbkdf2(password, salt, iterations, len(expected))
        return hmac.compare_digest(candidate, expected)

    # Weak salted format: salt_hex:hash_hex
    if ":" in encoded:
        try:
            salt_hex, hash_hex = encoded.split(":", 1)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
        except ValueError:
            return False

        candidate = hashlib.md5(salt + password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(candidate, hash_hex)

    # Weak unsalted format: raw hex digest. We must guess the algorithm
    # from the digest length. MD5 = 32 hex chars, SHA-256 = 64 hex chars.
    try:
        digest_bytes = bytes.fromhex(encoded)
    except ValueError:
        return False
    if len(digest_bytes) == 16:
        algo = ALGORITHM_MD5
    elif len(digest_bytes) == 32:
        algo = ALGORITHM_SHA256
    else:
        return False
    candidate = hashlib.new(algo, password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, encoded)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_weak(password: str, algorithm: str, use_salt: bool) -> str:
    """
    Fast, unsalted (or lightly salted) hash.

    Unsalted format: <hex digest>
    Salted format:   <salt_hex>:<hex digest>
    """
    pw_bytes = password.encode("utf-8")

    if not use_salt:
        return hashlib.new(algorithm, pw_bytes).hexdigest()

    salt = os.urandom(PBKDF2_SALT_BYTES)
    digest = hashlib.new(algorithm, salt + pw_bytes).hexdigest()
    return f"{salt.hex()}:{digest}"


def _hash_strong(password: str, iterations: int) -> str:
    """
    PBKDF2-HMAC-SHA256 with a fresh random salt.

    Encoded as: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    salt = os.urandom(PBKDF2_SALT_BYTES)
    dk = _pbkdf2(password, salt, iterations, PBKDF2_DKLEN)
    return f"{ALGORITHM_PBKDF2}${iterations}${salt.hex()}${dk.hex()}"


def _pbkdf2(password: str, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=dklen,
    )