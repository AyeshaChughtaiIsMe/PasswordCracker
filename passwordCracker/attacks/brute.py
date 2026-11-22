"""
Brute-force attack.

The idea: try every possible string over a given alphabet, up to a
maximum length. Guaranteed to succeed eventually; the only question is
*how long* it takes. This module exists to make that "how long" concrete.

Search-space size for alphabet size A and max length L:

    1 + A + A^2 + ... + A^L   =   (A^(L+1) - 1) / (A - 1)

With the default charset (36 chars: a-z0-9) this grows brutally fast:

    L=4 ->      1,679,616 candidates
    L=5 ->     62,193,780
    L=6 ->  2,176,782,336

That exponential wall is the entire point of the demo.
"""

from __future__ import annotations

import itertools
import string
import time
from typing import Optional

from ..hasher import verify_password


DEFAULT_CHARSET = string.ascii_lowercase + string.digits  # 36 chars


def _search_space_size(charset_size: int, max_length: int) -> int:
    """Total number of candidates for lengths 1..max_length, inclusive."""
    if charset_size == 0 or max_length < 1:
        return 0
    return (charset_size ** (max_length + 1) - 1) // (charset_size - 1) - 1


def brute_force_attack(
    target_hash: str,
    max_length: int = 4,
    charset: str = DEFAULT_CHARSET,
    time_limit_seconds: Optional[float] = None,
) -> Optional[str]:
    """
    Try every string of length 1..max_length over `charset`.

    Parameters
    ----------
    target_hash:
        Encoded hash string from hasher.hash_password.
    max_length:
        Maximum password length to attempt (inclusive). Must be >= 1.
    charset:
        Characters to draw from. Duplicates are removed; order preserved.
    time_limit_seconds:
        Optional wall-clock cutoff. When exceeded, the attack gives up
        and returns None. This prevents a demo from hanging forever on a
        hopeless target.

    Returns
    -------
    str | None
        The plaintext if cracked within the limits, otherwise None.
    """
    if max_length < 1:
        raise ValueError("max_length must be >= 1")

    # De-duplicate while preserving order (dict.fromkeys is ordered).
    alphabet = "".join(dict.fromkeys(charset))
    if not alphabet:
        raise ValueError("charset must not be empty")

    # Print a one-line estimate so the user sees the wall they're hitting.
    space = _search_space_size(len(alphabet), max_length)
    print(
        f"[brute] charset={len(alphabet)} chars, max_length={max_length}, "
        f"search space={space:,} candidates"
    )

    start = time.perf_counter()

    for length in range(1, max_length + 1):
        for combo in itertools.product(alphabet, repeat=length):
            if time_limit_seconds is not None:
                if time.perf_counter() - start > time_limit_seconds:
                    print(
                        f"[brute] time limit of {time_limit_seconds}s "
                        f"reached; giving up."
                    )
                    return None

            candidate = "".join(combo)
            if verify_password(candidate, target_hash):
                elapsed = time.perf_counter() - start
                print(f"[brute] cracked in {elapsed:.3f}s")
                return candidate

    elapsed = time.perf_counter() - start
    print(f"[brute] exhausted search space in {elapsed:.3f}s; not found")
    return None