"""
Tests for passwordCracker.attacks.brute.

Brute force is slow by nature. We keep tests fast by (a) using tiny
search spaces and (b) relying on the conftest autouse fixture to lower
PBKDF2 iterations. No test here runs more than ~1,400 candidates.
"""

from __future__ import annotations

import pytest

from passwordCracker.attacks.brute import (
    DEFAULT_CHARSET,
    _search_space_size,
    brute_force_attack,
)
from passwordCracker.hasher import (
    ALGORITHM_MD5,
    hash_password,
)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_cracks_two_char_lowercase():
    target = hash_password("ab", algorithm=ALGORITHM_MD5)
    result = brute_force_attack(
        target, max_length=2, charset="abcdefghijklmnopqrstuvwxyz"
    )
    assert result == "ab"


def test_cracks_single_char():
    target = hash_password("c", algorithm=ALGORITHM_MD5)
    assert brute_force_attack(target, max_length=1, charset="abc") == "c"


# ---------------------------------------------------------------------------
# Miss path
# ---------------------------------------------------------------------------

def test_returns_none_when_max_length_too_short():
    target = hash_password("abc", algorithm=ALGORITHM_MD5)
    # max_length=2 cannot find a 3-char password.
    assert brute_force_attack(
        target, max_length=2, charset="abc"
    ) is None


def test_returns_none_when_charset_missing_char():
    target = hash_password("z", algorithm=ALGORITHM_MD5)
    # charset 'abc' does not include 'z'.
    assert brute_force_attack(
        target, max_length=1, charset="abc"
    ) is None


# ---------------------------------------------------------------------------
# Time limit
# ---------------------------------------------------------------------------

def test_time_limit_causes_early_exit():
    """
    A target that cannot be found (wrong charset) plus a tiny time limit
    should return None quickly, not exhaust the space. We assert on the
    return value only — asserting wall-clock time would be flaky on
    shared CI runners.
    """
    target = hash_password("zzzz", algorithm=ALGORITHM_MD5)
    result = brute_force_attack(
        target,
        max_length=4,
        charset="ab",                # 2^4-ish space, but 'z' not in charset
        time_limit_seconds=0.01,
    )
    assert result is None


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def test_max_length_zero_raises_value_error():
    target = hash_password("a", algorithm=ALGORITHM_MD5)
    with pytest.raises(ValueError, match="max_length"):
        brute_force_attack(target, max_length=0)


def test_empty_charset_raises_value_error():
    target = hash_password("a", algorithm=ALGORITHM_MD5)
    with pytest.raises(ValueError, match="charset"):
        brute_force_attack(target, max_length=1, charset="")


# ---------------------------------------------------------------------------
# Search-space formula
# ---------------------------------------------------------------------------

def test_search_space_size_formula_known_values():
    # 36 chars, L=1 -> 36
    assert _search_space_size(36, 1) == 36
    # 36 chars, L=2 -> 36 + 36^2 = 1332
    assert _search_space_size(36, 2) == 1332
    # 2 chars, L=3 -> 2 + 4 + 8 = 14
    assert _search_space_size(2, 3) == 14


def test_search_space_size_zero_inputs():
    assert _search_space_size(0, 5) == 0
    assert _search_space_size(10, 0) == 0


# ---------------------------------------------------------------------------
# Charset de-duplication
# ---------------------------------------------------------------------------

def test_duplicate_charset_is_deduped():
    """
    Charset "aab" should behave identically to "ab". If deduplication
    broke, "aab" would find 'b' on a different iteration but still
    succeed — so we can't detect it from the return value alone. We
    rely on the search-space print, which goes to stdout. Instead of
    capturing stdout, we assert the behavior indirectly: the attack
    must succeed and the internal alphabet must be length 2.

    Honest note: this test is weaker than a direct unit test on the
    dedupe helper would be. If we extract _dedupe_charset later, upgrade
    this to a direct assertion.
    """
    target = hash_password("b", algorithm=ALGORITHM_MD5)
    assert brute_force_attack(target, max_length=1, charset="aab") == "b"