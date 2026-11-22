"""
Tests for passwordCracker.attacks.dictionary.

Every test that needs a wordlist uses the make_wordlist fixture, which
writes to tmp_path. The suite never depends on wordlists/common.txt.
"""

from __future__ import annotations

import pytest

from passwordCracker.attacks.dictionary import (
    dictionary_attack,
    _mutations,
    _read_wordlist,
)
from passwordCracker.hasher import (
    ALGORITHM_MD5,
    ALGORITHM_PBKDF2,
    hash_password,
)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_cracks_exact_word(make_wordlist):
    target = hash_password("Summer2024!", algorithm=ALGORITHM_MD5)
    path = make_wordlist(["password", "Summer2024!", "qwerty"])
    assert dictionary_attack(target, path) == "Summer2024!"


def test_cracks_via_append_1_mutation(make_wordlist):
    """'password' in the list must also yield 'password1' as a candidate."""
    target = hash_password("password1", algorithm=ALGORITHM_MD5)
    path = make_wordlist(["password"])
    assert dictionary_attack(target, path) == "password1"


def test_cracks_via_capitalize_mutation(make_wordlist):
    target = hash_password("Password", algorithm=ALGORITHM_MD5)
    path = make_wordlist(["password"])
    assert dictionary_attack(target, path) == "Password"


def test_cracks_via_year_suffix_mutation(make_wordlist):
    target = hash_password("Summer2024", algorithm=ALGORITHM_MD5)
    path = make_wordlist(["Summer"])
    assert dictionary_attack(target, path) == "Summer2024"


# ---------------------------------------------------------------------------
# Miss path
# ---------------------------------------------------------------------------

def test_returns_none_when_word_not_in_list(make_wordlist):
    target = hash_password("not-in-list-xyz", algorithm=ALGORITHM_MD5)
    path = make_wordlist(["password", "123456"])
    assert dictionary_attack(target, path) is None


# ---------------------------------------------------------------------------
# Wordlist parsing
# ---------------------------------------------------------------------------

def test_skips_blank_lines_and_comments(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text(
        "# a comment\n\npassword\n   \n123456\n# another\n",
        encoding="utf-8",
    )
    words = _read_wordlist(str(path))
    assert words == ["password", "123456"]


def test_missing_wordlist_raises_file_not_found(tmp_path):
    missing = tmp_path / "nope.txt"
    with pytest.raises(FileNotFoundError, match="wordlist not found"):
        _read_wordlist(str(missing))


def test_empty_wordlist_raises_value_error(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        _read_wordlist(str(path))


def test_comments_only_wordlist_raises_value_error(tmp_path):
    path = tmp_path / "comments.txt"
    path.write_text("# nothing\n# here\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        _read_wordlist(str(path))


# ---------------------------------------------------------------------------
# Format-agnostic verification: dictionary works against strong hashes too
# ---------------------------------------------------------------------------

def test_cracks_strong_hash_when_word_in_list(make_wordlist):
    """
    The attack doesn't care whether the hash is weak or strong — it just
    calls verify_password. Against a strong hash it is *slower* (PBKDF2
    per guess) but equally correct. The conftest autouse fixture keeps
    iterations at 1000, so this test is fast.
    """
    target = hash_password("Summer2024!", algorithm=ALGORITHM_PBKDF2)
    path = make_wordlist(["Summer2024!"])
    assert dictionary_attack(target, path, mode="strong") == "Summer2024!"


# ---------------------------------------------------------------------------
# Mutation generator (unit test)
# ---------------------------------------------------------------------------

def test_mutations_include_expected_variants():
    variants = list(_mutations("password"))
    assert "password" in variants
    assert "PASSWORD" in variants
    assert "Password" in variants
    assert "password1" in variants
    assert "password123" in variants
    assert "password!" in variants
    assert "password2024" in variants
    assert "password2025" in variants