"""
Tests for passwordCracker.attacks.rainbow.

Each test uses its own tmp_path for both the wordlist and the cache file,
so tests never share state. Cache validity is tested via content change
(the wordlist file is rewritten), which is what the current implementation
keys on.
"""

from __future__ import annotations

import hashlib

import pytest

from passwordCracker.attacks.rainbow import (
    _build_table,
    _content_hash,
    _load_or_build_table,
    _mutations,
    _read_wordlist,
    rainbow_attack,
)
from passwordCracker.hasher import (
    ALGORITHM_MD5,
    ALGORITHM_PBKDF2,
    hash_password,
)


# ---------------------------------------------------------------------------
# Mutation generator (must mirror dictionary.py)
# ---------------------------------------------------------------------------

def test_mutations_include_expected_variants():
    variants = _mutations("Summer2024")
    assert "Summer2024" in variants
    assert "summer2024" in variants
    assert "SUMMER2024" in variants
    assert "Summer2024!" in variants
    assert "Summer20241" in variants
    assert "Summer2024123" in variants
    assert "Summer20242024" in variants
    assert "Summer20242025" in variants


def test_mutations_dedupe():
    # "Password" capitalized equals the word itself -> one entry.
    variants = _mutations("Password")
    assert len(variants) == len(set(variants))


# ---------------------------------------------------------------------------
# Table building (now includes mutations)
# ---------------------------------------------------------------------------

def test_build_table_includes_plain_word():
    table = _build_table(["password"])
    assert table[hashlib.md5(b"password").hexdigest()] == "password"


def test_build_table_includes_mutations():
    table = _build_table(["Summer2024"])
    assert table[hashlib.md5(b"Summer2024").hexdigest()] == "Summer2024"
    assert table[hashlib.md5(b"Summer2024!").hexdigest()] == "Summer2024!"
    assert table[hashlib.md5(b"Summer2024123").hexdigest()] == "Summer2024123"


# ---------------------------------------------------------------------------
# Cache round-trip and invalidation
# ---------------------------------------------------------------------------

def test_first_run_builds_table(make_wordlist, tmp_path):
    wl = make_wordlist(["password", "Summer2024"])
    cache = tmp_path / "rainbow.json"
    table, was_cached = _load_or_build_table(wl, str(cache))
    assert was_cached is False
    assert cache.exists()
    # Table must contain at least the plain words (mutations add more).
    assert hashlib.md5(b"password").hexdigest() in table
    assert hashlib.md5(b"Summer2024").hexdigest() in table


def test_second_run_loads_cached_table(make_wordlist, tmp_path):
    wl = make_wordlist(["password", "Summer2024"])
    cache = tmp_path / "rainbow.json"
    _load_or_build_table(wl, str(cache))
    table, was_cached = _load_or_build_table(wl, str(cache))
    assert was_cached is True
    assert hashlib.md5(b"password").hexdigest() in table


def test_cache_invalidates_when_wordlist_content_changes(make_wordlist, tmp_path):
    """
    Rewrite the wordlist (content changes, path unchanged). The cache must
    be invalidated by the content hash, regardless of mtime.
    """
    wl = make_wordlist(["password"])
    cache = tmp_path / "rainbow.json"
    _load_or_build_table(wl, str(cache))

    # Rewrite with different content — no sleep needed; content hashing
    # does not care about timestamps.
    with open(wl, "w", encoding="utf-8") as fh:
        fh.write("password\n123456\n")

    table, was_cached = _load_or_build_table(wl, str(cache))
    assert was_cached is False
    assert hashlib.md5(b"123456").hexdigest() in table


def test_corrupt_cache_json_falls_back_to_rebuild(make_wordlist, tmp_path):
    wl = make_wordlist(["password"])
    cache = tmp_path / "rainbow.json"
    cache.write_text("not valid json {{{", encoding="utf-8")
    table, was_cached = _load_or_build_table(wl, str(cache))
    assert was_cached is False
    assert hashlib.md5(b"password").hexdigest() in table


# ---------------------------------------------------------------------------
# Happy path via public attack function
# ---------------------------------------------------------------------------

def test_rainbow_attack_cracks_exact_word(make_wordlist, tmp_path):
    target = hash_password("Summer2024!", algorithm=ALGORITHM_MD5)
    wl = make_wordlist(["Summer2024!"])
    cache = tmp_path / "rainbow.json"
    assert rainbow_attack(target, wl, table_path=str(cache)) == "Summer2024!"


def test_rainbow_attack_cracks_via_mutation(make_wordlist, tmp_path):
    """
    The regression test for the RT-2 bug: wordlist contains the BASE word
    'Summer2024', target password is 'Summer2024!'. The table must include
    mutations, so the lookup hits.
    """
    target = hash_password("Summer2024!", algorithm=ALGORITHM_MD5)
    wl = make_wordlist(["Summer2024"])        # base word, no bang
    cache = tmp_path / "rainbow.json"
    assert rainbow_attack(target, wl, table_path=str(cache)) == "Summer2024!"


# ---------------------------------------------------------------------------
# Salted and strong hashes miss (intended lesson, not a bug)
# ---------------------------------------------------------------------------

def test_rainbow_attack_returns_none_for_salted_hash(make_wordlist, tmp_path):
    target = hash_password("Summer2024!", algorithm=ALGORITHM_MD5, use_salt=True)
    wl = make_wordlist(["Summer2024"])
    cache = tmp_path / "rainbow.json"
    assert rainbow_attack(target, wl, table_path=str(cache)) is None


def test_rainbow_attack_returns_none_for_strong_hash(make_wordlist, tmp_path):
    target = hash_password("Summer2024!", algorithm=ALGORITHM_PBKDF2)
    wl = make_wordlist(["Summer2024"])
    cache = tmp_path / "rainbow.json"
    assert rainbow_attack(target, wl, table_path=str(cache)) is None


# ---------------------------------------------------------------------------
# Wordlist parsing
# ---------------------------------------------------------------------------

def test_empty_wordlist_raises_value_error(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        _read_wordlist(str(path))


def test_missing_wordlist_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError, match="wordlist not found"):
        _read_wordlist(str(tmp_path / "nope.txt"))


# ---------------------------------------------------------------------------
# Content hash helper
# ---------------------------------------------------------------------------

def test_content_hash_changes_when_file_changes(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text("password\n", encoding="utf-8")
    h1 = _content_hash(str(path))
    path.write_text("password\n123456\n", encoding="utf-8")
    h2 = _content_hash(str(path))
    assert h1 != h2


def test_content_hash_is_stable_for_same_content(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text("password\n", encoding="utf-8")
    h1 = _content_hash(str(path))
    h2 = _content_hash(str(path))
    assert h1 == h2