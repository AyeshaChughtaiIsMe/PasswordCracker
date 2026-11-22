"""
Shared pytest fixtures for the passwordCracker test suite.

Design principle: every test that needs a wordlist writes its own to
tmp_path. The suite must never depend on wordlists/common.txt existing
or having particular contents — that file is for manual demos, not tests.

The one global knob here is PBKDF2_ITERATIONS. The production value is
100_000, which makes a single strong-hash verify take ~30-50ms. A
dictionary attack that tries 20 candidates against a strong hash would
take ~1 second per test, and we have several such tests. That's too slow
for a tight feedback loop.

We lower it to 1_000 via an autouse fixture that patches the module
constant. This is NOT the same as monkeypatching verify_password to
always return True — the hashing math still runs, the salt is still
random, the format is still real. We just do fewer rounds. Every test
that cares about the *iteration count value* (e.g. asserting the encoded
string says "100000") uses the production constant explicitly.
"""

from __future__ import annotations

import pytest

from passwordCracker import hasher


# ---------------------------------------------------------------------------
# Fast PBKDF2 for the test suite
# ---------------------------------------------------------------------------

TEST_PBKDF2_ITERATIONS = 1_000


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch):
    """
    Lower PBKDF2 iterations for every test.

    Autouse=True means this applies without being requested. We restore
    the original value automatically (monkeypatch teardown).

    Note: this only works because hasher.hash_password resolves the
    default iterations *lazily* (at call time), not as a def-time default
    argument. That was a deliberate change made after the first test run
    revealed the def-time binding bug.
    """
    monkeypatch.setattr(hasher, "PBKDF2_ITERATIONS", TEST_PBKDF2_ITERATIONS)


# ---------------------------------------------------------------------------
# Wordlist helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def make_wordlist(tmp_path):
    """
    Factory fixture: returns a function that writes a wordlist to a
    unique temp file and returns its path.

    Usage:
        def test_x(make_wordlist):
            path = make_wordlist(["password", "123456"])
    """
    counter = {"n": 0}

    def _make(words: list[str], *, filename: str | None = None) -> str:
        counter["n"] += 1
        name = filename or f"wordlist_{counter['n']}.txt"
        path = tmp_path / name
        # Write exactly what the caller gave us, newline-separated, UTF-8.
        path.write_text("\n".join(words), encoding="utf-8")
        return str(path)

    return _make


@pytest.fixture
def known_passwords() -> list[str]:
    """
    A small set of passwords used across tests. Deliberately includes:
      - a lowercase word          ("password")
      - a digit-only password     ("123456")
      - a mixed-case + symbol one ("Summer2024!")
      - a short brute-forceable   ("ab")
    """
    return ["password", "123456", "Summer2024!", "ab"]