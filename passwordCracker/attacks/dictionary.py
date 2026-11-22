"""
Dictionary attack.

The idea: most humans pick passwords from a small set of common words,
names, and patterns. If we try every word in a wordlist (plus a few cheap
mutations), we will crack a surprising fraction of real-world passwords.

This is the fastest, most realistic attack — and the one the "strong"
hash mode is designed to survive (a salt doesn't stop a dictionary attack,
but PBKDF2's cost per guess makes it impractical at scale).

Format handling is delegated to hasher.verify_password, so this module
stays focused on the *attack loop*, not on parsing hash strings.
"""

from __future__ import annotations

import os
from typing import Iterable, Optional

from ..hasher import verify_password


# Cheap, human-realistic mutations applied to each wordlist entry.
# Order matters only for speed: the plain word is tried first.
def _mutations(word: str) -> Iterable[str]:
    yield word                       # password
    yield word.lower()               # password
    yield word.upper()               # PASSWORD
    yield word.capitalize()          # Password
    yield word + "1"                 # password1
    yield word + "123"               # password123
    yield word + "!"                 # password!
    yield word + "2024"              # password2024
    yield word + "2025"              # password2025


def _read_wordlist(path: str) -> list[str]:
    """
    Read a wordlist, one candidate per line. Blank lines and '#' comments
    are skipped.

    Missing file is a hard error — a silent empty wordlist would look like
    'attack failed' when the real problem is a typo.

    An existing-but-empty file is ALSO a hard error. This guard was added
    after a real debugging session where a zero-byte common.txt produced a
    confusing '[result] not cracked'. Loud failure beats silent confusion.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"wordlist not found: {path}")

    words: list[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            words.append(line)

    if not words:
        raise ValueError(
            f"wordlist is empty or contains only blanks/comments: {path}. "
            f"Populate it with one candidate per line (UTF-8)."
        )

    return words


def dictionary_attack(
    target_hash: str,
    wordlist_path: str,
    mode: str = "weak",
) -> Optional[str]:
    """
    Try every word (and its mutations) from `wordlist_path` against
    `target_hash`.

    Parameters
    ----------
    target_hash:
        The encoded hash string produced by hasher.hash_password.
    wordlist_path:
        Path to a newline-delimited wordlist.
    mode:
        'weak' or 'strong'. Currently only used for reporting/intent;
        verification itself is format-driven (see hasher.verify_password).

    Returns
    -------
    str | None
        The plaintext if cracked, otherwise None.
    """
    words = _read_wordlist(wordlist_path)

    # mode is accepted so the CLI signature is uniform across attacks and
    # so we can later add strong-only strategies (e.g. rule-based mangling)
    # without changing the call site.
    _ = mode

    for word in words:
        for candidate in _mutations(word):
            if verify_password(candidate, target_hash):
                return candidate

    return None