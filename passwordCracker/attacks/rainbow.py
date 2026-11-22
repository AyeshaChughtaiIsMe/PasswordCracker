"""
Rainbow-table (pre-computation) attack.

The idea: instead of hashing candidate passwords on the fly, precompute a
mapping from hash -> plaintext once, then look up the target hash in O(1).

A true rainbow table uses chained reduction functions to compress the
table; for a teaching demo we skip that complexity and build a plain
"hash -> plaintext" dictionary. The lesson is identical:

    Precomputation makes lookups instant, but only for UNSALTED hashes.
    A unique per-password salt defeats the entire approach, because the
    attacker would need a separate table per salt.

The table is cached to disk as JSON so repeat runs are fast and the
"build cost vs lookup cost" tradeoff is visible.

Cache validity is determined by a SHA-256 hash of the wordlist *contents*,
not by filesystem mtime. An earlier version used mtime and produced a
stale-cache bug on Windows: rewriting the wordlist within the same
timestamp granularity did not invalidate the cache. Content hashing is
bulletproof and costs microseconds for wordlists of realistic size.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Optional

from ..hasher import ALGORITHM_MD5, verify_password


DEFAULT_TABLE_PATH = "wordlists/rainbow_md5.json"


def _read_wordlist(path: str) -> list[str]:
    """
    Same reader semantics as dictionary.py — kept local to avoid a shared
    utils module for two small functions. If a third caller appears,
    extract to attacks/_wordlist.py.

    Raises FileNotFoundError for a missing file, ValueError for an empty
    one. The empty-file guard mirrors the fix made in dictionary.py after
    a zero-byte wordlist produced a silent 'not cracked'.
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


def _mutations(word: str) -> list[str]:
    """
    Same mutation set as dictionary.py, applied at table-build time so the
    rainbow table can crack variants (e.g. 'Summer2024' -> 'Summer2024!').

    Kept local rather than imported from dictionary.py to make the two
    attack modules independently readable. If a third caller appears,
    extract to attacks/_mutations.py.

    Duplicates are removed while preserving order. The plain word is
    always first, so a direct wordlist hit wins over a mutation hit.
    """
    candidates = [
        word,
        word.lower(),
        word.upper(),
        word.capitalize(),
        word + "1",
        word + "123",
        word + "!",
        word + "2024",
        word + "2025",
    ]
    # dict.fromkeys preserves insertion order and drops duplicates.
    return list(dict.fromkeys(candidates))


def _content_hash(path: str) -> str:
    """
    SHA-256 of the file's raw bytes. Used to validate the cache.

    Chosen over mtime because mtime is unreliable across platforms and
    filesystem granularities — see the module docstring.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_table(words: list[str]) -> dict[str, str]:
    """
    Build {md5_hex: plaintext} for every word AND its mutations.

    Only MD5 is supported here on purpose: the point of the demo is that
    fast, unsalted hashes are trivially precomputable. Adding SHA-256
    would work identically; MD5 is just the classic example.
    """
    table: dict[str, str] = {}
    for word in words:
        for candidate in _mutations(word):
            digest = hashlib.md5(candidate.encode("utf-8")).hexdigest()
            # First writer wins: preserves wordlist order for duplicates.
            table.setdefault(digest, candidate)
    return table


def _load_or_build_table(
    wordlist_path: str,
    table_path: str,
) -> tuple[dict[str, str], bool]:
    """
    Return (table, was_cached).

    Cache validity: the cached file stores the wordlist path and a
    SHA-256 of its contents. If the path matches and the content hash
    matches, the cache is trusted; otherwise we rebuild.
    """
    current_hash = _content_hash(wordlist_path)

    if os.path.isfile(table_path):
        try:
            with open(table_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            if (
                payload.get("wordlist_path") == wordlist_path
                and payload.get("wordlist_content_sha256") == current_hash
            ):
                return payload["table"], True
        except (json.JSONDecodeError, KeyError, OSError):
            # Corrupt or unreadable cache -> fall through and rebuild.
            pass

    words = _read_wordlist(wordlist_path)
    table = _build_table(words)

    os.makedirs(os.path.dirname(table_path) or ".", exist_ok=True)
    with open(table_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "wordlist_path": wordlist_path,
                "wordlist_content_sha256": current_hash,
                "algorithm": ALGORITHM_MD5,
                "table": table,
            },
            fh,
        )
    return table, False


def rainbow_attack(
    target_hash: str,
    wordlist_path: str,
    table_path: str = DEFAULT_TABLE_PATH,
) -> Optional[str]:
    """
    Look up `target_hash` in a precomputed MD5 table built from
    `wordlist_path` (and its mutations). Builds the table on first run,
    caches it to `table_path` for subsequent runs.

    Returns the plaintext if found, else None.

    Notes
    -----
    This attack only works on *unsalted* MD5 hashes. If `target_hash`
    is salted or uses another algorithm, the lookup will simply miss —
    which is the intended lesson, not a bug.
    """
    t0 = time.perf_counter()
    table, was_cached = _load_or_build_table(wordlist_path, table_path)
    build_or_load = time.perf_counter() - t0

    status = "loaded cached table" if was_cached else "built table"
    print(
        f"[rainbow] {status}: {len(table):,} entries "
        f"in {build_or_load:.3f}s"
    )

    t1 = time.perf_counter()
    plaintext = table.get(target_hash)
    lookup = time.perf_counter() - t1

    print(f"[rainbow] lookup completed in {lookup * 1_000:.3f} ms")

    if plaintext is None:
        if "$" in target_hash or ":" in target_hash:
            print(
                "[rainbow] target appears salted or non-MD5; "
                "rainbow tables cannot help here."
            )
        return None

    if not verify_password(plaintext, target_hash):
        print(
            "[rainbow] table hit failed verification (hash collision or "
            "stale table); refusing to return a wrong answer."
        )
        return None

    return plaintext