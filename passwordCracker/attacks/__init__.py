"""
Attack strategies against password hashes.

Each module exposes one public function with a consistent contract:

    attack(target_hash: str, ...) -> str | None

Returning the recovered plaintext on success, or None on failure.

    dictionary.py -> dictionary_attack(target_hash, wordlist_path, mode)
    brute.py      -> brute_force_attack(target_hash, max_length, charset)
    rainbow.py    -> rainbow_attack(target_hash, wordlist_path)

All attacks in this package are **offline** — they operate only on hashes
supplied by the user. Nothing here touches a network or a live system.

EDUCATIONAL USE ONLY. See SECURITY.md.
"""

__all__ = ["dictionary_attack", "brute_force_attack", "rainbow_attack"]