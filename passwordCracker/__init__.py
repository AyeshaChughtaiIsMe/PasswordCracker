"""
password_cracker
================

An educational password-cracking toolkit that demonstrates why weak
passwords and fast, unsalted hashes fail.

This package is intentionally split into two halves:

    hasher.py        -> the "defense" layer: how passwords *should* and
                        *should not* be stored.
    attacks/         -> the "offense" layer: dictionary, brute-force, and
                        rainbow-table attacks against those hashes.

Nothing in this package touches the network, the filesystem outside the
project, or any real credential store. It operates only on hashes the
user generates locally.

EDUCATIONAL USE ONLY. See SECURITY.md.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]