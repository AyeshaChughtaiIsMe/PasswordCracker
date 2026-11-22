"""
CLI entry point for the password-cracker tool.

Usage examples
--------------

    # Generate a weak (fast, unsalted) hash
    python -m passwordCracker hash --password "Summer2024!" --mode weak

    # Generate a strong (PBKDF2 + salt) hash
    python -m passwordCracker hash --password "Summer2024!" --mode strong

    # Crack a weak hash with a dictionary attack
    python -m passwordCracker crack --hash HASHHERE --mode weak \
        --attack dict --wordlist wordlists/common.txt

    # Crack with brute force up to 4 characters
    python -m passwordCracker crack --hash HASHHERE --mode weak \
        --attack brute --max-length 4

    # Build (or use) a rainbow table
    python -m passwordCracker crack --hash HASHHERE --mode weak \
        --attack rainbow --wordlist wordlists/common.txt

Note for Windows / PowerShell users
-----------------------------------
Arguments containing '$' (i.e. strong hashes) MUST be single-quoted.
PowerShell interpolates '$...' inside double-quoted or unquoted arguments,
silently corrupting the hash. Example:

    --hash 'pbkdf2_sha256$100000$...$...'

The validator below will catch most mangled hashes and report a clear
error instead of a misleading "not cracked".
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Optional

from .hasher import (
    hash_password,
    ALGORITHM_MD5,
    ALGORITHM_SHA256,
    ALGORITHM_PBKDF2,
)
from .attacks.dictionary import dictionary_attack
from .attacks.brute import brute_force_attack
from .attacks.rainbow import rainbow_attack


# Well-formed shapes we accept as a target hash:
#   weak unsalted MD5      -> 32 hex chars
#   weak unsalted SHA-256  -> 64 hex chars
#   weak salted            -> <32 hex>:<32 hex>   (MD5 + salt)
#   strong                 -> pbkdf2_sha256$<int>$<32 hex>$<64 hex>
_RE_WEAK_UNSALTED_32 = re.compile(r"^[0-9a-fA-F]{32}$")
_RE_WEAK_UNSALTED_64 = re.compile(r"^[0-9a-fA-F]{64}$")
_RE_WEAK_SALTED = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")
_RE_STRONG = re.compile(
    r"^pbkdf2_sha256\$\d+\$[0-9a-fA-F]{32}\$[0-9a-fA-F]{64}$"
)


def _looks_like_valid_hash(target: str) -> bool:
    """
    Return True if `target` matches one of the shapes we produce.

    This is a *shape* check, not a correctness check. It catches the most
    common real-world failure: a shell mangled the hash before Python saw
    it (e.g. PowerShell turned '$100000' into ''). A shape-valid but
    wrong hash will still be tried and will honestly report 'not cracked';
    only obviously-malformed input is rejected up front.
    """
    return bool(
        _RE_WEAK_UNSALTED_32.match(target)
        or _RE_WEAK_UNSALTED_64.match(target)
        or _RE_WEAK_SALTED.match(target)
        or _RE_STRONG.match(target)
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-cracker",
        description=(
            "Educational password cracker. Demonstrates why weak passwords "
            "and fast, unsalted hashes fail. For authorized, local use only."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- hash subcommand -------------------------------------------------
    p_hash = sub.add_parser("hash", help="Generate a hash for a password.")
    p_hash.add_argument("--password", required=True, help="Plaintext password.")
    p_hash.add_argument(
        "--mode",
        choices=["weak", "strong"],
        default="weak",
        help="weak = fast unsalted hash; strong = PBKDF2 + salt.",
    )
    p_hash.add_argument(
        "--algorithm",
        choices=[ALGORITHM_MD5, ALGORITHM_SHA256, ALGORITHM_PBKDF2],
        default=None,
        help="Override the algorithm (defaults are chosen by --mode).",
    )

    # ---- crack subcommand ------------------------------------------------
    p_crack = sub.add_parser("crack", help="Attempt to crack a hash.")
    p_crack.add_argument("--hash", required=True, dest="target_hash")
    p_crack.add_argument(
        "--mode",
        choices=["weak", "strong"],
        default="weak",
        help="Must match how the target hash was generated.",
    )
    p_crack.add_argument(
        "--attack",
        choices=["dict", "brute", "rainbow"],
        required=True,
        help="Attack strategy to use.",
    )
    p_crack.add_argument(
        "--wordlist",
        default="wordlists/common.txt",
        help="Path to a wordlist (dict/rainbow attacks).",
    )
    p_crack.add_argument(
        "--max-length",
        type=int,
        default=4,
        help="Max password length for brute-force (default 4).",
    )
    p_crack.add_argument(
        "--charset",
        default="abcdefghijklmnopqrstuvwxyz0123456789",
        help="Character set for brute-force.",
    )

    return parser


def _cmd_hash(args: argparse.Namespace) -> int:
    if args.algorithm:
        algorithm = args.algorithm
    else:
        algorithm = ALGORITHM_MD5 if args.mode == "weak" else ALGORITHM_PBKDF2

    try:
        result = hash_password(
            password=args.password,
            algorithm=algorithm,
            use_salt=(args.mode == "strong"),
        )
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    print(result)
    return 0


def _cmd_crack(args: argparse.Namespace) -> int:
    # Strong-hash attacks are only meaningful for dictionary attacks in
    # this project (brute/rainbow are demonstrated on weak hashes).
    if args.mode == "strong" and args.attack in ("brute", "rainbow"):
        print(
            "[error] brute and rainbow attacks are only supported against "
            "weak (fast, unsalted) hashes in this project.",
            file=sys.stderr,
        )
        return 2

    # Reject obviously-malformed target hashes before running any attack.
    # This catches the PowerShell '$'-interpolation class of failure where
    # a syntactically broken hash would otherwise be reported as a miss.
    if not _looks_like_valid_hash(args.target_hash):
        print(
            f"[error] target hash does not look like a valid encoded hash: "
            f"{args.target_hash!r}. Expected 32/64 hex chars, salt:hash, "
            f"or pbkdf2_sha256$<iterations>$<salt>$<hash>. "
            f"Tip (PowerShell): single-quote hashes containing '$'.",
            file=sys.stderr,
        )
        return 2

    try:
        if args.attack == "dict":
            result = dictionary_attack(
                target_hash=args.target_hash,
                wordlist_path=args.wordlist,
                mode=args.mode,
            )
        elif args.attack == "brute":
            result = brute_force_attack(
                target_hash=args.target_hash,
                max_length=args.max_length,
                charset=args.charset,
            )
        else:  # rainbow
            result = rainbow_attack(
                target_hash=args.target_hash,
                wordlist_path=args.wordlist,
            )
    except FileNotFoundError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    if result is None:
        print("[result] not cracked")
        return 1

    print(f"[result] cracked: {result}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "hash":
        return _cmd_hash(args)
    if args.command == "crack":
        return _cmd_crack(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())