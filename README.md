# Password Cracker

An educational password-cracking toolkit that demonstrates **why weak
passwords and fast, unsalted hashes fail**.

Built as Project #2 in a cybersecurity portfolio series. It is offline,
standard-library-only, and intended for authorized, local learning only —
see [`SECURITY.md`](SECURITY.md).

---

## Why weak passwords fail

Approximate time to crack, assuming an offline attack with a
consumer-grade GPU and a wordlist like rockyou:

| Password | MD5 (fast, unsalted) | PBKDF2-SHA256 (100k iters, salted) |
|---|---|---|
| `password123` | instant | instant (in wordlist) |
| `Summer2024!` | instant | seconds (in wordlist) |
| `P@ssw0rd` | minutes | hours |
| `Kx9#mP2$vL8&nQ5@` | years | effectively forever |

The lesson is in the **middle rows**. A password being in a wordlist — or
being reachable from a wordlist by a cheap mutation — is what makes it
fall. Once a password is *not* in any realistic wordlist, the per-guess
cost of a slow, salted hash turns the attack from seconds into years.

This project makes those three facts concrete:

1. **Weak, unsalted hashes fall in seconds.** The rainbow table demonstrates
   this starkly: a precomputed MD5 table cracks known passwords in under a
   millisecond, regardless of password complexity.
2. **A random per-password salt breaks precomputation.** The same lookup
   against a salted hash misses — the attacker has no table to consult.
3. **A slow hash makes brute force infeasible.** PBKDF2 at 100,000
   iterations turns a 2-character crack that took 3 milliseconds into a
   6-character crack that would take days.

---

## Features

- **Two hash modes:**
  - `weak` — MD5 or SHA-256, unsalted (the historical mistake).
  - `strong` — PBKDF2-HMAC-SHA256 with a fresh random salt and 100,000 iterations.
- **Three attacks:**
  - `dict` — dictionary attack with append-style mutations.
  - `brute` — brute force over a configurable charset and max length.
  - `rainbow` — precomputed MD5 table, cached to disk.
- **Honest about limits:** brute and rainbow are refused against strong
  hashes at the CLI, because they would run for hours. The restriction is
  a teaching constraint, not a technical one.
- **Standard-library only.** `hashlib`, `hmac`, `itertools`, `os`, `json`,
  `re`, `argparse`. No third-party runtime dependencies.

---

## Installation

Tested on Windows 11 + PowerShell and on Ubuntu CI.

```powershell
# 1. Clone
git clone https://github.com/AyeshaChughtaiIsMe/PasswordCracker.git
cd PasswordCracker

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate — PowerShell (recommended on Windows)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1

# 4. Install (editable, with dev extras)
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

Usage
All commands run from the project root. Hashes containing $ must be
single-quoted in PowerShell — see the gotcha below.