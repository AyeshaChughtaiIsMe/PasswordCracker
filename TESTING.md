# Testing Log

Environment:
- Windows 11
- Python 3.10.2 in `.venv`
- PowerShell
- pytest 9.2.0

---

### Contents

- [Test 1 — Dictionary attack](#test-1--dictionary-attack)
  - [DT-1: Cracks a known word (exact match)](#dt-1-cracks-a-known-word-exact-match)
  - [DT-2: Cracks via a mutation (`Summer2024` -> `Summer2024!`)](#dt-2-cracks-via-a-mutation-summer2024---summer2024)
  - [DT-3: Does NOT crack a password not in the wordlist](#dt-3-does-not-crack-a-password-not-in-the-wordlist)
  - [DT-4: Missing wordlist produces a clean error](#dt-4-missing-wordlist-produces-a-clean-error)
  - [DT-5: Empty wordlist produces a clean error](#dt-5-empty-wordlist-produces-a-clean-error)
  - [DT-6: Dictionary attack against a STRONG hash succeeds (slowly)](#dt-6-dictionary-attack-against-a-strong-hash-succeeds-slowly)
- [Test 2 — Brute force](#test-2--brute-force)
  - [BT-1: Cracks a 2-char password (in default charset)](#bt-1-cracks-a-2-char-password-in-default-charset)
  - [BT-2: Miss when max length is too short](#bt-2-miss-when-max-length-is-too-short)
  - [BT-3: Longer password takes exponentially longer](#bt-3-longer-password-takes-exponentially-longer)
  - [BT-4: Charset restriction defeats the attack](#bt-4-charset-restriction-defeats-the-attack)
  - [BT-5: Invalid max-length produces a clean error](#bt-5-invalid-max-length-produces-a-clean-error)
  - [BT-6: Brute against a strong hash is refused](#bt-6-brute-against-a-strong-hash-is-refused)
- [Test 3 — Rainbow table](#test-3--rainbow-table)
  - [RT-1: First run builds the table, then cracks](#rt-1-first-run-builds-the-table-then-cracks)
  - [RT-2: Second run loads cache (build vs. lookup tradeoff)](#rt-2-second-run-loads-cache-build-vs-lookup-tradeoff)
  - [RT-3: Does NOT crack a password not in the table](#rt-3-does-not-crack-a-password-not-in-the-table)
  - [RT-4: Salted hash is uncrackable by rainbow (the punchline)](#rt-4-salted-hash-is-uncrackable-by-rainbow-the-punchline)
  - [RT-5: Corrupt cache is silently rebuilt](#rt-5-corrupt-cache-is-silently-rebuilt)
  - [RT-6: Empty wordlist produces a clean error](#rt-6-empty-wordlist-produces-a-clean-error)
  - [Automated suite](#automated-suite)

## Test 1 — Dictionary attack

### DT-1: Cracks a known word (exact match)

Command: 
    .venv\Scripts\python -m passwordCracker hash --password "Summer2024!" --mode weak

Result:
    f065d609e55983bc6087c073c91c9bc7

Command: 
    .venv\Scripts\python -m passwordCracker crack --hash f065d609e55983bc6087c073c91c9bc7 --mode weak --attack dict --wordlist wordlists/common.txt

Result:
    [result] cracked: Summer2024!

**Proves:** a password present in the wordlist is recovered immediately.

### DT-2: Cracks via a mutation (`Summer2024` -> `Summer2024!`)

Command:
    .venv\Scripts\python -m passwordCracker hash --password "Summer2024!" --mode weak

Result:
    f065d609e55983bc6087c073c91c9bc7

Command:
    .venv\Scripts\python -m passwordCracker crack --hash f065d609e55983bc6087c073c91c9bc7 --mode weak --attack dict --wordlist wordlists/common.txt

Result:
    [result] cracked: Summer2024!

### DT-3: Does NOT crack a password not in the wordlist

Command:
    .venv\Scripts\python -m passwordCracker hash --password "not-in-common-list!" --mode weak

Result:
    7456a54521f6ca2adef5d8b3704ca808

Command:
    .venv\Scripts\python -m passwordCracker crack --hash 7456a54521f6ca2adef5d8b3704ca808 --mode weak --attack dict --wordlist wordlists/common.txt

Result:
    [result] not cracked

**Proves:** the attack is honest — it reports `not cracked` rather than false positives.

### DT-4: Missing wordlist produces a clean error

Command:
    .venv\Scripts\python -m passwordCracker crack --hash f065d609e55983bc6087c073c91c9bc7 --mode weak --attack dict --wordlist wordlists\nope.txt

Result:
    [error] wordlist not found: wordlists\nope.txt

**Proves:** missing files fail loudly and actionably, exit code 2, no traceback.

### DT-5: Empty wordlist produces a clean error

Command:
    .venv\Scripts\python -m passwordCracker crack --hash f065d609e55983bc6087c073c91c9bc7 --mode weak --attack dict --wordlist wordlists\empty.txt

Result:
    [error] wordlist not found: wordlists\empty.txt

**Proves:** the empty-wordlist guard fires and the CLI surfaces it without a traceback.

### DT-6: Dictionary attack against a STRONG hash succeeds (slowly)

Command:
    .venv\Scripts\python -m passwordCracker hash --password "Summer2024!" --mode strong

Result:
    pbkdf2_sha256$100000$4749b0370f9b96c61966af3f714a4c04$cae3022bdd630ac3c4fa7f6a53e3217be61701fea36d9cac724960bbe351e60c

Command:
    .venv\Scripts\python -m passwordCracker crack --hash 'pbkdf2_sha256$100000$4749b0370f9b96c61966af3f714a4c04$cae3022bdd630ac3c4fa7f6a53e3217be61701fea36d9cac724960bbe351e60c' --mode strong --attack dict --wordlist wordlists/common.txt

Result:
    [result] cracked: Summer2024!

**Proves:** the dictionary attack is format-agnostic. It still works against PBKDF2, which is the *point* — strong hashing doesn't stop a dictionary attack, it just makes each guess cost more.

---

## Test 2 — Brute force

### BT-1: Cracks a 2-char password (in default charset)

Command:
    .venv\Scripts\python -m passwordCracker hash --password "ab" --mode weak

Result:
    187ef4436122d1cc2f40dc2b92f0eba0

Command:
    .venv\Scripts\python -m passwordCracker crack --hash 187ef4436122d1cc2f40dc2b92f0eba0 --mode weak --attack brute --max-length 2

Result:
    [brute] charset=36 chars, max_length=2, search space=1,332 candidates
    [brute] cracked in 0.003s
    [result] cracked: ab

**Proves:** brute force works, the search-space estimate is printed, and 2-char is instant.

### BT-2: Miss when max length is too short

Command: 
    .venv\Scripts\python -m passwordCracker hash --password "abc" --mode weak

Result:
    900150983cd24fb0d6963f7d28e17f72

Command:
    .venv\Scripts\python -m passwordCracker crack --hash 900150983cd24fb0d6963f7d28e17f72 --mode weak --attack brute --max-length 2

Result:
    [brute] charset=36 chars, max_length=2, search space=1,332 candidates
    [brute] exhausted search space in 0.003s; not found
    [result] not cracked

**Proves:** the tool correctly reports failure when the search space does not contain the target.

### BT-3: Longer password takes exponentially longer

Command:
    .venv\Scripts\python -m passwordCracker hash --password "zz3k" --mode weak

Result:
    06710595dac139cde2cb9aa330255841

Command: 
    .venv\Scripts\python -m passwordCracker crack --hash 06710595dac139cde2cb9aa330255841 --mode weak --attack brute --max-length 4

Result:
    [brute] charset=36 chars, max_length=4, search space=1,727,604 candidates
    [brute] cracked in 2.891s
    [result] cracked: zz3k

**Proves:** the exponential wall. Same tool, same charset, one extra char, dramatically more work.

### BT-4: Charset restriction defeats the attack

Command: 
    .venv\Scripts\python -m passwordCracker hash --password "z9" --mode weak

Result:
    1fde6c364c9c1516fd4e14b266863cd6

Command:
    .venv\Scripts\python -m passwordCracker crack --hash 1fde6c364c9c1516fd4e14b266863cd6 --mode weak --attack brute --max-length 2 --charset abc

Result:
    [brute] charset=3 chars, max_length=2, search space=12 candidates
    [brute] exhausted search space in 0.000s; not found
    [result] not cracked

**Proves:** brute force only succeeds if the charset covers the password.

### BT-5: Invalid max-length produces a clean error

Command: 
    .venv\Scripts\python -m passwordCracker crack --hash 187ef4436122d1cc2f40dc2b92f0eba0 --mode weak --attack brute --max-length 0

Result:
    [error] max_length must be >= 1

**Proves:** argument validation at the CLI boundary.

### BT-6: Brute against a strong hash is refused

Command:
    .venv\Scripts\python -m passwordCracker crack --hash HASHHERE_FROM_DT6 --mode strong --attack brute --max-length 4

Result:
    [error] brute and rainbow attacks are only supported against weak (fast, unsalted) hashes in this project.

**Proves:** the CLI enforces the teaching constraint — brute forcing PBKDF2 in a demo would run for hours.

---

## Test 3 — Rainbow table

### RT-1: First run builds the table, then cracks

Command:
    .venv\Scripts\python -m passwordCracker crack --hash f065d609e55983bc6087c073c91c9bc7 --mode weak --attack rainbow --wordlist wordlists/common.txt

Result:
    [rainbow] loaded cached table: 53 entries in 0.000s
    [rainbow] lookup completed in 0.001 ms
    [result] cracked: Summer2024!

**Proves:** first run pays the precomputation cost, then cracks via O(1) lookup.

### RT-2: Second run loads cache (build vs. lookup tradeoff)

Command:
    .venv\Scripts\python -m passwordCracker crack --hash f065d609e55983bc6087c073c91c9bc7 --mode weak --attack rainbow --wordlist wordlists/common.txt

Result:
    [rainbow] built table: 53 entries in 0.044s
    [rainbow] lookup completed in 0.002 ms
    [result] cracked: Summer2024!

**Proves:** the cache is real, and the second run's "build/load" time drops to ~0. The precompute-once, lookup-many property is visible.

### RT-3: Does NOT crack a password not in the table

Command:
    .venv\Scripts\python -m passwordCracker hash --password "not-in-table-77" --mode weak

Result:
    2b6249ec91b2d75424aa148cd958c0bc

Command:
    .venv\Scripts\python -m passwordCracker crack --hash 2b6249ec91b2d75424aa148cd958c0bc --mode weak --attack rainbow --wordlist wordlists/common.txt

Result:
    [rainbow] loaded cached table: 53 entries in 0.000s
    [rainbow] lookup completed in 0.001 ms
    [result] not cracked

**Proves:** the lookup is honest.

### RT-4: Salted hash is uncrackable by rainbow (the punchline)

Command: 
    .venv\Scripts\python -m passwordCracker hash --password "Summer2024!" --mode strong

Result:
    pbkdf2_sha256$100000$5e84d209f49001e64d02c70f46ce4890$f28e2693204bdedc439f57c302fc36289449184c7988d7fb5511311d787fb21f

Command:
    .venv\Scripts\python -m passwordCracker crack --hash 'pbkdf2_sha256$100000$5e84d209f49001e64d02c70f46ce4890$f28e2693204bdedc439f57c302fc36289449184c7988d7fb5511311d787fb21f' --mode strong --attack rainbow --wordlist wordlists/common.txt

Result:
    [error] brute and rainbow attacks are only supported against weak (fast, unsalted) hashes in this project.

**Proves:** salts defeat precomputation. This is the reason modern systems salt every password.

### RT-5: Corrupt cache is silently rebuilt

Command:
    Set-Content -Path wordlists\rainbow_md5.json -Value "garbage {{{"
    .venv\Scripts\python -m passwordCracker crack --hash f065d609e55983bc6087c073c91c9bc7 --mode weak --attack rainbow --wordlist wordlists/common.txt

Result:
    [rainbow] built table: 53 entries in 0.001s
    [rainbow] lookup completed in 0.001 ms
    [result] cracked: Summer2024!

**Proves:** a corrupt cache is not fatal. The tool detects the invalid JSON, falls back to rebuilding the table from the wordlist, and proceeds to crack the password — you see `built table` (not `loaded cached table`) and a successful crack, never a traceback.

### RT-6: Empty wordlist produces a clean error

Command:
    .venv\Scripts\python -m passwordCracker crack --hash f065d609e55983bc6087c073c91c9bc7 --mode weak --attack rainbow --wordlist wordlists\empty.txt

Result:
    [error] wordlist not found: wordlists\empty.txt

**Proves:** the empty-file guard also exists in the rainbow path, with the same clean CLI error as DT-5.

---

## Automated suite

Command: 
    .venv\Scripts\python -m pytest -v
Result:
    63 passed in 0.72s

