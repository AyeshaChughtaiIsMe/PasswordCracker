# Security Policy

## Educational use only

This project is a **teaching tool**. It exists to make concrete why weak
passwords and fast, unsalted hashes fail. It is not intended to be used as
a practical cracking tool, and it is not a substitute for a real password
auditing product.

## Authorized use

You may use this tool only against:

- Hashes you generated yourself for learning or testing.
- Hashes from a system you own, with the explicit written permission of
  the system's owner.
- Hashes provided to you as part of an authorized security assessment,
  under a signed scope agreement.

Unauthorized access to computer systems is a criminal offense in most
jurisdictions, including but not limited to:

- **United States:** Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030.
- **United Kingdom:** Computer Misuse Act 1990.
- **European Union:** Directive 2013/40/EU on attacks against information
  systems, as implemented in each member state's national law.

"It was just a password hash" is not a defense. Password hashes are
authentication credentials; cracking one without authorization is
unauthorized access.

## Scope of the tool

- **Offline only.** No network calls, no live-system interaction, no
  service enumeration. Everything operates on hash strings you supply.
- **Local filesystem only.** Reads a wordlist you point it at. Writes a
  cache file under `wordlists/`. Does not touch anything else.
- **No credential harvesting.** The tool does not read password stores,
  browser databases, or OS credential managers. It has no code path to do so.

## What this tool does NOT do

To set expectations honestly:

- It does not implement a real rainbow table. The "rainbow" attack is a
  plain `{hash: plaintext}` dictionary lookup, not a chained-reduction
  table. It demonstrates the same precompute-then-lookup property at the
  cost of disk space.
- It does not implement GPU acceleration, rule-based mangling, or the
  large wordlists (rockyou, etc.) that real-world cracking relies on.
- It is not competitive with Hashcat or John the Ripper. It is not meant
  to be.

## Reporting a vulnerability

This is a personal educational project, not a maintained product. If you
find a bug in the *tool itself* (not a weakness in the algorithms it
demonstrates — that's the point), open an issue on the GitHub repository.

## A note on the algorithms

The tool demonstrates the weakness of MD5 and SHA-256 as password-storage
hashes, and the strength of PBKDF2-HMAC-SHA256 with a random per-password
salt and a high iteration count. These properties are well-established
and documented by OWASP, NIST, and others. The project does not claim to
discover anything new; it makes the existing knowledge tangible.