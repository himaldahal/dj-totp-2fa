# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub security advisories
(https://github.com/himaldahal/dj-totp-2fa/security/advisories/new) instead of opening a public issue.
Include the version, a description and, if possible, a way to reproduce it. We aim to reply within a few days.

## Threat model in short

dj-totp-2fa protects against an attacker who knows or guesses a password but does not hold the user's authenticator.
It limits online guessing of codes, refuses replayed codes, keeps secrets and recovery codes out of logs and (optionally)
encrypted at rest, and makes the second step enforceable on every login route.
It does not protect against malware on the user's device, real-time phishing proxies, a compromised server or a stolen
database combined with plaintext secrets. See docs/security.md for the full model and deployment checklist.
