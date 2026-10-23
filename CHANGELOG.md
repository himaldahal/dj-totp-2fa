# Changelog

## 0.1.0

First release.

- RFC 4226 / RFC 6238 TOTP in the standard library (SHA1, SHA256, SHA512, 6 to 8 digits), checked against the official test vectors.
- Replay protection, constant-time comparison over every window candidate, optional drift resync.
- Secrets at rest: plaintext or Fernet (optional `cryptography`), key rotation command.
- Recovery codes stored only as salted hashes, single use.
- Login wrapper, enforcement middleware, decorators, step-up re-verification, Django admin protection.
- Layered rate limiting (pending login, user, IP, site wide), progressive database backed lockouts.
- Trusted browser cookie, audit events, notification emails, privacy flags.
- Three themes (clean, midnight, aurora), client side QR code, English and Nepali.
- Management commands: totp_doctor, totp_simulate, totp_status, totp_disable, totp_reset_lockout, totp_purge_events, totp_rotate_keys, totp_settings, totp_enable_test, totp_code.
