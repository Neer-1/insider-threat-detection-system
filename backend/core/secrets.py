# NEW — reversible encryption for secrets that must be readable again later
# (a company's SMTP password), as opposed to auth/security.py's password
# hashing (Admin.password_hash), which is deliberately one-way. Different
# operation, kept in its own module rather than bolted onto security.py.

"""
Fernet (cryptography.fernet) -- a standard, simple, well-established choice
for exactly this: symmetric authenticated encryption with a single key,
no certificate/PKI machinery, no custom scheme to get subtly wrong. The
key itself (core/config.py's SMTP_ENCRYPTION_KEY) lives only in the
environment, never in the database -- ciphertext without the env-supplied
key is just noise, matching the same "the secret that unlocks other
secrets stays outside the DB" boundary SECRET_KEY already holds for JWTs.

Only ever called from notifications/ (encrypting a submitted SMTP
password before it's written, decrypting it in memory at the moment an
email is actually being sent) -- the plaintext password is never logged,
never returned from any API response, and never stored anywhere except
transiently in memory during a send.
"""

from cryptography.fernet import Fernet, InvalidToken

from backend.core.config import SMTP_ENCRYPTION_KEY

_fernet = Fernet(SMTP_ENCRYPTION_KEY.encode() if isinstance(SMTP_ENCRYPTION_KEY, str) else SMTP_ENCRYPTION_KEY)


def encrypt_secret(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Raises cryptography.fernet.InvalidToken if the ciphertext doesn't
    match the current SMTP_ENCRYPTION_KEY (wrong/rotated key, or corrupted
    data) -- deliberately NOT swallowed here, since silently returning a
    wrong/empty password would fail an SMTP login in a much more
    confusing way than a clear decryption error. Callers (notifications/)
    let this propagate into their own already-defensive try/except around
    the whole send attempt."""
    return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


__all__ = ["encrypt_secret", "decrypt_secret", "InvalidToken"]
