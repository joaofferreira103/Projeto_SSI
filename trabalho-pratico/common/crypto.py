"""
Design principle: every crypto operation in the project goes through this module.
No other file should import directly from `cryptography.*`.

"""

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidTag

# Import PBKDF2 - compatible with both old and new cryptography versions
try:
    # Versão mais recente (como no PC do amigo)
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
except ImportError:
    # Fallback para versões antigas
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    """
    Generate an ephemeral X25519 key pair.

    Returns:
        (private_key, public_key_bytes) — private key stays in memory;
        public_key_bytes are 32 raw bytes ready to send over the wire.
    """
    private_key = X25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, pub_bytes


def derive_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_bytes: bytes,
    info: bytes = b"chat-e2ee-v1",
) -> bytes:
    """
    Perform X25519 ECDH and derive a 32-byte AES-256 key via HKDF-SHA256.
    
    Returns:
        32 bytes suitable as an AES-256-GCM key.
    """
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    raw_secret = private_key.exchange(peer_public_key)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend(),
    ).derive(raw_secret)


def public_bytes_to_hex(public_bytes: bytes) -> str:
    """Serialize public key bytes to hex for JSON transport."""
    return public_bytes.hex()


def hex_to_public_bytes(hex_str: str) -> bytes:
    """Deserialize hex-encoded public key back to bytes."""
    return bytes.fromhex(hex_str)


GCM_NONCE_SIZE = 12


def encrypt_message(key: bytes, plaintext: str) -> str:
    """
    Encrypt a plaintext string with AES-256-GCM.

    Args:
        key:       32-byte symmetric key (from derive_shared_secret).
        plaintext: UTF-8 message to encrypt.

    Returns:
        Hex string: nonce (12 bytes) + ciphertext + GCM tag (16 bytes).
    """
    nonce = os.urandom(GCM_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # nonce is public — receiver needs it to decrypt; tag is inside ciphertext
    return (nonce + ciphertext).hex()


def decrypt_message(key: bytes, ciphertext_hex: str) -> str:
    """
    Decrypt a hex-encoded AES-256-GCM blob produced by encrypt_message.

    Raises:
        InvalidTag: if the ciphertext has been tampered with or the key is wrong.
            Callers MUST catch this and discard the message; never display it.
        ValueError: if the hex string is malformed or too short.

    Returns:
        The original plaintext string.
    """
    raw = bytes.fromhex(ciphertext_hex)
    if len(raw) < GCM_NONCE_SIZE + 16:  # nonce + minimum 1-byte payload + 16-byte tag
        raise ValueError("Ciphertext too short to be valid")

    nonce = raw[:GCM_NONCE_SIZE]
    ciphertext = raw[GCM_NONCE_SIZE:]

    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext_bytes.decode("utf-8")


#----------------------------SCRIPTS DA DATABASE------------------------------------------


SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32


def hash_password(password: str) -> str:
    """
    Hash a password with a fresh random salt using Scrypt.

    Returns:
        "salt_hex:hash_hex" string for database storage.
    """
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt, length=SCRYPT_LENGTH,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))
    return f"{salt.hex()}:{key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """
    Verify a plaintext password against a stored "salt_hex:hash_hex".

    Returns:
        True on match, False otherwise.
    """
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False

    kdf = Scrypt(
        salt=salt, length=SCRYPT_LENGTH,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        backend=default_backend(),
    )
    try:
        kdf.verify(password.encode("utf-8"), expected)
        return True
    except InvalidKey:
        return False


# Messagens offline 


def generate_offline_keypair() -> tuple[X25519PrivateKey, bytes]:
    """
    Generate a persistent X25519 key pair for offline messaging.
    
    This is semantically identical to generate_x25519_keypair(), but intended
    to be generated once per user and stored (encrypted) locally.
    
    Returns:
        (private_key, public_key_bytes) — same format as ephemeral keypair.
    """
    return generate_x25519_keypair()


def encrypt_offline_key(password: str, private_key: X25519PrivateKey, username: str) -> str:
    """
    Encrypt an offline private key with a password for local storage.
    
    The offline key is derived from the user's password and username,
    allowing the user to recover it as long as they remember their password
    and username.
    
    Args:
        password: User's login password
        private_key: X25519PrivateKey to encrypt
        username: Username (used as deterministic salt for PBKDF2)
    
    Returns:
        "salt_hex:nonce_hex:ciphertext_hex" for local storage.
    
    Raises:
        ValueError: if serialization fails
    """
    # Extract raw 32-byte private key
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    
    # Deterministic PBKDF2 salt: SHA256(username)[:16]
    # This ensures same password+username always produces same master key
    salt_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    salt_hash.update(username.encode("utf-8"))
    pbkdf2_salt = salt_hash.finalize()[:16]
    
    # Derive 32-byte master key via PBKDF2-SHA256
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pbkdf2_salt,
        iterations=100000,
        backend=default_backend(),
    )
    master_key = kdf.derive(password.encode("utf-8"))
    
    # Encrypt private key with AES-256-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(master_key)
    ciphertext = aesgcm.encrypt(nonce, priv_bytes, None)
    
    # Return as hex-encoded triplet
    return f"{pbkdf2_salt.hex()}:{nonce.hex()}:{ciphertext.hex()}"


def decrypt_offline_key(password: str, encrypted_blob: str, username: str) -> X25519PrivateKey:
    """
    Decrypt an offline private key from local storage.
    
    Args:
        password: User's login password
        encrypted_blob: "salt_hex:nonce_hex:ciphertext_hex" from storage
        username: Username (must match the one used during encryption)
    
    Returns:
        X25519PrivateKey
    
    Raises:
        ValueError: if blob format is invalid or username doesn't match
        InvalidTag: if password is wrong or blob is tampered
    """
    try:
        parts = encrypted_blob.split(":")
        if len(parts) != 3:
            raise ValueError("Invalid encrypted blob format: expected 3 parts")
        pbkdf2_salt = bytes.fromhex(parts[0])
        nonce = bytes.fromhex(parts[1])
        ciphertext = bytes.fromhex(parts[2])
    except (ValueError, AttributeError) as e:
        raise ValueError(f"Failed to parse encrypted blob: {e}")
    
    # Verify salt matches username
    expected_salt_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    expected_salt_hash.update(username.encode("utf-8"))
    expected_salt = expected_salt_hash.finalize()[:16]
    
    if pbkdf2_salt != expected_salt:
        raise ValueError("Username mismatch: this offline key belongs to a different user")
    
    # Derive master key
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pbkdf2_salt,
        iterations=100000,
        backend=default_backend(),
    )
    master_key = kdf.derive(password.encode("utf-8"))
    
    # Decrypt private key (raises InvalidTag if password wrong)
    aesgcm = AESGCM(master_key)
    priv_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    
    # Convert back to X25519PrivateKey
    return X25519PrivateKey.from_private_bytes(priv_bytes)


def derive_offline_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_bytes: bytes,
) -> bytes:
    """
    Perform X25519 ECDH with offline key pair to derive shared secret.
    
    This is identical to derive_shared_secret() but uses a different
    HKDF info string to ensure offline secrets are distinct from session secrets.
    
    Args:
        private_key: User's offline X25519PrivateKey
        peer_public_bytes: Peer's offline public key (32 bytes)
    
    Returns:
        32-byte shared secret suitable as an AES-256-GCM key.
    
    Raises:
        ValueError: if peer_public_bytes is invalid format
    """
    return derive_shared_secret(
        private_key,
        peer_public_bytes,
        info=b"chat-e2ee-offline-v1",
    )