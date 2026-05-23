#!/usr/bin/env python3
import hashlib
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PBAESG01"
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERS = 200_000
KEY_SIZE = 32


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, KDF_ITERS, dklen=KEY_SIZE)


def encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    header = MAGIC + salt + nonce
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, header)
    return header + ciphertext_and_tag


def decrypt(blob: bytes, password: str) -> bytes:
    min_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16
    if len(blob) < min_size:
        raise ValueError("Formato inválido (muito curto)")

    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("Formato inválido (magic incorreta)")

    offset = len(MAGIC)
    salt = blob[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext_and_tag = blob[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    header = MAGIC + salt + nonce
    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, header)
    except Exception as err:
        raise ValueError("Falha de integridade/autenticação (GCM tag inválida)") from err


def usage() -> None:
    print("Uso:")
    print("  enc <fich> <password>")
    print("  dec <fich.enc> <password>")


def main() -> int:
    if len(sys.argv) != 4:
        usage()
        return 1

    op, file_name, password = sys.argv[1], sys.argv[2], sys.argv[3]

    try:
        if op == "enc":
            plaintext = Path(file_name).read_bytes()
            blob = encrypt(plaintext, password)
            Path(f"{file_name}.enc").write_bytes(blob)
            return 0

        if op == "dec":
            blob = Path(file_name).read_bytes()
            plaintext = decrypt(blob, password)
            out_name = file_name[:-4] if file_name.endswith(".enc") else f"{file_name}.dec"
            Path(out_name).write_bytes(plaintext)
            return 0

    except FileNotFoundError as err:
        print(f"Erro: ficheiro não encontrado: {err.filename}", file=sys.stderr)
        return 1
    except ValueError as err:
        print(f"Erro: {err}", file=sys.stderr)
        return 1

    usage()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
