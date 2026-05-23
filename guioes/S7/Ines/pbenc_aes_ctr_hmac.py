#!/usr/bin/env python3
import hashlib
import hmac
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"PBAESCH1"
SALT_SIZE = 16
NONCE_SIZE = 16
HMAC_SIZE = 32
KDF_ITERS = 200_000
ENC_KEY_SIZE = 32
MAC_KEY_SIZE = 32


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    key_material = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, KDF_ITERS, dklen=ENC_KEY_SIZE + MAC_KEY_SIZE
    )
    return key_material[:ENC_KEY_SIZE], key_material[ENC_KEY_SIZE:]


def encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    enc_key, mac_key = derive_keys(password, salt)

    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    header = MAGIC + salt + nonce
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


def decrypt(blob: bytes, password: str) -> bytes:
    min_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + HMAC_SIZE
    if len(blob) < min_size:
        raise ValueError("Formato inválido (muito curto)")

    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("Formato inválido (magic incorreta)")

    offset = len(MAGIC)
    salt = blob[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext = blob[offset:-HMAC_SIZE]
    tag = blob[-HMAC_SIZE:]

    enc_key, mac_key = derive_keys(password, salt)
    expected = hmac.new(mac_key, blob[:-HMAC_SIZE], hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Falha de integridade/autenticação (HMAC inválido)")

    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


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
