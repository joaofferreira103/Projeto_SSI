# Cifra um ficheiro usando ChaCha20 com Password-Based Encryption (PBKDF2)
import os
import sys
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


KEY_SIZE   = 32   # 256-bit key for ChaCha20
NONCE_SIZE = 16   # cryptography ChaCha20 expects 16-byte nonce
SALT_SIZE  = 16   # 128-bit salt for PBKDF2
PBKDF2_ITERATIONS = 480_000  # NIST SP 800-132 recommendation for PBKDF2-SHA256


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase)


def encrypt_file(fich: str) -> None:
    passphrase = getpass.getpass("Pass-phrase: ").encode()

    with open(fich, "rb") as f:
        plaintext = f.read()

    salt  = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key   = derive_key(passphrase, salt)

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)

    out_file = f"{fich}.enc"
    with open(out_file, "wb") as out:
        # formato: salt (16) | nonce (16) | criptograma
        out.write(salt + nonce + ciphertext)

    print(f"[OK] Ficheiro cifrado: {out_file}")


def decrypt_file(fich: str) -> None:
    passphrase = getpass.getpass("Pass-phrase: ").encode()

    with open(fich, "rb") as f:
        data = f.read()

    min_size = SALT_SIZE + NONCE_SIZE
    if len(data) < min_size:
        raise ValueError("Criptograma inválido: tamanho insuficiente para conter salt e NONCE.")

    salt       = data[:SALT_SIZE]
    nonce      = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(passphrase, salt)

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)

    out_file = f"{fich}.dec"
    with open(out_file, "wb") as out:
        out.write(plaintext)

    print(f"[OK] Ficheiro decifrado: {out_file}")


def usage() -> None:
    print("Uso:")
    print("  enc <fich>   -- cifra o ficheiro com uma pass-phrase")
    print("  dec <fich>   -- decifra o ficheiro com uma pass-phrase")


def main() -> None:
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)

    op = sys.argv[1].lower()

    try:
        if op == "enc":
            encrypt_file(sys.argv[2])
        elif op == "dec":
            decrypt_file(sys.argv[2])
        else:
            usage()
            sys.exit(1)

    except FileNotFoundError as e:
        print(f"[ERRO] Ficheiro não encontrado: {e.filename}")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERRO] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERRO] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
