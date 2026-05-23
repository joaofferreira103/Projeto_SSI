import os
import sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEY_SIZE = 32       # AES-256
BLOCK_SIZE = 16     # AES block size in bytes


def setup_key(fkey: str) -> None:
    key = os.urandom(KEY_SIZE)
    with open(fkey, "wb") as fk:
        fk.write(key)
    print(f"[OK] Chave criada em: {fkey}")


def read_key(fkey: str) -> bytes:
    with open(fkey, "rb") as fk:
        key = fk.read()

    if len(key) != KEY_SIZE:
        raise ValueError(f"Chave inválida: esperado {KEY_SIZE} bytes, obtido {len(key)} bytes.")

    return key


def encrypt_file(fich: str, fkey: str) -> None:
    key = read_key(fkey)

    with open(fich, "rb") as f:
        plaintext = f.read()

    iv = os.urandom(BLOCK_SIZE)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    out_file = f"{fich}.enc"
    with open(out_file, "wb") as out:
        out.write(iv + ciphertext)

    print(f"[OK] Ficheiro cifrado: {out_file}")


def decrypt_file(fich: str, fkey: str) -> None:
    key = read_key(fkey)

    with open(fich, "rb") as f:
        data = f.read()

    if len(data) < BLOCK_SIZE:
        raise ValueError("Criptograma inválido: tamanho insuficiente para conter IV.")

    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Criptograma inválido: tamanho do ciphertext não é múltiplo do bloco.")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    out_file = f"{fich}.dec"
    with open(out_file, "wb") as out:
        out.write(plaintext)

    print(f"[OK] Ficheiro decifrado: {out_file}")


def usage() -> None:
    print("Uso:")
    print("  setup <fkey>")
    print("  enc <fich> <fkey>")
    print("  dec <fich> <fkey>")


def main() -> None:
    if len(sys.argv) < 3:
        usage()
        sys.exit(1)

    op = sys.argv[1].lower()

    try:
        if op == "setup":
            if len(sys.argv) != 3:
                usage()
                sys.exit(1)
            setup_key(sys.argv[2])

        elif op == "enc":
            if len(sys.argv) != 4:
                usage()
                sys.exit(1)
            encrypt_file(sys.argv[2], sys.argv[3])

        elif op == "dec":
            if len(sys.argv) != 4:
                usage()
                sys.exit(1)
            decrypt_file(sys.argv[2], sys.argv[3])

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