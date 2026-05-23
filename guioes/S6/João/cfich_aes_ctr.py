import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEY_SIZE = 32       # AES-256
NONCE_SIZE = 16     # initial counter block for AES-CTR


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

    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    out_file = f"{fich}.enc"
    with open(out_file, "wb") as out:
        out.write(nonce + ciphertext)

    print(f"[OK] Ficheiro cifrado: {out_file}")


def decrypt_file(fich: str, fkey: str) -> None:
    key = read_key(fkey)

    with open(fich, "rb") as f:
        data = f.read()

    if len(data) < NONCE_SIZE:
        raise ValueError("Criptograma inválido: tamanho insuficiente para conter nonce.")

    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

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