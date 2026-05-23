#!/usr/bin/env python3
import hashlib
import secrets
import sys
from pathlib import Path

KEY_SIZE = 32

## implementado o  SHA256 para evitar usar a biblioteca hashlib e facilitar o ataque de extensão de comprimento

def sha256_prefix_mac(key: bytes, message: bytes) -> bytes:
    return hashlib.sha256(key + message).digest()


def cmd_setup(fkey: str) -> None:
    key = secrets.token_bytes(KEY_SIZE)
    Path(fkey).write_bytes(key)


## ta incompleta, mas o resto do código é só para ler os ficheiros e chamar a função de MAC, que já está implementada


def cmd_mac(fich: str, fkey: str) -> None:
    key = Path(fkey).read_bytes()
    msg = Path(fich).read_bytes()
    mac = sha256_prefix_mac(key, msg).hex()
    Path(f"{fich}.mac").write_text(mac, encoding="ascii")


def cmd_ver(fich: str, fkey: str) -> None:
    key = Path(fkey).read_bytes()
    msg = Path(fich).read_bytes()
    stored_mac = Path(f"{fich}.mac").read_text(encoding="ascii").strip().lower()
    computed_mac = sha256_prefix_mac(key, msg).hex()
    print(computed_mac == stored_mac)


def usage() -> None:
    print("Uso:")
    print("  setup <fkey>")
    print("  mac <fich> <fkey>")
    print("  ver <fich> <fkey>")


def main() -> int:
    if len(sys.argv) < 2:
        usage()
        return 1

    op = sys.argv[1]
    try:
        if op == "setup" and len(sys.argv) == 3:
            cmd_setup(sys.argv[2])
            return 0
        if op == "mac" and len(sys.argv) == 4:
            cmd_mac(sys.argv[2], sys.argv[3])
            return 0
        if op == "ver" and len(sys.argv) == 4:
            cmd_ver(sys.argv[2], sys.argv[3])
            return 0
    except FileNotFoundError as err:
        print(f"Erro: ficheiro não encontrado: {err.filename}", file=sys.stderr)
        return 1

    usage()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
